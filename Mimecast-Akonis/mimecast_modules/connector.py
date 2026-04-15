"""Mimecast SIEM connector — polls all Mimecast security event sources and forwards them to Sekoia."""

import gzip
import io
import json
import time
from datetime import datetime, timedelta, timezone
from functools import cached_property
from typing import Generator, List, Optional

from sekoia_automation.connector import Connector, DefaultConnectorConfiguration
from sekoia_automation.storage import PersistentJSON
from pydantic.v1 import Field

from . import MimecastModule
from .client import MimecastClient
from .client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError
from .metrics import EVENTS_LAG, FORWARD_EVENTS_DURATION, INCOMING_EVENTS, OUTCOMING_EVENTS


class MimecastConnectorConfiguration(DefaultConnectorConfiguration):
    # ---- Polling settings ----
    frequency: int = Field(60, description="Seconds between polling cycles")
    chunk_size: int = Field(100, description="Max events per batch sent to Sekoia")
    historical_days: int = Field(7, description="Days of history to fetch on first run")

    # ---- Feature flags ----
    enable_siem_stream: bool = True
    enable_siem_logs: bool = True
    enable_ttp_url_logs: bool = True
    enable_ttp_attachment_logs: bool = True
    enable_ttp_impersonation_logs: bool = True
    enable_dlp_logs: bool = True
    enable_audit_events: bool = True
    enable_rejection_logs: bool = True
    enable_message_release_logs: bool = True
    enable_threat_events: bool = True
    enable_threat_intel_feed: bool = True
    enable_threat_incidents: bool = True
    enable_awareness_training: bool = False  # daily polling, off by default
    enable_web_security_logs: bool = False   # requires Web Security licence
    enable_archive_logs: bool = False        # requires Archive licence


class MimecastConnector(Connector):
    """Main Mimecast connector — one run() loop calling per-source fetchers."""

    module: MimecastModule
    configuration: MimecastConnectorConfiguration

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._state = PersistentJSON("context.json", self._data_path)

    # ------------------------------------------------------------------
    # HTTP client (lazy, single instance)
    # ------------------------------------------------------------------

    @staticmethod
    def _secret(val) -> str:
        """Return the plain-text value whether val is SecretStr or a raw str.

        The Sekoia SDK injects secrets via setattr(), bypassing pydantic
        validation, so SecretStr fields may arrive as plain str at runtime.
        """
        return val.get_secret_value() if hasattr(val, "get_secret_value") else val

    @cached_property
    def _has_v1_creds(self) -> bool:
        """True if all API 1.0 credentials are configured."""
        mod = self.module.configuration
        return all([mod.access_key, mod.secret_key, mod.app_id, mod.app_key])

    @cached_property
    def client(self) -> MimecastClient:
        mod = self.module.configuration
        return MimecastClient(
            base_url=mod.base_url,
            client_id=mod.client_id,
            client_secret=self._secret(mod.client_secret),
            base_url_v1=mod.base_url_v1,
            access_key=mod.access_key,
            secret_key=self._secret(mod.secret_key) if mod.secret_key else None,
            app_id=mod.app_id,
            app_key=self._secret(mod.app_key) if mod.app_key else None,
        )

    # ------------------------------------------------------------------
    # Cursor helpers (persistent state)
    # ------------------------------------------------------------------

    def _get_cursor(self, name: str) -> Optional[str]:
        with self._state as cache:
            return cache.get(name)

    def _set_cursor(self, name: str, value: str) -> None:
        with self._state as cache:
            cache[name] = value

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt_iso(dt: datetime) -> str:
        """Format a datetime as Mimecast expects: no microseconds, +0000 suffix."""
        return dt.strftime("%Y-%m-%dT%H:%M:%S+0000")

    def _start_iso(self) -> str:
        """Return an ISO-8601 timestamp `historical_days` ago (for first-run seeding)."""
        dt = datetime.now(timezone.utc) - timedelta(days=self.configuration.historical_days)
        return self._fmt_iso(dt)

    def _now_iso(self) -> str:
        return self._fmt_iso(datetime.now(timezone.utc))

    def _push_batch(self, events: List[dict], source: str) -> None:
        """Serialize a list of event dicts and push them to the intake."""
        if not events:
            return

        batch = [json.dumps(e) for e in events]
        INCOMING_EVENTS.labels(intake_key=self.configuration.intake_key, source=source).inc(len(batch))

        start = time.time()
        self.push_events_to_intakes(events=batch)
        duration = time.time() - start

        OUTCOMING_EVENTS.labels(intake_key=self.configuration.intake_key, source=source).inc(len(batch))
        FORWARD_EVENTS_DURATION.labels(intake_key=self.configuration.intake_key, source=source).observe(duration)

        self.log(message=f"[{source}] Pushed {len(batch)} events", level="info")

    def _push_lines(self, lines: List[str], source: str) -> None:
        """Push pre-serialized JSON strings to the intake."""
        if not lines:
            return

        INCOMING_EVENTS.labels(intake_key=self.configuration.intake_key, source=source).inc(len(lines))
        start = time.time()
        self.push_events_to_intakes(events=lines)
        duration = time.time() - start
        OUTCOMING_EVENTS.labels(intake_key=self.configuration.intake_key, source=source).inc(len(lines))
        FORWARD_EVENTS_DURATION.labels(intake_key=self.configuration.intake_key, source=source).observe(duration)

        self.log(message=f"[{source}] Pushed {len(lines)} events", level="info")

    # ------------------------------------------------------------------
    # Generic paginated fetcher helpers
    # ------------------------------------------------------------------

    def _fetch_paginated_v1(
        self,
        endpoint: str,
        data_payload: dict,
        cursor_name: str,
        source_name: str,
    ) -> None:
        """
        Generic helper for API 1.0 endpoints that paginate via meta.pagination.next.pageToken.

        The caller provides the inner `data` list item dict (e.g. date range, filters).
        This method drives pagination, collects events, and updates the cursor.

        The time-window cursor (ISO timestamp) lives under `cursor_name` and is managed
        exclusively by the caller.  This method uses a *separate* key
        ``{cursor_name}_page_token`` to track the current pagination position so the
        two concerns never collide.
        """
        page_cursor_name = f"{cursor_name}_page_token"
        page_token: Optional[str] = self._get_cursor(page_cursor_name)

        while self.running:
            meta: dict = {"pagination": {"pageSize": self.configuration.chunk_size}}
            if page_token:
                meta["pagination"]["pageToken"] = page_token

            body = {"meta": meta, "data": [data_payload]}

            try:
                resp = self.client.post_v1(endpoint, body=body)
            except MimecastAPIError as exc:
                # 404 = endpoint not available on this tenant (licence or wrong URL) — not a bug
                level = "warning" if exc.status_code == 404 else "error"
                self.log(message=f"[{source_name}] API error, skipping this cycle: {exc}", level=level)
                return
            except (MimecastRateLimitError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source_name}] API error, skipping this cycle")
                return

            payload = resp.json()
            fail = payload.get("fail", [])
            if fail:
                self.log(message=f"[{source_name}] API returned failures: {fail}", level="warning")

            items: List[dict] = []
            for result in payload.get("data", []):
                if isinstance(result, list):
                    items.extend(result)
                elif isinstance(result, dict):
                    # Mimecast uses different field names per endpoint (logs, audits, etc.)
                    # Prefer any list-valued key; fall back to the dict itself as one event.
                    found = False
                    for val in result.values():
                        if isinstance(val, list):
                            items.extend(val)
                            found = True
                            break
                    if not found:
                        items.append(result)

            if items:
                self._push_batch(items, source_name)

            # Mimecast pagination: "next" may be a dict {"pageToken": "..."} (most endpoints)
            # or a plain string token (e.g. audit_events). Handle both forms.
            pagination = payload.get("meta", {}).get("pagination", {})
            next_val = pagination.get("next")
            if isinstance(next_val, dict):
                next_token = next_val.get("pageToken")
            elif isinstance(next_val, str) and next_val:
                next_token = next_val
            else:
                next_token = None
            if not next_token:
                # Pagination complete — clear the page-token cursor so the next cycle
                # starts fresh from the beginning of the new time window.
                self._set_cursor(page_cursor_name, "")
                break

            page_token = next_token
            self._set_cursor(page_cursor_name, page_token)

    # ------------------------------------------------------------------
    # GROUP 1 — SIEM & Security Logs
    # ------------------------------------------------------------------

    def _fetch_siem_stream(self) -> None:
        """1.1 SIEM Stream API (API 2.0) — real-time email security events."""
        source = "siem_stream"
        page_token: Optional[str] = self._get_cursor("siem_stream_token")

        while self.running:
            params: dict = {"fileFormat": "JSON"}
            if page_token:
                params["pageToken"] = page_token

            try:
                resp = self.client.get_v2("/api/siem/v1/batch/events/cg", params=params)
            except (MimecastRateLimitError, MimecastAPIError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}] API error")
                return

            payload = resp.json()
            events = payload.get("data", [])

            lines: List[str] = []
            for event in events:
                lines.append(json.dumps(event) if isinstance(event, dict) else event)

            if lines:
                self._push_lines(lines, source)

            next_token = payload.get("nextToken")
            if next_token:
                self._set_cursor("siem_stream_token", next_token)
                page_token = next_token

            if payload.get("isCaughtUp", False):
                self.log(message=f"[{source}] Caught up — stopping poll", level="info")
                break

            if not next_token:
                break

    def _fetch_siem_logs(self) -> None:
        """1.2 SIEM Logs (API 1.0) — MTA logs as compressed binary stream."""
        source = "siem_logs"
        for log_type in ("MTA", "receipt", "process", "jrnl", "delivery"):
            if not self.running:
                return
            cursor_name = f"siem_logs_token_{log_type}"
            token = self._get_cursor(cursor_name)

            data_entry: dict = {"type": log_type, "compress": True}
            if token:
                data_entry["token"] = token

            try:
                resp = self.client.post_v1_raw(
                    "/api/audit/get-siem-logs",
                    body={"data": [data_entry]},
                )
            except (MimecastRateLimitError, MimecastAPIError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}/{log_type}] API error")
                continue

            # Save the new token from response header
            new_token = resp.headers.get("mc-siem-token")
            if new_token:
                self._set_cursor(cursor_name, new_token)

            content_type = resp.headers.get("Content-Type", "")
            raw = resp.content
            if not raw:
                continue

            # Decompress if gzip
            try:
                if "octet-stream" in content_type or self._is_gzip(raw):
                    raw = gzip.decompress(raw)
            except Exception:
                pass  # Not gzip, use as-is

            lines: List[str] = []
            for line in raw.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    # Try to parse as JSON; if not, wrap as raw string event
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict):
                            event.setdefault("_log_type", log_type)
                            lines.append(json.dumps(event))
                        else:
                            lines.append(json.dumps({"message": line, "_log_type": log_type}))
                    except json.JSONDecodeError:
                        lines.append(json.dumps({"message": line, "_log_type": log_type}))

            if lines:
                self._push_lines(lines, source)

    @staticmethod
    def _is_gzip(data: bytes) -> bool:
        return data[:2] == b"\x1f\x8b"

    def _fetch_ttp_url_logs(self) -> None:
        """1.3 TTP URL Logs (API 1.0) — clicks on malicious URLs."""
        source = "ttp_url_logs"
        cursor = self._get_cursor("ttp_url_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
            "route": "all",
            "scanResult": "all",
        }
        self._fetch_paginated_v1("/api/ttp/url/get-logs", data_payload, "ttp_url_logs_cursor", source)
        # Advance timestamp cursor to now so next run doesn't re-fetch old events
        self._set_cursor("ttp_url_logs_cursor", self._now_iso())

    def _fetch_ttp_attachment_logs(self) -> None:
        """1.4 TTP Attachment Protection Logs (API 1.0) — attachment scan results."""
        source = "ttp_attachment_logs"
        cursor = self._get_cursor("ttp_attachment_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
        }
        self._fetch_paginated_v1(
            "/api/ttp/attachment/get-logs", data_payload, "ttp_attachment_logs_cursor", source
        )
        self._set_cursor("ttp_attachment_logs_cursor", self._now_iso())

    def _fetch_ttp_impersonation_logs(self) -> None:
        """1.5 TTP Impersonation Protection Logs (API 1.0) — identity spoofing detections."""
        source = "ttp_impersonation_logs"
        cursor = self._get_cursor("ttp_impersonation_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
            "taggedMalicious": True,
        }
        self._fetch_paginated_v1(
            "/api/ttp/impersonation/get-logs", data_payload, "ttp_impersonation_logs_cursor", source
        )
        self._set_cursor("ttp_impersonation_logs_cursor", self._now_iso())

    def _fetch_dlp_logs(self) -> None:
        """1.6 DLP Logs (API 1.0) — messages that triggered a DLP policy."""
        source = "dlp_logs"
        cursor = self._get_cursor("dlp_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
        }
        self._fetch_paginated_v1("/api/dlp/get-logs", data_payload, "dlp_logs_cursor", source)
        self._set_cursor("dlp_logs_cursor", self._now_iso())

    def _fetch_audit_events(self) -> None:
        """1.7 Audit Events (API 1.0) — admin traceability events."""
        source = "audit_events"
        cursor = self._get_cursor("audit_events_cursor")

        data_payload = {
            "startDateTime": cursor or self._start_iso(),
            "endDateTime": self._now_iso(),
        }
        self._fetch_paginated_v1(
            "/api/audit/get-audit-events", data_payload, "audit_events_cursor", source
        )
        self._set_cursor("audit_events_cursor", self._now_iso())

    def _fetch_rejection_logs(self) -> None:
        """1.8 Rejection Logs (API 1.0) — rejected emails."""
        source = "rejection_logs"
        cursor = self._get_cursor("rejection_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
        }
        self._fetch_paginated_v1(
            "/api/gateway/get-rejections", data_payload, "rejection_logs_cursor", source
        )
        self._set_cursor("rejection_logs_cursor", self._now_iso())

    def _fetch_message_release_logs(self) -> None:
        """1.9 Message Release Logs (API 1.0) — messages released from quarantine."""
        source = "message_release_logs"
        cursor = self._get_cursor("message_release_logs_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
        }
        self._fetch_paginated_v1(
            "/api/gateway/get-message-release-logs",
            data_payload,
            "message_release_logs_cursor",
            source,
        )
        self._set_cursor("message_release_logs_cursor", self._now_iso())

    # ------------------------------------------------------------------
    # GROUP 2 — Threat Intelligence
    # ------------------------------------------------------------------

    def _fetch_threat_events(self) -> None:
        """2.1 Threat Events API 2.0 — detailed threat detections."""
        source = "threat_events"
        cursor = self._get_cursor("threat_events_cursor")
        start_ts = cursor or self._start_iso()
        now_ts = self._now_iso()

        page_token: Optional[str] = None
        while self.running:
            params: dict = {"timestampRangeStartsAt": start_ts, "timestampRangeEndsAt": now_ts}
            if page_token:
                params["pageToken"] = page_token

            try:
                resp = self.client.get_v2("/api/ttp/threat/find-in-batch", params=params)
            except (MimecastRateLimitError, MimecastAPIError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}] API error")
                return

            payload = resp.json()
            events = payload.get("data", [])
            if events:
                self._push_batch(events, source)

            next_token = payload.get("nextToken")
            if not next_token:
                break
            page_token = next_token

        self._set_cursor("threat_events_cursor", now_ts)

    def _fetch_threat_intel_feed(self) -> None:
        """2.2 Threat Intel Feed (API 1.0) — Mimecast IOC feeds."""
        source = "threat_intel_feed"
        for feed_type, cursor_name in (
            ("malware_customer", "threat_intel_malware_customer_token"),
            ("malware_grid", "threat_intel_malware_grid_token"),
        ):
            if not self.running:
                return
            token = self._get_cursor(cursor_name)
            data_entry: dict = {"feedType": feed_type}
            if token:
                data_entry["token"] = token

            try:
                resp = self.client.post_v1(
                    "/api/ttp/threatintel/get-feed", body={"data": [data_entry]}
                )
            except MimecastAPIError as exc:
                level = "warning" if exc.status_code == 404 else "error"
                self.log(message=f"[{source}/{feed_type}] API error: {exc}", level=level)
                continue
            except (MimecastRateLimitError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}/{feed_type}] API error")
                continue

            payload = resp.json()
            fail = payload.get("fail", [])
            if fail:
                self.log(message=f"[{source}/{feed_type}] failures: {fail}", level="warning")
                continue

            items: List[dict] = []
            for result in payload.get("data", []):
                if isinstance(result, list):
                    items.extend(result)
                elif isinstance(result, dict):
                    items.extend(result.get("items", []))

            if items:
                self._push_batch(items, f"{source}_{feed_type}")

            # Save the new token for next run
            for result in payload.get("data", []):
                if isinstance(result, dict):
                    new_token = result.get("token")
                    if new_token:
                        self._set_cursor(cursor_name, new_token)

    def _fetch_threat_incidents(self) -> None:
        """2.4 Threat Intel Incidents (API 1.0) — security incidents."""
        source = "threat_incidents"
        cursor = self._get_cursor("threat_incidents_cursor")

        data_payload = {
            "oldestFirst": True,
            "from": cursor or self._start_iso(),
            "to": self._now_iso(),
        }
        self._fetch_paginated_v1(
            "/api/ttp/remediation/find-incidents", data_payload, "threat_incidents_cursor", source
        )
        self._set_cursor("threat_incidents_cursor", self._now_iso())

    # ------------------------------------------------------------------
    # GROUP 3 — Awareness Training (daily polling)
    # ------------------------------------------------------------------

    def _fetch_awareness_training(self) -> None:
        """Group 3 — Awareness Training data (SAFE scores, phishing campaigns, watchlists)."""
        source = "awareness_training"

        # Only poll once per day
        last_run_str = self._get_cursor("awareness_training_last_run")
        if last_run_str:
            last_run = datetime.fromisoformat(last_run_str)
            # Ensure the parsed datetime is timezone-aware before comparing with
            # datetime.now(timezone.utc) — fromisoformat() may return a naive object
            # when the stored string has no UTC offset (Python < 3.11 behaviour).
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - last_run < timedelta(hours=24):
                return

        endpoints = [
            "/api/awareness-training/company/get-safe-score-details",
            "/api/awareness-training/company/get-safe-score-summary",
            "/api/awareness-training/phishing/get-campaigns",
            "/api/awareness-training/phishing/get-user-data",
            "/api/awareness-training/company/get-watchlist-details",
            "/api/awareness-training/company/get-performance-details",
        ]
        for endpoint in endpoints:
            if not self.running:
                return
            try:
                resp = self.client.post_v1(endpoint, body={"data": [{}]})
            except (MimecastRateLimitError, MimecastAPIError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}] Error on {endpoint}")
                continue

            payload = resp.json()
            items: List[dict] = []
            for result in payload.get("data", []):
                if isinstance(result, list):
                    items.extend(result)
                elif isinstance(result, dict):
                    items.append(result)

            if items:
                ep_label = endpoint.split("/")[-1]
                self._push_batch(items, f"{source}_{ep_label}")

        self._set_cursor("awareness_training_last_run", self._now_iso())

    # ------------------------------------------------------------------
    # GROUP 4 — Web Security / ESS Logs
    # ------------------------------------------------------------------

    def _fetch_web_security_logs(self) -> None:
        """Group 4 — Web Security DNS and Proxy event logs."""
        source = "web_security"
        for log_type, cursor_name, endpoint in (
            ("dns", "web_security_dns_token", "/api/ess/dns-logs"),
            ("proxy", "web_security_proxy_token", "/api/ess/proxy-logs"),
        ):
            if not self.running:
                return
            token = self._get_cursor(cursor_name)
            data_entry: dict = {}
            if token:
                data_entry["url"] = token

            try:
                resp = self.client.post_v1(endpoint, body={"data": [data_entry]})
            except (MimecastRateLimitError, MimecastAPIError, MimecastAuthError) as exc:
                self.log_exception(exc, message=f"[{source}/{log_type}] API error")
                continue

            payload = resp.json()
            items: List[dict] = []
            new_token: Optional[str] = None
            for result in payload.get("data", []):
                if isinstance(result, dict):
                    items.extend(result.get("logs", []))
                    new_token = result.get("url") or result.get("token") or new_token
                elif isinstance(result, list):
                    items.extend(result)

            if items:
                self._push_batch(items, f"{source}_{log_type}")

            if new_token:
                self._set_cursor(cursor_name, new_token)

    # ------------------------------------------------------------------
    # GROUP 5 — Archive Logs
    # ------------------------------------------------------------------

    def _fetch_archive_logs(self) -> None:
        """Group 5 — Archive search and message view logs."""
        source = "archive_logs"
        for log_type, cursor_name, endpoint in (
            ("search", "archive_search_logs_cursor", "/api/audit/get-archive-search-logs"),
            ("message_view", "archive_message_view_logs_cursor", "/api/audit/get-archive-message-view-logs"),
        ):
            if not self.running:
                return
            cursor = self._get_cursor(cursor_name)
            data_payload = {
                "from": cursor or self._start_iso(),
                "to": self._now_iso(),
            }
            self._fetch_paginated_v1(endpoint, data_payload, cursor_name, f"{source}_{log_type}")
            self._set_cursor(cursor_name, self._now_iso())

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    def run(self) -> None:  # pragma: no cover
        self.log(message="Mimecast connector starting", level="info")

        if not self._has_v1_creds:
            self.log(
                message=(
                    "API 1.0 credentials (access_key, secret_key, app_id, app_key) are not "
                    "configured — all API 1.0 fetchers will be skipped. "
                    "Only SIEM Stream and Threat Events (API 2.0) will run."
                ),
                level="warning",
            )

        while self.running:
            cycle_start = time.time()
            v1 = self._has_v1_creds

            fetchers = [
                # API 2.0 fetchers — always available when enabled
                (self.configuration.enable_siem_stream, self._fetch_siem_stream),
                (self.configuration.enable_threat_events, self._fetch_threat_events),
                # API 1.0 fetchers — skipped silently if v1 creds are absent
                (self.configuration.enable_siem_logs and v1, self._fetch_siem_logs),
                (self.configuration.enable_ttp_url_logs and v1, self._fetch_ttp_url_logs),
                (self.configuration.enable_ttp_attachment_logs and v1, self._fetch_ttp_attachment_logs),
                (self.configuration.enable_ttp_impersonation_logs and v1, self._fetch_ttp_impersonation_logs),
                (self.configuration.enable_dlp_logs and v1, self._fetch_dlp_logs),
                (self.configuration.enable_audit_events and v1, self._fetch_audit_events),
                (self.configuration.enable_rejection_logs and v1, self._fetch_rejection_logs),
                (self.configuration.enable_message_release_logs and v1, self._fetch_message_release_logs),
                (self.configuration.enable_threat_intel_feed and v1, self._fetch_threat_intel_feed),
                (self.configuration.enable_threat_incidents and v1, self._fetch_threat_incidents),
                (self.configuration.enable_awareness_training and v1, self._fetch_awareness_training),
                (self.configuration.enable_web_security_logs and v1, self._fetch_web_security_logs),
                (self.configuration.enable_archive_logs and v1, self._fetch_archive_logs),
            ]

            for enabled, fetcher in fetchers:
                if not self.running:
                    break
                if enabled:
                    try:
                        fetcher()
                    except Exception as exc:
                        self.log_exception(exc, message=f"Unhandled error in {fetcher.__name__}")

            elapsed = time.time() - cycle_start
            sleep_time = self.configuration.frequency - elapsed
            if sleep_time > 0:
                self.log(message=f"Cycle done in {elapsed:.1f}s — sleeping {sleep_time:.1f}s", level="info")
                time.sleep(sleep_time)
