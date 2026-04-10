#!/usr/bin/env python3
"""
scripts/test_live.py — Test the Mimecast connector against the real API.

Never sends events to Sekoia.IO.  Reads credentials from a .env file only.

Usage (run from the Mimecast-Akonis/ directory):
    python scripts/test_live.py
    python scripts/test_live.py --env /path/to/.env
    python scripts/test_live.py --days 2
    python scripts/test_live.py --fetchers siem_stream,ttp_url_logs,audit_events
    python scripts/test_live.py --max-pages 3   # pages per paginated fetcher

Expected .env keys:
    MIMECAST_CLIENT_ID       OAuth2 client ID  (API 2.0) — required
    MIMECAST_CLIENT_SECRET   OAuth2 client secret        — required
    MIMECAST_ACCESS_KEY      API 1.0 access key          — required for HMAC tests
    MIMECAST_SECRET_KEY      API 1.0 secret key (base64) — required for HMAC tests
    MIMECAST_APP_ID          API 1.0 application ID      — required for HMAC tests
    MIMECAST_APP_KEY         API 1.0 application key     — required for HMAC tests
    MIMECAST_BASE_URL        API 2.0 base URL            — default https://api.services.mimecast.com
    MIMECAST_BASE_URL_V1     API 1.0 base URL (region)  — default https://us-api.mimecast.com
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# sys.path — make mimecast_modules importable when the script is run from the
# Mimecast-Akonis/ directory (or from anywhere via an absolute path).
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_MODULE_ROOT = os.path.dirname(_SCRIPT_DIR)  # Mimecast-Akonis/
if _MODULE_ROOT not in sys.path:
    sys.path.insert(0, _MODULE_ROOT)

try:
    from mimecast_modules.client.http_client import MimecastClient
    from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError
except ImportError as exc:
    sys.exit(
        f"Cannot import mimecast_modules: {exc}\n"
        "Run the script from the Mimecast-Akonis/ directory:\n"
        "  python scripts/test_live.py"
    )

# ---------------------------------------------------------------------------
# Terminal colours (disabled automatically when stdout is not a TTY)
# ---------------------------------------------------------------------------

_USE_COLOUR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def green(t: str) -> str:  return _c("32", t)
def red(t: str)   -> str:  return _c("31", t)
def yellow(t: str) -> str: return _c("33", t)
def bold(t: str)  -> str:  return _c("1",  t)
def dim(t: str)   -> str:  return _c("2",  t)


# ---------------------------------------------------------------------------
# .env parser (no python-dotenv dependency)
# ---------------------------------------------------------------------------

def _load_env_file(path: str) -> Dict[str, str]:
    """Parse a .env file and return a dict of key→value pairs."""
    env: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes (single or double)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            env[key] = value
    return env


def load_env(path: Optional[str] = None) -> Dict[str, str]:
    """
    Search for a .env file in the following order:
      1. ``path`` argument (CLI --env)
      2. Current working directory
      3. Parent directory of this script (Mimecast-Akonis/)
    Values are merged into os.environ so that later calls to os.getenv() work.
    """
    candidates = []
    if path:
        candidates.append(path)
    candidates += [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(_MODULE_ROOT, ".env"),
        os.path.join(_SCRIPT_DIR, ".env"),
    ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            env = _load_env_file(candidate)
            os.environ.update(env)
            return env

    return {}  # no file found — rely on environment variables already set


def _require(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        sys.exit(f"Missing required environment variable: {key}")
    return value


def _optional(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


# ---------------------------------------------------------------------------
# Timestamp extraction
# ---------------------------------------------------------------------------

# Common timestamp field names across Mimecast event types, in priority order.
_TS_FIELDS = (
    "eventTime", "date", "datetime", "timestamp", "time",
    "createdAt", "updatedAt", "detectionTime", "sentDate",
)


def _extract_timestamp(event: Any) -> Optional[str]:
    """Return the first recognisable timestamp string found in an event dict."""
    if not isinstance(event, dict):
        return None
    for field_name in _TS_FIELDS:
        value = event.get(field_name)
        if isinstance(value, str) and value:
            return value
    # One level deep: look inside every dict-valued key
    for v in event.values():
        if isinstance(v, dict):
            ts = _extract_timestamp(v)
            if ts:
                return ts
    return None


def _ts_range(events: List[Any]) -> Tuple[str, str]:
    """Return (first_ts, last_ts) from a list of events, or ("—", "—") if unavailable."""
    timestamps = [t for e in events if (t := _extract_timestamp(e))]
    if not timestamps:
        return "—", "—"
    return timestamps[0], timestamps[-1]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FetchResult:
    name: str
    count: int = 0
    first_ts: str = "—"
    last_ts: str = "—"
    status: str = "OK"
    error: str = ""
    elapsed: float = 0.0
    skipped: bool = False


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _start_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

def test_oauth2(client: MimecastClient) -> None:
    """Test OAuth2 authentication and print token expiry."""
    print(f"\n{bold('[ AUTH ] OAuth2 (API 2.0)')}")
    t0 = time.time()
    try:
        client._refresh_oauth_token()
        expires_in = int(client._oauth_token_expiry - time.time()) + 300  # re-add the 5 min buffer
        print(f"  {green('✓')} OAuth2 OK — token expires in {expires_in}s "
              f"(~{expires_in // 60} min)  [{time.time() - t0:.2f}s]")
    except (MimecastAuthError, MimecastAPIError) as exc:
        print(f"  {red('✗')} OAuth2 FAILED: {exc}")
        sys.exit(1)


def test_hmac_account(client: MimecastClient) -> None:
    """
    Test HMAC-SHA1 authentication by calling POST /api/account/get-account
    and printing the account name.
    """
    print(f"\n{bold('[ AUTH ] HMAC-SHA1 (API 1.0)')}")
    if not all([client._access_key, client._secret_key, client._app_id, client._app_key]):
        print(f"  {yellow('⚠')} HMAC credentials not configured — skipping HMAC test")
        return

    t0 = time.time()
    try:
        resp = client.post_v1("/api/account/get-account", body={"data": [{}]})
        payload = resp.json()
        # The API returns a list under "data"; the first item has account details.
        accounts = payload.get("data", [])
        account_name = "—"
        if accounts and isinstance(accounts[0], dict):
            account_name = accounts[0].get("accountName") or accounts[0].get("name") or "—"
        print(f"  {green('✓')} HMAC OK — account: {bold(account_name)}  [{time.time() - t0:.2f}s]")
    except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError) as exc:
        print(f"  {red('✗')} HMAC FAILED: {exc}")


# ---------------------------------------------------------------------------
# Individual fetcher tests
# — Each function makes the same HTTP calls as the connector but collects events
#   into a local list instead of calling push_events_to_intakes().
# — Only the first `max_pages` pages are fetched to keep the test fast.
# ---------------------------------------------------------------------------

def _paginated_v1(
    client: MimecastClient,
    endpoint: str,
    data_payload: dict,
    chunk_size: int,
    max_pages: int,
) -> List[dict]:
    """Replicate _fetch_paginated_v1 logic, returning collected items."""
    items: List[dict] = []
    page_token: Optional[str] = None
    page = 0

    while page < max_pages:
        meta: dict = {"pagination": {"pageSize": chunk_size}}
        if page_token:
            meta["pagination"]["pageToken"] = page_token

        body = {"meta": meta, "data": [data_payload]}
        resp = client.post_v1(endpoint, body=body)
        payload = resp.json()

        for result in payload.get("data", []):
            if isinstance(result, list):
                items.extend(result)
            elif isinstance(result, dict):
                found = False
                for val in result.values():
                    if isinstance(val, list):
                        items.extend(val)
                        found = True
                        break
                if not found:
                    items.append(result)

        next_token = (
            payload.get("meta", {}).get("pagination", {}).get("next", {}).get("pageToken")
        )
        page += 1
        if not next_token:
            break
        page_token = next_token

    return items


def _run(name: str, fn) -> FetchResult:
    """Execute a fetcher function, catch all exceptions, and return a FetchResult."""
    result = FetchResult(name=name)
    print(f"  {dim('→')} {name} ...", end=" ", flush=True)
    t0 = time.time()
    try:
        events = fn()
        result.elapsed = time.time() - t0
        result.count = len(events)
        result.first_ts, result.last_ts = _ts_range(events)
        print(f"{green('OK')} ({result.count} events, {result.elapsed:.2f}s)")
    except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError) as exc:
        result.elapsed = time.time() - t0
        result.status = "ERROR"
        result.error = str(exc)[:80]
        print(f"{red('ERROR')} — {result.error}")
    except Exception as exc:
        result.elapsed = time.time() - t0
        result.status = "ERROR"
        result.error = f"{type(exc).__name__}: {exc}"[:80]
        print(f"{red('ERROR')} — {result.error}")
    return result


# ---- GROUP 1 — SIEM & Security Logs ----------------------------------------

def fetch_siem_stream(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    events: List[dict] = []
    page_token: Optional[str] = None
    page = 0
    while page < max_pages:
        params: dict = {"fileFormat": "JSON"}
        if page_token:
            params["pageToken"] = page_token
        resp = client.get_v2("/api/siem/v1/batch/events/cg", params=params)
        payload = resp.json()
        events.extend(payload.get("data", []))
        next_token = payload.get("nextToken")
        page += 1
        if payload.get("isCaughtUp", False) or not next_token:
            break
        page_token = next_token
    return events


def fetch_siem_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    """Binary/gzip SIEM log stream — all log types, first page only per type."""
    events: List[dict] = []
    for log_type in ("MTA", "receipt", "process", "jrnl", "delivery"):
        data_entry: dict = {"type": log_type, "compress": True}
        try:
            resp = client.post_v1_raw("/api/audit/get-siem-logs", body={"data": [data_entry]})
        except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError):
            continue
        raw = resp.content
        if not raw:
            continue
        try:
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
        except Exception:
            pass
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    obj["_log_type"] = log_type
                    events.append(obj)
                else:
                    events.append({"message": line, "_log_type": log_type})
            except json.JSONDecodeError:
                events.append({"message": line, "_log_type": log_type})
    return events


def fetch_ttp_url_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/ttp/url/get-logs",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso(),
         "route": "all", "scanResult": "all"},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_ttp_attachment_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/ttp/attachment/get-logs",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_ttp_impersonation_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/ttp/impersonation/get-logs",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso(),
         "taggedMalicious": True},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_dlp_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/dlp/get-logs",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_audit_events(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/audit/get-audit-events",
        {"startDateTime": _start_iso(days), "endDateTime": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_rejection_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/gateway/get-rejections",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


def fetch_message_release_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/gateway/get-message-release-logs",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


# ---- GROUP 2 — Threat Intelligence ------------------------------------------

def fetch_threat_events(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    events: List[dict] = []
    page_token: Optional[str] = None
    page = 0
    start_ts = _start_iso(days)
    now_ts = _now_iso()
    while page < max_pages:
        params: dict = {"timestampRangeStartsAt": start_ts, "timestampRangeEndsAt": now_ts}
        if page_token:
            params["pageToken"] = page_token
        resp = client.get_v2("/api/ttp/threat/find-in-batch", params=params)
        payload = resp.json()
        events.extend(payload.get("data", []))
        next_token = payload.get("nextToken")
        page += 1
        if not next_token:
            break
        page_token = next_token
    return events


def fetch_threat_intel_feed(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    items: List[dict] = []
    for feed_type in ("malware_customer", "malware_grid"):
        try:
            resp = client.post_v1(
                "/api/ttp/threatintel/get-feed",
                body={"data": [{"feedType": feed_type}]},
            )
        except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError):
            continue
        payload = resp.json()
        if payload.get("fail"):
            continue
        for result in payload.get("data", []):
            if isinstance(result, list):
                items.extend(result)
            elif isinstance(result, dict):
                items.extend(result.get("items", []))
    return items


def fetch_threat_incidents(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    return _paginated_v1(
        client, "/api/ttp/remediation/find-incidents",
        {"oldestFirst": True, "from": _start_iso(days), "to": _now_iso()},
        chunk_size=100, max_pages=max_pages,
    )


# ---- GROUP 3 — Awareness Training -------------------------------------------

def fetch_awareness_training(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    items: List[dict] = []
    endpoints = [
        "/api/awareness-training/company/get-safe-score-details",
        "/api/awareness-training/company/get-safe-score-summary",
        "/api/awareness-training/phishing/get-campaigns",
        "/api/awareness-training/phishing/get-user-data",
        "/api/awareness-training/company/get-watchlist-details",
        "/api/awareness-training/company/get-performance-details",
    ]
    for ep in endpoints:
        try:
            resp = client.post_v1(ep, body={"data": [{}]})
        except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError):
            continue
        payload = resp.json()
        for result in payload.get("data", []):
            if isinstance(result, list):
                items.extend(result)
            elif isinstance(result, dict):
                items.append(result)
    return items


# ---- GROUP 4 — Web Security -------------------------------------------------

def fetch_web_security_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    items: List[dict] = []
    for log_type, endpoint in (
        ("dns", "/api/ess/dns-logs"),
        ("proxy", "/api/ess/proxy-logs"),
    ):
        try:
            resp = client.post_v1(endpoint, body={"data": [{}]})
        except (MimecastAuthError, MimecastAPIError, MimecastRateLimitError):
            continue
        payload = resp.json()
        for result in payload.get("data", []):
            if isinstance(result, dict):
                items.extend(result.get("logs", []))
            elif isinstance(result, list):
                items.extend(result)
    return items


# ---- GROUP 5 — Archive Logs -------------------------------------------------

def fetch_archive_logs(client: MimecastClient, days: int, max_pages: int) -> List[dict]:
    items: List[dict] = []
    for endpoint in (
        "/api/audit/get-archive-search-logs",
        "/api/audit/get-archive-message-view-logs",
    ):
        items.extend(
            _paginated_v1(
                client, endpoint,
                {"from": _start_iso(days), "to": _now_iso()},
                chunk_size=100, max_pages=max_pages,
            )
        )
    return items


# ---------------------------------------------------------------------------
# Fetcher registry
# ---------------------------------------------------------------------------

# Each entry: (name, function, requires_hmac)
FETCHER_REGISTRY = [
    ("siem_stream",           fetch_siem_stream,           False),
    ("siem_logs",             fetch_siem_logs,             True),
    ("ttp_url_logs",          fetch_ttp_url_logs,          True),
    ("ttp_attachment_logs",   fetch_ttp_attachment_logs,   True),
    ("ttp_impersonation_logs",fetch_ttp_impersonation_logs,True),
    ("dlp_logs",              fetch_dlp_logs,              True),
    ("audit_events",          fetch_audit_events,          True),
    ("rejection_logs",        fetch_rejection_logs,        True),
    ("message_release_logs",  fetch_message_release_logs,  True),
    ("threat_events",         fetch_threat_events,         False),
    ("threat_intel_feed",     fetch_threat_intel_feed,     True),
    ("threat_incidents",      fetch_threat_incidents,      True),
    ("awareness_training",    fetch_awareness_training,    True),
    ("web_security_logs",     fetch_web_security_logs,     True),
    ("archive_logs",          fetch_archive_logs,          True),
]

FETCHER_NAMES = [name for name, _, _ in FETCHER_REGISTRY]


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def print_summary(results: List[FetchResult]) -> None:
    """Print a box-drawing summary table to stdout."""

    # Column widths
    W_NAME   = max(24, max(len(r.name) for r in results))
    W_COUNT  = 7
    W_TS     = 24
    W_STATUS = 30
    W_TIME   = 7

    sep = (
        f"┼{'─' * (W_NAME + 2)}┼{'─' * (W_COUNT + 2)}┼{'─' * (W_TS + 2)}"
        f"┼{'─' * (W_TS + 2)}┼{'─' * (W_STATUS + 2)}┼{'─' * (W_TIME + 2)}┤"
    )
    top = sep.replace("┼", "┬").replace("┤", "┐").replace("─┬", "─┌", 1)
    bot = sep.replace("┼", "┴").replace("┤", "┘")
    hdr_sep = sep.replace("┼", "╪").replace("┤", "╡").replace("─╪", "─╞", 1)

    def row(name: str, count: str, first: str, last: str, status: str, t: str) -> str:
        return (
            f"│ {name:<{W_NAME}} │ {count:>{W_COUNT}} │ {first:<{W_TS}} "
            f"│ {last:<{W_TS}} │ {status:<{W_STATUS}} │ {t:>{W_TIME}} │"
        )

    print(f"\n{bold('─' * 10 + '  SUMMARY  ' + '─' * 10)}")
    print(top)
    print(row("Fetcher", "Events", "First event", "Last event", "Status", "Time(s)"))
    print(hdr_sep)

    ok_count = 0
    total_events = 0
    for r in results:
        if r.skipped:
            status_str = yellow("SKIP (no HMAC creds)")
        elif r.status == "OK":
            status_str = green(f"✓ OK")
            ok_count += 1
            total_events += r.count
        else:
            status_str = red(f"✗ {_trunc(r.error, W_STATUS - 2)}")

        # Strip ANSI codes for width calculation, pad manually
        raw_status = r.error[:W_STATUS] if r.status == "ERROR" else ""
        visible_status = f"✓ OK" if r.status == "OK" and not r.skipped else \
                         ("SKIP (no HMAC creds)" if r.skipped else f"✗ {_trunc(r.error, W_STATUS - 2)}")
        pad = W_STATUS - len(visible_status)
        padded_status = status_str + (" " * pad)

        print(
            f"│ {r.name:<{W_NAME}} │ {r.count:>{W_COUNT}} │ "
            f"{_trunc(r.first_ts, W_TS):<{W_TS}} │ {_trunc(r.last_ts, W_TS):<{W_TS}} │ "
            f"{padded_status} │ {r.elapsed:>{W_TIME}.2f} │"
        )

    print(bot)
    errors = [r for r in results if r.status == "ERROR"]
    skipped = [r for r in results if r.skipped]
    print(
        f"\n  {bold('Total:')} {ok_count}/{len(results) - len(skipped)} fetchers OK"
        f" — {bold(str(total_events))} events collected"
        + (f" — {yellow(str(len(skipped)))} skipped" if skipped else "")
        + (f" — {red(str(len(errors)))} errors" if errors else "")
    )

    if errors:
        print(f"\n  {bold('Errors:')}")
        for r in errors:
            print(f"    {red('✗')} {r.name}: {r.error}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_client(hmac_available: bool) -> MimecastClient:
    return MimecastClient(
        base_url=_optional("MIMECAST_BASE_URL", "https://api.services.mimecast.com"),
        client_id=_require("MIMECAST_CLIENT_ID"),
        client_secret=_require("MIMECAST_CLIENT_SECRET"),
        base_url_v1=_optional("MIMECAST_BASE_URL_V1", "https://us-api.mimecast.com"),
        access_key=_optional("MIMECAST_ACCESS_KEY") or None,
        secret_key=_optional("MIMECAST_SECRET_KEY") or None,
        app_id=_optional("MIMECAST_APP_ID") or None,
        app_key=_optional("MIMECAST_APP_KEY") or None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live test for the Mimecast connector — never sends to Sekoia.IO.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available fetchers:\n  " + "\n  ".join(FETCHER_NAMES),
    )
    parser.add_argument(
        "--env", metavar="FILE",
        help="Path to .env file (default: auto-detected)",
    )
    parser.add_argument(
        "--days", type=int, default=1,
        help="Historical window in days for time-range queries (default: 1)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=1, dest="max_pages",
        help="Max pages to fetch per paginated endpoint (default: 1)",
    )
    parser.add_argument(
        "--fetchers", metavar="f1,f2,...",
        help="Comma-separated list of fetchers to run (default: all)",
    )
    args = parser.parse_args()

    # ---- Load credentials ---------------------------------------------------
    env_file = load_env(args.env)
    if env_file:
        print(dim(f"Loaded .env from {args.env or '[auto-detected]'}"))

    hmac_available = all([
        _optional("MIMECAST_ACCESS_KEY"),
        _optional("MIMECAST_SECRET_KEY"),
        _optional("MIMECAST_APP_ID"),
        _optional("MIMECAST_APP_KEY"),
    ])

    client = build_client(hmac_available)

    print(bold(f"\n{'='*60}"))
    print(bold("  Mimecast Connector — Live API Test"))
    print(bold(f"{'='*60}"))
    print(f"  Base URL (v2): {_optional('MIMECAST_BASE_URL', 'https://api.services.mimecast.com')}")
    print(f"  Base URL (v1): {_optional('MIMECAST_BASE_URL_V1', 'https://us-api.mimecast.com')}")
    print(f"  Window:        last {args.days} day(s)")
    print(f"  Max pages:     {args.max_pages}")
    print(f"  HMAC creds:    {'yes' if hmac_available else yellow('no — v1 fetchers will be skipped')}")

    # ---- Auth tests ---------------------------------------------------------
    test_oauth2(client)
    test_hmac_account(client)

    # ---- Determine which fetchers to run ------------------------------------
    selected: Optional[List[str]] = None
    if args.fetchers:
        selected = [f.strip() for f in args.fetchers.split(",")]
        unknown = [f for f in selected if f not in FETCHER_NAMES]
        if unknown:
            sys.exit(f"Unknown fetcher(s): {', '.join(unknown)}\nValid: {', '.join(FETCHER_NAMES)}")

    # ---- Run fetchers -------------------------------------------------------
    print(f"\n{bold('[ FETCHERS ]')}")
    results: List[FetchResult] = []

    for name, fn, requires_hmac in FETCHER_REGISTRY:
        if selected and name not in selected:
            continue
        if requires_hmac and not hmac_available:
            r = FetchResult(name=name, skipped=True)
            print(f"  {yellow('⊘')} {name} — skipped (no HMAC credentials)")
            results.append(r)
            continue
        result = _run(name, lambda f=fn: f(client, args.days, args.max_pages))
        results.append(result)

    # ---- Summary table ------------------------------------------------------
    if results:
        print_summary(results)
    else:
        print("\nNo fetchers were run.")


if __name__ == "__main__":
    main()
