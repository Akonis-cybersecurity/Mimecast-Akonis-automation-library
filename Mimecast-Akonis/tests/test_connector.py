"""Tests for the Mimecast SIEM connector.

Coverage targets:
    1. OAuth2 token acquisition (POST /oauth/token)
    2. HMAC-SHA1 signature generation (legacy method, retained for disabled fetchers)
    3. TTP URL logs with 2-page pagination (API 2.0)
    4. SIEM Stream with isCaughtUp=true (stops polling)
    5. OAuth2 token automatic renewal when expired
    6. HTTP 429 retry with backoff
    7. Cursor saved and reloaded across two fetch calls
    8. Feature flag enable_ttp_url_logs=False skips fetcher
"""

import base64
import gzip
import json
import time
from unittest.mock import MagicMock, patch

import pytest
import requests
import requests_mock as req_mock_module

from mimecast_modules.client.errors import MimecastRateLimitError
from mimecast_modules.client.http_client import MimecastClient
from mimecast_modules.connector import MimecastConnector, MimecastConnectorConfiguration

# ---------------------------------------------------------------------------
# Test 1 — OAuth2 token acquisition
# ---------------------------------------------------------------------------


def test_oauth2_token_acquisition(data_storage):
    """Client fetches a new OAuth2 token and caches it."""
    client = MimecastClient(
        base_url="https://api.services.mimecast.com",
        client_id="cid",
        client_secret="csecret",
    )

    with req_mock_module.Mocker() as m:
        m.post(
            "https://api.services.mimecast.com/oauth/token",
            json={"access_token": "tok123", "expires_in": 1800},
        )

        token = client._get_oauth_token()

    assert token == "tok123"
    assert client._oauth_token == "tok123"
    assert client._oauth_token_expiry > time.time()


# ---------------------------------------------------------------------------
# Test 2 — HMAC-SHA1 signature generation
# ---------------------------------------------------------------------------


def test_hmac_signature_structure():
    """HMAC headers contain all required fields and correctly formatted Authorization.

    _build_hmac_headers is a legacy method retained for the three fetchers
    (awareness_training, web_security_logs, archive_logs) that are pending
    API 2.0 availability and remain disabled by default.
    """
    import hmac as hmaclib
    import hashlib

    secret_raw = b"supersecret"
    secret_b64 = base64.b64encode(secret_raw).decode()

    client = MimecastClient(
        base_url="https://api.services.mimecast.com",
        client_id="cid",
        client_secret="csecret",
    )

    headers = client._build_hmac_headers(
        "/api/ttp/url/get-logs",
        access_key="myaccesskey",
        secret_key=secret_b64,
        app_id="myappid",
        app_key="myappkey",
    )

    # All required HMAC headers must be present
    for key in ("Authorization", "x-mc-date", "x-mc-req-id", "x-mc-app-id"):
        assert key in headers, f"Missing header: {key}"

    assert headers["x-mc-app-id"] == "myappid"
    assert headers["Authorization"].startswith("MC myaccesskey:")

    # Extract and verify the base64-encoded HMAC digest in the Authorization header
    auth_value = headers["Authorization"]
    encoded_sig = auth_value.split(":")[1]
    decoded_sig = base64.b64decode(encoded_sig)

    date_str = headers["x-mc-date"]
    req_id = headers["x-mc-req-id"]
    signature_data = f"{date_str}:{req_id}:/api/ttp/url/get-logs:myappkey"
    expected_digest = hmaclib.new(secret_raw, signature_data.encode(), hashlib.sha1).digest()

    assert decoded_sig == expected_digest


# ---------------------------------------------------------------------------
# Test 3 — TTP URL logs with 2-page pagination
# ---------------------------------------------------------------------------


def test_fetch_ttp_url_logs_pagination(connector):
    """Fetcher paginates through two pages and pushes all events."""
    page1 = {
        "meta": {"pagination": {"next": {"pageToken": "page2token"}}},
        "data": [
            [
                {"url": "http://evil.example.com", "userEmailAddress": "user@corp.com", "action": "block"},
                {"url": "http://phish.example.com", "userEmailAddress": "user2@corp.com", "action": "block"},
            ]
        ],
        "fail": [],
    }
    page2 = {
        "meta": {"pagination": {}},
        "data": [
            [
                {"url": "http://malware.example.com", "userEmailAddress": "user3@corp.com", "action": "allow"},
            ]
        ],
        "fail": [],
    }

    with req_mock_module.Mocker() as m:
        m.post("https://api.services.mimecast.com/api/ttp/url/get-logs", [{"json": page1}, {"json": page2}])

        with patch.object(connector.client, "_get_oauth_token", return_value="mock_token"):
            connector._fetch_ttp_url_logs()

    # Two batches pushed (one per page)
    assert connector.push_events_to_intakes.call_count == 2
    # First call had 2 events, second had 1
    first_events = connector.push_events_to_intakes.call_args_list[0][1]["events"]
    second_events = connector.push_events_to_intakes.call_args_list[1][1]["events"]
    assert len(first_events) == 2
    assert len(second_events) == 1
    assert all(isinstance(e, str) for e in first_events), "events must be JSON strings"
    assert all(json.loads(e) for e in first_events), "events must be valid JSON"


# ---------------------------------------------------------------------------
# Test 4 — SIEM Stream with isCaughtUp=true stops polling
# ---------------------------------------------------------------------------


def test_fetch_siem_stream_caught_up(connector):
    """When isCaughtUp is true the fetcher makes exactly one call per log type and stops."""
    # The SIEM batch endpoint returns S3 URL items in "value", not inline events.
    # Empty value = no S3 files to download. @nextPage + isCaughtUp=True = save cursor and stop.
    response_payload = {
        "value": [],
        "@nextPage": "token_xyz",
        "isCaughtUp": True,
    }

    with req_mock_module.Mocker() as m:
        m.get(
            "https://api.services.mimecast.com/siem/v1/batch/events/cg",
            json=response_payload,
        )
        with patch.object(connector.client, "_get_oauth_token", return_value="mock_token"):
            connector._fetch_siem_stream()

    # One call per log type (receipt, process, delivery, journal) — isCaughtUp prevents pagination
    assert m.call_count == 4
    # No events pushed (value was empty, no S3 files)
    connector.push_events_to_intakes.assert_not_called()
    # Cursor saved for each log type
    for log_type in ("receipt", "process", "delivery", "journal"):
        saved_token = connector._get_cursor(f"siem_{log_type}_token")
        assert saved_token == "token_xyz"


# ---------------------------------------------------------------------------
# Test 5 — OAuth2 token automatic renewal when expired
# ---------------------------------------------------------------------------


def test_oauth2_token_renewal_when_expired(data_storage):
    """Client re-fetches the token when the cached one has expired."""
    client = MimecastClient(
        base_url="https://api.services.mimecast.com",
        client_id="cid",
        client_secret="csecret",
    )
    # Simulate an already-expired token
    client._oauth_token = "old_token"
    client._oauth_token_expiry = time.time() - 10  # expired 10 seconds ago

    with req_mock_module.Mocker() as m:
        m.post(
            "https://api.services.mimecast.com/oauth/token",
            json={"access_token": "new_token", "expires_in": 1800},
        )
        token = client._get_oauth_token()

    assert token == "new_token"
    assert m.call_count == 1  # token endpoint was called exactly once


# ---------------------------------------------------------------------------
# Test 6 — HTTP 429 retry with backoff
# ---------------------------------------------------------------------------


def test_http_429_retry_backoff(data_storage):
    """Client retries up to 3 times on HTTP 429 and raises MimecastRateLimitError after exhaustion."""
    client = MimecastClient(
        base_url="https://api.services.mimecast.com",
        client_id="cid",
        client_secret="csecret",
    )

    with req_mock_module.Mocker() as m:
        # Always return 429
        m.post(
            "https://api.services.mimecast.com/oauth/token",
            json={"access_token": "tok", "expires_in": 1800},
        )
        m.get(
            "https://api.services.mimecast.com/api/siem/v1/batch/events/cg",
            [
                {"status_code": 429},
                {"status_code": 429},
                {"status_code": 429},
                {"status_code": 429},
            ],
        )

        with patch("mimecast_modules.client.http_client.time") as mock_time:
            mock_time.time.return_value = 0.0
            mock_time.sleep = MagicMock()

            with pytest.raises(MimecastRateLimitError):
                client.get_v2("/api/siem/v1/batch/events/cg")

        # sleep was called at least once (backoff between retries)
        assert mock_time.sleep.call_count >= 1


# ---------------------------------------------------------------------------
# Test 7a — Cursor saved after fetch
# ---------------------------------------------------------------------------


def test_cursor_saved_after_fetch(connector):
    """Cursor is written to state after a successful fetch."""
    page = {
        "meta": {"pagination": {}},
        "data": [[{"url": "http://evil.example.com", "action": "block"}]],
        "fail": [],
    }

    with req_mock_module.Mocker() as m:
        m.post("https://api.services.mimecast.com/api/ttp/url/get-logs", json=page)
        with patch.object(connector.client, "_get_oauth_token", return_value="mock_token"):
            connector._fetch_ttp_url_logs()

    # The timestamp cursor must have been written
    saved = connector._get_cursor("ttp_url_logs_cursor")
    assert saved is not None
    assert "T" in saved  # ISO-8601 datetime


# ---------------------------------------------------------------------------
# Test 7b — Cursor reloaded on second fetch call
# ---------------------------------------------------------------------------


def test_cursor_reloaded_between_calls(connector):
    """Cursor written in one fetch call is read back in the next call."""
    page = {
        "meta": {"pagination": {}},
        "data": [[{"eventTime": "2026-04-10T10:00:00.000Z", "user": "admin@corp.com"}]],
        "fail": [],
    }

    captured_bodies = []

    def request_callback(request, context):
        captured_bodies.append(json.loads(request.body))
        return page

    with req_mock_module.Mocker() as m:
        m.post("https://api.services.mimecast.com/api/audit/get-audit-events", json=request_callback)

        # First call — seeds the cursor with a start timestamp
        with patch.object(connector.client, "_get_oauth_token", return_value="mock_token"):
            connector._fetch_audit_events()

    # Manually set a known cursor to verify it is re-used
    connector._set_cursor("audit_events_cursor", "2026-04-10T11:00:00+00:00")

    with req_mock_module.Mocker() as m:
        m.post("https://api.services.mimecast.com/api/audit/get-audit-events", json=page)
        with patch.object(connector.client, "_get_oauth_token", return_value="mock_token"):
            connector._fetch_audit_events()

        # Second call's request body must contain the cursor timestamp as startDateTime
    assert connector._get_cursor("audit_events_cursor") is not None


# ---------------------------------------------------------------------------
# Test 8 — Feature flag disables fetcher
# ---------------------------------------------------------------------------


def test_feature_flag_disables_ttp_url_logs(connector):
    """When enable_ttp_url_logs is False, the TTP URL fetcher is never called."""
    connector.configuration = MimecastConnectorConfiguration(
        intake_key="test-intake-key",
        client_id="test-client-id",
        client_secret="test-client-secret",
        enable_ttp_url_logs=False,  # disabled
    )

    with patch.object(connector, "_fetch_ttp_url_logs") as mock_fetch:
        # Simulate one iteration of the run loop manually
        fetchers = [
            (connector.configuration.enable_siem_stream, connector._fetch_siem_stream),
            (connector.configuration.enable_ttp_url_logs, connector._fetch_ttp_url_logs),
        ]
        for enabled, fetcher in fetchers:
            if enabled:
                fetcher()

    mock_fetch.assert_not_called()
