from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_threat_event_details import MimecastGetThreatEventDetails
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

EVENT_ID = "det-abc123"
SAMPLE_DETAIL = {
    "id": EVENT_ID,
    "sender": "attacker@evil.com",
    "recipients": ["victim@corp.com"],
    "subject": "Urgent Invoice",
    "threats": [{"type": "malware"}],
    "attachments": [{"name": "invoice.exe"}],
    "urls": [{"url": "https://evil.com/payload"}],
    "timestamp": "2026-04-01T10:00:00+0000",
    "status": "blocked",
}


@pytest.fixture
def action(module):
    a = MimecastGetThreatEventDetails(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetThreatEventDetailsSuccess:
    def test_returns_all_fields(self, action):
        _mock_get(action, {"data": [SAMPLE_DETAIL]})

        result = action.run({"event_id": EVENT_ID})

        assert result["id"] == EVENT_ID
        assert result["sender"] == "attacker@evil.com"
        assert result["recipients"] == ["victim@corp.com"]
        assert result["subject"] == "Urgent Invoice"
        assert result["threats"] == [{"type": "malware"}]
        assert result["attachments"] == [{"name": "invoice.exe"}]
        assert result["urls"] == [{"url": "https://evil.com/payload"}]
        assert result["timestamp"] == "2026-04-01T10:00:00+0000"
        assert result["status"] == "blocked"

    def test_correct_endpoint_with_event_id(self, action):
        _mock_get(action, {"data": [SAMPLE_DETAIL]})

        action.run({"event_id": EVENT_ID})

        path = action.client.get_v2.call_args[0][0]
        assert path == f"/threats/v1/events/{EVENT_ID}/details"

    def test_default_source_is_email(self, action):
        _mock_get(action, {"data": [SAMPLE_DETAIL]})

        action.run({"event_id": EVENT_ID})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["source"] == "EMAIL"

    def test_custom_source_forwarded(self, action):
        _mock_get(action, {"data": [SAMPLE_DETAIL]})

        action.run({"event_id": EVENT_ID, "source": "URL"})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["source"] == "URL"

    def test_empty_data_uses_event_id_fallback(self, action):
        _mock_get(action, {})

        result = action.run({"event_id": EVENT_ID})

        assert result["id"] == EVENT_ID
        assert result["sender"] == ""
        assert result["recipients"] == []

    def test_missing_event_id_raises(self, action):
        with pytest.raises(Exception):
            action.run({})


class TestGetThreatEventDetailsErrors:
    def test_api_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(404, "not found"))

        with pytest.raises(MimecastAPIError):
            action.run({"event_id": EVENT_ID})

        action.log.assert_called_once()

    def test_auth_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"event_id": EVENT_ID})

    def test_rate_limit_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"event_id": EVENT_ID})

        action.log.assert_called_once()
