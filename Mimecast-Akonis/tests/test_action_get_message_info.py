from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_message_info import MimecastGetMessageInfo
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastGetMessageInfo(module=module)
    a.log = MagicMock()
    return a


def _mock_post(action, json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


SAMPLE_MESSAGE = {
    "id": "msg-abc123",
    "subject": "Suspicious Invoice",
    "fromEnv": "attacker@evil.com",
    "to": ["victim@corp.com"],
    "status": "held",
    "timestamp": "2026-04-22T10:00:00+0000",
    "attachments": [{"name": "invoice.pdf", "size": 12345}],
    "route": "inbound",
    "heldReason": "Suspected malware",
}


class TestGetMessageInfoSuccess:
    def test_returns_all_fields(self, action):
        _mock_post(action, {"data": [SAMPLE_MESSAGE]})

        result = action.run({"message_id": "msg-abc123"})

        assert result["id"] == "msg-abc123"
        assert result["subject"] == "Suspicious Invoice"
        assert result["from"] == "attacker@evil.com"
        assert result["to"] == ["victim@corp.com"]
        assert result["status"] == "held"
        assert result["timestamp"] == "2026-04-22T10:00:00+0000"
        assert result["attachments"] == [{"name": "invoice.pdf", "size": 12345}]
        assert result["route"] == "inbound"
        assert result["held_reason"] == "Suspected malware"

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"data": [SAMPLE_MESSAGE]})

        action.run({"message_id": "msg-abc123"})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/api/message-finder/get-message-info"

    def test_message_id_sent_in_body(self, action):
        _mock_post(action, {"data": [SAMPLE_MESSAGE]})

        action.run({"message_id": "msg-abc123"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["data"][0]["id"] == "msg-abc123"

    def test_falls_back_to_from_key_when_fromenv_missing(self, action):
        msg = {**SAMPLE_MESSAGE}
        del msg["fromEnv"]
        msg["from"] = "sender@example.com"
        _mock_post(action, {"data": [msg]})

        result = action.run({"message_id": "msg-abc123"})

        assert result["from"] == "sender@example.com"

    def test_empty_data_response_returns_empty_strings(self, action):
        _mock_post(action, {})

        result = action.run({"message_id": "msg-abc123"})

        assert result["id"] == ""
        assert result["subject"] == ""
        assert result["status"] == ""
        assert result["to"] == []
        assert result["attachments"] == []

    def test_no_held_reason_returns_empty_string(self, action):
        msg = {**SAMPLE_MESSAGE}
        del msg["heldReason"]
        _mock_post(action, {"data": [msg]})

        result = action.run({"message_id": "msg-abc123"})

        assert result["held_reason"] == ""


class TestGetMessageInfoErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(404, "not found"))

        with pytest.raises(MimecastAPIError):
            action.run({"message_id": "msg-abc123"})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"message_id": "msg-abc123"})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"message_id": "msg-abc123"})

        action.log.assert_called_once()

    def test_missing_message_id_raises(self, action):
        with pytest.raises(Exception):
            action.run({})
