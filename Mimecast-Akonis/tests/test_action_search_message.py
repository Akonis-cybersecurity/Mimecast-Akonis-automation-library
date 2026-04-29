from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_search_message import MimecastSearchMessage
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastSearchMessage(module=module)
    a.log = MagicMock()
    return a


def _mock_post(action, json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


SAMPLE_MESSAGES = [
    {"id": "msg-1", "subject": "Hello", "status": "accepted"},
    {"id": "msg-2", "subject": "Invoice", "status": "held"},
]


class TestSearchMessageSuccess:
    def test_returns_messages_list(self, action):
        _mock_post(action, {"data": SAMPLE_MESSAGES})

        result = action.run({"from_email": "sender@example.com"})

        assert result["messages"] == SAMPLE_MESSAGES

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"data": []})

        action.run({})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/api/message-finder/search"

    def test_from_email_mapped_to_from_key(self, action):
        _mock_post(action, {"data": []})

        action.run({"from_email": "sender@example.com"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["data"][0]["from"] == "sender@example.com"
        assert "from_email" not in body["data"][0]

    def test_to_email_mapped_to_to_key(self, action):
        _mock_post(action, {"data": []})

        action.run({"to_email": "recipient@example.com"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["data"][0]["to"] == "recipient@example.com"

    def test_optional_fields_omitted_when_not_provided(self, action):
        _mock_post(action, {"data": []})

        action.run({})

        body = action.client.post_v2.call_args[1]["json"]
        query = body["data"][0]
        assert query == {}

    def test_all_optional_fields_included_when_provided(self, action):
        _mock_post(action, {"data": []})

        action.run(
            {
                "from_email": "a@b.com",
                "to_email": "c@d.com",
                "subject": "Test",
                "start": "2026-01-01T00:00:00+0000",
                "end": "2026-01-02T00:00:00+0000",
                "route": ["inbound"],
                "status": ["accepted", "held"],
                "message_id": "<abc@example.com>",
                "url": "https://example.com",
                "sender_ip": "1.2.3.4",
            }
        )

        body = action.client.post_v2.call_args[1]["json"]
        query = body["data"][0]
        assert query["from"] == "a@b.com"
        assert query["subject"] == "Test"
        assert query["route"] == ["inbound"]
        assert query["status"] == ["accepted", "held"]
        assert query["messageId"] == "<abc@example.com>"
        assert query["senderIp"] == "1.2.3.4"

    def test_empty_data_response_returns_empty_list(self, action):
        _mock_post(action, {})

        result = action.run({})

        assert result["messages"] == []


class TestSearchMessageErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(400, "bad request"))

        with pytest.raises(MimecastAPIError):
            action.run({})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({})

        action.log.assert_called_once()
