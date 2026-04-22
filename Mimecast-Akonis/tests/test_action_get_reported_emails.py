from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_reported_emails import MimecastGetReportedEmails
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

SAMPLE_EMAILS = [
    {
        "reportedMessageAggregateId": "agg-123",
        "sender": "phisher@evil.com",
        "subject": "Win a prize",
        "lastReportedDate": "2026-04-01T10:00:00+0000",
    }
]


@pytest.fixture
def action(module):
    a = MimecastGetReportedEmails(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetReportedEmailsSuccess:
    def test_returns_emails(self, action):
        _mock_get(action, {"data": SAMPLE_EMAILS})

        result = action.run({})

        assert result["emails"] == SAMPLE_EMAILS

    def test_correct_endpoint(self, action):
        _mock_get(action, {"data": []})

        action.run({})

        assert action.client.get_v2.call_args[0][0] == "/threat-reporting/v1/reported-emails"

    def test_no_required_params(self, action):
        _mock_get(action, {"data": []})

        action.run({})

        # Should not raise even with empty arguments

    def test_start_end_forwarded(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": "2026-04-01T00:00:00+0000", "end": "2026-04-08T00:00:00+0000"})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["start"] == "2026-04-01T00:00:00+0000"
        assert params["end"] == "2026-04-08T00:00:00+0000"

    def test_page_size_converted_to_string(self, action):
        _mock_get(action, {"data": []})

        action.run({"page_size": 100})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["pageSize"] == "100"

    def test_offset_converted_to_string(self, action):
        _mock_get(action, {"data": []})

        action.run({"offset": 50})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["offset"] == "50"

    def test_emails_key_fallback(self, action):
        _mock_get(action, {"emails": SAMPLE_EMAILS})

        result = action.run({})

        assert result["emails"] == SAMPLE_EMAILS

    def test_empty_response_returns_empty_list(self, action):
        _mock_get(action, {})

        result = action.run({})

        assert result["emails"] == []


class TestGetReportedEmailsErrors:
    def test_api_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({})

        action.log.assert_called_once()

    def test_auth_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({})

    def test_rate_limit_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({})

        action.log.assert_called_once()
