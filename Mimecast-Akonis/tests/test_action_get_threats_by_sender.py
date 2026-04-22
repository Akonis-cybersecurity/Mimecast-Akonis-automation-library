from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_threats_by_sender import MimecastGetThreatsBySender
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

START = "2026-04-01T00:00:00+0000"
SAMPLE_SENDERS = [
    {"sender": "spammer@evil.com", "spamCount": 10, "malwareCount": 2, "totalCount": 12}
]


@pytest.fixture
def action(module):
    a = MimecastGetThreatsBySender(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetThreatsBySenderSuccess:
    def test_returns_senders(self, action):
        _mock_get(action, {"data": SAMPLE_SENDERS})

        result = action.run({"start": START})

        assert result["senders"] == SAMPLE_SENDERS

    def test_correct_endpoint(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        assert action.client.get_v2.call_args[0][0] == "/threats/v1/stats/threats-by-sender"

    def test_start_param_sent(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["start"] == START

    def test_optional_params_forwarded(self, action):
        _mock_get(action, {"data": []})

        action.run({
            "start": START,
            "end": "2026-04-02T00:00:00+0000",
            "email": "target@corp.com",
            "page_size": 50,
            "limit": 100,
            "order_by": "totalCount:desc",
        })

        params = action.client.get_v2.call_args[1]["params"]
        assert params["end"] == "2026-04-02T00:00:00+0000"
        assert params["email"] == "target@corp.com"
        assert params["pageSize"] == 50
        assert params["limit"] == 100
        assert params["orderBy"] == "totalCount:desc"

    def test_optional_params_omitted_when_absent(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert "email" not in params
        assert "pageSize" not in params
        assert "limit" not in params
        assert "orderBy" not in params

    def test_senders_key_fallback(self, action):
        _mock_get(action, {"senders": SAMPLE_SENDERS})

        result = action.run({"start": START})

        assert result["senders"] == SAMPLE_SENDERS

    def test_empty_response_returns_empty_list(self, action):
        _mock_get(action, {})

        result = action.run({"start": START})

        assert result["senders"] == []

    def test_missing_start_raises(self, action):
        with pytest.raises(Exception):
            action.run({})


class TestGetThreatsBySenderErrors:
    def test_api_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({"start": START})

        action.log.assert_called_once()

    def test_auth_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"start": START})

    def test_rate_limit_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"start": START})

        action.log.assert_called_once()
