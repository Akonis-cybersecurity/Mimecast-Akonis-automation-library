from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_threats_by_recipient import MimecastGetThreatsByRecipient
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

START = "2026-04-01T00:00:00+0000"
SAMPLE_RECIPIENTS = [{"recipient": "victim@corp.com", "malwareCount": 3, "phishingCount": 1, "totalCount": 4}]


@pytest.fixture
def action(module):
    a = MimecastGetThreatsByRecipient(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetThreatsByRecipientSuccess:
    def test_returns_recipients(self, action):
        _mock_get(action, {"data": SAMPLE_RECIPIENTS})

        result = action.run({"start": START})

        assert result["recipients"] == SAMPLE_RECIPIENTS

    def test_correct_endpoint(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        assert action.client.get_v2.call_args[0][0] == "/threats/v1/stats/threats-by-recipient"

    def test_start_param_sent(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["start"] == START

    def test_optional_params_forwarded(self, action):
        _mock_get(action, {"data": []})

        action.run(
            {
                "start": START,
                "end": "2026-04-02T00:00:00+0000",
                "email": "victim@corp.com",
                "page_size": 25,
                "limit": 50,
                "order_by": "malwareCount:desc",
            }
        )

        params = action.client.get_v2.call_args[1]["params"]
        assert params["email"] == "victim@corp.com"
        assert params["pageSize"] == 25
        assert params["limit"] == 50
        assert params["orderBy"] == "malwareCount:desc"

    def test_optional_params_omitted_when_absent(self, action):
        _mock_get(action, {"data": []})

        action.run({"start": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert "email" not in params
        assert "pageSize" not in params

    def test_recipients_key_fallback(self, action):
        _mock_get(action, {"recipients": SAMPLE_RECIPIENTS})

        result = action.run({"start": START})

        assert result["recipients"] == SAMPLE_RECIPIENTS

    def test_empty_response_returns_empty_list(self, action):
        _mock_get(action, {})

        result = action.run({"start": START})

        assert result["recipients"] == []

    def test_missing_start_raises(self, action):
        with pytest.raises(Exception):
            action.run({})


class TestGetThreatsByRecipientErrors:
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
