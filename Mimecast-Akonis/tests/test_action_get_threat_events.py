from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_threat_events import MimecastGetThreatEvents
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

START = "2026-04-01T00:00:00+0000"
SAMPLE_EVENTS = [{"id": "ev-1", "analysis": "malware"}, {"id": "ev-2", "analysis": "spam"}]


@pytest.fixture
def action(module):
    a = MimecastGetThreatEvents(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetThreatEventsSuccess:
    def test_returns_events_list(self, action):
        _mock_get(action, {"data": SAMPLE_EVENTS, "total": 2})

        result = action.run({"timestamp_range_starts_at": START})

        assert result["events"] == SAMPLE_EVENTS
        assert result["total"] == 2

    def test_correct_endpoint(self, action):
        _mock_get(action, {"data": []})

        action.run({"timestamp_range_starts_at": START})

        assert action.client.get_v2.call_args[0][0] == "/threats/v1/events"

    def test_required_start_param_sent(self, action):
        _mock_get(action, {"data": []})

        action.run({"timestamp_range_starts_at": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["timestampRangeStartsAt"] == START

    def test_optional_params_omitted_when_absent(self, action):
        _mock_get(action, {"data": []})

        action.run({"timestamp_range_starts_at": START})

        params = action.client.get_v2.call_args[1]["params"]
        assert "timestampRangeEndsAt" not in params
        assert "analysis" not in params
        assert "pageSize" not in params

    def test_list_params_sent_as_lists(self, action):
        _mock_get(action, {"data": []})

        action.run({
            "timestamp_range_starts_at": START,
            "analysis": ["malware", "phishing"],
            "status": ["blocked"],
        })

        params = action.client.get_v2.call_args[1]["params"]
        assert params["analysis"] == ["malware", "phishing"]
        assert params["status"] == ["blocked"]

    def test_all_optional_params_forwarded(self, action):
        _mock_get(action, {"data": []})

        action.run({
            "timestamp_range_starts_at": START,
            "timestamp_range_ends_at": "2026-04-02T00:00:00+0000",
            "direction": ["inbound"],
            "source": ["email"],
            "page_size": 50,
            "limit": 100,
            "order_by": "timestamp:desc",
        })

        params = action.client.get_v2.call_args[1]["params"]
        assert params["timestampRangeEndsAt"] == "2026-04-02T00:00:00+0000"
        assert params["pageSize"] == 50
        assert params["limit"] == 100
        assert params["orderBy"] == "timestamp:desc"

    def test_events_key_fallback(self, action):
        _mock_get(action, {"events": SAMPLE_EVENTS})

        result = action.run({"timestamp_range_starts_at": START})

        assert result["events"] == SAMPLE_EVENTS

    def test_empty_response_returns_empty_list(self, action):
        _mock_get(action, {})

        result = action.run({"timestamp_range_starts_at": START})

        assert result["events"] == []
        assert result["total"] == 0

    def test_missing_start_raises(self, action):
        with pytest.raises(Exception):
            action.run({})


class TestGetThreatEventsErrors:
    def test_api_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({"timestamp_range_starts_at": START})

        action.log.assert_called_once()

    def test_auth_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"timestamp_range_starts_at": START})

    def test_rate_limit_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"timestamp_range_starts_at": START})

        action.log.assert_called_once()
