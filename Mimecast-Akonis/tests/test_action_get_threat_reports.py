from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_get_threat_reports import MimecastGetThreatReports
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

AGG_ID = "agg-abc123"
SAMPLE_REPORTS = [
    {
        "reportedDate": "2026-04-01T10:00:00+0000",
        "sender": "phisher@evil.com",
        "subject": "Win a prize",
        "analysisType": "phishing",
    }
]


@pytest.fixture
def action(module):
    a = MimecastGetThreatReports(module=module)
    a.log = MagicMock()
    return a


def _mock_get(action, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    resp.json.return_value = json_data
    action.client.get_v2 = MagicMock(return_value=resp)
    return resp


class TestGetThreatReportsSuccess:
    def test_returns_reports(self, action):
        _mock_get(action, {"data": SAMPLE_REPORTS})

        result = action.run({"reported_message_aggregate_id": AGG_ID})

        assert result["reports"] == SAMPLE_REPORTS

    def test_correct_endpoint(self, action):
        _mock_get(action, {"data": []})

        action.run({"reported_message_aggregate_id": AGG_ID})

        assert action.client.get_v2.call_args[0][0] == "/threat-reporting/v1/threat-reports"

    def test_aggregate_id_param_sent(self, action):
        _mock_get(action, {"data": []})

        action.run({"reported_message_aggregate_id": AGG_ID})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["reportedMessageAggregateId"] == AGG_ID

    def test_page_size_converted_to_string(self, action):
        _mock_get(action, {"data": []})

        action.run({"reported_message_aggregate_id": AGG_ID, "page_size": 100})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["pageSize"] == "100"

    def test_offset_converted_to_string(self, action):
        _mock_get(action, {"data": []})

        action.run({"reported_message_aggregate_id": AGG_ID, "offset": 25})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["offset"] == "25"

    def test_optional_params_omitted_when_absent(self, action):
        _mock_get(action, {"data": []})

        action.run({"reported_message_aggregate_id": AGG_ID})

        params = action.client.get_v2.call_args[1]["params"]
        assert "pageSize" not in params
        assert "offset" not in params

    def test_reports_key_fallback(self, action):
        _mock_get(action, {"reports": SAMPLE_REPORTS})

        result = action.run({"reported_message_aggregate_id": AGG_ID})

        assert result["reports"] == SAMPLE_REPORTS

    def test_empty_response_returns_empty_list(self, action):
        _mock_get(action, {})

        result = action.run({"reported_message_aggregate_id": AGG_ID})

        assert result["reports"] == []

    def test_missing_aggregate_id_raises(self, action):
        with pytest.raises(Exception):
            action.run({})


class TestGetThreatReportsErrors:
    def test_api_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(404, "not found"))

        with pytest.raises(MimecastAPIError):
            action.run({"reported_message_aggregate_id": AGG_ID})

        action.log.assert_called_once()

    def test_auth_error_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"reported_message_aggregate_id": AGG_ID})

    def test_rate_limit_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"reported_message_aggregate_id": AGG_ID})

        action.log.assert_called_once()
