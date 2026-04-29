from unittest.mock import MagicMock, call

import pytest

from mimecast_modules.actions.action_get_blocked_sender_policies import MimecastGetBlockedSenderPolicies
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastGetBlockedSenderPolicies(module=module)
    a.log = MagicMock()
    return a


def _make_resp(policies: list, next_token: str | None = None) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    payload: dict = {"policies": policies}
    if next_token:
        payload["nextToken"] = next_token
    resp.json.return_value = payload
    return resp


POLICY_A = {"id": "pol-1", "description": "Block spammer", "enabled": True}
POLICY_B = {"id": "pol-2", "description": "Block phisher", "enabled": True}
POLICY_C = {"id": "pol-3", "description": "Block malware", "enabled": False}


class TestGetBlockedSenderPoliciesSuccess:
    def test_single_page_returns_all_policies(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([POLICY_A, POLICY_B]))

        result = action.run({})

        assert result["policies"] == [POLICY_A, POLICY_B]

    def test_correct_endpoint_called(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([]))

        action.run({})

        path = action.client.get_v2.call_args[0][0]
        assert path == "/policy-management/cloud-gateway/v1/blocked-senders/policies"

    def test_default_page_size_is_100(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([]))

        action.run({})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["pageSize"] == 100

    def test_custom_page_size_respected(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([]))

        action.run({"page_size": 25})

        params = action.client.get_v2.call_args[1]["params"]
        assert params["pageSize"] == 25

    def test_pagination_follows_next_token(self, action):
        page1 = _make_resp([POLICY_A], next_token="tok-page2")
        page2 = _make_resp([POLICY_B], next_token=None)
        action.client.get_v2 = MagicMock(side_effect=[page1, page2])

        result = action.run({})

        assert result["policies"] == [POLICY_A, POLICY_B]
        assert action.client.get_v2.call_count == 2
        # Second call must pass pageToken
        second_params = action.client.get_v2.call_args_list[1][1]["params"]
        assert second_params["pageToken"] == "tok-page2"

    def test_first_page_has_no_page_token(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([]))

        action.run({})

        params = action.client.get_v2.call_args[1]["params"]
        assert "pageToken" not in params

    def test_max_results_limits_output(self, action):
        page1 = _make_resp([POLICY_A, POLICY_B], next_token="tok-page2")
        page2 = _make_resp([POLICY_C], next_token=None)
        action.client.get_v2 = MagicMock(side_effect=[page1, page2])

        result = action.run({"max_results": 2})

        assert len(result["policies"]) == 2
        assert result["policies"] == [POLICY_A, POLICY_B]
        # Should stop after first page already hit max_results
        assert action.client.get_v2.call_count == 1

    def test_max_results_truncates_within_page(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([POLICY_A, POLICY_B, POLICY_C]))

        result = action.run({"max_results": 2})

        assert result["policies"] == [POLICY_A, POLICY_B]

    def test_empty_response_returns_empty_list(self, action):
        action.client.get_v2 = MagicMock(return_value=_make_resp([]))

        result = action.run({})

        assert result["policies"] == []

    def test_data_key_fallback(self, action):
        """API may return policies under 'data' instead of 'policies'."""
        resp = MagicMock()
        resp.ok = True
        resp.json.return_value = {"data": [POLICY_A]}
        action.client.get_v2 = MagicMock(return_value=resp)

        result = action.run({})

        assert result["policies"] == [POLICY_A]


class TestGetBlockedSenderPoliciesErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.get_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({})

        action.log.assert_called_once()

    def test_api_error_on_second_page_is_re_raised(self, action):
        page1 = _make_resp([POLICY_A], next_token="tok-page2")
        action.client.get_v2 = MagicMock(side_effect=[page1, MimecastAPIError(500, "server error")])

        with pytest.raises(MimecastAPIError):
            action.run({})
