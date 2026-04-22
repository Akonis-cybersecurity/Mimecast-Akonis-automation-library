from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_delete_blocked_sender_policy import MimecastDeleteBlockedSenderPolicy
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastDeleteBlockedSenderPolicy(module=module)
    a.log = MagicMock()
    return a


def _mock_delete(action, status_code: int = 204) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    action.client.delete_v2 = MagicMock(return_value=resp)
    return resp


class TestDeleteBlockedSenderPolicySuccess:
    def test_returns_deleted_status(self, action):
        _mock_delete(action)

        result = action.run({"policy_id": "pol-abc123"})

        assert result["policy_id"] == "pol-abc123"
        assert result["status"] == "deleted"

    def test_correct_endpoint_called(self, action):
        _mock_delete(action)

        action.run({"policy_id": "pol-abc123"})

        path = action.client.delete_v2.call_args[0][0]
        assert path == "/policy-management/cloud-gateway/v1/blocked-senders/policies/pol-abc123"

    def test_policy_id_injected_into_path(self, action):
        _mock_delete(action)

        action.run({"policy_id": "my-policy-id-xyz"})

        path = action.client.delete_v2.call_args[0][0]
        assert "my-policy-id-xyz" in path

    def test_200_response_also_returns_deleted(self, action):
        _mock_delete(action, status_code=200)

        result = action.run({"policy_id": "pol-200"})

        assert result["status"] == "deleted"


class TestDeleteBlockedSenderPolicyErrors:
    def test_api_error_404_is_re_raised(self, action):
        action.client.delete_v2 = MagicMock(side_effect=MimecastAPIError(404, "not found"))

        with pytest.raises(MimecastAPIError):
            action.run({"policy_id": "missing-policy"})

        action.log.assert_called_once()

    def test_api_error_403_is_re_raised(self, action):
        action.client.delete_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({"policy_id": "pol-forbidden"})

    def test_auth_error_is_re_raised(self, action):
        action.client.delete_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"policy_id": "pol-abc123"})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.delete_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"policy_id": "pol-abc123"})

        action.log.assert_called_once()

    def test_missing_policy_id_raises(self, action):
        with pytest.raises(Exception):
            action.run({})
