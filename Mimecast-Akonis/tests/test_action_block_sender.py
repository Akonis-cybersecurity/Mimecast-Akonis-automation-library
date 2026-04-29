from unittest.mock import MagicMock, patch

import pytest

from mimecast_modules.actions.action_block_sender import MimecastBlockSender
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError


@pytest.fixture
def action(module):
    a = MimecastBlockSender(module=module)
    a.log = MagicMock()
    return a


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_post(action, json_data: dict, status_code: int = 200):
    """Patch client.post_v2 to return a mock response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


# ---------------------------------------------------------------------------
# Success cases
# ---------------------------------------------------------------------------


class TestBlockSenderSuccess:
    def test_block_everyone_returns_policy_id(self, action):
        _mock_post(action, {"id": "policy-abc123"})

        result = action.run({"sender_email": "spammer@evil.com"})

        assert result["policy_id"] == "policy-abc123"
        assert result["sender_email"] == "spammer@evil.com"
        assert result["status"] == "blocked"

    def test_block_specific_recipient(self, action):
        _mock_post(action, {"id": "policy-xyz"})

        result = action.run(
            {
                "sender_email": "spammer@evil.com",
                "to_email": "victim@corp.com",
            }
        )

        call_body = action.client.post_v2.call_args[1]["json"]
        assert call_body["to"] == {
            "type": "individual_email_address",
            "emailAddress": "victim@corp.com",
        }
        assert result["policy_id"] == "policy-xyz"

    def test_default_to_is_everyone(self, action):
        _mock_post(action, {"id": "p1"})

        action.run({"sender_email": "x@evil.com"})

        call_body = action.client.post_v2.call_args[1]["json"]
        assert call_body["to"] == {"type": "everyone"}

    def test_custom_description_is_used(self, action):
        _mock_post(action, {"id": "p2"})

        action.run({"sender_email": "x@evil.com", "description": "My custom reason"})

        call_body = action.client.post_v2.call_args[1]["json"]
        assert call_body["description"] == "My custom reason"

    def test_default_description_includes_email(self, action):
        _mock_post(action, {"id": "p3"})

        action.run({"sender_email": "x@evil.com"})

        call_body = action.client.post_v2.call_args[1]["json"]
        assert "x@evil.com" in call_body["description"]

    def test_policy_flags_are_set(self, action):
        _mock_post(action, {"id": "p4"})

        action.run({"sender_email": "x@evil.com"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["enabled"] is True
        assert body["enforced"] is True
        assert body["override"] is True
        assert body["option"] == "block_sender"
        assert body["fromPart"] == "both"

    def test_policy_id_from_nested_data(self, action):
        _mock_post(action, {"data": {"id": "nested-id"}})

        result = action.run({"sender_email": "x@evil.com"})

        assert result["policy_id"] == "nested-id"

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"id": "p5"})

        action.run({"sender_email": "x@evil.com"})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/policy-management/cloud-gateway/v1/blocked-senders/policies"


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


class TestBlockSenderErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({"sender_email": "x@evil.com"})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"sender_email": "x@evil.com"})

    def test_rate_limit_error_is_re_raised(self, action):
        from mimecast_modules.client.errors import MimecastRateLimitError

        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"sender_email": "x@evil.com"})

        action.log.assert_called_once()

    def test_missing_sender_email_raises(self, action):
        with pytest.raises(Exception):
            action.run({})
