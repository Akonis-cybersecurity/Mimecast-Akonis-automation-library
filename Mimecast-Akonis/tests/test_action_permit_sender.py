from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_permit_sender import MimecastPermitSender
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastPermitSender(module=module)
    a.log = MagicMock()
    return a


def _mock_post(action, json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


class TestPermitSenderSuccess:
    def test_returns_permitted_status(self, action):
        _mock_post(action, {"data": [{"id": "rule-123"}]})

        result = action.run({"sender_email": "trusted@partner.com", "to_email": "user@corp.com"})

        assert result["id"] == "rule-123"
        assert result["sender"] == "trusted@partner.com"
        assert result["status"] == "permitted"

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"data": [{"id": "r1"}]})

        action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/api/managedsender/permit-or-block-sender"

    def test_request_body_has_permit_action(self, action):
        _mock_post(action, {"data": [{"id": "r2"}]})

        action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["data"][0]["action"] == "permit"
        assert body["data"][0]["sender"] == "a@b.com"
        assert body["data"][0]["to"] == "c@d.com"

    def test_empty_data_response_returns_empty_id(self, action):
        _mock_post(action, {})

        result = action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

        assert result["id"] == ""
        assert result["status"] == "permitted"


class TestPermitSenderErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(403, "forbidden"))

        with pytest.raises(MimecastAPIError):
            action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"sender_email": "a@b.com", "to_email": "c@d.com"})

        action.log.assert_called_once()

    def test_missing_required_fields_raises(self, action):
        with pytest.raises(Exception):
            action.run({"sender_email": "a@b.com"})

        with pytest.raises(Exception):
            action.run({"to_email": "c@d.com"})
