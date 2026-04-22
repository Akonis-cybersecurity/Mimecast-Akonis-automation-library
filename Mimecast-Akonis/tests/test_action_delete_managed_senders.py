from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_delete_managed_senders import MimecastDeleteManagedSenders
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastDeleteManagedSenders(module=module)
    a.log = MagicMock()
    return a


def _mock_post(action, json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


class TestDeleteManagedSendersSuccess:
    def test_returns_deleted_status(self, action):
        _mock_post(action, {"deletedCount": 3})

        result = action.run({"ids": ["a@b.com", "c@d.com", "e@f.com"]})

        assert result["deleted_count"] == 3
        assert result["status"] == "deleted"

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"deletedCount": 1})

        action.run({"ids": ["a@b.com"]})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/email/cloud-gateway/v1/managed-senders/senders/bulk-delete"

    def test_ids_sent_in_body(self, action):
        _mock_post(action, {"deletedCount": 2})
        ids = ["x@y.com", "z@w.com"]

        action.run({"ids": ids})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["ids"] == ids

    def test_optional_action_filter_included_when_provided(self, action):
        _mock_post(action, {"deletedCount": 1})

        action.run({"ids": ["a@b.com"], "action": "block"})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["action"] == "block"

    def test_optional_fields_omitted_when_not_provided(self, action):
        _mock_post(action, {"deletedCount": 1})

        action.run({"ids": ["a@b.com"]})

        body = action.client.post_v2.call_args[1]["json"]
        assert "action" not in body
        assert "type" not in body
        assert "trusted" not in body

    def test_fallback_to_len_ids_when_no_count_in_response(self, action):
        _mock_post(action, {})
        ids = ["a@b.com", "c@d.com"]

        result = action.run({"ids": ids})

        assert result["deleted_count"] == 2

    def test_trusted_flag_included(self, action):
        _mock_post(action, {"deletedCount": 0})

        action.run({"ids": ["a@b.com"], "trusted": True})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["trusted"] is True


class TestDeleteManagedSendersErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(400, "bad request"))

        with pytest.raises(MimecastAPIError):
            action.run({"ids": ["a@b.com"]})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"ids": ["a@b.com"]})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(120))

        with pytest.raises(MimecastRateLimitError):
            action.run({"ids": ["a@b.com"]})

        action.log.assert_called_once()

    def test_missing_ids_raises(self, action):
        with pytest.raises(Exception):
            action.run({})
