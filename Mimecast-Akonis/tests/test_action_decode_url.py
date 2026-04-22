from unittest.mock import MagicMock

import pytest

from mimecast_modules.actions.action_decode_url import MimecastDecodeURL
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


@pytest.fixture
def action(module):
    a = MimecastDecodeURL(module=module)
    a.log = MagicMock()
    return a


def _mock_post(action, json_data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.json.return_value = json_data
    action.client.post_v2 = MagicMock(return_value=resp)
    return resp


ENCODED_URL = "https://protect-eu.mimecast.com/s/abc123?domain=malware.example.com"
DECODED_URL = "https://malware.example.com/payload"


class TestDecodeURLSuccess:
    def test_returns_decoded_url(self, action):
        _mock_post(action, {"data": [{"url": DECODED_URL, "category": "Malicious"}]})

        result = action.run({"url": ENCODED_URL})

        assert result["decoded_url"] == DECODED_URL
        assert result["category"] == "Malicious"

    def test_correct_endpoint_called(self, action):
        _mock_post(action, {"data": [{"url": DECODED_URL}]})

        action.run({"url": ENCODED_URL})

        path = action.client.post_v2.call_args[0][0]
        assert path == "/api/ttp/url/decode-url"

    def test_encoded_url_sent_in_body(self, action):
        _mock_post(action, {"data": [{"url": DECODED_URL}]})

        action.run({"url": ENCODED_URL})

        body = action.client.post_v2.call_args[1]["json"]
        assert body["data"][0]["url"] == ENCODED_URL

    def test_empty_data_response_returns_empty_strings(self, action):
        _mock_post(action, {})

        result = action.run({"url": ENCODED_URL})

        assert result["decoded_url"] == ""
        assert result["category"] == ""

    def test_missing_category_returns_empty_string(self, action):
        _mock_post(action, {"data": [{"url": DECODED_URL}]})

        result = action.run({"url": ENCODED_URL})

        assert result["category"] == ""


class TestDecodeURLErrors:
    def test_api_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAPIError(400, "invalid url"))

        with pytest.raises(MimecastAPIError):
            action.run({"url": ENCODED_URL})

        action.log.assert_called_once()

    def test_auth_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastAuthError("bad creds"))

        with pytest.raises(MimecastAuthError):
            action.run({"url": ENCODED_URL})

    def test_rate_limit_error_is_re_raised(self, action):
        action.client.post_v2 = MagicMock(side_effect=MimecastRateLimitError(60))

        with pytest.raises(MimecastRateLimitError):
            action.run({"url": ENCODED_URL})

        action.log.assert_called_once()

    def test_missing_url_raises(self, action):
        with pytest.raises(Exception):
            action.run({})
