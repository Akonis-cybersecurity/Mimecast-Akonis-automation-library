"""Unified HTTP client for Mimecast API 1.0 (HMAC-SHA1) and API 2.0 (OAuth2)."""

import base64
import hashlib
import hmac
import time
import uuid
from email.utils import formatdate
from typing import Any, Optional

import requests

from .errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError

# Retry delays in seconds for 429 responses: 60s → 120s → 240s
_RETRY_DELAYS = [60, 120, 240]


class MimecastClient:
    """HTTP client for Mimecast API 2.0 (OAuth2 Bearer token).

    API 1.0 (HMAC-SHA1) methods are retained as stubs for three fetchers
    (awareness_training, web_security_logs, archive_logs) that are pending
    API 2.0 availability and are disabled by default.
    """

    def __init__(
        self,
        # API 2.0 (OAuth2)
        base_url: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret

        # OAuth2 token state
        self._oauth_token: Optional[str] = None
        self._oauth_token_expiry: float = 0.0

        self._session = requests.Session()

    # ------------------------------------------------------------------
    # OAuth2 token management
    # ------------------------------------------------------------------

    def _refresh_oauth_token(self) -> None:
        """Fetch a new OAuth2 bearer token from Mimecast."""
        url = f"{self._base_url}/oauth/token"
        response = self._session.post(
            url,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if response.status_code == 401:
            raise MimecastAuthError("OAuth2 authentication failed: invalid client credentials")
        if not response.ok:
            raise MimecastAuthError(f"OAuth2 token request failed with status {response.status_code}")

        data = response.json()
        self._oauth_token = data["access_token"]
        # Refresh 5 minutes before the token expires
        self._oauth_token_expiry = time.time() + data.get("expires_in", 1800) - 300

    def _get_oauth_token(self) -> str:
        """Return a valid OAuth2 bearer token, refreshing if necessary."""
        if self._oauth_token is None or time.time() >= self._oauth_token_expiry:
            self._refresh_oauth_token()
        return self._oauth_token  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # HMAC-SHA1 header builder (API 1.0)
    # Retained for the three fetchers pending API 2.0 migration.
    # ------------------------------------------------------------------

    def _build_hmac_headers(
        self,
        uri: str,
        access_key: str,
        secret_key: str,
        app_id: str,
        app_key: str,
    ) -> dict:
        """Build the authentication headers required for API 1.0 (HMAC-SHA1)."""
        request_id = str(uuid.uuid4())
        # RFC 2822 date in UTC, e.g. "Thu, 01 Jan 2026 00:00:00 -0000"
        date_str = formatdate(usegmt=True)

        # Signature data: date:requestId:uri:app_key
        signature_data = ":".join([date_str, request_id, uri, app_key])

        # HMAC-SHA1: key = base64_decode(secret_key), message = signature_data
        secret_bytes = base64.b64decode(secret_key)
        hmac_digest = hmac.new(secret_bytes, signature_data.encode("utf-8"), hashlib.sha1).digest()
        signature_b64 = base64.b64encode(hmac_digest).decode("utf-8")

        return {
            "Authorization": f"MC {access_key}:{signature_b64}",
            "x-mc-date": date_str,
            "x-mc-req-id": request_id,
            "x-mc-app-id": app_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Generic request helpers with retry on 429
    # ------------------------------------------------------------------

    def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: dict,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute an HTTP request, retrying up to 3 times on HTTP 429."""
        for attempt, delay in enumerate([0] + _RETRY_DELAYS):
            if delay:
                time.sleep(delay)

            response = self._session.request(method, url, headers=headers, timeout=60, **kwargs)

            if response.status_code == 429:
                if attempt < len(_RETRY_DELAYS):
                    retry_after = int(response.headers.get("Retry-After", _RETRY_DELAYS[attempt]))
                    # Use the server-provided Retry-After if it's reasonable
                    actual_delay = min(retry_after, _RETRY_DELAYS[attempt])
                    time.sleep(actual_delay)
                    continue
                raise MimecastRateLimitError()

            if response.status_code == 401:
                raise MimecastAuthError(f"Authentication error on {url}")

            if not response.ok:
                # Never include the response body for the token endpoint — it echoes
                # the submitted credentials in error payloads.
                detail = "" if "/oauth/token" in url else response.text[:200]
                raise MimecastAPIError(response.status_code, detail)

            return response

        raise MimecastRateLimitError()

    # ------------------------------------------------------------------
    # Public API 2.0 methods (OAuth2 / Bearer token)
    # ------------------------------------------------------------------

    def get_v2(self, path: str, params: Optional[dict] = None) -> requests.Response:
        """HTTP GET against the API 2.0 base URL with OAuth2 auth."""
        token = self._get_oauth_token()
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        return self._request_with_retry("GET", url, headers=headers, params=params)

    def post_v2(self, path: str, json: Optional[dict] = None) -> requests.Response:
        """HTTP POST against the API 2.0 base URL with OAuth2 auth."""
        token = self._get_oauth_token()
        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return self._request_with_retry("POST", url, headers=headers, json=json)

    # ------------------------------------------------------------------
    # Public API 1.0 methods (HMAC-SHA1)
    # Pending API 2.0 migration for awareness_training, web_security_logs,
    # and archive_logs fetchers. Those fetchers are disabled by default.
    # ------------------------------------------------------------------

    def post_v1(
        self,
        path: str,
        body: Any = None,
        base_url_v1: str = "https://us-api.mimecast.com",
        access_key: str = "",
        secret_key: str = "",
        app_id: str = "",
        app_key: str = "",
    ) -> requests.Response:
        """HTTP POST against the API 1.0 base URL with HMAC-SHA1 auth."""
        url = f"{base_url_v1.rstrip('/')}{path}"
        headers = self._build_hmac_headers(path, access_key, secret_key, app_id, app_key)
        return self._request_with_retry("POST", url, headers=headers, json=body)

    def post_v1_raw(
        self,
        path: str,
        body: Any = None,
        base_url_v1: str = "https://us-api.mimecast.com",
        access_key: str = "",
        secret_key: str = "",
        app_id: str = "",
        app_key: str = "",
    ) -> requests.Response:
        """Like post_v1 but for binary responses (stream=True).

        Uses the same 429 backoff as _request_with_retry: up to 3 retries
        with delays of 60 s → 120 s → 240 s.
        """
        url = f"{base_url_v1.rstrip('/')}{path}"

        for attempt, delay in enumerate([0] + _RETRY_DELAYS):
            if delay:
                time.sleep(delay)

            headers = self._build_hmac_headers(path, access_key, secret_key, app_id, app_key)
            # This endpoint returns binary gzip — override the default Accept: application/json
            # set by _build_hmac_headers, otherwise the server returns HTTP 406.
            headers["Accept"] = "application/octet-stream"
            response = self._session.post(url, headers=headers, json=body, timeout=120, stream=True)

            if response.status_code == 429:
                if attempt < len(_RETRY_DELAYS):
                    retry_after = int(response.headers.get("Retry-After", _RETRY_DELAYS[attempt]))
                    actual_delay = min(retry_after, _RETRY_DELAYS[attempt])
                    time.sleep(actual_delay)
                    continue
                raise MimecastRateLimitError()

            if response.status_code == 401:
                raise MimecastAuthError(f"Authentication error on {path}")
            if not response.ok:
                raise MimecastAPIError(response.status_code, response.text[:200])

            return response

        raise MimecastRateLimitError()
