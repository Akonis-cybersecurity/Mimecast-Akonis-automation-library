from typing import Any

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class DecodeURLArguments(BaseModel):
    url: str = Field(..., description="Mimecast-encoded URL to decode (e.g. https://protect-xx.mimecast.com/...)")


class MimecastDecodeURL(MimecastAction):
    """Decode a Mimecast-rewritten URL to its original form."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = DecodeURLArguments(**arguments)

        body = {"data": [{"url": args.url}]}

        try:
            resp = self.client.post_v2("/api/ttp/url/decode-url", json=body)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error decoding URL: {exc}", level="error")
            raise

        payload = resp.json()
        data = (payload.get("data") or [{}])[0] if payload.get("data") else {}

        return {
            "decoded_url": str(data.get("url", "")),
            "category": str(data.get("category", "")),
        }
