from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetStatsURLClicksArguments(BaseModel):
    start: str = Field(..., description="Start of the time range (ISO-8601 with timezone)")
    end: Optional[str] = Field(None, description="End of the time range (ISO-8601 with timezone)")


class MimecastGetStatsURLClicks(MimecastAction):
    """Retrieve malicious URL click statistics from Mimecast."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetStatsURLClicksArguments(**arguments)

        params: dict[str, Any] = {"start": args.start}
        if args.end is not None:
            params["end"] = args.end

        try:
            resp = self.client.get_v2("/threats/v1/stats/url-clicks", params=params)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving URL click stats: {exc}", level="error")
            raise

        payload = resp.json()
        stats = payload.get("data") or payload.get("stats") or []

        return {"stats": stats}
