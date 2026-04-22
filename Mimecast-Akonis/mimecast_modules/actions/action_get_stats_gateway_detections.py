from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetStatsGatewayDetectionsArguments(BaseModel):
    start: str = Field(..., description="Start of the time range (ISO-8601 with timezone)")
    end: Optional[str] = Field(None, description="End of the time range (ISO-8601 with timezone)")
    type: str = Field(..., description="Detection type: 'spam' or 'malware'")


class MimecastGetStatsGatewayDetections(MimecastAction):
    """Retrieve gateway detection statistics (spam or malware) from Mimecast."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetStatsGatewayDetectionsArguments(**arguments)

        params: dict[str, Any] = {"start": args.start, "type": args.type}
        if args.end is not None:
            params["end"] = args.end

        try:
            resp = self.client.get_v2("/threats/v1/stats/gateway-detections", params=params)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving gateway detection stats: {exc}", level="error")
            raise

        payload = resp.json()
        stats = payload.get("data") or payload.get("stats") or []

        return {"stats": stats}
