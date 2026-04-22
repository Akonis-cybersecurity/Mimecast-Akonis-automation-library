from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetThreatEventDetailsArguments(BaseModel):
    event_id: str = Field(..., description="Detection ID of the threat event")
    source: Optional[str] = Field("EMAIL", description="Event source (default: EMAIL)")
    page_size: Optional[int] = Field(100, description="Results per page (1-100, default 100)")


class MimecastGetThreatEventDetails(MimecastAction):
    """Retrieve detailed information for a specific Mimecast threat event."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetThreatEventDetailsArguments(**arguments)

        params: dict[str, Any] = {}
        if args.source is not None:
            params["source"] = args.source
        if args.page_size is not None:
            params["pageSize"] = args.page_size

        try:
            resp = self.client.get_v2(
                f"/threats/v1/events/{args.event_id}/details",
                params=params if params else None,
            )
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving threat event details for {args.event_id}: {exc}", level="error")
            raise

        payload = resp.json()
        data = (payload.get("data") or [payload])[0] if payload else {}

        return {
            "id": str(data.get("id", args.event_id)),
            "sender": data.get("sender", ""),
            "recipients": data.get("recipients", []),
            "subject": str(data.get("subject", "")),
            "threats": data.get("threats", []),
            "attachments": data.get("attachments", []),
            "urls": data.get("urls", []),
            "timestamp": str(data.get("timestamp", "")),
            "status": str(data.get("status", "")),
        }
