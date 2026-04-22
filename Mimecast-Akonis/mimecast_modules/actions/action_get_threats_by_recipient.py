from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetThreatsByRecipientArguments(BaseModel):
    start: str = Field(..., description="Start of the time range (ISO-8601 with timezone)")
    end: Optional[str] = Field(None, description="End of the time range (ISO-8601 with timezone)")
    email: Optional[str] = Field(None, description="Filter by recipient email address")
    page_size: Optional[int] = Field(None, description="Results per page (1-100)")
    limit: Optional[int] = Field(None, description="Maximum results to return (1-1000, default 5)")
    order_by: Optional[str] = Field(None, description="Sort order, e.g. 'totalCount:desc'")


class MimecastGetThreatsByRecipient(MimecastAction):
    """Retrieve threat statistics grouped by recipient from Mimecast."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetThreatsByRecipientArguments(**arguments)

        params: dict[str, Any] = {"start": args.start}
        if args.end is not None:
            params["end"] = args.end
        if args.email is not None:
            params["email"] = args.email
        if args.page_size is not None:
            params["pageSize"] = args.page_size
        if args.limit is not None:
            params["limit"] = args.limit
        if args.order_by is not None:
            params["orderBy"] = args.order_by

        try:
            resp = self.client.get_v2("/threats/v1/stats/threats-by-recipient", params=params)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving threats by recipient: {exc}", level="error")
            raise

        payload = resp.json()
        recipients = payload.get("data") or payload.get("recipients") or []

        return {"recipients": recipients}
