from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetThreatReportsArguments(BaseModel):
    reported_message_aggregate_id: str = Field(..., description="Aggregate ID returned by Get Reported Emails")
    page_size: Optional[int] = Field(None, description="Page size: 25, 50, 100, 250, or 500 (default 50)")
    offset: Optional[int] = Field(None, description="Pagination offset (default 0)")


class MimecastGetThreatReports(MimecastAction):
    """Retrieve threat reports for a specific reported email from Mimecast."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetThreatReportsArguments(**arguments)

        params: dict[str, Any] = {"reportedMessageAggregateId": args.reported_message_aggregate_id}
        if args.page_size is not None:
            params["pageSize"] = str(args.page_size)
        if args.offset is not None:
            params["offset"] = str(args.offset)

        try:
            resp = self.client.get_v2("/threat-reporting/v1/threat-reports", params=params)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving threat reports: {exc}", level="error")
            raise

        payload = resp.json()
        reports = payload.get("data") or payload.get("reports") or []

        return {"reports": reports}
