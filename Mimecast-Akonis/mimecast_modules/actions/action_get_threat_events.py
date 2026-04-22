from typing import Any, List, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetThreatEventsArguments(BaseModel):
    timestamp_range_starts_at: str = Field(
        ..., description="Start of time range (ISO-8601 with timezone)"
    )
    timestamp_range_ends_at: Optional[str] = Field(None, description="End of time range (ISO-8601 with timezone)")
    analysis: Optional[List[str]] = Field(
        None, description="Filter by analysis type: malware, phishing, spam, suspicious, unwanted"
    )
    status: Optional[List[str]] = Field(
        None, description="Filter by status: blocked, rejected, delivered, held, bounced, unknown"
    )
    direction: Optional[List[str]] = Field(None, description="Filter by direction: inbound")
    source: Optional[List[str]] = Field(None, description="Filter by source: email, url")
    page_size: Optional[int] = Field(None, description="Results per page (1-100)")
    limit: Optional[int] = Field(None, description="Maximum results to return (1-1000, default 5)")
    order_by: Optional[str] = Field(None, description="Sort order, e.g. 'timestamp:desc'")


class MimecastGetThreatEvents(MimecastAction):
    """Retrieve threat events from Mimecast Threat Intelligence."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetThreatEventsArguments(**arguments)

        params: dict[str, Any] = {"timestampRangeStartsAt": args.timestamp_range_starts_at}
        if args.timestamp_range_ends_at is not None:
            params["timestampRangeEndsAt"] = args.timestamp_range_ends_at
        if args.analysis is not None:
            params["analysis"] = args.analysis
        if args.status is not None:
            params["status"] = args.status
        if args.direction is not None:
            params["direction"] = args.direction
        if args.source is not None:
            params["source"] = args.source
        if args.page_size is not None:
            params["pageSize"] = args.page_size
        if args.limit is not None:
            params["limit"] = args.limit
        if args.order_by is not None:
            params["orderBy"] = args.order_by

        try:
            resp = self.client.get_v2("/threats/v1/events", params=params)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving threat events: {exc}", level="error")
            raise

        payload = resp.json()
        events = payload.get("data") or payload.get("events") or []
        total = payload.get("total", len(events))

        return {"events": events, "total": total}
