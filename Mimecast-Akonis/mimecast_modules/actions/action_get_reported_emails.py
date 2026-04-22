from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetReportedEmailsArguments(BaseModel):
    start: Optional[str] = Field(None, description="Start datetime (ISO-8601), defaults to 7 days ago")
    end: Optional[str] = Field(None, description="End datetime (ISO-8601), defaults to now")
    page_size: Optional[int] = Field(
        None, description="Page size: 25, 50, 100, 250, or 500 (default 50)"
    )
    offset: Optional[int] = Field(None, description="Pagination offset (default 0)")


class MimecastGetReportedEmails(MimecastAction):
    """Retrieve user-reported emails from Mimecast Threat Reporting."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetReportedEmailsArguments(**arguments)

        params: dict[str, Any] = {}
        if args.start is not None:
            params["start"] = args.start
        if args.end is not None:
            params["end"] = args.end
        if args.page_size is not None:
            params["pageSize"] = str(args.page_size)
        if args.offset is not None:
            params["offset"] = str(args.offset)

        try:
            resp = self.client.get_v2(
                "/threat-reporting/v1/reported-emails",
                params=params if params else None,
            )
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving reported emails: {exc}", level="error")
            raise

        payload = resp.json()
        emails = payload.get("data") or payload.get("emails") or []

        return {"emails": emails}
