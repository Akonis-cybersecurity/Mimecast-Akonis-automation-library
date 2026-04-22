from typing import Any, List, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class SearchMessageArguments(BaseModel):
    from_email: Optional[str] = Field(None, description="Sender email address filter")
    to_email: Optional[str] = Field(None, description="Recipient email address filter")
    subject: Optional[str] = Field(None, description="Message subject filter")
    start: Optional[str] = Field(None, description="Start datetime (yyyy-MM-dd'T'HH:mm:ssZ)")
    end: Optional[str] = Field(None, description="End datetime (yyyy-MM-dd'T'HH:mm:ssZ)")
    route: Optional[List[str]] = Field(None, description="Message direction: inbound, outbound, internal")
    status: Optional[List[str]] = Field(None, description="Message status: accepted, held, rejected, etc.")
    message_id: Optional[str] = Field(None, description="Internet message ID")
    url: Optional[str] = Field(None, description="URL present in the message")
    sender_ip: Optional[str] = Field(None, description="Source IP address of the sender")


class MimecastSearchMessage(MimecastAction):
    """Search Mimecast message tracking logs."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = SearchMessageArguments(**arguments)

        query: dict[str, Any] = {}
        if args.from_email is not None:
            query["from"] = args.from_email
        if args.to_email is not None:
            query["to"] = args.to_email
        if args.subject is not None:
            query["subject"] = args.subject
        if args.start is not None:
            query["start"] = args.start
        if args.end is not None:
            query["end"] = args.end
        if args.route is not None:
            query["route"] = args.route
        if args.status is not None:
            query["status"] = args.status
        if args.message_id is not None:
            query["messageId"] = args.message_id
        if args.url is not None:
            query["url"] = args.url
        if args.sender_ip is not None:
            query["senderIp"] = args.sender_ip

        body = {"data": [query]}

        try:
            resp = self.client.post_v2("/api/message-finder/search", json=body)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error searching messages: {exc}", level="error")
            raise

        payload = resp.json()
        messages = payload.get("data") or []

        return {"messages": messages}
