from typing import Any

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetMessageInfoArguments(BaseModel):
    message_id: str = Field(..., description="Mimecast message ID (returned by SearchMessage)")


class MimecastGetMessageInfo(MimecastAction):
    """Retrieve detailed information about a specific Mimecast message."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetMessageInfoArguments(**arguments)

        body = {"data": [{"id": args.message_id}]}

        try:
            resp = self.client.post_v2("/api/message-finder/get-message-info", json=body)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error retrieving message info: {exc}", level="error")
            raise

        payload = resp.json()
        data = (payload.get("data") or [{}])[0] if payload.get("data") else {}

        return {
            "id": str(data.get("id", "")),
            "subject": str(data.get("subject", "")),
            "from": str(data.get("fromEnv", data.get("from", ""))),
            "to": data.get("to", []),
            "status": str(data.get("status", "")),
            "timestamp": str(data.get("timestamp", data.get("receiveTime", ""))),
            "attachments": data.get("attachments", []),
            "route": str(data.get("route", "")),
            "held_reason": str(data.get("heldReason", "")),
        }
