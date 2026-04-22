from typing import Any

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class PermitSenderArguments(BaseModel):
    sender_email: str = Field(..., description="Email address of the sender to permit")
    to_email: str = Field(..., description="Email address of the recipient")


class MimecastPermitSender(MimecastAction):
    """Allow a sender in Mimecast via the Managed Senders API."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = PermitSenderArguments(**arguments)

        body = {
            "data": [
                {
                    "action": "permit",
                    "sender": args.sender_email,
                    "to": args.to_email,
                }
            ]
        }

        try:
            resp = self.client.post_v2("/api/managedsender/permit-or-block-sender", json=body)
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error permitting sender: {exc}", level="error")
            raise

        payload = resp.json()
        data = (payload.get("data") or [{}])[0] if payload.get("data") else {}

        return {
            "id": str(data.get("id", "")),
            "sender": args.sender_email,
            "status": "permitted",
        }
