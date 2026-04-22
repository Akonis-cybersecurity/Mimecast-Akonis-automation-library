from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class BlockSenderArguments(BaseModel):
    sender_email: str = Field(..., description="Email address of the sender to block")
    description: Optional[str] = Field(None, description="Policy description")
    to_email: Optional[str] = Field(None, description="Restrict the block to this recipient only")


class MimecastBlockSender(MimecastAction):
    """Block a sender in Mimecast by creating a blocked senders policy."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = BlockSenderArguments(**arguments)

        to_block = (
            {"type": "individual_email_address", "emailAddress": args.to_email}
            if args.to_email
            else {"type": "everyone"}
        )

        body = {
            "description": args.description or f"Blocked by Sekoia SOAR - {args.sender_email}",
            "option": "block_sender",
            "fromPart": "both",
            "from": {
                "type": "individual_email_address",
                "emailAddress": args.sender_email,
            },
            "to": to_block,
            "enabled": True,
            "enforced": True,
            "override": True,
        }

        try:
            resp = self.client.post_v2(
                "/policy-management/cloud-gateway/v1/blocked-senders/policies",
                json=body,
            )
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error creating blocked-sender policy: {exc}", level="error")
            raise

        payload = resp.json()

        # The API may return the policy ID at the top level or nested under "data"
        policy_id = (
            payload.get("id")
            or payload.get("policyId")
            or (payload.get("data") or {}).get("id", "")
        )

        return {
            "policy_id": str(policy_id),
            "sender_email": args.sender_email,
            "status": "blocked",
        }
