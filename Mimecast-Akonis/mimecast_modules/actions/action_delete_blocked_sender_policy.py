from typing import Any

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class DeleteBlockedSenderPolicyArguments(BaseModel):
    policy_id: str = Field(
        ...,
        description="ID of the blocked sender policy to delete, as returned by BlockSender or GetBlockedSenderPolicies",
    )


class MimecastDeleteBlockedSenderPolicy(MimecastAction):
    """Delete a blocked sender policy from Mimecast by its ID."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = DeleteBlockedSenderPolicyArguments(**arguments)

        try:
            self.client.delete_v2(f"/policy-management/cloud-gateway/v1/blocked-senders/policies/{args.policy_id}")
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error deleting blocked sender policy {args.policy_id}: {exc}", level="error")
            raise

        return {
            "policy_id": args.policy_id,
            "status": "deleted",
        }
