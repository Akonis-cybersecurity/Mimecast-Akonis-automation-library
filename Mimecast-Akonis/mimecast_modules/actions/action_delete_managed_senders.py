from typing import Any, List, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class DeleteManagedSendersArguments(BaseModel):
    ids: List[str] = Field(..., description="List of sender email addresses or domains to delete (1-1000)")
    action: Optional[str] = Field(None, description="Filter by entry type: 'block' or 'permit'")
    type: Optional[str] = Field(None, description="Filter by entry origin: 'auto' or 'manual'")
    trusted: Optional[bool] = Field(None, description="Filter on trusted entries only")


class MimecastDeleteManagedSenders(MimecastAction):
    """Delete managed sender entries in Mimecast (bulk delete)."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = DeleteManagedSendersArguments(**arguments)

        body: dict[str, Any] = {"ids": args.ids}
        if args.action is not None:
            body["action"] = args.action
        if args.type is not None:
            body["type"] = args.type
        if args.trusted is not None:
            body["trusted"] = args.trusted

        try:
            resp = self.client.post_v2(
                "/email/cloud-gateway/v1/managed-senders/senders/bulk-delete",
                json=body,
            )
        except MimecastAuthError as exc:
            self.log(message=f"Authentication failed: {exc}", level="error")
            raise
        except MimecastRateLimitError as exc:
            self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
            raise
        except MimecastAPIError as exc:
            self.log(message=f"API error deleting managed senders: {exc}", level="error")
            raise

        payload = resp.json()
        deleted_count = (
            payload.get("deletedCount")
            or payload.get("deleted_count")
            or len(args.ids)
        )

        return {
            "deleted_count": int(deleted_count),
            "status": "deleted",
        }
