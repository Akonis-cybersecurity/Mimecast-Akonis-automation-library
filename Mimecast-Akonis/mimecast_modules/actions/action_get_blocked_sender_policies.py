from typing import Any, List, Optional

from pydantic.v1 import BaseModel, Field

from mimecast_modules.actions import MimecastAction
from mimecast_modules.client.errors import MimecastAPIError, MimecastAuthError, MimecastRateLimitError


class GetBlockedSenderPoliciesArguments(BaseModel):
    page_size: int = Field(100, description="Number of policies per page (1-100)")
    max_results: Optional[int] = Field(None, description="Maximum total number of policies to return")


class MimecastGetBlockedSenderPolicies(MimecastAction):
    """Retrieve all blocked sender policies from Mimecast, with pagination."""

    def run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        args = GetBlockedSenderPoliciesArguments(**arguments)

        policies: List[dict] = []
        page_token: Optional[str] = None

        while True:
            params: dict[str, Any] = {"pageSize": args.page_size}
            if page_token:
                params["pageToken"] = page_token

            try:
                resp = self.client.get_v2(
                    "/policy-management/cloud-gateway/v1/blocked-senders/policies",
                    params=params,
                )
            except MimecastAuthError as exc:
                self.log(message=f"Authentication failed: {exc}", level="error")
                raise
            except MimecastRateLimitError as exc:
                self.log(message=f"Rate limit exceeded after retries: {exc}", level="error")
                raise
            except MimecastAPIError as exc:
                self.log(message=f"API error retrieving blocked sender policies: {exc}", level="error")
                raise

            payload = resp.json()
            # The API may return policies under "policies" or "data"
            page_items: List[dict] = payload.get("policies") or payload.get("data") or []
            policies.extend(page_items)

            if args.max_results is not None and len(policies) >= args.max_results:
                policies = policies[: args.max_results]
                break

            next_token = payload.get("nextToken") or payload.get("next_token")
            if not next_token:
                break
            page_token = next_token

        return {"policies": policies}
