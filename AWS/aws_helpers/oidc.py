from datetime import datetime, timedelta, timezone
from functools import cached_property
from urllib.parse import urljoin

import boto3
import requests
from sekoia_automation.aio.helpers.aws.client import AwsConfiguration

from .base import AwsModule


class OidcAwsMixin:
    """Mixin providing OIDC-based AWS role assumption.

    The concrete class must expose:
    - self.module.configuration with aws_region_name, aws_role_arn,
      base_url, and api_key fields (i.e. AwsModule with AwsModuleConfiguration).
    """

    module: AwsModule
    _cached_aws_config: AwsConfiguration | None = None
    _config_expiration: datetime | None = None

    @cached_property
    def url(self) -> str:
        """OIDC token endpoint URL."""
        return urljoin(
            self.module.configuration.base_url,
            "api/v2/oidc/token?audience=sts.amazonaws.com",
        )

    @cached_property
    def headers(self) -> dict[str, str]:
        """Authorization headers for OIDC token request."""
        return {"Authorization": f"Bearer {self.module.configuration.api_key}"}

    def _get_oidc_token(self) -> str:
        """Fetch OIDC token from the configured endpoint."""
        result = requests.get(self.url, headers=self.headers, timeout=60)
        if not result.ok:
            raise Exception(f"Could not get OIDC token: {result.status_code} - {result.text}")
        token: str = result.json().get("access_token")
        if not token:
            raise Exception("Could not get OIDC token: access_token not found in response")
        return token

    def get_assume_role(self) -> AwsConfiguration:
        """Assume AWS role via OIDC web identity and return temporary credentials.

        Credentials are cached and reused until 5 minutes before expiration.
        """
        now = datetime.now(timezone.utc)
        if (
            self._cached_aws_config is not None
            and self._config_expiration is not None
            and self._config_expiration - timedelta(minutes=5) > now
        ):
            return self._cached_aws_config

        sts_client = boto3.client("sts", region_name=self.module.configuration.aws_region_name)
        try:
            oidc_token = self._get_oidc_token()
            response = sts_client.assume_role_with_web_identity(
                RoleArn=self.module.configuration.aws_role_arn,
                RoleSessionName="sekoia-automation-session",
                WebIdentityToken=oidc_token,
            )
            credentials = response["Credentials"]
            self._config_expiration = credentials["Expiration"]
            self._cached_aws_config = AwsConfiguration(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_region=self.module.configuration.aws_region_name,
                aws_session_token=credentials["SessionToken"],
            )
            return self._cached_aws_config
        except Exception as e:
            raise Exception(f"Could not assume role: {str(e)}")
