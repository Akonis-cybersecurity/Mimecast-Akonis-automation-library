from abc import ABCMeta
from functools import cached_property
from urllib.parse import urljoin

import boto3
import requests
from pydantic.v1 import BaseModel, Field
from sekoia_automation.aio.helpers.aws.client import AwsConfiguration
from sekoia_automation.connector import Connector
from sekoia_automation.module import Module


class AWSConfiguration(BaseModel):
    aws_role_arn: str = Field(description="The ARN of the AWS role to assume")
    aws_audience: str = Field(description="The audience to use when requesting the OIDC token")
    aws_region_name: str = Field(description="The area hosting the AWS resources")


# Canonical alias imported by connectors/ and asset_connector/
AwsModuleConfiguration = AWSConfiguration


class AWSModule(Module):
    configuration: AWSConfiguration


class OidcAwsMixin:
    """Mixin providing OIDC-based AWS role assumption.

    The concrete class must expose:
    - self.configuration with 'base_url' and 'api_key' accessible as dict keys
    - self.module.configuration with aws_audience, aws_region_name, aws_role_arn
    """

    @cached_property
    def url(self) -> str:
        """OIDC token endpoint URL."""
        return urljoin(
            self.configuration["base_url"],
            f"api/v2/oidc/token?audience={self.module.configuration.aws_audience}",
        )

    @property
    def headers(self) -> dict:
        """Authorization headers for OIDC token request."""
        return {"Authorization": f"Bearer {self.configuration['api_key']}"}

    def _get_oidc_token(self) -> str:
        """Fetch OIDC token from the configured endpoint."""
        result = requests.get(self.url, headers=self.headers, timeout=60)
        if not result.ok:
            raise Exception(f"Could not get OIDC token: {result.status_code} - {result.text}")
        token = result.json().get("access_token")
        if not token:
            raise Exception("Could not get OIDC token: access_token not found in response")
        return token

    def get_assume_role(self) -> AwsConfiguration:
        """Assume AWS role via OIDC web identity and return temporary credentials."""
        sts_client = boto3.client("sts", region_name=self.module.configuration.aws_region_name)
        try:
            oidc_token = self._get_oidc_token()
            response = sts_client.assume_role_with_web_identity(
                RoleArn=self.module.configuration.aws_role_arn,
                RoleSessionName="sekoia-automation-session",
                WebIdentityToken=oidc_token,
            )
            credentials = response["Credentials"]
            return AwsConfiguration(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_region=self.module.configuration.aws_region_name,
                aws_session_token=credentials.get("SessionToken"),
            )
        except Exception as e:
            raise Exception(f"Could not assume role: {str(e)}")


class AWSConnector(OidcAwsMixin, Connector, metaclass=ABCMeta):
    """Abstract connector for AWS integrations using OIDC-based role assumption."""

    module: AWSModule

    def new_session(self) -> boto3.Session:
        """Create a new boto3 session using assumed-role credentials."""
        assume_role = self.get_assume_role()
        return boto3.Session(
            aws_access_key_id=assume_role.aws_access_key_id,
            aws_secret_access_key=assume_role.aws_secret_access_key,
            region_name=assume_role.aws_region,
            aws_session_token=assume_role.aws_session_token,
        )

    @property
    def session(self) -> boto3.Session:
        """boto3 session backed by assumed-role credentials."""
        return self.new_session()
