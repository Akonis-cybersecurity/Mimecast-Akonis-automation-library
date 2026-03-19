import boto3

from awsbyassumerole.provider.models import AwsByAssumeroleConfiguration


class AwsByAssumeroleClient(boto3.Session):
    """Aws by assumerole client."""

    def __init__(self, configuration: AwsByAssumeroleConfiguration):
        super().__init__()
        self.configuration = configuration

    def get_client(self, service_name: str, **kwargs):
        """Get client for service."""
        identity_token = self.get_identity_token()
        sts_client = super().client("sts")

        assumed_role_object = sts_client.assume_role_with_web_identity(
            RoleArn=self.configuration.role_arn,
            WebIdentityToken=identity_token,
            ExternalId=self.configuration.external_id,
        )
