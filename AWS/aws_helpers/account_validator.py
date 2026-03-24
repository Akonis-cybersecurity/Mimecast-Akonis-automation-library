import boto3
from sekoia_automation.account_validator import AccountValidator

from aws_helpers.base import AwsModule
from aws_helpers.oidc import OidcAwsMixin


class AwsAccountValidator(OidcAwsMixin, AccountValidator):
    module: AwsModule

    def client(self) -> boto3.client:
        assume_role = self.get_assume_role()
        session = boto3.Session(
            aws_access_key_id=assume_role.aws_access_key_id,
            aws_secret_access_key=assume_role.aws_secret_access_key,
            aws_session_token=assume_role.aws_session_token,
            region_name=assume_role.aws_region,
        )
        return session.client("iam")

    def validate(self) -> bool:
        try:
            client = self.client()
            client.get_login_profile()
            return True
        except Exception as e:
            # Check if it's a specific AWS exception by examining the exception type
            if hasattr(e, "__class__") and "NoSuchEntity" in e.__class__.__name__:
                self.error(
                    f"The AWS credentials are invalid or do not have the required permissions. Reason: {str(e)}"
                )
            elif hasattr(e, "__class__") and "ServiceFailure" in e.__class__.__name__:
                self.error(f"AWS service failure occurred during validation. Reason: {str(e)}")
            else:
                self.error(f"An error occurred during AWS account validation: {str(e)}")
            return False
