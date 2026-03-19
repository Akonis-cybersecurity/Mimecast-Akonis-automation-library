from aws_helpers.base import AWSModule as AwsModule, OidcAwsMixin
from aws_helpers.provider import AwsProvider
from aws_helpers.s3_wrapper import S3Configuration, S3Wrapper
from aws_helpers.sqs_wrapper import SqsConfiguration, SqsWrapper
from connectors.s3 import AwsS3QueuedConfiguration
from sekoia_automation.aio.helpers.aws.client import AwsConfiguration


class AwsAccountProvider(OidcAwsMixin, AwsProvider):
    """
    AWS provider with access key and secret access key.
    """

    module: AwsModule
    configuration: AwsS3QueuedConfiguration

    _s3_wrapper: S3Wrapper | None = None
    _sqs_wrapper: SqsWrapper | None = None

    @property
    def s3_wrapper(self) -> S3Wrapper:
        """
        Get S3 wrapper.

        Returns:
            S3Wrapper:
        """
        if self._s3_wrapper is not None:
            return self._s3_wrapper
        assume_role : AwsConfiguration = self.get_assume_role()
        config = S3Configuration(
            aws_access_key_id=assume_role.aws_access_key_id,
            aws_secret_access_key=assume_role.aws_secret_access_key,
            aws_region=assume_role.aws_region,
            aws_session_token=assume_role.aws_session_token,
        )

        return S3Wrapper(config)

    @s3_wrapper.setter
    def s3_wrapper(self, value: S3Wrapper) -> None:
        self._s3_wrapper = value

    @property
    def sqs_wrapper(self) -> SqsWrapper:
        """
        Get SQS wrapper.

        Returns:
            SqsWrapper:
        """
        if self._sqs_wrapper is not None:
            return self._sqs_wrapper
        assume_role : AwsConfiguration = self.get_assume_role()
        config = SqsConfiguration(
            frequency=self.configuration.sqs_frequency,
            delete_consumed_messages=self.configuration.delete_consumed_messages,
            queue_name=self.configuration.queue_name,
            aws_access_key_id=assume_role.aws_access_key_id,
            aws_secret_access_key=assume_role.aws_secret_access_key,
            aws_region=assume_role.aws_region,
            aws_session_token=assume_role.aws_session_token,
        )

        return SqsWrapper(config)

    @sqs_wrapper.setter
    def sqs_wrapper(self, value: SqsWrapper) -> None:
        self._sqs_wrapper = value