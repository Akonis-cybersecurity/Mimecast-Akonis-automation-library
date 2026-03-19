"""Contains AwsS3LogsTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_logs import BaseAwsS3LogsTrigger 


class AwsS3LogsTrigger(BaseAwsS3LogsTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider):
    """AWS S3 Logs Trigger connector."""
