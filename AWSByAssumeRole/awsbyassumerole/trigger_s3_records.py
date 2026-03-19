"""Contains AwsS3RecordsTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_records import BaseAwsS3RecordsTrigger


class AwsS3RecordsTrigger(BaseAwsS3RecordsTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider):
    """AWS S3 Records Trigger connector."""
