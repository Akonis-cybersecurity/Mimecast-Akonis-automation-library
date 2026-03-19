"""Contains AwsS3FlowLogsTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_flowlogs import BaseAwsS3FlowLogsTrigger


class AwsS3FlowLogsTrigger(BaseAwsS3FlowLogsTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider):
    """AWS S3 Flow Logs Trigger connector."""
