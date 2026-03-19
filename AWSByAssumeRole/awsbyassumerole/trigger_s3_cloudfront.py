"""Contains AwsS3CloudFrontTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_cloudfront import BaseAwsS3CloudFrontTrigger


class AwsS3CloudFrontTrigger(BaseAwsS3CloudFrontTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider):
    """AWS S3 CloudFront Logs Trigger connector."""
