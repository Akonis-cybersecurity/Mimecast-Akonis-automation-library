"""Contains AwsS3ParquetRecordsTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_ocsf_parquet import BaseAwsS3OcsfTrigger


class AwsS3OcsfTrigger(BaseAwsS3OcsfTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider):
    """AWS S3 OCSF Trigger connector."""
