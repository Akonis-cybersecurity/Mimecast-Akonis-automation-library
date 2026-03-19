"""Contains AwsS3ParquetRecordsTrigger."""

from connectors.s3 import AbstractAwsS3QueuedConnector
from connectors.s3.provider import AwsAccountProvider
from connectors.s3.trigger_s3_flowlogs_parquet import BaseAwsS3FlowLogsParquetRecordsTrigger


class AwsS3FlowLogsParquetRecordsTrigger(
    BaseAwsS3FlowLogsParquetRecordsTrigger, AbstractAwsS3QueuedConnector, AwsAccountProvider
):
    """AWS S3 Flow Logs Parquet Records Trigger connector."""
