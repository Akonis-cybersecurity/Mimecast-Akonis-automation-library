"""Initialize module and all connectors."""

from sekoia_automation.loguru.config import init_logging

from asset_connector.device_assets import AwsDeviceAssetConnector
from asset_connector.users_assets import AwsUsersAssetConnector
from awsbyassumerole.account_validator import AwsAccountValidator
from awsbyassumerole.trigger_s3_cloudfront import AwsS3CloudFrontTrigger
from awsbyassumerole.trigger_s3_flowlogs import AwsS3FlowLogsTrigger
from awsbyassumerole.trigger_s3_flowlogs_parquet import AwsS3FlowLogsParquetRecordsTrigger
from awsbyassumerole.trigger_s3_logs import AwsS3LogsTrigger
from awsbyassumerole.trigger_s3_ocsf_parquet import AwsS3OcsfTrigger
from awsbyassumerole.trigger_s3_records import AwsS3RecordsTrigger
from awsbyassumerole.trigger_sqs_messages import AwsSqsMessagesTrigger
from connectors import AwsModule

if __name__ == "__main__":
    init_logging()

    module = AwsModule()
    module.register_account_validator(AwsAccountValidator)
    module.register(AwsDeviceAssetConnector, "aws_device_asset_connector")
    module.register(AwsUsersAssetConnector, "aws_users_asset_connector")
    module.register(AwsS3LogsTrigger, "aws_s3_logs_trigger")
    module.register(AwsS3RecordsTrigger, "aws_s3_cloudtrail_records_trigger")
    module.register(AwsS3FlowLogsParquetRecordsTrigger, "aws_s3_flowlogs_parquet_records_trigger")
    module.register(AwsSqsMessagesTrigger, "aws_sqs_messages_trigger")
    module.register(AwsS3FlowLogsTrigger, "aws_s3_flowlogs_trigger")
    module.register(AwsS3CloudFrontTrigger, "aws_s3_cloudfront_trigger")
    module.register(AwsS3OcsfTrigger, "aws_s3_oscf_trigger")

    module.run()
