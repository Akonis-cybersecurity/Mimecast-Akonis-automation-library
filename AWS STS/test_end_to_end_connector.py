from pathlib import Path

from sekoia_automation import constants

from aws_helpers.base import AWSModule, AWSConfiguration
from connectors.s3.logs.base import AwsS3FetcherConfiguration
from connectors.s3.logs.trigger_cloudtrail_logs import CloudTrailLogsTrigger

if __name__ == "__main__":
    current_path: Path = Path("/test_data")
    configuration = {
        "aws_role_arn": "arn:aws:iam::516755368338:role/vault-s3-sqs-access-eu-west-3",
        "aws_audience": "vault-aws-client",
        "aws_region_name": "eu-west-3",
    }
    configuration = AWSConfiguration(**configuration)

    aws_s3_fetcher_configuration = AwsS3FetcherConfiguration(
        bucket_name="sekoiabucket-516755368338",
    )

    cloud_trail_connector = CloudTrailLogsTrigger()
    cloud_trail_connector.configuration = aws_s3_fetcher_configuration
    cloud_trail_connector.module = AWSModule()
    cloud_trail_connector.module.configuration = configuration
    cloud_trail_connector.run()