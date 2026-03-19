import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from aws_helpers.provider import AwsS3Client

from awsbyassumerole.provider.client import AwsByAssumeroleClient


class S3Wrapper(AwsByAssumeroleClient, AwsS3Client):
    """Aws S3 wrapper."""

    @asynccontextmanager
    async def read_key(
        self, key: str, bucket: str | None = None, loop: asyncio.AbstractEventLoop | None = None
    ) -> AsyncGenerator[AsyncReader, None]:
        """
        Reads text file from S3 bucket.

        Args:
            key: str
            bucket: str | None: if not provided, then use default bucket from configuration

        Yields:
            str:
        """
        if loop is None:
            loop = asyncio.get_running_loop()

        logger.info(f"Reading object {key} from bucket {bucket}")

        async with self.get_client("s3") as s3:
            response = await s3.get_object(Bucket=bucket, Key=key)
            async with response["Body"] as stream:
                with io.BytesIO(await stream.read()) as content:
                    if is_gzip_compressed(content.getbuffer()):
                        async_reader = await async_gzip_open(content, loop=loop)
                    else:
                        async_reader = AsyncBufferedReader(content, loop=loop, executor=None)
                    try:
                        yield async_reader
                    finally:
                        await async_reader.close()
