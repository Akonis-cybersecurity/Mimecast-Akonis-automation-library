from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from aws_helpers.provider import AwsSqsClient

from awsbyassumerole.provider.client import AwsByAssumeroleClient
from awsbyassumerole.provider.models import AwsByAssumeroleConfiguration


class SqsConfiguration(AwsByAssumeroleConfiguration):
    queue_url: str
    frequency: int = 20
    delete_consumed_messages: bool = True


class SqsWrapper(AwsByAssumeroleClient, AwsSqsClient):
    """Aws SQS wrapper."""

    def __init__(self, configuration: SqsConfiguration) -> None:
         """
         Initialize SqsWrapper.

         Args:
             configuration: AWS configuration
         """
        super().__init__(configuration)

        logger.info(
            """
                Initializing SQS client with configuration:
                    queue_arn = {queue_arn}
                    frequency = {frequency}
                    delete_consumed_messages = {delete_consumed_messages}
            """,
            queue_url=configuration.queue_url,
            frequency=configuration.frequency,
            delete_consumed_messages=configuration.delete_consumed_messages,
        )

    @asynccontextmanager
    async def receive_messages(
        self,
        frequency: int | None = None,
        max_messages: int = 10,
        delete_consumed_messages: bool | None = None,
        visibility_timeout: int | None = None,
    ) -> AsyncGenerator[list[tuple[str, int]], None]:
        """
        Receive SQS messages.

        After processing messages they will be deleted from queue if delete_consumed_messages is True.

        Example of usage:
        with sqs.receive_messages() as messages:
            # do something with messages

        Args:
            frequency: int
            max_messages: int
            delete_consumed_messages: int
            visibility_timeout: int

        Yields:
            list[tuple[str, int]]: list of message content and message sent timestamp
        """
        if max_messages < 1 or max_messages > 10:
            raise ValueError("max_messages should be between 1 and 10")

        frequency = frequency or self.configuration.frequency
        delete_consumed_messages = delete_consumed_messages or self.configuration.delete_consumed_messages

        # Ensure visibility timeout is a positive integer if it is provided
        if visibility_timeout is not None and visibility_timeout < 0:
            raise ValueError("timeout should be a positive integer")

        async with self.get_client("sqs") as sqs:
            try:
                response = await sqs.receive_message(
                    QueueUrl=self.configuration.queue_url,
                    MaxNumberOfMessages=max_messages,
                    WaitTimeSeconds=frequency,
                    MessageAttributeNames=["All"],
                    MessageSystemAttributeNames=["All"],
                    VisibilityTimeout=visibility_timeout,
                )

            except Exception as e:  # pragma: no cover
                logger.error(f"Failed to receive messages from sqs: {e}")

                raise e

            result = []

            try:
                for message in response.get("Messages", []):
                    result.append((message["Body"], int(message["Attributes"]["SentTimestamp"])))

                logger.info(f"Received {len(result)} messages from sqs queue {self._configuration.queue_url}")

                yield result
            finally:
                # We should delete messages from queue after releasing context manager if it is configured
                if delete_consumed_messages and response.get("Messages", []):
                    logger.info("Deleting consumed messages from sqs")
                    for message in response.get("Messages", []):
                        await sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
