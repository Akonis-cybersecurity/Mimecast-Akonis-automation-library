"""Additional fixtures for this package."""

from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from faker import Faker
from sekoia_automation.aio.helpers.aws.client import AwsConfiguration as SekoiaAwsConfiguration

from aws_helpers.base import OidcAwsMixin
from connectors import AwsModule, AwsModuleConfiguration


@pytest.fixture
def mock_push_data_to_intakes() -> AsyncMock:
    """
    Mocked push_data_to_intakes method.

    Returns:
        AsyncMock:
    """

    def side_effect_return_input(events: list[str]) -> list[str]:
        """
        Return input value.

        Uses in side_effect to return input value from mocked function.

        Args:
            events: list[str]

        Returns:
            list[str]:
        """
        return events

    return AsyncMock(side_effect=side_effect_return_input)


@pytest.fixture
def intake_key(faker: Faker) -> str:
    """
    Create an intake key.

    Args:
        faker: Faker

    Returns:
        str:
    """
    return faker.word()


@pytest.fixture
def aws_configuration(faker: Faker) -> dict[str, str]:
    """
    Create a configuration for the AWS module.

    Args:
        faker: Faker

    Returns:
        dict[str, str]:
    """
    return {
        "aws_role_arn": "arn:aws:iam::123456789012:role/test-role",
        "aws_audience": "test-audience",
        "aws_region_name": "us-west-2",
    }


@pytest.fixture(autouse=True)
def mock_get_assume_role():
    """
    Mock OidcAwsMixin.get_assume_role for all connector tests to avoid real OIDC/STS calls.
    """
    fake_credentials = SekoiaAwsConfiguration(
        aws_access_key_id="fakeKeyId",
        aws_secret_access_key="fakeSecret",
        aws_region="us-west-2",
        aws_session_token="fakeSessionToken",
    )
    with mock.patch.object(OidcAwsMixin, "get_assume_role", return_value=fake_credentials):
        yield


@pytest.fixture
def aws_module(symphony_storage: Path, aws_configuration) -> AwsModule:
    """
    Create an AWS module.

    Args:
        symphony_storage: Path
        aws_configuration: dict[str, str]

    Returns:
        AwsModule: The AWS module.
    """
    module = AwsModule()
    module.configuration = AwsModuleConfiguration(**aws_configuration)

    return module
