from shutil import rmtree
from tempfile import mkdtemp
from unittest.mock import MagicMock

import pytest
from sekoia_automation import constants

from mimecast_modules import MimecastModule
from mimecast_modules.connector import MimecastConnector, MimecastConnectorConfiguration


@pytest.fixture
def data_storage():
    original_storage = constants.DATA_STORAGE
    constants.DATA_STORAGE = mkdtemp()

    yield constants.DATA_STORAGE

    rmtree(constants.DATA_STORAGE)
    constants.DATA_STORAGE = original_storage


@pytest.fixture
def connector(data_storage):
    """Return a fully configured MimecastConnector with mocked push/log methods."""
    module = MimecastModule()
    module.configuration = {}  # Module has no required fields

    connector = MimecastConnector(module=module, data_path=data_storage)
    connector.configuration = MimecastConnectorConfiguration(
        intake_key="test-intake-key",
        client_id="test-client-id",
        client_secret="test-client-secret",
        base_url="https://api.services.mimecast.com",
        access_key="test-access-key",
        secret_key="dGVzdC1zZWNyZXQta2V5",  # base64-encoded for HMAC tests
        app_id="test-app-id",
        app_key="test-app-key",
        base_url_v1="https://us-api.mimecast.com",
        frequency=60,
        chunk_size=100,
        historical_days=7,
    )

    connector.log = MagicMock()
    connector.log_exception = MagicMock()
    connector.push_events_to_intakes = MagicMock()

    yield connector
