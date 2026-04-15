"""Account validator for the Mimecast module — tests OAuth2 credentials."""

from requests.exceptions import RequestException, Timeout

from sekoia_automation.account_validator import AccountValidator

from .client.http_client import MimecastClient
from .client.errors import MimecastAuthError


class MimecastAccountValidator(AccountValidator):
    """Validate Mimecast API 2.0 (OAuth2) credentials by requesting a token."""

    def validate(self) -> bool:
        self.log(message="Starting Mimecast credential validation", level="info")

        config = self.module.configuration

        # configuration may be a pydantic model (attribute access) or a plain dict
        if hasattr(config, "client_id"):
            client_id = config.client_id
            client_secret = config.client_secret
            base_url = config.base_url
        else:
            client_id = config.get("client_id", "")
            client_secret = config.get("client_secret", "")
            base_url = config.get("base_url", "https://api.services.mimecast.com")

        # Unwrap SecretStr if needed (Sekoia SDK may inject it as plain str)
        if hasattr(client_secret, "get_secret_value"):
            client_secret = client_secret.get_secret_value()

        client = MimecastClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
        )

        try:
            client._refresh_oauth_token()
        except MimecastAuthError as e:
            self.log(message=f"Mimecast credential validation failed: {e}", level="error")
            self.error(message=f"Invalid Mimecast credentials: {e}")
            return False
        except Timeout:
            self.log(message="Mimecast credential validation timed out", level="error")
            self.error(message="Mimecast API did not respond in time — check the base URL")
            return False
        except RequestException as e:
            self.log(message=f"Network error during Mimecast validation: {e}", level="error")
            self.error(message=f"Network error while contacting Mimecast API: {e}")
            return False
        except Exception as e:
            self.log(message=f"Unexpected error during Mimecast validation: {e}", level="error")
            self.error(message=f"Unexpected error: {e}")
            return False

        self.log(message="Mimecast credentials validated successfully", level="info")
        return True
