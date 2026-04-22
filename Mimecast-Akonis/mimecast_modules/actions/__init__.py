from functools import cached_property

from sekoia_automation.action import Action

from mimecast_modules import MimecastModule
from mimecast_modules.client import MimecastClient


class MimecastAction(Action):
    """Base class for all Mimecast response actions."""

    module: MimecastModule

    @staticmethod
    def _secret(val) -> str:
        """Return the plaintext secret whether val is SecretStr or a raw str.

        The Sekoia SDK injects secrets via setattr(), bypassing pydantic
        validation, so SecretStr fields may arrive as plain str at runtime.
        """
        return val.get_secret_value() if hasattr(val, "get_secret_value") else val

    @cached_property
    def client(self) -> MimecastClient:
        mod = self.module.configuration
        return MimecastClient(
            base_url=mod.base_url,
            client_id=mod.client_id,
            client_secret=self._secret(mod.client_secret),
        )
