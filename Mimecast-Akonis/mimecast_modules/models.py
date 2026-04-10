from pydantic.v1 import BaseModel


class MimecastModuleConfiguration(BaseModel):
    """Module-level configuration — empty because all credentials live at the connector level."""

    pass
