from pydantic.v1 import BaseModel, Field, SecretStr


class MimecastModuleConfiguration(BaseModel):
    """Module-level configuration — credentials shared across all connectors and actions."""

    # ---- API 2.0 (OAuth2) ----
    client_id: str = Field(..., description="OAuth2 Client ID (API 2.0)")
    client_secret: SecretStr = Field(..., description="OAuth2 Client Secret (API 2.0)")
    base_url: str = Field("https://api.services.mimecast.com", description="Mimecast API 2.0 base URL")
