from typing import Optional

from pydantic.v1 import BaseModel, Field, SecretStr


class MimecastModuleConfiguration(BaseModel):
    """Module-level configuration — credentials shared across all connectors and actions."""

    # ---- API 2.0 (OAuth2) — required ----
    client_id: str = Field(..., description="OAuth2 Client ID (API 2.0)")
    client_secret: SecretStr = Field(..., description="OAuth2 Client Secret (API 2.0)")
    base_url: str = Field("https://api.services.mimecast.com", description="Mimecast API 2.0 base URL")

    # ---- API 1.0 (HMAC-SHA1) — optional, required only for legacy endpoints ----
    access_key: Optional[str] = Field(None, description="API 1.0 Access Key")
    secret_key: Optional[SecretStr] = Field(None, description="API 1.0 Secret Key")
    app_id: Optional[str] = Field(None, description="API 1.0 Application ID")
    app_key: Optional[SecretStr] = Field(None, description="API 1.0 Application Key")
    base_url_v1: str = Field("https://us-api.mimecast.com", description="API 1.0 base URL (region-specific)")
