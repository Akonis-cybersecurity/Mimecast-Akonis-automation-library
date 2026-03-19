from pydantic.v1 import BaseModel


class AwsByAssumeroleConfiguration(BaseModel):
    role_arn: str
    external_id: str
