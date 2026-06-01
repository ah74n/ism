from pydantic import BaseModel, field_validator


class URLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty")

        return value