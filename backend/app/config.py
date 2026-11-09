import json
from typing import Any, List
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustLens AI"
    TAGLINE: str = "Investigate. Understand. Verify. Protect."
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    
    HOST: str = "127.0.0.1"
    PORT: int = Field(default=8000, ge=1, le=65535)
    
    DATABASE_URL: str = "sqlite:///./trustlens.db"
    APP_ACCESS_TOKEN: str = ""
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    
    REQUEST_TIMEOUT_SECONDS: int = Field(default=8, ge=1, le=60)
    MAX_REDIRECTS: int = Field(default=5, ge=1, le=20)
    MAX_RESPONSE_BYTES: int = Field(default=1048576, ge=1, le=10485760)

    COMMUNITY_WRITES_ENABLED: bool = False
    COMMUNITY_ABUSE_KEY: str = ""
    
    # Optional Threat Intel Keys
    VIRUSTOTAL_API_KEY: str = ""
    URLHAUS_API_ENABLED: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            cleaned = v.strip()
            if cleaned.startswith("[") and cleaned.endswith("]"):
                try:
                    parsed = json.loads(cleaned)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in cleaned.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def require_production_access_token(self):
        if self.ENVIRONMENT.lower() == "production" and len(self.APP_ACCESS_TOKEN) < 32:
            raise ValueError("APP_ACCESS_TOKEN must contain at least 32 characters in production.")
        return self
    
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()
