from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustLens AI"
    TAGLINE: str = "Investigate. Understand. Verify. Protect."
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    DATABASE_URL: str = "sqlite:///./trustlens.db"
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    
    REQUEST_TIMEOUT_SECONDS: int = 8
    MAX_REDIRECTS: int = 5
    MAX_RESPONSE_BYTES: int = 1048576  # 1 MB
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Optional Threat Intel Keys
    VIRUSTOTAL_API_KEY: str = ""
    URLHAUS_API_ENABLED: bool = True
    PHISHTANK_API_ENABLED: bool = True
    OPENPHISH_API_ENABLED: bool = True
    
    # Optional AI Provider Keys
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    AI_PROVIDER: str = "deterministic"
    
    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()
