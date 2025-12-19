from pydantic_settings import BaseSettings
from typing import Optional
import secrets


class Settings(BaseSettings):
    # API Settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "SecScan Pro"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://secscan:secscan@localhost:5432/secscan"
    DATABASE_URL_SYNC: str = "postgresql://secscan:secscan@localhost:5432/secscan"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # NVD API
    NVD_API_KEY: Optional[str] = None
    NVD_RATE_LIMIT: int = 5  # requests per 30 seconds (without API key)

    # STIG Scanner
    STIG_SCANNER_PATH: str = "/etc/ansible/roles/Evaluate-STIG"

    # Scan Settings
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_SSH_TIMEOUT: int = 30
    DEFAULT_SCAN_TIMEOUT: int = 3600
    VULN_TIMEOUT: int = 15

    # Report Settings
    REPORT_OUTPUT_DIR: str = "/tmp/secscan-reports"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
