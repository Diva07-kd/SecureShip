"""
Configuration settings for SecureScan backend.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureScan"
    API_V1_PREFIX: str = "/api"
    SCAN_TIMEOUT_SECONDS: int = 600
    MAX_CONCURRENCY: int = 1
    MAX_UPLOAD_SIZE_BYTES: int = 600 * 1024 * 1024     # 600 MB
    MAX_EXTRACTED_BYTES: int = 1500 * 1024 * 1024     # 1500 MB (1.5 GB)
    MAX_SINGLE_FILE_BYTES: int = 100 * 1024 * 1024     # 100 MB
    MAX_COMPRESSION_RATIO: float = 100.0
    MAX_FILE_COUNT: int = 30000
    NODE_PATH: Optional[str] = None
    SECURESHIP_CLI_PATH: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
