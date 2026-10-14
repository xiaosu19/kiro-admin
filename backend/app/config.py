from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite:///./console.db"
    secret_key: str
    fernet_key: str
    secure_cookie: bool = True
    session_hours: int = 12
    frontend_dir: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    aws_timeout: int = 30
    worker_lease_seconds: int = 180
    worker_concurrency: int = Field(default=4, ge=1, le=16)
    auth_worker_concurrency: int = Field(default=2, ge=1, le=16)
    per_account_concurrency: int = Field(default=2, ge=1, le=8)
    auth_per_account_concurrency: int | None = Field(default=None, ge=1, le=16)
    plan_changes_enabled: bool = False
    app_origin: str = "https://console.example.com"
    verify_origin: str = "https://verify.example.com"
    auth_allow_local_origins: bool = False
    auth_batch_ttl_hours: int = Field(default=72, ge=1, le=168)
    auth_download_ttl_seconds: int = Field(default=900, ge=30, le=3600)
    auth_worker_lease_seconds: int = Field(default=180, ge=60, le=900)
    auth_worker_lock_path: Path | None = None
    captcha_vision_api_key: SecretStr = Field(default=SecretStr(""), repr=False)
    captcha_vision_endpoint: str = "https://api.anthropic.com/v1/messages"
    captcha_vision_model: str = "claude-opus-4.6"
    captcha_vision_timeout_seconds: float = Field(default=20, gt=0, le=60)
    captcha_max_attempts: int = Field(default=6, ge=1, le=6)
    captcha_total_timeout_seconds: float = Field(default=60, ge=5, le=60)
    captcha_browser_concurrency: int = Field(default=2, ge=1, le=4)
    captcha_chromium_executable: str | None = None
    backup_status_path: Path = Path("/var/lib/kiro-console/backup-status.json")

    @model_validator(mode="after")
    def isolated_auth_origins(self):
        parsed = []
        for value in (self.app_origin, self.verify_origin):
            p = urlsplit(value)
            local = self.auth_allow_local_origins and p.hostname in (
                "localhost",
                "127.0.0.1",
                "::1",
            )
            if (p.scheme != "https" and not (local and p.scheme == "http")) or (
                not p.hostname
                or p.username
                or p.password
                or p.path
                or p.query
                or p.fragment
                or any(c.isspace() or ord(c) < 32 for c in value)
                or p.port is not None
                and not 1 <= p.port <= 65535
            ):
                raise ValueError("APP_ORIGIN/VERIFY_ORIGIN must be exact HTTPS origins")
            parsed.append(p)
        if parsed[0].hostname == parsed[1].hostname:
            raise ValueError("Verification requires a separate origin and hostname")
        return self


settings = Settings()
