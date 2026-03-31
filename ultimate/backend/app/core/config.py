from __future__ import annotations

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://bastion:bastion_secret_2026@localhost:5432/ssh_bastion"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "change_me_in_production_2026"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480

    vt_api_key: str = ""
    vt_base_url: str = "https://www.virustotal.com/api/v3"

    cors_origins: str = "http://localhost:5173"

    bastion_port: int = 2222
    api_url: str = "http://localhost:8000"

    rate_limit_window: int = 60
    rate_limit_max: int = 30

    strict_mode: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
