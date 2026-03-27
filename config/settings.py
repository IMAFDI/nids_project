"""
NIDS — Settings / Configuration Module
======================================
Pydantic-settings based configuration with support for:
  - config/settings.yaml
  - .env file
  - Environment variables

All secrets come from environment variables only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
MODELS_DIR = BASE_DIR / "models"
SETTINGS_FILE = CONFIG_DIR / "settings.yaml"


# ---------------------------------------------------------------------------
# Database settings
# ---------------------------------------------------------------------------

class DatabaseSettings(BaseSettings):
    url: str = Field(
        default="sqlite:///logs/nids.db",
        description="Database connection URL. Use postgres://... for PostgreSQL or sqlite://... for SQLite."
    )
    pool_size: int = Field(default=5, ge=1)
    max_overflow: int = Field(default=10, ge=0)
    echo: bool = Field(default=False)

    model_config = SettingsConfigDict(env_prefix="NIDS_DB_")


# ---------------------------------------------------------------------------
# Capture settings
# ---------------------------------------------------------------------------

class CaptureSettings(BaseSettings):
    interface: str | None = Field(default=None)
    packet_filter: str | None = Field(default=None)
    batch_timeout: int = Field(default=10, ge=1)
    max_queue_depth: int = Field(default=10000, ge=100)

    model_config = SettingsConfigDict(env_prefix="NIDS_CAPTURE_")


# ---------------------------------------------------------------------------
# ML Model settings
# ---------------------------------------------------------------------------

class MLSettings(BaseSettings):
    model_dir: Path = Field(default=MODELS_DIR / "versions")
    retrain_interval_hours: int = Field(default=24, ge=1)
    retrain_window_hours: int = Field(default=168, ge=1)
    contamination: float = Field(default=0.05, ge=0.0, le=1.0)
    ensemble_threshold: int = Field(default=2, ge=1, le=3,
                                    description="Number of models that must agree to flag anomaly")

    model_config = SettingsConfigDict(env_prefix="NIDS_ML_")


# ---------------------------------------------------------------------------
# Notification settings
# ---------------------------------------------------------------------------

class EmailSettings(BaseSettings):
    enabled: bool = Field(default=False)
    host: str = Field(default="smtp.gmail.com")
    port: int = Field(default=587, ge=1, le=65535)
    user: str = Field(default="")
    password: str = Field(default="")
    from_addr: str = Field(default="")
    to_addr: str = Field(default="")

    model_config = SettingsConfigDict(env_prefix="NIDS_EMAIL_")


class SlackSettings(BaseSettings):
    enabled: bool = Field(default=False)
    webhook_url: str = Field(default="")

    model_config = SettingsConfigDict(env_prefix="NIDS_SLACK_")


class PagerDutySettings(BaseSettings):
    enabled: bool = Field(default=False)
    routing_key: str = Field(default="")

    model_config = SettingsConfigDict(env_prefix="NIDS_PAGERDUTY_")


class TeamsSettings(BaseSettings):
    enabled: bool = Field(default=False)
    webhook_url: str = Field(default="")

    model_config = SettingsConfigDict(env_prefix="NIDS_TEAMS_")


class SyslogSettings(BaseSettings):
    enabled: bool = Field(default=False)
    host: str = Field(default="localhost")
    port: int = Field(default=514, ge=1, le=65535)
    protocol: Literal["udp", "tcp"] = Field(default="udp")

    model_config = SettingsConfigDict(env_prefix="NIDS_SYSLOG_")


class NotificationSettings(BaseSettings):
    dedup_window_seconds: int = Field(default=300, ge=0)
    max_retries: int = Field(default=3, ge=0)
    retry_backoff_base: float = Field(default=2.0, ge=1.0)
    email: EmailSettings = Field(default_factory=EmailSettings)
    slack: SlackSettings = Field(default_factory=SlackSettings)
    pagerduty: PagerDutySettings = Field(default_factory=PagerDutySettings)
    teams: TeamsSettings = Field(default_factory=TeamsSettings)
    syslog: SyslogSettings = Field(default_factory=SyslogSettings)


# ---------------------------------------------------------------------------
# Dashboard / API settings
# ---------------------------------------------------------------------------

class DashboardSettings(BaseSettings):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=5000, ge=1, le=65535)
    debug: bool = Field(default=False)

    model_config = SettingsConfigDict(env_prefix="NIDS_DASHBOARD_")


class JWTSettings(BaseSettings):
    secret: str = Field(default="")
    algorithm: str = Field(default="HS256")
    expiry_hours: int = Field(default=24, ge=1)
    rate_limit_per_minute: int = Field(default=100, ge=1)

    @model_validator(mode="after")
    def _check_secret(self) -> "JWTSettings":
        if not self.secret:
            import uuid
            self.secret = str(uuid.uuid4())
        return self

    model_config = SettingsConfigDict(env_prefix="NIDS_JWT_")


class APISettings(BaseSettings):
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)

    model_config = SettingsConfigDict(env_prefix="NIDS_API_")


# ---------------------------------------------------------------------------
# Threat Intelligence settings
# ---------------------------------------------------------------------------

class ThreatIntelSettings(BaseSettings):
    abuseipdb_api_key: str = Field(default="")
    abuseipdb_check_severity: int = Field(default=50, ge=1, le=100,
                                          description="Min severity score (0-100) to auto-escalate")
    blocklist_dir: Path = Field(default=CONFIG_DIR / "blocklists")
    cache_ttl_seconds: int = Field(default=3600, ge=60)
    enabled: bool = Field(default=True)

    model_config = SettingsConfigDict(env_prefix="NIDS_THREATINTEL_")


# ---------------------------------------------------------------------------
# Rate limit settings
# ---------------------------------------------------------------------------

class RateLimitSettings(BaseSettings):
    packets_per_second_per_ip: int = Field(default=1000, ge=1)
    events_per_second: int = Field(default=100, ge=1)

    model_config = SettingsConfigDict(env_prefix="NIDS_RATELIMIT_")


# ---------------------------------------------------------------------------
# Root settings
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    capture: CaptureSettings = Field(default_factory=CaptureSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)
    api: APISettings = Field(default_factory=APISettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    rate_limits: RateLimitSettings = Field(default_factory=RateLimitSettings)

    model_config = SettingsConfigDict(
        env_file=(".env",),
        env_nested_delimiter="__",
        extra="ignore",
    )

    @classmethod
    def load(cls) -> "Settings":
        """Load settings from YAML file if it exists, then env vars override."""
        if SETTINGS_FILE.exists():
            import yaml
            with open(SETTINGS_FILE) as f:
                yaml_data = yaml.safe_load(f) or {}
            return cls.model_validate(yaml_data)
        return cls()


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the global settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings


def reload_settings() -> Settings:
    """Force reload settings from disk/env."""
    global _settings
    _settings = Settings.load()
    return _settings
