"""Runtime configuration.

Everything security-relevant comes from the environment. In production the
application refuses to start without its secrets instead of falling back to a
default value (a default secret is a forged-session waiting to happen).
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MIN_SECRET_LENGTH = 32


class ConfigError(RuntimeError):
    """Raised when the application cannot start safely."""


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines). Real environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value not in (None, "") else default


@dataclass
class Settings:
    env: str = "development"
    database_url: str = ""
    master_key: str = ""
    audit_key: str = ""
    secure_cookies: bool = False
    trust_proxy_hops: int = 0
    demo_mode: bool = True
    seed_demo: bool = True
    session_idle_minutes: int = 30
    session_absolute_hours: int = 8
    max_upload_mb: int = 10
    user_quota_mb: int = 100
    uploads_per_hour: int = 60
    login_max_failures: int = 5
    login_ip_max_failures: int = 30
    login_window_minutes: int = 15
    rate_limit_per_minute: int = 300
    log_audit_to_stdout: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def _dev_secrets(instance_dir: Path) -> dict:
    """Development only: generate and persist random secrets so a fresh clone runs."""
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / "dev-secrets.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    data = {"master_key": secrets.token_urlsafe(48), "audit_key": secrets.token_urlsafe(48)}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def load_settings(overrides: dict | None = None) -> Settings:
    _load_dotenv(PROJECT_ROOT / ".env")
    env = os.environ.get("TRUSTVAULT_ENV", "development").strip().lower()
    instance_dir = Path(os.environ.get("TRUSTVAULT_INSTANCE_DIR", PROJECT_ROOT / "instance"))

    database_url = os.environ.get("DATABASE_URL", "").strip()
    master_key = os.environ.get("TRUSTVAULT_MASTER_KEY", "").strip()
    audit_key = os.environ.get("TRUSTVAULT_AUDIT_KEY", "").strip()

    if env == "production":
        missing = [name for name, value in (
            ("DATABASE_URL", database_url),
            ("TRUSTVAULT_MASTER_KEY", master_key),
            ("TRUSTVAULT_AUDIT_KEY", audit_key),
        ) if not value]
        if missing:
            raise ConfigError("Refusing to start in production without: " + ", ".join(missing))
    else:
        if not database_url:
            instance_dir.mkdir(parents=True, exist_ok=True)
            database_url = "sqlite:///" + str((instance_dir / "trustvault.db").as_posix())
        if not master_key or not audit_key:
            generated = _dev_secrets(instance_dir)
            master_key = master_key or generated["master_key"]
            audit_key = audit_key or generated["audit_key"]

    for name, value in (("TRUSTVAULT_MASTER_KEY", master_key), ("TRUSTVAULT_AUDIT_KEY", audit_key)):
        if len(value) < MIN_SECRET_LENGTH:
            raise ConfigError(f"{name} must be at least {MIN_SECRET_LENGTH} characters of random data")
    if master_key == audit_key:
        raise ConfigError("TRUSTVAULT_MASTER_KEY and TRUSTVAULT_AUDIT_KEY must be different secrets")

    settings = Settings(
        env=env,
        database_url=database_url,
        master_key=master_key,
        audit_key=audit_key,
        secure_cookies=_bool("TRUSTVAULT_SECURE_COOKIES", env == "production"),
        trust_proxy_hops=_int("TRUSTVAULT_TRUST_PROXY_HOPS", 1 if env == "production" else 0),
        demo_mode=_bool("TRUSTVAULT_DEMO_MODE", True),
        seed_demo=_bool("TRUSTVAULT_SEED_DEMO", True),
        session_idle_minutes=_int("TRUSTVAULT_SESSION_IDLE_MINUTES", 30),
        session_absolute_hours=_int("TRUSTVAULT_SESSION_ABSOLUTE_HOURS", 8),
        max_upload_mb=_int("TRUSTVAULT_MAX_UPLOAD_MB", 10),
        user_quota_mb=_int("TRUSTVAULT_USER_QUOTA_MB", 100),
        uploads_per_hour=_int("TRUSTVAULT_UPLOADS_PER_HOUR", 60),
        login_max_failures=_int("TRUSTVAULT_LOGIN_MAX_FAILURES", 5),
        login_ip_max_failures=_int("TRUSTVAULT_LOGIN_IP_MAX_FAILURES", 30),
        login_window_minutes=_int("TRUSTVAULT_LOGIN_WINDOW_MINUTES", 15),
        rate_limit_per_minute=_int("TRUSTVAULT_RATE_LIMIT_PER_MINUTE", 300),
        log_audit_to_stdout=_bool("TRUSTVAULT_LOG_AUDIT_TO_STDOUT", True),
    )
    for key, value in (overrides or {}).items():
        setattr(settings, key, value)
    return settings
