from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .config import Settings
from .crypto import Vault
from .db import Connection


@dataclass
class Ctx:
    """Everything a service call needs: who is asking, from where, and the stores."""
    conn: Connection
    user: dict | None
    ip: str | None
    settings: Settings
    vault: Vault
    audit: AuditLog

    def log(self, action: str, **kwargs: Any) -> dict:
        return self.audit.record(self.conn, action=action, actor=self.user, ip=self.ip, **kwargs)
