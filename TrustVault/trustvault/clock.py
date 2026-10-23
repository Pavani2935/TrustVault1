"""Single source of time. Timestamps are stored as fixed-width UTC ISO-8601 strings
(e.g. 2026-10-23T09:15:02.123456Z) so they sort and compare identically in
SQLite and PostgreSQL. Tests move time with `advance()` instead of sleeping."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

_offset = timedelta(0)
FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> datetime:
    return datetime.now(timezone.utc) + _offset


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(FORMAT)


def now_iso() -> str:
    return iso(utcnow())


def ago_iso(**delta) -> str:
    return iso(utcnow() - timedelta(**delta))


def ahead_iso(**delta) -> str:
    return iso(utcnow() + timedelta(**delta))


def parse(value: str) -> datetime:
    return datetime.strptime(value, FORMAT).replace(tzinfo=timezone.utc)


def advance(**delta) -> None:  # test helper
    global _offset
    _offset += timedelta(**delta)


def reset() -> None:  # test helper
    global _offset
    _offset = timedelta(0)
