"""Thin database layer supporting SQLite (local/dev/tests) and PostgreSQL (production).

SQL in this codebase is written once with `?` placeholders and always
parameterised; the PostgreSQL adapter rewrites `?` to `%s`. No query text is
ever built from user input.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from importlib import resources
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

AUDIT_LOCK_ID = 7_310_442  # advisory lock that serialises audit-chain appends in PostgreSQL


class Database:
    def __init__(self, url: str):
        self.url = url
        if url.startswith(("postgres://", "postgresql://")):
            self.kind = "postgres"
        elif url.startswith("sqlite:///"):
            self.kind = "sqlite"
            self.path = url[len("sqlite:///"):]
        else:
            raise ValueError("DATABASE_URL must be postgresql://... or sqlite:///path")

    def connect(self) -> "Connection":
        if self.kind == "postgres":
            import psycopg
            from psycopg.rows import dict_row

            raw = psycopg.connect(self.url, autocommit=True, row_factory=dict_row, connect_timeout=10)
        else:
            raw = sqlite3.connect(self.path, isolation_level=None, timeout=15, check_same_thread=False)
            raw.row_factory = sqlite3.Row
            raw.execute("PRAGMA foreign_keys = ON")
            raw.execute("PRAGMA journal_mode = WAL")
            raw.execute("PRAGMA busy_timeout = 15000")
        return Connection(raw, self.kind)

    def init_schema(self) -> None:
        script = resources.files("trustvault.schema").joinpath(f"{self.kind}.sql").read_text(encoding="utf-8")
        conn = self.connect()
        try:
            conn.executescript(script)
        finally:
            conn.close()

    def describe(self) -> str:
        if self.kind == "sqlite":
            return f"sqlite ({self.path})"
        parsed = urlparse(self.url)
        return f"postgresql ({parsed.hostname}/{parsed.path.lstrip('/')})"


class Connection:
    def __init__(self, raw: Any, kind: str):
        self.raw = raw
        self.kind = kind
        self.in_transaction = False
        self._after_commit: list[Callable[[], None]] = []

    # -- execution -------------------------------------------------------
    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.kind == "postgres" else sql

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        return self.raw.execute(self._sql(sql), tuple(params))

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        row = self.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def all(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return [dict(r) for r in self.execute(sql, params).fetchall()]

    def scalar(self, sql: str, params: Iterable[Any] = ()) -> Any:
        row = self.execute(sql, params).fetchone()
        if row is None:
            return None
        return list(dict(row).values())[0]

    def insert_returning_id(self, sql: str, params: Iterable[Any]) -> int:
        row = self.execute(sql + " RETURNING id", params).fetchone()
        return int(dict(row)["id"])

    def executescript(self, script: str) -> None:
        if self.kind == "sqlite":
            self.raw.executescript(script)
        else:
            self.raw.execute(script)

    # -- transactions ----------------------------------------------------
    @contextmanager
    def transaction(self, audit_lock: bool = True):
        """One atomic unit of work. Business change + its audit event commit together.

        SQLite: BEGIN IMMEDIATE takes the write lock up front, which also serialises the
        audit hash chain. PostgreSQL: an advisory transaction lock does the same.
        """
        if self.in_transaction:  # nested use joins the outer transaction
            yield self
            return
        self.in_transaction = True
        try:
            if self.kind == "sqlite":
                self.raw.execute("BEGIN IMMEDIATE")
                try:
                    yield self
                    self.raw.execute("COMMIT")
                except BaseException:
                    self.raw.execute("ROLLBACK")
                    raise
            else:
                with self.raw.transaction():
                    if audit_lock:
                        self.raw.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
                    yield self
        except BaseException:
            self._after_commit.clear()
            raise
        finally:
            self.in_transaction = False
        callbacks, self._after_commit = self._after_commit, []
        for callback in callbacks:
            try:
                callback()
            except Exception:  # pragma: no cover - logging must never break a request
                pass

    def after_commit(self, callback: Callable[[], None]) -> None:
        self._after_commit.append(callback)

    def close(self) -> None:
        try:
            self.raw.close()
        except Exception:  # pragma: no cover
            pass


def like_pattern(term: str) -> str:
    """Escape LIKE wildcards so user input is matched literally (ESCAPE '!')."""
    escaped = term.lower().replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return f"%{escaped}%"
