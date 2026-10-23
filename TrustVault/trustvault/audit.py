"""Tamper-evident audit trail.

Each event is chained to the previous one with HMAC-SHA256:

    event_hash = HMAC(audit_key, canonical_json(seq, time, actor, action, ..., prev_hash))

What stops someone quietly altering it:
1. The application exposes no route that updates or deletes audit rows.
2. Database triggers refuse UPDATE / DELETE / TRUNCATE on audit_events.
3. Someone who bypasses the triggers (e.g. drops them as DB owner) and edits, inserts,
   removes or reorders rows cannot produce valid hashes without TRUSTVAULT_AUDIT_KEY,
   which is held by the host's secret store, not the database. `verify_chain` reports
   the first broken sequence number. Sequence numbers are contiguous, so gaps show.
4. Every event is also written as one JSON line to stdout, so the hosting platform's
   log store holds an independent copy, including the running head hash. Truncating
   the tail of the table is detected by comparing with that copy.
Residual risk (accepted, see THREATS.md): someone holding BOTH the database and the
audit key could rewrite history; production would anchor head hashes in WORM storage.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from typing import Any

from . import clock
from .crypto import derive_key, key_fingerprint

GENESIS = "0" * 64
_FIELDS = ("seq", "event_time", "actor_id", "actor_username", "actor_role", "ip", "action",
           "outcome", "document_id", "target", "details", "prev_hash")


class AuditLog:
    def __init__(self, audit_secret: str, to_stdout: bool = True):
        self._key = derive_key(audit_secret, "audit-chain-hmac")
        self.key_id = key_fingerprint(self._key)
        self.to_stdout = to_stdout

    def _digest(self, event: dict) -> str:
        canonical = json.dumps({f: event[f] for f in _FIELDS}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=True)
        return hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()

    def record(self, conn, *, action: str, actor: dict | None, outcome: str = "success",
               document_id: str | None = None, target: str | None = None,
               details: dict | None = None, ip: str | None = None,
               actor_name_hint: str | None = None) -> dict:
        """Append one event. Runs inside the caller's transaction when there is one, so a
        business change and its audit record commit (or roll back) together."""
        with conn.transaction():
            head = conn.one("SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
            event = {
                "seq": (head["seq"] + 1) if head else 1,
                "event_time": clock.now_iso(),
                "actor_id": actor["id"] if actor else None,
                "actor_username": (actor["username"] if actor else (actor_name_hint or "anonymous"))[:80],
                "actor_role": actor["role"] if actor else None,
                "ip": (ip or "")[:64] or None,
                "action": action,
                "outcome": outcome,
                "document_id": (document_id or None) and str(document_id)[:80],
                "target": (target or None) and str(target)[:120],
                "details": json.dumps(details or {}, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True, default=str)[:4000],
                "prev_hash": head["event_hash"] if head else GENESIS,
            }
            event["event_hash"] = self._digest(event)
            event["key_id"] = self.key_id
            conn.execute(
                "INSERT INTO audit_events (seq, event_time, actor_id, actor_username, actor_role, ip, action,"
                " outcome, document_id, target, details, prev_hash, event_hash, key_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [event[f] for f in _FIELDS] + [event["event_hash"], event["key_id"]],
            )
            if self.to_stdout:
                line = json.dumps({"audit": event}, sort_keys=True, ensure_ascii=True)
                conn.after_commit(lambda: print(line, file=sys.stdout, flush=True))
        return event

    def verify_chain(self, conn, batch: int = 2000) -> dict[str, Any]:
        expected_prev, expected_seq, count = GENESIS, 1, 0
        last_seq = 0
        while True:
            rows = conn.all("SELECT * FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?", (last_seq, batch))
            if not rows:
                break
            for row in rows:
                if row["seq"] != expected_seq:
                    return {"ok": False, "checked": count, "broken_at": expected_seq,
                            "reason": f"sequence gap: expected {expected_seq}, found {row['seq']}"}
                if row["prev_hash"] != expected_prev:
                    return {"ok": False, "checked": count, "broken_at": row["seq"],
                            "reason": "previous-hash link broken (row inserted, removed or reordered)"}
                if row["key_id"] != self.key_id:
                    return {"ok": False, "checked": count, "broken_at": row["seq"],
                            "reason": f"signed with unknown key {row['key_id']}"}
                if not hmac.compare_digest(self._digest(row), row["event_hash"]):
                    return {"ok": False, "checked": count, "broken_at": row["seq"],
                            "reason": "HMAC mismatch (row contents altered)"}
                expected_prev, expected_seq, count = row["event_hash"], expected_seq + 1, count + 1
                last_seq = row["seq"]
        return {"ok": True, "checked": count, "broken_at": None, "reason": None,
                "head_seq": last_seq, "head_hash": expected_prev}
