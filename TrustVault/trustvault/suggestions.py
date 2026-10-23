"""Access suggestions: help an owner decide who should see a document.

Rules this feature is built around:
  * It only SUGGESTS. It has no write path to the grants table. A person must press
    "Grant", which goes through the normal owner-only grant endpoint.
  * Both the suggestion and the human decision are audited
    (`access_suggested`, then `grant` with source=suggestion, or `suggestion_dismissed`).
  * It only learns from the requesting owner's own sharing history, so it cannot reveal
    who has access to other people's documents.
  * No document content or metadata is sent to an external model. The scoring is a
    transparent, explainable heuristic; an LLM ranker could be plugged in behind the
    same interface later without changing any of the guarantees above.
"""
from __future__ import annotations

from .context import Ctx
from .documents import _authorize, document_operation


@document_operation
def suggest(ctx: Ctx, doc_id: str, limit: int = 3) -> list[dict]:
    with ctx.conn.transaction():
        doc, _ = _authorize(ctx, doc_id, "suggest_access")
        rows = ctx.conn.all(
            "SELECT u.username, u.display_name, d.category, g.permission"
            " FROM grants g JOIN documents d ON d.id = g.document_id JOIN users u ON u.id = g.user_id"
            " WHERE d.owner_id = ? AND d.id <> ? AND d.deleted_at IS NULL AND u.is_active = 1",
            (ctx.user["id"], doc_id))
        already = {r["username"] for r in ctx.conn.all(
            "SELECT u.username FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = ?", (doc_id,))}
        scores: dict[str, dict] = {}
        for row in rows:
            if row["username"] in already:
                continue
            entry = scores.setdefault(row["username"], {"username": row["username"], "display_name": row["display_name"],
                                                        "same_category": 0, "other": 0, "edit": 0})
            if row["category"].lower() == doc["category"].lower():
                entry["same_category"] += 1
            else:
                entry["other"] += 1
            if row["permission"] == "edit":
                entry["edit"] += 1
        ranked = []
        for entry in scores.values():
            score = entry["same_category"] * 3 + entry["other"]
            if entry["same_category"] == 0:
                continue  # only suggest people you already share this kind of document with
            parts = [f"you share {entry['same_category']} other '{doc['category']}' document(s) with them"]
            if entry["other"]:
                parts.append(f"and {entry['other']} document(s) in other categories")
            ranked.append({"username": entry["username"], "display_name": entry["display_name"],
                           "permission": "read", "score": score, "reason": " ".join(parts)})
        ranked.sort(key=lambda e: (-e["score"], e["username"]))
        ranked = ranked[:limit]
        ctx.log("access_suggested", document_id=doc_id,
                details={"suggested": [{"user": r["username"], "permission": r["permission"], "score": r["score"]}
                                       for r in ranked],
                         "engine": "heuristic-v1"})
    return ranked


@document_operation
def dismiss(ctx: Ctx, doc_id: str, username: str) -> None:
    with ctx.conn.transaction():
        _authorize(ctx, doc_id, "suggest_access")
        ctx.log("suggestion_dismissed", document_id=doc_id, target=(username or "")[:64].lower())


def suggestion_payload(username: str, reason: str) -> dict:
    return {"user": username, "reason": reason[:200], "engine": "heuristic-v1"}

