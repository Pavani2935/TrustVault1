"""Black-box check of a running TrustVault (local or deployed). Standard library only.

    python scripts/live_check.py http://127.0.0.1:8000
    python scripts/live_check.py https://your-app.onrender.com

Uses the seeded demo accounts. It grants and then revokes one permission, so it leaves
the data as it found it (plus audit events, which is the point).
"""
from __future__ import annotations

import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

PASSWORDS = {"admin": "Admin#Vault2026", "alice": "Alice#Vault2026", "bob": "Bob#Vault2026!",
             "victor": "Victor#Vault2026", "wendy": "Wendy#Vault2026"}
results: list[tuple[bool, str]] = []


class Session:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = None

    def call(self, method: str, path: str, body=None, csrf: bool = True):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if csrf and self.csrf:
            request.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def login(self, username: str) -> "Session":
        status, _, body = self.call("POST", "/api/v1/auth/login",
                                    {"username": username, "password": PASSWORDS[username]}, csrf=False)
        check(status == 200, f"{username} can sign in")
        self.csrf = json.loads(body)["csrf_token"] if status == 200 else None
        return self

    def json(self, method, path, body=None):
        status, _, raw = self.call(method, path, body)
        try:
            return status, json.loads(raw or b"{}")
        except ValueError:
            return status, {}


def check(ok: bool, label: str) -> None:
    results.append((ok, label))
    print(("PASS  " if ok else "FAIL  ") + label, flush=True)


def main(base: str) -> int:
    print(f"Checking {base} (first request may take ~1 minute if a free instance is waking up)\n")
    status, _, body = Session(base).call("GET", "/healthz")
    check(status == 200, "health check responds")

    status, headers, _ = Session(base).call("GET", "/login")
    csp = headers.get("Content-Security-Policy", "")
    check("frame-ancestors 'none'" in csp and headers.get("X-Content-Type-Options") == "nosniff",
          "security headers present")
    if base.startswith("https://"):
        check("Strict-Transport-Security" in headers, "HSTS enabled on HTTPS")

    victor, bob, admin = Session(base).login("victor"), Session(base).login("bob"), Session(base).login("admin")
    Session(base).login("alice")
    Session(base).login("wendy")

    _, mine = victor.json("GET", "/api/v1/documents")
    titles = {d["title"] for d in mine.get("documents", [])}
    check(not any("Audit papers" in t for t in titles), "viewer's list does not include other people's documents")

    _, bobs = bob.json("GET", "/api/v1/documents?q=Audit%20papers")
    target = next((d["id"] for d in bobs.get("documents", []) if d["title"].startswith("Audit papers")), None)
    check(target is not None, "owner can find their private document")
    if not target:
        return summary()

    for path in (f"/api/v1/documents/{target}", f"/api/v1/documents/{target}/content",
                 f"/api/v1/documents/{target}/grants", f"/api/v1/documents/{target}/activity",
                 f"/documents/{target}/download"):
        status, _, _ = victor.call("GET", path)
        check(status == 404, f"viewer without grant gets 404 on {path.replace(target, '<id>')}")
        status, _, _ = admin.call("GET", path)
        check(status == 404, f"admin without grant gets 404 on {path.replace(target, '<id>')}")

    status, _, _ = victor.call("PUT", f"/api/v1/documents/{target}/grants/victor", {"permission": "edit"})
    check(status == 404, "viewer cannot grant themselves access")
    status, _, _ = bob.call("DELETE", f"/api/v1/documents/{target}", csrf=False)
    check(status == 403, "state change without CSRF token is refused (even for the owner)")
    request_spoof = urllib.request.Request(base.rstrip("/") + f"/api/v1/documents/{target}/content",
                                           headers={"X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/healthz"})
    try:
        spoof_status = victor.opener.open(request_spoof, timeout=60).status
    except urllib.error.HTTPError as error:
        spoof_status = error.code
    check(spoof_status == 404, "spoofed proxy headers do not bypass authorisation")

    status, _ = bob.json("PUT", f"/api/v1/documents/{target}/grants/victor", {"permission": "read"})
    check(status == 200, "owner grants read access")
    status, _, data = victor.call("GET", f"/api/v1/documents/{target}/content")
    check(status == 200 and data.startswith(b"account,amount"), "grantee can now download")
    status, _ = bob.json("DELETE", f"/api/v1/documents/{target}/grants/victor")
    check(status == 200, "owner revokes access")
    status, _, _ = victor.call("GET", f"/api/v1/documents/{target}/content")
    check(status == 404, "revocation is immediate for the same, still-open session")

    status, events = bob.json("GET", f"/api/v1/documents/{target}/activity")
    actions = [(e["actor_username"], e["action"], e["outcome"]) for e in events.get("events", [])]
    check(("victor", "access_denied", "denied") in actions and ("admin", "access_denied", "denied") in actions,
          "owner's access history shows the refused attempts")

    status, verify = admin.json("POST", "/api/v1/admin/audit/verify")
    check(status == 200 and verify.get("ok") is True, f"audit chain verifies ({verify.get('checked')} events)")
    return summary()


def summary() -> int:
    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
