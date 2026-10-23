"""Demo seed data: one account per role (plus extra owner/viewer accounts so reviewers can
test cross-user isolation) and harmless sample documents. Runs only on an empty database."""
from __future__ import annotations

import io
import struct
import zipfile
import zlib

from . import clock
from .auth import hash_password
from .context import Ctx
from .documents import create_document, set_grant

DEMO_USERS = [
    # username, display name, role, password
    ("admin", "Asha Admin (Security Officer)", "admin", "Admin#Vault2026"),
    ("alice", "Alice Rao (HR, owner)", "owner", "Alice#Vault2026"),
    ("bob", "Bob Mehta (Legal, owner)", "owner", "Bob#Vault2026!"),
    ("victor", "Victor Das (employee, viewer)", "viewer", "Victor#Vault2026"),
    ("wendy", "Wendy Iyer (partner, viewer)", "viewer", "Wendy#Vault2026"),
]


def _pdf(title: str, lines: list[str]) -> bytes:
    text = "BT /F1 18 Tf 72 740 Td (" + title.replace("(", "[").replace(")", "]") + ") Tj ET\n"
    y = 710
    for line in lines:
        text += f"BT /F1 11 Tf 72 {y} Td (" + line.replace("(", "[").replace(")", "]") + ") Tj ET\n"
        y -= 18
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text.encode("latin-1") + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        out.write(f"{offset:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def _png(width: int = 160, height: int = 90) -> bytes:
    rows = b""
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            line = (x % 20 == 0) or (y % 15 == 0)
            row += bytes((30, 60, 90) if line else (235, 242, 248))
        rows += bytes(row)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def _docx(paragraphs: list[str]) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                               '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                               '<Default Extension="xml" ContentType="application/xml"/>'
                               '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                             f"<w:body>{body}</w:body></w:document>",
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return out.getvalue()


def seed_if_empty(ctx_factory) -> bool:
    """ctx_factory(user) -> Ctx. Returns True if seeding happened."""
    system_ctx: Ctx = ctx_factory(None)
    conn = system_ctx.conn
    with conn.transaction():
        if conn.scalar("SELECT COUNT(*) AS n FROM users"):
            return False
        now = clock.now_iso()
        for username, display, role, password in DEMO_USERS:
            conn.execute(
                "INSERT INTO users (username, display_name, password_hash, role, is_active, is_demo, created_at,"
                " updated_at, password_changed_at) VALUES (?,?,?,?,1,1,?,?,?)",
                (username, display, hash_password(password), role, now, now, now))
        system_ctx.audit.record(conn, action="seed_demo_accounts", actor=None, actor_name_hint="system",
                                details={"accounts": [u[0] for u in DEMO_USERS]})

    users = {row["username"]: row for row in conn.all("SELECT * FROM users")}
    alice, bob = ctx_factory(users["alice"]), ctx_factory(users["bob"])

    salary = create_document(alice, "Salary letter - Victor Das (FY2026)", "HR", "salary-letter-victor.pdf",
                             _pdf("Salary letter - CONFIDENTIAL (sample)", [
                                 "Employee: Victor Das", "Annual CTC: INR 9,40,000 (sample data)",
                                 "Effective: 1 April 2026", "This is demo content for TrustVault."]))
    set_grant(alice, salary, "victor", "read")

    handbook = create_document(alice, "Employee handbook v3", "HR", "employee-handbook.txt",
                               b"TrustVault demo - Employee handbook v3\n\n1. Leave policy...\n2. Code of conduct...\n")
    set_grant(alice, handbook, "victor", "read")
    set_grant(alice, handbook, "wendy", "read")
    set_grant(alice, handbook, "bob", "edit")

    offer = create_document(alice, "Offer letter - Wendy Iyer", "HR", "offer-letter-wendy.pdf",
                            _pdf("Offer letter (sample)", ["Candidate: Wendy Iyer", "Demo content only."]))
    set_grant(alice, offer, "wendy", "read", expires_on=clock.ahead_iso(days=30)[:10])

    contract = create_document(bob, "Customer contract - Acme Industries", "Legal", "acme-contract.docx",
                               _docx(["Master Services Agreement (sample)", "Between Example Corp and Acme Industries.",
                                      "Demo content for TrustVault."]))
    set_grant(bob, contract, "wendy", "edit")

    create_document(bob, "Audit papers FY2025 (no one else has access)", "Finance", "audit-papers-fy2025.csv",
                    b"account,amount,note\nRevenue,1200000,sample\nExpenses,800000,sample\n")

    drawing = create_document(bob, "Partner drawing - Line 4 layout", "Engineering", "line4-layout.png", _png())
    set_grant(bob, drawing, "victor", "read")
    return True
