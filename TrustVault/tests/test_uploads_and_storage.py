"""Upload validation and storage protection. Threat ids refer to THREATS.md."""
import io
import zipfile

import pytest

from conftest import audit_rows, db, doc_id
from trustvault.seed import _docx, _pdf, _png


def _zip(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return out.getvalue()


BAD_FILES = [
    ("payload.exe", b"MZ\x90\x00 windows executable"),
    ("invoice.pdf", b"MZ\x90\x00 executable renamed to pdf"),
    ("page.html", b"<script>alert(1)</script>"),
    ("image.svg", b"<svg onload=alert(1)>"),
    ("notes.txt", b"binary\x00content"),
    ("notes.txt", b"\xff\xfe\xfa not utf8"),
    ("empty.pdf", b""),
    ("photo.png", b"GIF89a not a png"),
    ("macro.docx", _zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w/>", "word/vbaProject.bin": "x"})),
    ("macro.docx", _zip({"[Content_Types].xml": "<Types>macroEnabled</Types>", "word/document.xml": "<w/>"})),
    ("sheet.xlsx", _docx(["a word file pretending to be excel"])),
    ("evil.pdf", _pdf("x", ["y"]).replace(b"/Type /Catalog", b"/Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >>")),
    ("bomb.docx", _zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "A" * 5_000_000})),
    ("noext", b"hello"),
    ("archive.zip", _zip({"a.txt": "x"})),
]


@pytest.mark.parametrize("filename,content", BAD_FILES)
def test_T16_dangerous_or_mislabelled_files_are_rejected(app, browser, filename, content):
    """T-16 The server decides what a file is from its bytes."""
    alice = browser("alice")
    response = alice.upload(title="Bad file", filename=filename, content=content)
    assert response.status_code == 400, filename
    conn = db(app)
    try:
        assert conn.one("SELECT id FROM documents WHERE title = 'Bad file'") is None
    finally:
        conn.close()
    assert audit_rows(app, action="upload", outcome="denied")


@pytest.mark.parametrize("filename,content", [
    ("ok.pdf", _pdf("Fine", ["fine"])), ("ok.txt", "Grüße, plain text\n".encode()),
    ("ok.csv", b"a,b\n1,2\n"), ("ok.docx", _docx(["fine"])), ("ok.png", _png()),
    ("ok.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9"),
    ("ok.xlsx", _zip({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": "<w/>"})),
])
def test_T16_legitimate_files_are_accepted(app, browser, filename, content):
    response = browser("alice").upload(title="Good " + filename, filename=filename, content=content)
    assert response.status_code == 302, response.data[:300]


def test_T16_oversized_request_is_refused(app, browser):
    alice = browser("alice")
    response = alice.upload(title="Huge", filename="huge.txt", content=b"a" * (12 * 1024 * 1024))
    assert response.status_code == 413


def test_T16_path_traversal_filenames_are_neutralised(app, browser):
    alice = browser("alice")
    for name in ("../../../etc/passwd.txt", "..\\..\\windows\\win.ini.txt", "a/b/c/<script>.txt"):
        assert alice.upload(title="Traversal " + name, filename=name, content=b"x").status_code == 302
    conn = db(app)
    try:
        names = [r["original_name"] for r in conn.all("SELECT original_name FROM document_versions")]
    finally:
        conn.close()
    assert all("/" not in n and "\\" not in n and "<" not in n and ".." not in n for n in names), names


def test_T17_downloads_cannot_execute_in_the_browser(app, browser):
    """T-17 Content type comes from validation, never from the client; always an attachment."""
    alice = browser("alice")
    alice.post("/documents/new", data={"title": "Sniff", "category": "X",
                                       "file": (io.BytesIO(b"<html><script>alert(1)</script></html>"), "x.txt", "text/html")},
               content_type="multipart/form-data")
    response = alice.get(f"/documents/{doc_id(app, 'Sniff')}/download")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/plain")
    assert response.headers["Content-Disposition"].startswith("attachment")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_T24_files_are_encrypted_at_rest(app, browser):
    """T-24 A database dump or backup does not contain readable documents."""
    browser("alice").upload(title="Plaintext check", content=b"the merger closes on friday")
    conn = db(app)
    try:
        for row in conn.all("SELECT ciphertext, wrapped_key FROM document_versions"):
            blob = bytes(row["ciphertext"])
            assert b"merger" not in blob and b"%PDF" not in blob and b"account,amount" not in blob
    finally:
        conn.close()


def test_T24_swapped_ciphertext_is_detected_not_served(app, browser):
    """Copying one document's encrypted bytes over another's (DB tampering) fails authentication."""
    salary, private = doc_id(app, "Salary letter"), doc_id(app, "Audit papers")
    conn = db(app)
    try:
        source = conn.one("SELECT wrapped_key, ciphertext, sha256 FROM document_versions WHERE document_id = ?", (private,))
        conn.execute("UPDATE document_versions SET wrapped_key = ?, ciphertext = ?, sha256 = ? WHERE document_id = ?",
                     (source["wrapped_key"], source["ciphertext"], source["sha256"], salary))
    finally:
        conn.close()
    response = browser("victor").get(f"/documents/{salary}/download")
    assert response.status_code == 500
    assert b"account,amount" not in response.data
    assert audit_rows(app, action="integrity_failure", document_id=salary)


def test_T24_wrong_master_key_cannot_decrypt(app, browser, monkeypatch):
    from trustvault.crypto import IntegrityError, Vault
    conn = db(app)
    try:
        v = conn.one("SELECT * FROM document_versions LIMIT 1")
    finally:
        conn.close()
    other = Vault("a-completely-different-master-key-" + "z" * 20)
    with pytest.raises(IntegrityError):
        other.decrypt(v["wrapped_key"], v["ciphertext"], v["document_id"], v["id"], v["sha256"], v["key_id"])
    with pytest.raises(IntegrityError):  # even if the key id check is skipped
        other.decrypt(v["wrapped_key"], v["ciphertext"], v["document_id"], v["id"], v["sha256"], other.key_id)
