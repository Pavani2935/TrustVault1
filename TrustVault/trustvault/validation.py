"""Input validation. The server decides what a file is from its bytes, never from the
client-supplied Content-Type, and never trusts the filename beyond its extension."""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from datetime import date, datetime, timedelta, timezone

from . import clock


class ValidationError(ValueError):
    pass


_CONTROL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]")
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9 ._()\-]")
USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,31}$")
DOC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def clean_text(value: str | None, field: str, max_len: int, min_len: int = 1) -> str:
    value = unicodedata.normalize("NFKC", (value or "")).strip()
    value = re.sub(r"\s+", " ", value)
    if _CONTROL.search(value):
        raise ValidationError(f"{field} contains control or direction-override characters.")
    if not (min_len <= len(value) <= max_len):
        raise ValidationError(f"{field} must be {min_len}-{max_len} characters.")
    return value


def clean_username(value: str | None) -> str:
    value = (value or "").strip().lower()
    if not USERNAME_RE.match(value):
        raise ValidationError("Username must be 3-32 characters: lowercase letters, digits, dot, dash, underscore; starting with a letter.")
    return value


COMMON_PASSWORDS = {"password1234", "123456789012", "qwertyuiop12", "trustvault123", "letmein12345",
                    "welcome12345", "administrator", "passwordpassword", "changeme1234"}


def check_password(password: str | None, username: str) -> str:
    password = password or ""
    if len(password) < 12 or len(password) > 128:
        raise ValidationError("Password must be 12-128 characters.")
    if password.lower() in COMMON_PASSWORDS or username.lower() in password.lower():
        raise ValidationError("Password is too easy to guess.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        raise ValidationError("Password needs at least three of: lowercase, uppercase, digit, symbol.")
    return password


def is_doc_id(value: str) -> bool:
    return bool(DOC_ID_RE.match(value or ""))


def parse_date(value: str | None, field: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValidationError(f"{field} must be a date (YYYY-MM-DD).") from exc


def grant_expiry(value: str | None) -> str | None:
    """Optional expiry date -> ISO timestamp at the end of that day (UTC)."""
    day = parse_date(value, "Expiry date")
    if day is None:
        return None
    end = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) + timedelta(days=1)
    now = clock.utcnow()
    if end <= now:
        raise ValidationError("Expiry date must be in the future.")
    if end > now + timedelta(days=366):
        raise ValidationError("Expiry can be at most one year ahead.")
    return clock.iso(end)


# ---------------------------------------------------------------- uploads ----------
def _pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-"):
        raise ValidationError("File is not a PDF (signature missing).")
    if b"%%EOF" not in data[-2048:]:
        raise ValidationError("PDF is truncated or malformed.")
    lowered = data.lower()
    for marker in (b"/javascript", b"/launch", b"/embeddedfile", b"/richmedia", b"/xfa"):
        if marker in lowered:
            raise ValidationError("PDFs containing scripts, launch actions or embedded files are not accepted.")


def _text(data: bytes) -> None:
    if b"\x00" in data:
        raise ValidationError("Text files must not contain binary data.")
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("Text files must be UTF-8.") from exc


def _ooxml(required_prefix: str):
    def check(data: bytes) -> None:
        if not data.startswith(b"PK\x03\x04"):
            raise ValidationError("File is not an Office Open XML document.")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                if len(infos) > 2000:
                    raise ValidationError("Document has too many parts.")
                total = 0
                names = set()
                for info in infos:
                    name = info.filename
                    if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                        raise ValidationError("Document contains unsafe paths.")
                    total += info.file_size
                    if total > 100 * 1024 * 1024 or (info.compress_size and info.file_size / info.compress_size > 200):
                        raise ValidationError("Document expands too much (possible zip bomb).")
                    names.add(name)
                if "[Content_Types].xml" not in names or not any(n.startswith(required_prefix) for n in names):
                    raise ValidationError("File is not a valid Office document of the declared type.")
                if any(n.lower().endswith(("vbaproject.bin", ".bin")) for n in names):
                    raise ValidationError("Macro-enabled or binary-embedded Office documents are not accepted.")
                content_types = archive.read("[Content_Types].xml").lower()
                if b"macroenabled" in content_types or b"vbaproject" in content_types:
                    raise ValidationError("Macro-enabled Office documents are not accepted.")
        except zipfile.BadZipFile as exc:
            raise ValidationError("Office document is corrupt.") from exc
    return check


def _png(data: bytes) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValidationError("File is not a PNG image.")


def _jpeg(data: bytes) -> None:
    if not data.startswith(b"\xff\xd8\xff"):
        raise ValidationError("File is not a JPEG image.")


FILE_TYPES = {
    ".pdf": ("application/pdf", _pdf),
    ".txt": ("text/plain; charset=utf-8", _text),
    ".csv": ("text/csv; charset=utf-8", _text),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", _ooxml("word/")),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _ooxml("xl/")),
    ".png": ("image/png", _png),
    ".jpg": ("image/jpeg", _jpeg),
    ".jpeg": ("image/jpeg", _jpeg),
}
ALLOWED_EXTENSIONS = sorted(FILE_TYPES)


def safe_filename(name: str | None) -> str:
    name = unicodedata.normalize("NFKC", name or "").replace("\\", "/").split("/")[-1]
    name = _FILENAME_SAFE.sub("_", name).strip(" .")
    name = re.sub(r"_+", "_", name)
    if len(name) > 120:
        stem, dot, ext = name.rpartition(".")
        name = stem[: 120 - len(ext) - 1] + dot + ext
    return name


def validate_upload(filename: str | None, data: bytes, max_bytes: int) -> tuple[str, str]:
    """Return (safe_filename, server_decided_content_type) or raise ValidationError."""
    name = safe_filename(filename)
    if not name or "." not in name:
        raise ValidationError("File needs a name with an extension.")
    ext = "." + name.rsplit(".", 1)[1].lower()
    if ext not in FILE_TYPES:
        raise ValidationError("File type not allowed. Allowed: " + ", ".join(ALLOWED_EXTENSIONS))
    if not data:
        raise ValidationError("File is empty.")
    if len(data) > max_bytes:
        raise ValidationError(f"File exceeds {max_bytes // (1024 * 1024)} MB.")
    content_type, checker = FILE_TYPES[ext]
    checker(data)
    return name, content_type
