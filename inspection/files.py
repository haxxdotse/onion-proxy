from email.parser import BytesParser
from email.policy import default
from pathlib import PurePath
import re

from config import ANALYZABLE_EXTENSIONS


_SENSITIVE_FILENAME_TERMS = frozenset({
    "env", "credential", "credentials", "password", "passwords", "passwd", "pwd",
    "secret", "secrets", "token", "tokens", "private", "wallet", "mnemonic", "seed",
    "recovery", "cookie", "cookies", "history", "logins", "login", "bank", "banking",
    "passport", "identity", "ssn", "tax", "medical", "health", "patient", "ssh",
    "aws", "azure", "kube", "кошелек", "паспорт", "пароль", "ключ", "банк",
    "налог", "медкарта", "здоровье", "учетка",
})
_SENSITIVE_KEY_FILE = re.compile(r"(?:^|[._-])(?:id_rsa|id_ed25519|authorized_keys|known_hosts)(?:$|[._-])", re.I)
_SENSITIVE_FILE_EXTENSIONS = frozenset({".pem", ".key", ".p12", ".pfx", ".kdbx", ".wallet"})


def is_sensitive_filename(filename: str) -> bool:
    """Heuristic filename warning; it is a signal, not proof of malicious collection."""
    basename = PurePath(filename.replace("\\", "/")).name.casefold()
    tokens = set(re.findall(r"[a-zа-яё0-9]+", basename))
    extension = PurePath(basename).suffix.casefold()
    return bool(tokens & _SENSITIVE_FILENAME_TERMS) or bool(_SENSITIVE_KEY_FILE.search(basename)) or extension in _SENSITIVE_FILE_EXTENSIONS


def extract_files(request) -> list[dict]:
    content_type = request.headers.get(
        "content-type",
        "",
    )

    if not content_type.startswith(
        "multipart/form-data"
    ):
        return []

    body = request.content or b""

    if not body:
        return []

    raw_message = (
        b"Content-Type: "
        + content_type.encode()
        + b"\r\n\r\n"
        + body
    )

    try:
        message = BytesParser(
            policy=default
        ).parsebytes(raw_message)
    except Exception:
        return []

    if not message.is_multipart():
        return []

    files = []

    for part in message.iter_parts():
        filename = part.get_filename()

        if not filename:
            continue

        content = (
            part.get_payload(
                decode=True
            )
            or b""
        )

        extension = PurePath(
            filename
        ).suffix.lower()

        files.append({
            "name": filename,
            "size": len(content),
            "content": content,
            "is_text": extension in ANALYZABLE_EXTENSIONS,
            "sensitive_name": is_sensitive_filename(filename),
        })

    return files


def extract_text_fields(request) -> list[tuple[str, str]]:
    """Return plain text fields from multipart bodies, excluding file payloads."""
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("multipart/form-data"):
        return []
    body = request.content or b""
    if not body:
        return []
    raw_message = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    try:
        message = BytesParser(policy=default).parsebytes(raw_message)
        if not message.is_multipart():
            return []
        fields = []
        for index, part in enumerate(message.iter_parts(), start=1):
            if part.get_filename() or part.get_content_maintype() != "text":
                continue
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            name = part.get_param("name", header="content-disposition") or f"поле {index}"
            fields.append((str(name), payload.decode(charset, errors="replace")))
        return fields
    except (LookupError, UnicodeError, ValueError):
        return []
