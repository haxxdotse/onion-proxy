import re


PATTERNS = (
    (
        "PASSWORD",
        re.compile(
            r"[\"']?\b(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"',;&}]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "API_KEY",
        re.compile(
            r"[\"']?\b(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?([^\s\"',;&}]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "ACCESS_TOKEN",
        re.compile(
            r"[\"']?\b(access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)"
            r"[\"']?\s*[:=]\s*[\"']?(?:Bearer\s+)?([A-Za-z0-9._~+/-]{8,})",
            re.IGNORECASE,
        ),
    ),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    ),
)


def scan_text(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS if pattern.search(text)]
