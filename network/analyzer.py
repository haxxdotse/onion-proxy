import json
import re
from urllib.parse import parse_qsl

from config import TEXT_CONTENT_TYPES
from inspection.credentials import PATTERNS as CREDENTIAL_PATTERNS
from inspection.files import extract_files, extract_text_fields, is_sensitive_filename
from inspection.personal_data import find_personal_data_matches, is_plausible_phone


MAX_EVIDENCE_LENGTH = 2_000
MAX_EVIDENCE_ITEMS = 40
PHONE_FIELD_HINT = re.compile(
    r"(?:^|[^a-z0-9])(?:phone|mobile|telephone|tel|msisdn|cell)(?:[_-]?number)?(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


def mask_evidence_value(kind: str, value: str) -> str:
    """Keep enough context to explain a finding without displaying the secret."""
    if kind == "PHONE":
        positions = [index for index, char in enumerate(value) if char.isdigit()]
        if len(positions) <= 4:
            return "•" * len(value)
        hidden = set(positions[2:-2])
        return "".join("•" if index in hidden else char for index, char in enumerate(value))
    if kind == "EMAIL" and "@" in value:
        local, domain = value.rsplit("@", 1)
        visible_local = local[:1] + ("•" * max(1, len(local) - 1))
        return f"{visible_local}@{domain}"
    if kind in {"PASSWORD", "API_KEY", "ACCESS_TOKEN", "JWT", "PRIVATE_KEY", "CREDIT_CARD", "IBAN"}:
        return "[скрыто]"
    return value


def analyze_request_details(request) -> tuple[list[str], list[dict[str, str]]]:
    """Return detection labels and short-lived matched values for the local UI."""
    findings: list[str] = []
    evidence: list[dict[str, str]] = []
    seen_evidence: set[tuple[str, str, str]] = set()

    def add_evidence(kind: str, value: str, source: str) -> None:
        value = value.strip()
        if not value:
            return
        if kind not in findings:
            findings.append(kind)
        if len(value) > MAX_EVIDENCE_LENGTH:
            value = value[:MAX_EVIDENCE_LENGTH] + " … [фрагмент сокращён]"
        key = (kind, value, source)
        if key not in seen_evidence and len(evidence) < MAX_EVIDENCE_ITEMS:
            seen_evidence.add(key)
            evidence.append({"type": kind, "value": mask_evidence_value(kind, value), "source": source})

    def scan(value: str, source: str) -> None:
        for kind, pattern in CREDENTIAL_PATTERNS:
            for match in pattern.finditer(value):
                add_evidence(kind, match.group(0), source)
        for kind, match in find_personal_data_matches(value):
            add_evidence(kind, match.group(0), source)

    def scan_field(name: str, value: str, source: str) -> None:
        scan(f"{name}={value}", source)
        value_types = {kind for kind, _ in find_personal_data_matches(value)}
        if (
            PHONE_FIELD_HINT.search(name)
            and not value_types.intersection({"CREDIT_CARD", "IBAN"})
            and is_plausible_phone(value, explicit_phone_field=True)
        ):
            add_evidence("PHONE", value, source)

    def scan_json_value(value: object, source: str, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, (str, int)) and not isinstance(child, bool):
                    scan_field(str(key), str(child), f"JSON: {key}")
                else:
                    scan_json_value(child, source, depth + 1)
        elif isinstance(value, list):
            for child in value:
                scan_json_value(child, source, depth + 1)
        elif isinstance(value, (str, int)) and not isinstance(value, bool):
            scan(str(value), source)

    content_type = request.headers.get("content-type", "").lower()
    files = extract_files(request)
    for file in files:
        add_evidence("FILE", file["name"], "имя файла")
        if file.get("sensitive_name") or is_sensitive_filename(file["name"]):
            add_evidence("SENSITIVE_FILENAME", file["name"], "имя файла похоже на секретный или личный файл")
        if file["is_text"]:
            scan(file["content"].decode("utf-8", errors="replace"), file["name"])

    for field_name, field_text in extract_text_fields(request):
        scan_field(field_name, field_text, f"поле формы «{field_name}»")

    if not files:
        raw_body = request.content or b""
    else:
        raw_body = b""
    if not files and content_type.startswith(TEXT_CONTENT_TYPES):
        body = raw_body.decode("utf-8", errors="replace")
        if content_type.startswith("application/x-www-form-urlencoded"):
            for key, value in parse_qsl(body, keep_blank_values=True):
                scan_field(key, value, f"поле формы «{key or 'без имени'}»")
        elif content_type.startswith("application/json"):
            try:
                scan_json_value(json.loads(body), "JSON")
            except (json.JSONDecodeError, RecursionError):
                scan(body, "тело запроса")
        else:
            scan(body, "тело запроса")
    elif not files and raw_body:
        # Unknown/binary bodies must not silently pass as if they had been inspected.
        disposition = request.headers.get("content-disposition", "")
        filename_match = re.search(r"filename\*?\s*=\s*(?:UTF-8''|\")?([^;\"]+)", disposition, re.IGNORECASE)
        filename = filename_match.group(1).strip().strip('"') if filename_match else ""
        add_evidence("FILE", filename or f"Непрозрачная передача данных ({len(raw_body)} байт)", "содержимое не распознано")
        add_evidence("UNSCANNED_UPLOAD", "Формат тела запроса не поддерживает проверку содержимого", "непроверенный запрос")
        if filename and is_sensitive_filename(filename):
            add_evidence("SENSITIVE_FILENAME", filename, "имя файла похоже на секретный или личный файл")

    return findings, evidence


def analyze_request(request) -> list[str]:
    """Compatibility helper for the console mitmproxy addon."""
    findings, _ = analyze_request_details(request)
    return findings
