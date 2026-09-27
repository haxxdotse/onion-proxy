import ipaddress
import re


PATTERNS = (
    (
        "EMAIL",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    ),
    (
        "PHONE",
        re.compile(
            r"(?<!\d)"
            r"(?:\+\d{1,3}[\s.-]?)?"
            r"(?:\(\d{2,4}\)[\s.-]?)?"
            r"(?:\d{2,4}(?:[\s.-]\d{2,4}){1,4}|\d{1,4}[\s.-]\d{6,10})"
            r"(?!\d)"
        ),
    ),
    (
        "CREDIT_CARD",
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    ),
    (
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.IGNORECASE),
    ),
)

def _luhn_valid(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        digits = str(ord(character) - 55) if character.isalpha() else character
        for digit in digits:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def is_plausible_phone(value: str, explicit_phone_field: bool = False) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 9 <= len(digits) <= 15 or len(set(digits)) == 1:
        return False
    if re.match(r"^(?:19|20)\d{2}[./-]\d{1,2}[./-]\d{1,2}(?:\b|$)", value.strip()):
        return False
    if explicit_phone_field:
        return True
    if len(digits) < 10 and not value.lstrip().startswith("+") and "(" not in value:
        return False

    # Dotted numeric groups are overwhelmingly IPv4 addresses or version numbers.
    if "." in value and not any(separator in value for separator in (" ", "-", "+", "(", ")")):
        groups = value.split(".")
        if len(groups) == 4 and all(group.isdigit() and len(group) <= 3 for group in groups):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return False
            return False
        if all(group.isdigit() and len(group) <= 3 for group in groups):
            return False
    return True


def find_personal_data_matches(text: str) -> list[tuple[str, re.Match[str]]]:
    matches: list[tuple[str, re.Match[str]]] = []
    protected_spans = []
    for kind in ("CREDIT_CARD", "IBAN"):
        pattern = dict(PATTERNS)[kind]
        for match in pattern.finditer(text):
            valid = _luhn_valid(match.group(0)) if kind == "CREDIT_CARD" else _iban_valid(match.group(0))
            if valid:
                matches.append((kind, match))
                protected_spans.append(match.span())

    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if name in {"CREDIT_CARD", "IBAN"}:
                continue
            if name == "PHONE" and any(
                match.start() < end and match.end() > start for start, end in protected_spans
            ):
                continue
            if name == "PHONE" and not is_plausible_phone(value):
                continue
            matches.append((name, match))
    return matches


def scan_personal_data(text: str) -> list[str]:
    return list(dict.fromkeys(name for name, _ in find_personal_data_matches(text)))
