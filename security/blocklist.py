"""Permanent user-maintained deny rules for destination domains and URLs."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class BlockRule:
    original: str
    host: str
    scheme: str
    port: int | None
    path: str


def load_blocklist(path: Path) -> tuple[BlockRule, ...]:
    if not path.is_file():
        return ()
    rules: list[BlockRule] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        value = raw_line.partition("#")[0].strip()
        if not value:
            continue
        try:
            parts = urlsplit(value if "://" in value else "//" + value)
            host = (parts.hostname or "").strip().lower().rstrip(".")
            port = parts.port
        except ValueError:
            continue
        if not host or any(character.isspace() for character in host):
            continue
        rules.append(BlockRule(
            original=value,
            host=host.removeprefix("*.") if host.startswith("*.") else host,
            scheme=parts.scheme.lower(),
            port=port,
            path=unquote(parts.path or "").rstrip("/"),
        ))
    return tuple(rules)


def find_block_rule(url: str, host: str, rules: tuple[BlockRule, ...]) -> BlockRule | None:
    request = urlsplit(url)
    normalized_host = (host or request.hostname or "").lower().rstrip(".")
    try:
        request_port = request.port
    except ValueError:
        request_port = None
    request_path = unquote(request.path or "")

    for rule in rules:
        if normalized_host != rule.host and not normalized_host.endswith("." + rule.host):
            continue
        if rule.scheme and request.scheme.lower() != rule.scheme:
            continue
        if rule.port is not None and request_port != rule.port:
            continue
        if rule.path:
            base_path = rule.path.rstrip("/")
            if request_path != base_path and not request_path.startswith(base_path + "/"):
                continue
        return rule
    return None
