from pathlib import Path

from config import IGNORE_DOMAINS_PATH


def load_ignored_domains(
    path: Path = IGNORE_DOMAINS_PATH,
) -> frozenset[str]:
    if not path.is_file():
        return frozenset()

    domains = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        domain = line.partition("#")[0].strip().lower().rstrip(".")
        if domain:
            domains.add(domain)

    return frozenset(domains)


def is_ignored_domain(
    host: str,
    ignored_domains: frozenset[str],
) -> bool:
    normalized_host = host.strip().lower().rstrip(".")
    return any(
        normalized_host == domain
        or normalized_host.endswith("." + domain)
        for domain in ignored_domains
    )
