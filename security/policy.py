from config import DEFAULT_ACTION
from security.rules import find_rule


def decide(
    application: str,
    domain: str,
    findings: list[str],
) -> str:

    rule = find_rule(
        application,
        domain,
        findings,
    )

    if rule is not None:
        return rule

    return DEFAULT_ACTION