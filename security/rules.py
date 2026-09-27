RULES = []


def find_rule(
    application: str,
    domain: str,
    findings: list[str],
) -> str | None:

    for rule in RULES:

        if not _matches(
            rule.get("application", "*"),
            application,
        ):
            continue

        if not _matches(
            rule.get("domain", "*"),
            domain,
        ):
            continue

        rule_findings = rule.get(
            "findings",
            {"*"},
        )

        if "*" in rule_findings:
            return rule["action"]

        if set(findings) & set(rule_findings):
            return rule["action"]

    return None


def _matches(
    rule_value: str,
    actual_value: str,
) -> bool:

    return (
        rule_value == "*"
        or rule_value == actual_value
    )