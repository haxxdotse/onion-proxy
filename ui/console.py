import os


def clear_console() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def decision_summary(
    action: str,
    domain: str,
    findings: list[str],
) -> str:
    files = [finding[5:] for finding in findings if finding.startswith("FILE:")]
    if action == "BLOCK" and files:
        label = "BLOCKED FILE" if len(files) == 1 else "BLOCKED FILES"
        return f"{label}: {', '.join(files)} -> {domain}"
    return f"{action} {domain} -> {', '.join(findings)}"


def blocked_response_body(
    domain: str,
    findings: list[str],
) -> bytes:
    files = [finding[5:] for finding in findings if finding.startswith("FILE:")]
    if files:
        file_label = "Blocked file" if len(files) == 1 else "Blocked files"
        details = f"{file_label}: {', '.join(files)}"
    else:
        details = f"Detected: {', '.join(findings)}"

    return (
        "Blocked by onion-proxy.\n"
        f"Destination: {domain}\n"
        f"{details}\n"
    ).encode("utf-8")


def ask_user(
    application: str,
    domain: str,
    findings: list[str],
) -> str:

    clear_console()

    print()
    print("SECURITY ALERT")
    print("-" * 40)

    print(
        f"Application: {application}"
    )

    print(
        f"Destination: {domain}"
    )

    print(
        f"Detected: {', '.join(findings)}"
    )

    print()

    while True:

        choice = input(
            "[1] Allow  [2] Block: "
        ).strip()

        if choice == "1":
            return "ALLOW"

        if choice == "2":
            return "BLOCK"

        print(
            "Enter 1 or 2."
        )
