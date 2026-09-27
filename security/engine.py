import logging

from mitmproxy import http

from database.storage import save_event
from security.policy import decide
from ui.console import ask_user, blocked_response_body, decision_summary


logger = logging.getLogger(__name__)


def process_event(
    flow: http.HTTPFlow,
    request_data: dict,
    findings: list[str],
) -> None:

    application = "UNKNOWN"
    domain = request_data["host"]

    action = decide(
        application,
        domain,
        findings,
    )

    if action == "ASK":
        action = ask_user(
            application,
            domain,
            findings,
        )

    if action == "BLOCK":
        block_request(flow, domain, findings)

    save_event(
        application,
        domain,
        findings,
        action,
    )

    logger.info(decision_summary(action, domain, findings))


def block_request(
    flow: http.HTTPFlow,
    domain: str,
    findings: list[str],
) -> None:

    flow.response = http.Response.make(
        403,
        blocked_response_body(domain, findings),
        {
            "Content-Type": "text/plain",
        },
    )
