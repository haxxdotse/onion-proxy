import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from mitmproxy import http

from inspection.http import inspect_request
from network.analyzer import analyze_request
from security.engine import process_event
from security.domain_filter import is_ignored_domain, load_ignored_domains


IGNORED_DOMAINS = load_ignored_domains()


def request(flow: http.HTTPFlow) -> None:
    request_data = inspect_request(flow.request)

    if is_ignored_domain(
        request_data["host"],
        IGNORED_DOMAINS,
    ):
        return

    if not request_data["is_upload"]:
        return

    if request_data.get("body_unavailable"):
        findings = ["UNSCANNED_UPLOAD"]
    elif request_data["size"] > request_data["max_body_size"]:
        findings = ["UNSCANNED_UPLOAD"]
    else:
        findings = analyze_request(flow.request)

    if not findings:
        return

    process_event(
        flow,
        request_data,
        findings,
    )
