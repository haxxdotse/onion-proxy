from config import (
    MAX_BODY_SIZE,
    UPLOAD_CONTENT_TYPES,
    UPLOAD_METHODS,
)


def inspect_request(request) -> dict:
    method = request.method.upper()

    content_type = request.headers.get(
        "content-type",
        "",
    ).lower()

    body_unavailable = False
    try:
        body = request.content
    except ValueError:
        body = None
        body_unavailable = True

    content_length = request.headers.get("content-length", "")
    try:
        declared_size = max(0, int(content_length)) if content_length else 0
    except ValueError:
        declared_size = 0
    transfer_encoding = request.headers.get("transfer-encoding", "").lower()
    has_payload = bool((body is not None and len(body) > 0) or declared_size or "chunked" in transfer_encoding)
    if body is None and has_payload:
        body_unavailable = True
    body_bytes = body or b""

    is_upload = (
        method in UPLOAD_METHODS
        or content_type.startswith(UPLOAD_CONTENT_TYPES)
    )

    return {
        "method": method,
        "host": request.host,
        "url": request.pretty_url,
        "content_type": content_type,
        "size": len(body_bytes) if body is not None else declared_size,
        "body_unavailable": body_unavailable,
        "max_body_size": MAX_BODY_SIZE,
        "is_upload": is_upload,
    }
