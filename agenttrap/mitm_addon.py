"""mitmproxy addon, run INSIDE the proxy container on the sandbox's private network.

For every request the sandbox makes (HTTP, or HTTPS once the sandbox's trusted certificate has
let the proxy read it) it prints one JSON line, then answers the request itself. No request is
ever sent upstream, so there is nothing to exfiltrate to: this is a honeypot, not a relay.

Environment: SINKHOLE_SERVED (JSON: full URL -> response body for runtime-fetch fixtures).
"""

from __future__ import annotations

import base64
import json
import os

from mitmproxy import http

SERVED: dict[str, str] = json.loads(os.environ.get("SINKHOLE_SERVED", "{}"))
RAW_LIMIT = 5 * 1024 * 1024  # bytes of a binary body passed on for unpacking, at most


def _raw_body(request: http.Request) -> str | None:
    """A body that is not text (an archive, compressed data) is passed on as base64 so the host
    can unpack it and search inside: as text it would be garbled."""
    raw = request.get_content(strict=False) or b""
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(raw[:RAW_LIMIT]).decode()
    return None


class Recorder:
    def running(self) -> None:
        print(json.dumps({"kind": "ready"}), flush=True)

    def request(self, flow: http.HTTPFlow) -> None:
        request = flow.request
        print(
            json.dumps(
                {
                    "kind": "http",
                    "scheme": request.scheme,
                    "method": request.method,
                    "host": request.pretty_host,
                    "path": request.path,
                    "headers": dict(request.headers),
                    "body": request.get_text(strict=False) or "",
                    "body_b64": _raw_body(request),
                }
            ),
            flush=True,
        )
        body = SERVED.get(request.pretty_url, "")
        flow.response = http.Response.make(200, body.encode(), {"Content-Type": "text/plain"})


addons = [Recorder()]
