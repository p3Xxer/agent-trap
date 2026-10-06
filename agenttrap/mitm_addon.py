"""mitmproxy addon, run INSIDE the proxy container on the sandbox's private network.

For every request the sandbox makes (HTTP, or HTTPS once the sandbox's trusted certificate has
let the proxy read it) it prints one JSON line, then answers the request itself. No request is
ever sent upstream, so there is nothing to exfiltrate to: this is a honeypot, not a relay.

Environment: SINKHOLE_SERVED (JSON: full URL -> response body for runtime-fetch fixtures).
"""

from __future__ import annotations

import json
import os

from mitmproxy import http

SERVED: dict[str, str] = json.loads(os.environ.get("SINKHOLE_SERVED", "{}"))


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
                }
            ),
            flush=True,
        )
        body = SERVED.get(request.pretty_url, "")
        flow.response = http.Response.make(200, body.encode(), {"Content-Type": "text/plain"})


addons = [Recorder()]
