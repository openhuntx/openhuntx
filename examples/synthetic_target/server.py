#!/usr/bin/env python3
"""A tiny, deliberately imperfect local HTTP server for the WebGuard demo.

Not a real application -- just enough response surface (a couple of
headers set, several deliberately missing) to produce a representative,
reproducible set of passive findings without touching any external
target. See examples/README.md for how it's used.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"""<!doctype html>
<html>
<head><title>WebGuard demo target</title></head>
<body><h1>Synthetic WebGuard demo target</h1></body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        # Intentionally set: a Server header that discloses version info.
        self.send_header("Server", "DemoServer/1.0 (synthetic)")
        # Intentionally NOT set: CSP, frame-protection, X-Content-Type-Options,
        # Referrer-Policy -- so the demo scan reproduces real, common findings.
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *_args: object) -> None:  # quiet by default
        pass


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8921
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
