"""Receive Coolify's webhook notifications.

Coolify's webhook has no signature, only a URL, so the URL carries a random secret and the
listener is reachable only from inside the VPC. Anything else is dropped.
"""
from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

log = logging.getLogger("shipyard.webhook")

MAX_BODY = 64 * 1024
EVENTS = {"deployment_failed", "status_changed"}   # what we alert on; the rest is ignored


def make_handler(secret: str, on_event: Callable[[dict[str, Any]], None]):
    prefix = "/hooks/coolify/"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _reply(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            supplied = path[len(prefix):] if path.startswith(prefix) else ""
            if not supplied or not hmac.compare_digest(supplied, secret):
                log.warning("webhook with a wrong path from %s", self.client_address[0])
                return self._reply(404)                      # reveal nothing
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._reply(400)
            if length > MAX_BODY:
                return self._reply(413)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._reply(400)
            if not isinstance(payload, dict) or payload.get("event") not in EVENTS:
                return self._reply(202)                      # accepted, ignored
            self._reply(200)
            try:
                on_event(payload)
            except Exception:
                log.exception("alert handling failed")

        def do_GET(self) -> None:
            self._reply(405)

    return Handler


def serve(secret: str, on_event: Callable[[dict[str, Any]], None], bind: str, port: int) -> ThreadingHTTPServer:
    if len(secret) < 24:
        raise ValueError("the webhook secret must be at least 24 characters")
    server = ThreadingHTTPServer((bind, port), make_handler(secret, on_event))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("webhook listener on %s:%d", bind, port)
    return server
