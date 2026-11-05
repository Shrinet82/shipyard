"""Receive Coolify's webhook notifications.

Coolify's webhook has no signature, only a URL, so the URL carries a random secret and the
listener is reachable only from inside the VPC. Anything else is dropped.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

log = logging.getLogger("shipyard.webhook")

MAX_BODY = 64 * 1024
MAX_GITHUB_BODY = 1024 * 1024
GITHUB_EVENTS = {"pull_request", "pull_request_review", "check_run", "check_suite", "workflow_run", "status"}   # the rest (push, issues, ...) is ignored


def github_signature_ok(secret: bytes, body: bytes, header: str) -> bool:
    """GitHub signs the raw body with the webhook secret: `X-Hub-Signature-256: sha256=<hex hmac>`."""
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return bool(header) and hmac.compare_digest(want, header)
EVENTS = {"deployment_failed", "status_changed", "deployment_success", "restart_limit_reached", "container_restarted", "high_disk_usage"}   # alerts, and a finished deploy for the Board; the rest is ignored


def make_handler(secret: str, on_event: Callable[[dict[str, Any]], None], github_secret: bytes | None = None,
                 on_github: Callable[[str, dict[str, Any]], None] | None = None):
    prefix = "/hooks/coolify/"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _reply(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _github(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._reply(400)
            if length > MAX_GITHUB_BODY:
                return self._reply(413)
            body = self.rfile.read(length)
            if not github_signature_ok(github_secret or b"", body, self.headers.get("X-Hub-Signature-256", "")):
                log.warning("GitHub webhook with a wrong signature from %s", self.client_address[0])
                return self._reply(404)                      # reveal nothing
            event = self.headers.get("X-GitHub-Event", "")
            try:
                payload = json.loads(body or b"{}")
            except ValueError:
                return self._reply(400)
            if event not in GITHUB_EVENTS or not isinstance(payload, dict):
                return self._reply(202)                      # accepted (a ping, a push ...), ignored
            self._reply(202)
            try:
                on_github(event, payload)                    # type: ignore[misc]
            except Exception:
                log.exception("GitHub webhook handling failed")

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/hooks/github" and github_secret and on_github:
                return self._github()
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


def serve(secret: str, on_event: Callable[[dict[str, Any]], None], bind: str, port: int, github_secret: bytes | None = None,
          on_github: Callable[[str, dict[str, Any]], None] | None = None) -> ThreadingHTTPServer:
    if len(secret) < 24:
        raise ValueError("the webhook secret must be at least 24 characters")
    if github_secret is not None and len(github_secret) < 24:
        raise ValueError("the GitHub webhook secret must be at least 24 characters")
    server = ThreadingHTTPServer((bind, port), make_handler(secret, on_event, github_secret, on_github))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("webhook listener on %s:%d", bind, port)
    return server
