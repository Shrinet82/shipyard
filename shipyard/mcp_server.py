"""The Gatekeeper's MCP endpoint for agents: one tool, `request_action`.

Streamable HTTP, JSON-RPC, bearer token, localhost only. Agents cannot approve
anything through it: a proposal that needs approval returns `awaiting_human_approval`.
"""
from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .service import Service
from .ticketflow import TOOL_NAMES, TOOLS as TICKET_TOOLS

log = logging.getLogger("shipyard.mcp")

TOOL = {
    "name": "request_action",
    "description": (
        "Ask the Shipyard Gatekeeper to run an operation on the project's infrastructure for the person who just "
        "asked you. You hold no write access yourself. Cite `message_id`, the id of that person's message. "
        "Reads run at once; deploys, restarts and rollbacks are posted in the room for a person to approve, so "
        "tell them the approval id and do not retry. Actions: coolify.status, coolify.deploy, coolify.restart, "
        "coolify.rollback, repo.pr_list (target: any word), repo.pr_status (target: the PR number), signoz.read (target: alerts, rules, logs:<service> or errors:<service>; SigNoz alerts and logs, read only), repo.ci (target: a PR number, a commit, or the word workflows; the CI that ran, who started it and its artifacts), and k8s.exec or "
        "coolify.exec (target: the application; args {\"argv\": [\"tail\", \"-n\", \"50\", \"/var/log/app.log\"]}) to run one "
        "read-only diagnostic inside its container or pod: ls, cat, tail, grep, ps, df, curl http://localhost:PORT/health and the like. "
        "Files that hold credentials are refused. You cannot merge."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "e.g. coolify.deploy"},
            "target": {"type": "string", "description": "application name, e.g. demo-app"},
            "args": {"type": "object", "description": "optional, e.g. {\"tag\": \"1.27-alpine\"} for a rollback"},
            "message_id": {"type": "string", "description": "id of the person's message you are acting on"},
            "agent": {"type": "string", "description": "your own name"},
        },
        "required": ["action", "target", "message_id"],
    },
    "annotations": {"readOnlyHint": False, "destructiveHint": False},
}
ALLOWED_ACTIONS = {"coolify.status", "coolify.deploy", "coolify.restart", "coolify.rollback", "repo.pr_list", "repo.pr_status", "repo.ci", "signoz.read",
                   "k8s.exec", "coolify.exec"}


def make_handler(service: Service, token: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # quiet
            pass

        def _send(self, status: int, body: dict | None = None) -> None:
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not hmac.compare_digest(supplied, token):
                return self._send(401, {"error": "unauthorized"})
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            method, rid = req.get("method"), req.get("id")
            if method == "initialize":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "protocolVersion": "2025-03-26", "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "shipyard-gatekeeper", "version": "0.1"}}})
            if rid is None:                      # notifications
                return self._send(202)
            if method == "tools/list":
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [TOOL, *TICKET_TOOLS]}})
            if method == "tools/call":
                params = req.get("params") or {}
                if params.get("name") in TOOL_NAMES:                       # the Board's tools: the caller is whoever wrote the cited message
                    a = params.get("arguments") or {}
                    try:
                        result = service.ticket_tool(params["name"], a if isinstance(a, dict) else {}, str(a.get("message_id", "")) if isinstance(a, dict) else "",
                                                     str(a.get("agent", "agent"))[:40] if isinstance(a, dict) else "agent")
                    except Exception:
                        log.exception("ticket tool failed")
                        result = {"status": "denied", "reason": "the Gatekeeper hit an error; nothing was changed"}
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": json.dumps(result)}], "isError": result["status"] == "denied"}})
                if params.get("name") != "request_action":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown tool"}})
                a = params.get("arguments") or {}
                if a.get("action") not in ALLOWED_ACTIONS:
                    result = {"status": "denied", "reason": "unsupported action"}
                else:
                    try:
                        result = service.propose(action=a["action"], target=str(a.get("target", "")),
                                                 args=a.get("args") if isinstance(a.get("args"), dict) else {},
                                                 message_id=str(a.get("message_id", "")), agent=str(a.get("agent", "agent"))[:40])
                    except Exception:            # fail closed
                        log.exception("request_action failed")
                        result = {"status": "denied", "reason": "the Gatekeeper hit an error; nothing was changed"}
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": json.dumps(result)}], "isError": result["status"] == "denied"}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})

        def do_GET(self) -> None:
            self._send(405, {"error": "this endpoint takes POST"})

    return Handler


def serve(service: Service, port: int, token: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(service, token))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("MCP endpoint on 127.0.0.1:%d", port)
    return server
