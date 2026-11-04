"""Coolify adapter over its MCP endpoint (streamable HTTP, bearer token).

The Gatekeeper is the only holder of the write token. Every method raises
CoolifyError on any failure, so callers fail closed.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any


class CoolifyError(Exception):
    pass


class CoolifyMcp:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.url = base_url.rstrip("/") + "/mcp"
        self.token = token
        self.timeout = timeout
        self.session: str | None = None
        self._id = 0
        self.lock = threading.Lock()

    def _rpc(self, method: str, params: dict | None = None, notify: bool = False) -> dict:
        self._id += 1
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            body["id"] = self._id
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                self.session = r.headers.get("Mcp-Session-Id") or self.session
                raw = r.read().decode()
        except urllib.error.HTTPError as e:
            raise CoolifyError(f"Coolify answered HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise CoolifyError(f"Coolify unreachable: {e}") from e
        for line in raw.splitlines():
            if line.startswith("data:"):
                raw = line[5:].strip()
        if notify or not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError as e:
            raise CoolifyError("Coolify sent an unreadable reply") from e

    def _ensure(self) -> None:
        if self.session:
            return
        self._rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                 "clientInfo": {"name": "shipyard-gatekeeper", "version": "0.1"}})
        self._rpc("notifications/initialized", notify=True)

    def tool(self, name: str, args: dict[str, Any]) -> Any:
        with self.lock:
            for attempt in (1, 2):
                try:
                    self._ensure()
                    reply = self._rpc("tools/call", {"name": name, "arguments": args})
                    break
                except CoolifyError:
                    self.session = None  # a stale session id looks like an HTTP error
                    if attempt == 2:
                        raise
        if "error" in reply:
            raise CoolifyError(str(reply["error"].get("message", reply["error"]))[:200])
        result = reply.get("result", {})
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        if result.get("isError"):
            raise CoolifyError(text[:200] or f"{name} failed")
        try:
            value = json.loads(text)
        except ValueError:
            return text
        if isinstance(value, dict) and isinstance(value.get("data"), (dict, list)):
            return value["data"]          # Coolify wraps replies in {"data": ...}
        return value

    # -- operations -----------------------------------------------------------

    def status(self, uuid: str) -> str:
        app = self.tool("get_application", {"uuid": uuid})
        if isinstance(app, dict):
            return f"{app.get('name', uuid)}: {app.get('status', 'unknown')}"
        return str(app)[:200]

    def deploy(self, uuid: str) -> str:
        out = self.tool("deploy", {"uuid": uuid})
        return f"deployment queued ({_brief(out)})"

    def restart(self, uuid: str) -> str:
        out = self.tool("control", {"resource": "application", "action": "restart", "uuid": uuid})
        return f"restart requested ({_brief(out)})"

    def rollback_tags(self, uuid: str) -> tuple[str | None, list[str]]:
        """(current tag, tags available to roll back to, newest first)."""
        out = self.tool("list_rollback_images", {"action": "list", "uuid": uuid})
        return _parse_rollback(out)

    def rollback(self, uuid: str, tag: str | None = None) -> str:
        current, tags = self.rollback_tags(uuid)
        candidates = [t for t in tags if t != current]
        if tag is None:
            if not candidates:
                raise CoolifyError("no earlier image to roll back to")
            tag = candidates[0]
        elif tag not in candidates:
            raise CoolifyError(f"{tag!r} is not an available rollback image")
        out = self.tool("rollback_application", {"action": "rollback", "uuid": uuid, "data": {"commit": tag}, "confirm": True})
        return f"rollback to {tag} queued ({_brief(out)})"


def _brief(out: Any) -> str:
    if isinstance(out, dict):
        for key in ("message", "deployment_uuid", "status"):
            if key in out:
                return str(out[key])[:80]
        return json.dumps(out)[:80]
    return str(out)[:80]


def _parse_rollback(out: Any) -> tuple[str | None, list[str]]:
    """Be tolerant: the MCP returns the REST API's JSON."""
    if not isinstance(out, dict):
        return None, []
    current = out.get("current_tag") or out.get("current") or out.get("current_image_tag")
    items = out.get("images") or out.get("data") or out.get("tags") or []
    tags: list[str] = []
    for item in items:
        tag = item.get("tag") if isinstance(item, dict) else item
        if isinstance(tag, str):
            tags.append(tag)
    return (str(current) if current else None), tags
