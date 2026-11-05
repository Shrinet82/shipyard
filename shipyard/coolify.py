"""Coolify adapter over its MCP endpoint (streamable HTTP, bearer token).

The Gatekeeper is the only holder of the write token. Every method raises
CoolifyError on any failure, so callers fail closed.
"""
from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from typing import Any


class CoolifyError(Exception):
    pass


class CoolifyMcp:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.url = self.base + "/mcp"
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

    # -- evidence (read-only) -------------------------------------------------

    def deployment_logs(self, deployment_uuid: str) -> list[str]:
        """Build/deploy log lines of one deployment. Only the REST API returns them."""
        req = urllib.request.Request(f"{self.base}/api/v1/deployments/{deployment_uuid}",
                                     headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise CoolifyError(f"could not read the deployment log: {e}") from e
        logs = data.get("logs")
        try:
            entries = json.loads(logs) if isinstance(logs, str) else (logs or [])
        except ValueError:
            return [str(logs)]
        return [e.get("output", "") for e in entries if isinstance(e, dict) and not e.get("hidden")]

    def deployment_commit(self, deployment_uuid: str) -> str:
        """The git commit one deployment built, or "" when Coolify has only recorded "HEAD" for it."""
        req = urllib.request.Request(f"{self.base}/api/v1/deployments/{deployment_uuid}", headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise CoolifyError(f"could not read the deployment: {e}") from e
        sha = str((data or {}).get("commit") or "")
        return sha if re.fullmatch(r"[0-9a-fA-F]{7,40}", sha) else ""

    def deployment_history(self, uuid: str, limit: int = 8) -> list[str]:
        req = urllib.request.Request(f"{self.base}/api/v1/deployments/applications/{uuid}",
                                     headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise CoolifyError(f"could not read the deployment history: {e}") from e
        rows = data if isinstance(data, list) else data.get("deployments", [])
        return [f"{(d.get('created_at') or '')[:19]} {d.get('status', '?')} {(d.get('commit') or '')[:7]} "
                f"{(d.get('commit_message') or '').strip().splitlines()[0][:70] if d.get('commit_message') else ''}".rstrip()
                for d in rows[:limit]]

    def container_logs(self, uuid: str, lines: int = 100) -> list[str]:
        out = self.tool("get_logs", {"resource": "application", "uuid": uuid, "lines": lines})
        if isinstance(out, dict):          # {"ok": true, "logs": "...", ...}: an empty log is empty, not the wrapper
            out = out["logs"] if "logs" in out else (out.get("output") or "")
        return str(out).splitlines()

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
