"""Minimal Switch agent-protocol client: SSE event stream, heartbeat, posting.

Stdlib only. Reconnects with the same connection id, so Switch treats it as
one connection that survived a dropped socket.
"""
from __future__ import annotations

import http.client
import json
import logging
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

log = logging.getLogger("shipyard.switch")


class SwitchClient:
    def __init__(self, base_url: str, agent_id: str, api_key: str):
        self.base = base_url.rstrip("/")
        self.agent_id, self.key = agent_id, api_key
        self.connection_id = str(uuid.uuid4())
        self.cursor = 0
        self.stop = threading.Event()

    # -- posting --------------------------------------------------------------

    def post(self, room_id: str, content: str) -> None:
        """Post as this agent. Needs no connection. Never raises: a failed post is logged."""
        body = json.dumps({"room_id": room_id, "content": content}).encode()
        req = urllib.request.Request(f"{self.base}/agents/{self.agent_id}/message", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except (urllib.error.URLError, OSError) as exc:
            log.error("post to room %s failed: %s", room_id, exc)

    # -- stream ---------------------------------------------------------------

    def _beat_loop(self) -> None:
        while not self.stop.is_set():
            body = json.dumps({"connection_id": self.connection_id, "cursor": self.cursor}).encode()
            req = urllib.request.Request(f"{self.base}/agents/{self.agent_id}/connection/beat", data=body, method="POST",
                                         headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=5).read()
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 409):
                    log.warning("heartbeat refused (%s): the stream will reopen", exc.code)
            except (urllib.error.URLError, OSError):
                pass
            self.stop.wait(2.0)

    def events(self) -> Iterator[dict[str, Any]]:
        """Yield domain events (`message`, ...) forever, reconnecting on failure."""
        threading.Thread(target=self._beat_loop, daemon=True).start()
        url = urlparse(self.base)
        while not self.stop.is_set():
            try:
                conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=60)
                path = (f"/agents/{self.agent_id}/events?connection_id={self.connection_id}&scope=all&filter=all"
                        f"&start_from=head&protocol=1&client=shipyard-gatekeeper")
                conn.request("GET", path, headers={"Authorization": f"Bearer {self.key}", "Accept": "text/event-stream",
                                                   **({"Last-Event-ID": str(self.cursor)} if self.cursor else {})})
                resp = conn.getresponse()
                if resp.status != 200:
                    raise OSError(f"stream refused: HTTP {resp.status}")
                log.info("stream open")
                ev: dict[str, Any] = {}
                for raw in resp:
                    line = raw.decode().rstrip("\n")
                    if line.startswith("id:"):
                        ev["id"] = line[3:].strip()
                    elif line.startswith("event:"):
                        ev["event"] = line[6:].strip()
                    elif line.startswith("data:"):
                        ev["data"] = json.loads(line[5:])
                    elif line == "" and ev:
                        if "id" in ev:
                            self.cursor = max(self.cursor, int(ev["id"]))
                        if ev.get("event") in ("message", "room_join", "command") and "data" in ev:
                            yield ev["data"]
                        elif ev.get("event") == "evicted":
                            log.warning("evicted: another process uses this connection id")
                        ev = {}
                    if self.stop.is_set():
                        return
            except (OSError, ValueError, http.client.HTTPException) as exc:
                log.warning("stream dropped: %s; reconnecting", exc)
            self.stop.wait(3.0)
