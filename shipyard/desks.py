"""Personal desk rooms: `<project>-desk-<name>`, one private room per member, where the Repo Agent answers only that person and the owners.

The Gatekeeper makes them through Switch (a private channel on the member's chat app, with the Repo Agent and the Gatekeeper in it), remembers
which room is whose in a small overlay file, and the daily standup posts each member's own briefing there. The addressing rule that keeps the Repo Agent
to that person and the owners is part of `access.py`'s policy sync.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .config import Config, Project
from .policy import Role

AGENT = "repo-agent"               # the agent that answers in a desk
_NAME = re.compile(r"^@switch-[a-z]+-[0-9a-f-]{36}-(?P<name>[^:\s]{1,80}):[^:\s]{1,80}$")


class DeskError(Exception):
    """A refusal whose message is safe to show."""


def username_of(identity: str) -> str | None:
    m = _NAME.match(identity)
    return m.group("name") if m else None


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "member"


class Desks:
    def __init__(self, cfg: Config, path: str | Path, audit: AuditLog | None, gateway: Callable[[], Any] | None):
        self.cfg, self.path, self.audit, self.gateway = cfg, Path(path), audit, gateway
        self.lock = threading.RLock()
        self.finder: Callable[[str, str], str | None] | None = None        # (bridge, name) -> id of a chat-app channel that is already there, set by the room sync

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            for project, rooms in data.items():
                if project in self.cfg.projects and isinstance(rooms, dict):
                    self.cfg.desks.setdefault(project, {}).update({str(i): str(r) for i, r in rooms.items()})
        except (ValueError, AttributeError) as exc:
            raise SystemExit(f"{self.path} is damaged ({exc}); fix or remove it") from None

    def forget(self, project: str, identity: str) -> None:
        """Drop a desk whose room was removed, so the next sync makes it again."""
        with self.lock:
            self.cfg.desks.get(project, {}).pop(identity, None)
            self._write()

    def room_for(self, project: str, identity: str) -> str | None:
        return self.cfg.desks.get(project, {}).get(identity)

    def missing(self, project: Project) -> list[str]:
        members = self.cfg.policy.members.get(project.name, {})
        return sorted(i for i in members if i not in self.cfg.desks.get(project.name, {}) and username_of(i))

    def create(self, project: Project, actor: str, identities: list[str] | None = None) -> tuple[list[str], list[str]]:
        """Make the missing desks. Returns (names made, problems). One member failing does not stop the others."""
        if self.gateway is None:
            raise DeskError("Switch's admin login is not set up here (gateway_env_file), so I can't create rooms.")
        with self.lock:
            return self._create(project, actor, identities)

    def _create(self, project: Project, actor: str, identities: list[str] | None) -> tuple[list[str], list[str]]:
        have = self.cfg.desks.get(project.name, {})
        todo = [i for i in (identities if identities is not None else self.missing(project)) if i not in have]       # re-read under the lock: never twice for one person
        if not todo:
            return [], []
        gw = self.gateway()
        details: dict[str, dict[str, Any]] = {}              # chat app (bridge) -> a project room on it, to copy the app and group from
        for room in [*sorted(project.ops_rooms), *sorted(project.maintainer_rooms), *sorted(project.incident_rooms)]:
            status, d = gw.call("GET", f"/rooms/{room}")
            if status == 200 and isinstance(d, dict) and d.get("bridge_id"):
                details.setdefault(str(d["bridge_id"]), d)
        if not details:
            raise DeskError("None of the project's rooms could be read from Switch, so there is nothing to copy the chat app from.")
        members = self.cfg.policy.members.get(project.name, {})
        status, listing = gw.call("GET", "/rooms")
        rooms_now = listing if status == 200 and isinstance(listing, list) else []
        made, problems = [], []
        for ident in todo:
            user = username_of(ident)
            if ident not in members or not user:
                problems.append(f"{ident}: not a member with a chat name")
                continue
            bridge = next((b for b in details if f"-{b}-" in ident), None)
            if bridge is None:
                problems.append(f"{user}: the project has no room on their chat app, so no desk room can be made there")
                continue
            owners = [n for i, r in sorted(members.items()) if r is Role.OWNER and f"-{bridge}-" in i and (n := username_of(i))]
            name = f"{project.name}-desk-{slug(user)}"
            body = {"name": name, "description": f"Personal desk for {user}: your briefing and tickets. Only you and the owners are here.",
                    "channel_type": "channel_private", "agent_names": [AGENT, "gatekeeper"], "user_names": sorted({user, *owners}),
                    "bridge_id": bridge, "group_id": details[bridge].get("group_id")}
            existing = next((r for r in rooms_now if r.get("name") == name and r.get("bridge_id") == bridge), None)
            channel = None if existing is not None or self.finder is None else self.finder(bridge, name)
            if channel is not None:                                             # the channel is already there with no room: link it
                body = {**{k: v for k, v in body.items() if k != "channel_type"}, "external_channel_id": channel}
            if existing is not None:                                            # a desk made earlier and not remembered: take it, do not make a second
                status, room = 200, {"id": existing["id"]}
            else:
                status, room = gw.call("POST", "/rooms", {k: v for k, v in body.items() if v is not None})
            if status not in (200, 201) or not isinstance(room, dict) or "id" not in room:
                problems.append(f"{name}: Switch answered {status} {str(room)[:100]}")
                continue
            with self.lock:
                self.cfg.desks.setdefault(project.name, {})[ident] = room["id"]
                self._write()
            if self.audit:
                self.audit.write(project=project.name, actor=actor, event="desk_created", action="desks.create", target=ident, room=name)
            made.append(name)
        return made, problems

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".desks.")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(self.cfg.desks, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
