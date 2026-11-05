"""Room sync: every chat app the project is used on gets the project's whole set of rooms.

A project has an ops room, a maintainers room and an incidents room, and each member a personal desk. They were made on the first chat app (Mattermost)
and nothing made them on the others, so on Discord an alert pointed at "#demo-incidents (Mattermost)", a room the people there cannot see.

`plan` says what is missing on each chat app, `apply` makes it through Switch (or adopts a room that already has the expected name), remembers the new
rooms in an overlay file the Gatekeeper reads at start-up (the same idea as the roles overlay), starts listening in them at once, and then runs the
desk rooms and the agent-access sync so the agents answer there. An owner asks for it; the dashboard shows a preview first.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .config import Config, Project

KINDS = ("ops", "maintainers", "incidents")
AGENTS = {"ops": ("ops-agent",), "maintainers": ("repo-agent",), "incidents": ("ops-agent",)}
WHAT = {"ops": "Deploys, rollbacks, status and logs. Commands are mentions of @gatekeeper.",
        "maintainers": "Pull request alerts, CI, the daily digest, merges and SBOM reports.",
        "incidents": "Alerts with real log evidence, and the Ops Agent's diagnosis."}
_BRIDGE = re.compile(r"^@switch-[a-z]+-(?P<bridge>[0-9a-f-]{36})-")


class RoomSyncError(Exception):
    """A refusal whose message is safe to show."""


class RoomSync:
    def __init__(self, cfg: Config, path: str | Path, audit: AuditLog | None, gateway: Callable[[], Any] | None,
                 desks: Any = None, access_sync: Callable[[Project, str], Any] | None = None):
        self.cfg, self.path, self.audit, self.gateway = cfg, Path(path), audit, gateway
        self.desks, self.access_sync = desks, access_sync
        self.lock = threading.RLock()

    # -- the overlay -----------------------------------------------------------------------------------

    def _read(self) -> dict[str, dict[str, dict[str, str]]]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text())
            return {str(p): {k: {str(i): str(n) for i, n in rooms.items()} for k, rooms in kinds.items() if k in KINDS} for p, kinds in data.items()}
        except (ValueError, AttributeError) as exc:
            raise SystemExit(f"{self.path} is damaged ({exc}); fix or remove it") from None

    def load(self) -> None:
        for project, kinds in self._read().items():
            if project in self.cfg.projects:
                self._attach(project, kinds)

    def _attach(self, project: str, kinds: dict[str, dict[str, str]]) -> None:
        """Make the Gatekeeper listen in the remembered rooms. The project object is replaced, never edited."""
        p = self.cfg.projects[project]
        names = dict(p.room_names)
        fields: dict[str, frozenset[str]] = {}
        for kind, attr in (("ops", "ops_rooms"), ("maintainers", "maintainer_rooms"), ("incidents", "incident_rooms")):
            ids = kinds.get(kind, {})
            fields[attr] = frozenset(getattr(p, attr)) | frozenset(ids)
            names.update({i: n for i, n in ids.items() if i not in names})
        self.cfg.projects[project] = dataclasses.replace(p, room_names=names, **fields)

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rooms.")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- what Switch has -------------------------------------------------------------------------------

    def _need_gateway(self) -> Any:
        if self.gateway is None:
            raise RoomSyncError("Switch's admin login is not set up here (gateway_env_file), so I can't see or make rooms.")
        return self.gateway()

    def _world(self, gw: Any) -> dict[str, Any]:
        status, rooms = gw.call("GET", "/rooms")
        if status != 200 or not isinstance(rooms, list):
            raise RoomSyncError(f"Switch would not list its rooms ({status}).")
        status, apps = gw.call("GET", "/collaborations")
        apps = apps if status == 200 and isinstance(apps, list) else []
        status, agents = gw.call("GET", "/agents")
        agents = agents if isinstance(agents, list) else ((agents or {}).get("agents", []) if isinstance(agents, dict) else [])
        return {"rooms": rooms, "apps": {a["bridge_id"]: a for a in apps if "bridge_id" in a}, "agents": {a["name"]: a["id"] for a in agents if "name" in a}}

    def _kind_of(self, p: Project, room_id: str) -> str | None:
        return "incidents" if room_id in p.incident_rooms else "maintainers" if room_id in p.maintainer_rooms else "ops" if room_id in p.ops_rooms else None

    def _app_name(self, world: dict[str, Any], bridge: str) -> str:
        a = world["apps"].get(bridge, {})
        return str(a.get("display_name") or a.get("name") or a.get("bridge_type") or bridge[:8])

    def plan(self, project: Project, world: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """What each chat app is missing. One item per (app, kind): `create` a room, or `adopt` one Switch already has under the expected name."""
        world = world or self._world(self._need_gateway())
        by_id = {r["id"]: r for r in world["rooms"]}
        apps: dict[str, dict[str, set[str]]] = {}                           # bridge -> kind -> room ids the project has there
        for rid in project.rooms:
            r = by_id.get(rid)
            if r and r.get("bridge_id"):
                apps.setdefault(r["bridge_id"], {k: set() for k in KINDS})[self._kind_of(project, rid)].add(rid)       # type: ignore[index]
        for ident in self.cfg.policy.members.get(project.name, {}):         # a chat app where people have a role is one the project is used on
            m = _BRIDGE.match(ident)
            if m and m["bridge"] in world["apps"]:
                apps.setdefault(m["bridge"], {k: set() for k in KINDS})
        out: list[dict[str, Any]] = []
        for bridge, have in sorted(apps.items()):
            group = next((by_id[i].get("group_id") for ids in have.values() for i in ids if i in by_id and by_id[i].get("group_id")), None)
            for kind in KINDS:
                if have[kind]:
                    continue
                name = f"{project.name}-{kind}"
                existing = next((r for r in world["rooms"] if r.get("bridge_id") == bridge and r.get("name") == name), None)
                out.append({"op": "adopt" if existing else "create", "kind": kind, "name": name, "bridge": bridge, "app": self._app_name(world, bridge),
                            "group": group, "room_id": existing["id"] if existing else None})
        return out

    def preview(self, project: Project) -> list[dict[str, str]]:
        """The same list as a page shows it: what would be made, then the desks."""
        world = self._world(self._need_gateway())
        changes = [{"op": "+", "agent": it["app"], "text": f"#{it['name']}: {it['kind']} room" + (" (already in Switch; it would be taken into the project)" if it["op"] == "adopt" else "")}
                   for it in self.plan(project, world)]
        if self.desks is not None:
            missing = self.desks.missing(project)
            if missing:
                changes.append({"op": "+", "agent": "desks", "text": f"{len(missing)} personal desk room{'s' if len(missing) != 1 else ''}: "
                                + ", ".join(f"{project.name}-desk-{i.rsplit('-', 1)[-1].split(':')[0]}" for i in missing[:6]) + (" …" if len(missing) > 6 else "")})
        return changes

    # -- making them -------------------------------------------------------------------------------------

    def apply(self, project: Project, actor: str) -> dict[str, Any]:
        gw = self._need_gateway()
        world = self._world(gw)
        made: list[str] = []
        problems: list[str] = []
        added: dict[str, dict[str, str]] = {}
        for it in self.plan(project, world):
            agent_names = [*AGENTS[it["kind"]], "gatekeeper"]
            label = f"#{it['name']} ({it['app']})"
            if it["op"] == "adopt":
                room_id = it["room_id"]
                ids = [world["agents"][n] for n in agent_names if n in world["agents"]]
                status, body = gw.call("POST", f"/rooms/{room_id}/agents", {"agent_ids": ids})
                if status not in (200, 201):
                    problems.append(f"{label}: could not add the agents ({status})")
                    continue
            else:
                body = {"name": it["name"], "description": WHAT[it["kind"]], "agent_names": agent_names, "bridge_id": it["bridge"], "group_id": it["group"]}
                status, room = gw.call("POST", "/rooms", {k: v for k, v in body.items() if v is not None})
                if status not in (200, 201) or not isinstance(room, dict) or "id" not in room:
                    problems.append(f"{label}: Switch answered {status} {str(room)[:100]}")
                    continue
                room_id = room["id"]
            added.setdefault(it["kind"], {})[room_id] = label
            made.append(label)
        if added:
            with self.lock:
                data = self._read()
                for kind, ids in added.items():
                    data.setdefault(project.name, {}).setdefault(kind, {}).update(ids)
                self._write(data)
                self._attach(project.name, added)
            if self.audit:
                self.audit.write(project=project.name, actor=actor, event="executed", action="rooms.sync", target=",".join(made)[:200], rooms=len(made))
        desks: list[str] = []
        if self.desks is not None and self.desks.missing(self.cfg.projects[project.name]):
            try:
                desks, more = self.desks.create(self.cfg.projects[project.name], actor)
                problems += more
            except Exception as exc:                                       # DeskError, or Switch unreachable
                problems.append(f"desk rooms: {exc}")
        synced = False
        if (made or desks) and self.access_sync is not None:               # the agents may only answer where Switch's addressing policy says so
            try:
                self.access_sync(self.cfg.projects[project.name], actor)
                synced = True
            except Exception as exc:
                problems.append(f"agent access sync: {exc}")
        return {"rooms": made, "desks": desks, "agent_access_synced": synced, "problems": problems}
