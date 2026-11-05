"""Room sync: every chat app the project is used on gets the whole set of rooms, and a room whose channel is gone is made again.

A project has an ops room, a maintainers room and an incidents room, and each member a personal desk. They were made on the first chat app (Mattermost)
and nothing made them on the others, so on Discord an alert pointed at "#demo-incidents (Mattermost)", a room the people there cannot see.

`plan` says what is missing on each chat app, `apply` makes it through Switch, remembers the new rooms in an overlay file the Gatekeeper reads at
start-up (the same idea as the roles overlay), starts listening in them at once, and then runs the desk rooms and the agent-access sync so the agents
answer there. An owner asks for it; the dashboard shows a preview first.

With a read-only Discord bot token the sync also looks at the server's real channel list. Switch does not notice a channel deleted in Discord, so a room
that points at a gone channel is found and made again (only the rooms the sync itself made, and the desks; rooms from the config file are reported, not
touched), and a channel that already has the expected name is linked to its room instead of making a second one.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .config import Config, Project
from .desks import slug, username_of
from .discordapi import TEXT_CHANNEL

log = logging.getLogger("shipyard.roomsync")
KINDS = ("ops", "maintainers", "incidents")
ATTR = {"ops": "ops_rooms", "maintainers": "maintainer_rooms", "incidents": "incident_rooms"}
AGENTS = {"ops": ("ops-agent",), "maintainers": ("repo-agent",), "incidents": ("ops-agent",)}
WHAT = {"ops": "Deploys, rollbacks, status and logs. Commands are mentions of @gatekeeper.",
        "maintainers": "Pull request alerts, CI, the daily digest, merges and SBOM reports.",
        "incidents": "Alerts with real log evidence, and the Ops Agent's diagnosis."}
_BRIDGE = re.compile(r"^@switch-[a-z]+-(?P<bridge>[0-9a-f-]{36})-")
_DISCORD_URL = re.compile(r"^https://discord\.com/channels/(?P<guild>\d+)/(?P<channel>\d+)$")


class RoomSyncError(Exception):
    """A refusal whose message is safe to show."""


class RoomSync:
    def __init__(self, cfg: Config, path: str | Path, audit: AuditLog | None, gateway: Callable[[], Any] | None,
                 desks: Any = None, access_sync: Callable[[Project, str], Any] | None = None, discord: Any = None):
        self.cfg, self.path, self.audit, self.gateway = cfg, Path(path), audit, gateway
        self.desks, self.access_sync, self.discord = desks, access_sync, discord
        self.lock = threading.RLock()
        self.running = threading.Lock()                                        # one sync at a time: a double click must not make everything twice
        if desks is not None:
            desks.finder = self.find_channel                                   # a desk takes a channel that is already there instead of making another

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
        for kind, attr in ATTR.items():
            ids = kinds.get(kind, {})
            fields[attr] = frozenset(getattr(p, attr)) | frozenset(ids)
            names.update({i: n for i, n in ids.items() if i not in names})
        self.cfg.projects[project] = dataclasses.replace(p, room_names=names, **fields)

    def _detach(self, project: str, kind: str, room_id: str) -> None:
        p = self.cfg.projects[project]
        names = {i: n for i, n in p.room_names.items() if i != room_id}
        self.cfg.projects[project] = dataclasses.replace(p, room_names=names, **{ATTR[kind]: frozenset(getattr(p, ATTR[kind])) - {room_id}})

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".rooms.")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- what Switch and Discord have --------------------------------------------------------------------

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
        return {"rooms": rooms, "apps": {a["bridge_id"]: a for a in apps if "bridge_id" in a}, "agents": {a["name"]: a["id"] for a in agents if "name" in a},
                "discord": {}}

    @staticmethod
    def _chan(room: dict[str, Any]) -> tuple[str, str] | None:
        m = _DISCORD_URL.match(str(room.get("external_channel_url") or ""))
        return (m["guild"], m["channel"]) if m else None

    def _channels(self, world: dict[str, Any], guild: str) -> dict[str, dict[str, Any]] | None:
        """The server's channels by id, or None when there is no token or Discord would not say (then nothing is judged gone)."""
        if self.discord is None:
            return None
        if guild not in world["discord"]:
            try:
                listing = {c["id"]: c for c in self.discord.channels(guild)}
                world["discord"][guild] = listing or None                   # a server always has channels: an empty list means the bot cannot see them, not that they are gone
            except Exception as exc:
                log.warning("room sync: could not read the Discord channel list: %s", exc)
                world["discord"][guild] = None
        return world["discord"][guild]

    def _guild_of_bridge(self, world: dict[str, Any], bridge: str) -> str | None:
        for r in world["rooms"]:
            if r.get("bridge_id") == bridge and (c := self._chan(r)):
                return c[0]
        return None

    def find_channel(self, bridge: str, name: str, world: dict[str, Any] | None = None) -> str | None:
        """The id of a text channel with this name that no Switch room is linked to yet (so it can be linked, not duplicated)."""
        if self.discord is None or self.gateway is None:
            return None
        try:
            world = world or self._world(self.gateway())
        except RoomSyncError:
            return None
        guild = self._guild_of_bridge(world, bridge)
        chans = self._channels(world, guild) if guild else None
        if not chans:
            return None
        linked = {c[1] for r in world["rooms"] if (c := self._chan(r))}
        return next((i for i, c in chans.items() if c["name"] == name and c["type"] == TEXT_CHANNEL and i not in linked), None)

    def _kind_of(self, p: Project, room_id: str) -> str | None:
        return "incidents" if room_id in p.incident_rooms else "maintainers" if room_id in p.maintainer_rooms else "ops" if room_id in p.ops_rooms else None

    def _app_name(self, world: dict[str, Any], bridge: str) -> str:
        a = world["apps"].get(bridge, {})
        return str(a.get("display_name") or a.get("name") or a.get("bridge_type") or bridge[:8])

    def stale(self, project: Project, world: dict[str, Any]) -> list[dict[str, Any]]:
        """Rooms whose Discord channel is gone. `repair` is true for rooms the sync made and for desks (they can be made again); a room from the
        config file is only reported."""
        mine = {i: (k, n) for k, ids in self._read().get(project.name, {}).items() for i, n in ids.items()}
        desks = {r: i for i, r in self.cfg.desks.get(project.name, {}).items()}
        out = []
        for r in world["rooms"]:
            rid = r["id"]
            chan = self._chan(r)
            if chan is None or (rid not in project.rooms and rid not in desks):
                continue
            chans = self._channels(world, chan[0])
            if chans is None or chan[1] in chans:
                continue
            kind = mine[rid][0] if rid in mine else "desk" if rid in desks else self._kind_of(project, rid)
            out.append({"room_id": rid, "name": r.get("name", rid[:8]), "kind": kind, "app": self._app_name(world, r.get("bridge_id", "")),
                        "repair": rid in mine or rid in desks, "identity": desks.get(rid)})
        return out

    def plan(self, project: Project, world: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """What each chat app is missing. One item per (app, kind): `create` a room, `adopt` one Switch already has under the expected name, or `link`
        a Discord channel that is already there."""
        world = world or self._world(self._need_gateway())
        by_id = {r["id"]: r for r in world["rooms"]}
        gone = {s["room_id"] for s in self.stale(project, world) if s["repair"]}          # a room that is about to be made again does not count as present
        apps: dict[str, dict[str, set[str]]] = {}                           # bridge -> kind -> room ids the project has there
        for rid in project.rooms:
            r = by_id.get(rid)
            if r and r.get("bridge_id"):
                apps.setdefault(r["bridge_id"], {k: set() for k in KINDS})
                if rid not in gone:
                    apps[r["bridge_id"]][self._kind_of(project, rid)].add(rid)       # type: ignore[index]
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
                existing = next((r for r in world["rooms"] if r.get("bridge_id") == bridge and r.get("name") == name and r["id"] not in gone), None)
                channel = None if existing else self.find_channel(bridge, name, world)
                out.append({"op": "adopt" if existing else "link" if channel else "create", "kind": kind, "name": name, "bridge": bridge, "app": self._app_name(world, bridge),
                            "group": group, "room_id": existing["id"] if existing else None, "channel_id": channel})
        return out

    def preview(self, project: Project) -> list[dict[str, str]]:
        """The same list as a page shows it: what is gone from Discord, what would be made, then the desks."""
        world = self._world(self._need_gateway())
        changes: list[dict[str, str]] = []
        for s in self.stale(project, world):
            changes.append({"op": "~" if s["repair"] else "!", "agent": s["app"], "text": f"#{s['name']} is gone from Discord" + (": its room is removed from Switch and made again" if s["repair"]
                                                                                                                                     else " (a room from the config file: not touched, recreate it by hand)")})
        for it in self.plan(project, world):
            how = {"adopt": " (already in Switch; it would be taken into the project)", "link": " (the Discord channel is already there; it is linked, not duplicated)"}.get(it["op"], "")
            changes.append({"op": "+", "agent": it["app"], "text": f"#{it['name']}: {it['kind']} room{how}"})
        if self.desks is not None:
            gone_desks = {s["identity"] for s in self.stale(project, world) if s["kind"] == "desk"}
            missing = [*self.desks.missing(project), *sorted(i for i in gone_desks if i)]
            if missing:
                changes.append({"op": "+", "agent": "desks", "text": f"{len(missing)} personal desk room{'s' if len(missing) != 1 else ''}: "
                                + ", ".join(f"{project.name}-desk-{slug(username_of(i) or i)}" for i in missing[:6]) + (" …" if len(missing) > 6 else "")})
        return changes

    # -- making them -------------------------------------------------------------------------------------

    def apply(self, project: Project, actor: str) -> dict[str, Any]:
        if not self.running.acquire(blocking=False):
            raise RoomSyncError("A room sync is already running. Wait for it to finish.")
        try:
            return self._apply(project, actor)
        finally:
            self.running.release()

    def _forget(self, project: Project, s: dict[str, Any], gw: Any, problems: list[str], actor: str) -> bool:
        """Remove a room whose channel is gone: from Switch (its channel is already gone, so nothing is retired), the overlay and the Gatekeeper."""
        status, body = gw.call("DELETE", f"/rooms/{s['room_id']}")
        if status not in (200, 204, 404):
            problems.append(f"#{s['name']}: Switch would not remove the stale room ({status})")
            log.warning("room sync: could not remove stale room %s: %s %s", s["room_id"], status, str(body)[:200])
            return False
        with self.lock:
            if s["kind"] == "desk":
                if self.desks is not None and s.get("identity"):
                    self.desks.forget(project.name, s["identity"])
            else:
                data = self._read()
                data.get(project.name, {}).get(s["kind"], {}).pop(s["room_id"], None)
                self._write(data)
                self._detach(project.name, s["kind"], s["room_id"])
        if self.audit:
            self.audit.write(project=project.name, actor=actor, event="executed", action="rooms.remove_stale", target=s["name"], room=s["room_id"][:8])
        return True

    def _apply(self, project: Project, actor: str) -> dict[str, Any]:
        gw = self._need_gateway()
        world = self._world(gw)
        project = self.cfg.projects[project.name]                           # the latest one: a sync that just finished may have added rooms
        problems: list[str] = []
        removed = [f"#{s['name']}" for s in self.stale(project, world) if s["repair"] and self._forget(project, s, gw, problems, actor)]
        if removed:
            world = self._world(gw)
            project = self.cfg.projects[project.name]
        made: list[str] = []
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
                    log.warning("room sync: could not add agents to %s: %s %s", label, status, str(body)[:200])
                    continue
            else:
                body = {"name": it["name"], "description": WHAT[it["kind"]], "agent_names": agent_names, "bridge_id": it["bridge"], "group_id": it["group"]}
                if it["op"] == "link":
                    body["external_channel_id"] = it["channel_id"]           # the channel is already in Discord: link it, make no second one
                else:
                    body["channel_type"] = "channel_public"                  # Switch refuses a new chat-app channel without one
                status, room = gw.call("POST", "/rooms", {k: v for k, v in body.items() if v is not None})
                if status not in (200, 201) or not isinstance(room, dict) or "id" not in room:
                    problems.append(f"{label}: Switch answered {status} {str(room)[:100]}")
                    log.warning("room sync: Switch refused to create %s: %s %s", label, status, str(room)[:300])
                    if self.audit:
                        self.audit.write(project=project.name, actor=actor, event="failed", action="rooms.sync", target=label, error=f"Switch answered {status}: {str(room)[:120]}")
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
        return {"rooms": made, "desks": desks, "removed": removed, "agent_access_synced": synced, "problems": problems}
