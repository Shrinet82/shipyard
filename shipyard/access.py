"""Agent access: who may talk to each agent, kept in Switch as the agent's addressing policy.

The roles are the source of truth. This module turns them into policies, shows what would change, and applies it
through Switch's Gateway (admin login read from Switch's own env file). The same rules as scripts/sync_addressing.py:
only the project's members, only in its rooms; the Switch owner keeps access everywhere; platform senders are not admitted.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .config import Config, Project
from .desks import AGENT as DESK_AGENT
from .policy import Role

SCHEMA = "CREATE TABLE IF NOT EXISTS agent_sync (agent TEXT PRIMARY KEY, ts REAL NOT NULL, actor TEXT NOT NULL);"
_SENDER = re.compile(r"^@switch-(?P<platform>[a-z]+)-(?P<bridge>[0-9a-f-]{36})-(?P<name>.+):[^:]+$")


class AccessError(Exception):
    """Switch refused or is unreachable; the message is safe to show."""


def read_env(path: str) -> dict[str, str]:
    out = {}
    for line in open(os.path.expanduser(path)):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            out[k] = v.strip().strip("'\"")
    return out


class Gateway:
    def __init__(self, base: str, email: str, password: str, timeout: float = 20.0):
        self.base, self.timeout = base.rstrip("/") + "/gateway", timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        status, _ = self.call("POST", "/auth/login", {"email": email, "password": password})
        if status != 200:
            raise AccessError(f"Switch refused the admin login ({status})")

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        req = urllib.request.Request(self.base + path, method=method, headers={"Content-Type": "application/json"},
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace")[:200]
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AccessError(f"Switch is unreachable ({exc})") from None


def _squash(text: str) -> str:
    return "".join(ch for ch in (text or "").lower() if ch.isalnum())


class AgentAccess:
    def __init__(self, cfg: Config, gateway: Callable[[], Gateway], db: sqlite3.Connection, lock: threading.RLock,
                 audit, now: Callable[[], float] = time.time):
        self.cfg, self.gateway, self.db, self.lock, self.audit, self.now = cfg, gateway, db, lock, audit, now
        with self.lock:
            self.db.executescript(SCHEMA)

    # -- what Switch knows ------------------------------------------------------------

    @staticmethod
    def _get(gw: Gateway, path: str) -> Any:
        status, data = gw.call("GET", path)
        if status != 200:
            raise AccessError(f"Switch answered {status} for {path}")
        return data

    def _world(self, gw: Gateway) -> dict[str, Any]:
        agents = self._get(gw, "/agents")
        agents = agents if isinstance(agents, list) else agents.get("agents", [])
        users: dict[str, tuple[str, str]] = {}               # external user id -> (bridge prefix, username)
        prefixes: dict[str, list[dict[str, Any]]] = {}
        for b in self._get(gw, "/collaborations"):
            prefix = f"@switch-{b['bridge_type']}-{b['bridge_id']}-"
            status, rows = gw.call("GET", f"/collaborations/{b['bridge_id']}/users")
            for u in rows if status == 200 and isinstance(rows, list) else []:
                users[u["id"]] = (prefix, u.get("external_username") or "")
                prefixes.setdefault(prefix, []).append(u)
        return {"agents": {a["name"]: a for a in agents}, "users": users, "prefixes": prefixes}

    @staticmethod
    def _resolve(identity: str, prefixes: dict[str, list[dict[str, Any]]]) -> str | None:
        for prefix, rows in prefixes.items():
            if identity.startswith(prefix):
                want = _squash(identity[len(prefix):].rsplit(":", 1)[0])
                return next((u["id"] for u in rows if _squash(u.get("external_username") or "") == want), None)
        return None

    # -- what it should be --------------------------------------------------------------

    def _desired(self, project: Project, world: dict[str, Any]) -> dict[str, Any]:
        members = self.cfg.policy.members.get(project.name, {})
        rooms = sorted(project.rooms)
        resolved = {m: self._resolve(m, world["prefixes"]) for m in members}
        user_ids = sorted({v for v in resolved.values() if v})
        allow = [world["agents"][n]["id"] for n in self.cfg.allow_agents if n in world["agents"]]
        policies = {}
        for name in self.cfg.managed_agents:
            if name not in world["agents"]:
                continue
            desk_rules = []
            if name == DESK_AGENT:                      # a personal desk admits only its member and the owners
                owner_ids = sorted({resolved[m] for m, r in members.items() if r is Role.OWNER and resolved.get(m)})
                for ident, room in sorted(self.cfg.desks.get(project.name, {}).items()):
                    if resolved.get(ident):
                        desk_rules.append({"rooms": [room], "users": sorted({resolved[ident], *owner_ids}), "agents": [], "owner": False, "platform": False})
            policies[name] = {"rules": [
                {"rooms": rooms, "users": user_ids, "agents": [], "owner": False, "platform": False},
                *desk_rules,
                *([{"rooms": rooms, "users": [], "agents": allow, "owner": False, "platform": False}] if allow else []),
                {"rooms": "*", "users": [], "agents": [], "owner": True, "platform": False}]}
        return {"policies": policies, "resolved": resolved, "unresolved": sorted(m for m, v in resolved.items() if not v)}

    @staticmethod
    def _summary(policy: dict[str, Any] | None) -> tuple[set[str], set[str]]:
        """(user ids, room ids) a policy lets through, ignoring the owner and agent rules."""
        users: set[str] = set()
        rooms: set[str] = set()
        for rule in (policy or {}).get("rules", []):
            if rule.get("users"):
                users |= set(rule["users"])
                if isinstance(rule.get("rooms"), list):
                    rooms |= set(rule["rooms"])
        return users, rooms

    def rooms(self, project: Project) -> list[dict[str, Any]]:
        """The project's rooms as Switch sees them: which chat app, which group, which agents are in them."""
        gw = self.gateway()
        rows = {r["id"]: r for r in self._get(gw, "/rooms") if r.get("id") in project.rooms}
        agents = self._get(gw, "/agents")
        names = {a["id"]: a["name"] for a in (agents if isinstance(agents, list) else agents.get("agents", []))}
        out = []
        for rid in sorted(project.rooms):
            r = rows.get(rid)
            if r is None:
                out.append({"id": rid, "name": project.room_names.get(rid, rid[:8]), "kind": self._kind(project, rid), "missing": True})
                continue
            status, detail = gw.call("GET", f"/rooms/{rid}")
            ids = (detail or {}).get("agent_ids", []) if status == 200 and isinstance(detail, dict) else []
            url = r.get("external_channel_url")
            out.append({"id": rid, "name": r["name"], "kind": self._kind(project, rid), "bridge": r.get("bridge_display_name") or "",
                        "group": r.get("group_name") or "", "agents": sorted(names.get(i, "?") for i in ids), "users": r.get("connected_user_count", 0),
                        "alerts": rid in project.alert_rooms, "url": url if isinstance(url, str) and url.startswith("https://") else None, "missing": False})
        return out

    @staticmethod
    def _kind(project: Project, rid: str) -> str:
        return "incidents" if rid in project.incident_rooms else "maintainers" if rid in project.maintainer_rooms else "ops"

    # -- for the page ---------------------------------------------------------------------

    def _synced(self) -> dict[str, tuple[float, str]]:
        with self.lock:
            return {r[0]: (r[1], r[2]) for r in self.db.execute("SELECT agent, ts, actor FROM agent_sync")}

    def state(self, project: Project, display: Callable[[str], dict[str, Any]], room_label: Callable[[str], str]) -> dict[str, Any]:
        world = self._world(self.gateway())
        desired = self._desired(project, world)
        synced = self._synced()
        members = self.cfg.policy.members.get(project.name, {})
        out = []
        for name in self.cfg.managed_agents:
            agent = world["agents"].get(name)
            if agent is None:
                out.append({"name": name, "status": "missing", "may_address": [], "rooms": [], "last_synced": None})
                continue
            users, rooms = self._summary(agent.get("addressing_policy"))
            by_id = {v: k for k, v in desired["resolved"].items() if v}
            listed = []
            for uid in sorted(users):
                ident = by_id.get(uid)
                listed.append({**display(ident), "role": members[ident].name.lower()} if ident in members
                              else {"name": (world["users"].get(uid) or ("", uid))[1], "platform": "", "role": "no longer a member"})
            out.append({"name": name, "status": "registered" if agent.get("addressing_policy") else "open to everyone",
                        "may_address": listed, "rooms": [room_label(r) for r in sorted(rooms)],
                        "last_synced": (synced.get(name) or (None,))[0]})
        for n in self.cfg.allow_agents:
            if n in world["agents"]:
                out.append({"name": n, "status": "system", "may_address": None, "rooms": None, "last_synced": None})
        return {"agents": out, "unresolved": [display(m) for m in desired["unresolved"]]}

    def preview(self, project: Project, display: Callable[[str], dict[str, Any]], room_label: Callable[[str], str]) -> list[dict[str, str]]:
        world = self._world(self.gateway())
        desired = self._desired(project, world)
        by_new = {v: k for k, v in desired["resolved"].items() if v}
        changes: list[dict[str, str]] = []
        for name, policy in desired["policies"].items():
            cur_users, cur_rooms = self._summary(world["agents"][name].get("addressing_policy"))
            new_users, new_rooms = self._summary(policy)
            who = lambda uid: (display(by_new[uid])["name"] if uid in by_new else (world["users"].get(uid) or ("", uid))[1])  # noqa: E731
            for uid in sorted(new_users - cur_users):
                changes.append({"op": "+", "agent": name, "text": f"{who(uid)} may address it"})
            for uid in sorted(cur_users - new_users):
                changes.append({"op": "-", "agent": name, "text": f"{who(uid)} may no longer address it"})
            if cur_rooms != new_rooms:
                changes.append({"op": "~", "agent": name, "text": "rooms: " + (", ".join(room_label(r) for r in sorted(cur_rooms)) or "none") +
                                " → " + (", ".join(room_label(r) for r in sorted(new_rooms)) or "none")})
        for m in desired["unresolved"]:
            changes.append({"op": "!", "agent": "", "text": f"{display(m)['name']} has no Switch record yet (they have not posted in a bridged room), so they cannot be admitted"})
        return changes

    def apply(self, project: Project, actor: str) -> dict[str, Any]:
        gw = self.gateway()
        world = self._world(gw)
        desired = self._desired(project, world)
        done = []
        for name, policy in desired["policies"].items():
            status, body = gw.call("PUT", f"/agents/{world['agents'][name]['id']}/addressing-policy", {"policy": policy})
            if status not in (200, 204):
                self.audit.write(project=project.name, actor=actor, event="failed", action="agents.sync", target=name, error=f"Switch answered {status}")
                raise AccessError(f"Switch refused the policy for {name} ({status})")
            with self.lock:
                self.db.execute("INSERT OR REPLACE INTO agent_sync (agent, ts, actor) VALUES (?,?,?)", (name, self.now(), actor))
                self.db.commit()
            done.append(name)
        self.audit.write(project=project.name, actor=actor, event="executed", action="agents.sync", target=",".join(done),
                         members=len(self.cfg.policy.members.get(project.name, {})), unresolved=len(desired["unresolved"]))
        return {"agents": done, "unresolved": len(desired["unresolved"])}
