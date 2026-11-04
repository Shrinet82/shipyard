"""Load shipyard.yaml. Any malformed entry raises: never guess."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy import Policy, Role, Tier


@dataclass(frozen=True)
class Project:
    name: str
    rooms: frozenset[str]          # Switch room ids where this project's commands are accepted
    apps: dict[str, str]           # app name -> Coolify application uuid


@dataclass(frozen=True)
class Config:
    policy: Policy
    projects: dict[str, Project]
    switch_url: str = "http://localhost:8000"
    agent_credentials_file: str = "~/gatekeeper.json"
    coolify_url: str = ""
    coolify_token_file: str = "~/coolify.env"
    mcp_port: int = 8765
    mcp_token_file: str = "~/gatekeeper-mcp.token"
    db_path: str = "~/shipyard.db"
    known_agents: frozenset[str] = frozenset({"ops-agent", "repo-agent"})
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    def project_for_room(self, room_id: str) -> Project | None:
        return next((p for p in self.projects.values() if room_id in p.rooms), None)


def _role(name: str) -> Role:
    try:
        return Role[str(name).upper()]
    except KeyError:
        raise ValueError(f"unknown role {name!r}") from None


def _policy(raw: dict[str, Any]) -> Policy:
    members = {
        project: {str(identity): _role(role) for identity, role in (spec.get("members") or {}).items()}
        for project, spec in (raw.get("projects") or {}).items()
    }
    actions = {name: Tier(tier) for name, tier in (raw.get("actions") or {}).items()}
    min_role = {name: _role(role) for name, role in (raw.get("min_role") or {}).items()}
    overrides = frozenset(name for name, on in (raw.get("approval_overrides") or {}).items() if on)
    unknown = (set(overrides) | set(min_role)) - set(actions)
    if unknown:
        raise ValueError(f"overrides for undeclared actions: {sorted(unknown)}")
    return Policy(
        members=members,
        actions=actions,
        approval_overrides=overrides,
        min_role=min_role,
        approval_timeout_seconds=int(raw.get("approval_timeout_seconds", 600)),
    )


def load_policy(path: str | Path) -> Policy:
    return _policy(yaml.safe_load(Path(path).read_text()))


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text())
    projects = {}
    for name, spec in (raw.get("projects") or {}).items():
        apps = {str(k): str(v) for k, v in (spec.get("apps") or {}).items()}
        projects[name] = Project(name, frozenset(str(r) for r in (spec.get("rooms") or [])), apps)
    rooms = [r for p in projects.values() for r in p.rooms]
    if len(rooms) != len(set(rooms)):
        raise ValueError("a room may belong to only one project")
    switch, coolify, gk = raw.get("switch") or {}, raw.get("coolify") or {}, raw.get("gatekeeper") or {}
    return Config(
        policy=_policy(raw),
        projects=projects,
        switch_url=switch.get("url", "http://localhost:8000"),
        agent_credentials_file=switch.get("credentials_file", "~/gatekeeper.json"),
        coolify_url=coolify.get("url", ""),
        coolify_token_file=coolify.get("token_file", "~/coolify.env"),
        mcp_port=int(gk.get("mcp_port", 8765)),
        mcp_token_file=gk.get("mcp_token_file", "~/gatekeeper-mcp.token"),
        db_path=gk.get("db_path", "~/shipyard.db"),
        known_agents=frozenset(gk.get("known_agents", ["ops-agent", "repo-agent"])),
        raw=raw,
    )


def expand(path: str) -> str:
    return os.path.expanduser(path)
