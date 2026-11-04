"""Load shipyard.yaml into a Policy. Any malformed entry raises: never guess."""
from __future__ import annotations

from pathlib import Path

import yaml

from .policy import Policy, Role, Tier


def _role(name: str) -> Role:
    try:
        return Role[str(name).upper()]
    except KeyError:
        raise ValueError(f"unknown role {name!r}") from None


def load_policy(path: str | Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text())
    members = {
        project: {identity: _role(role) for identity, role in (spec.get("members") or {}).items()}
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
