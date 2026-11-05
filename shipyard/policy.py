"""Policy engine: who may do what. Pure functions, no I/O, fails closed."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Mapping


class Role(IntEnum):
    VIEWER = 1
    DEPLOYER = 2
    MAINTAINER = 3
    OWNER = 4


class Tier(str, Enum):
    READ = "read"
    CHANGE = "change"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


TIER_MIN_ROLE = {
    Tier.READ: Role.VIEWER,
    Tier.CHANGE: Role.DEPLOYER,
    Tier.DANGEROUS: Role.MAINTAINER,
}

# Targets are resource names (app, deployment, PR number); never free text.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

# Commands nobody may run, even with approval. Matched against the whole string.
_BLOCKED_COMMANDS = [
    re.compile(r"\brm\s+(-\w*\s+)*-\w*[rf]\w*\s+(--no-preserve-root\s+)?/(\s|$|\*)"),
    re.compile(r"\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b"),
    re.compile(r"\bgit\s+push\b.*(--force\b|-f\b|--force-with-lease\b).*\b(main|master)\b"),
    re.compile(r"\bmkfs(\.\w+)?\b|\bdd\s+.*\bof=/dev/"),
    re.compile(r"\b(cat|echo|printenv|env)\b.*(\.env|id_rsa|kubeconfig|token|secret)", re.I),
]


@dataclass(frozen=True)
class Policy:
    members: Mapping[str, Mapping[str, Role]]  # project -> identity -> role
    actions: Mapping[str, Tier]
    approval_overrides: frozenset[str] = frozenset()
    min_role: Mapping[str, Role] = field(default_factory=dict)
    approval_timeout_seconds: int = 600


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    tier: Tier | None = None
    role: Role | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


def _deny(reason: str, tier: Tier | None = None, role: Role | None = None) -> Decision:
    return Decision(Verdict.DENY, reason, tier, role)


def command_is_blocked(command: str) -> bool:
    return any(p.search(command) for p in _BLOCKED_COMMANDS)


def evaluate(
    policy: Policy,
    *,
    project: str,
    identity: str,
    is_human: bool,
    action: str,
    target: str,
    args: Mapping[str, Any] | None = None,
) -> Decision:
    """Decide a request. `identity` must come from the chat platform's verified
    sender id, never from message text or from an agent's claim."""
    args = args or {}

    tier = policy.actions.get(action)
    if tier is None:
        return _deny(f"unknown action {action!r}")
    if tier is Tier.BLOCKED:
        return _deny(f"{action} is blocked for everyone", tier)

    if not is_human:
        return _deny("requests must come from a human sender", tier)

    roles = policy.members.get(project)
    if roles is None:
        return _deny(f"unknown project {project!r}", tier)
    role = roles.get(identity)
    if role is None:
        return _deny("not a member of this project", tier)

    if not _TARGET_RE.match(target or ""):
        return _deny("invalid target name", tier, role)
    for key in ("command",):
        cmd = args.get(key)
        if cmd is not None:
            if not isinstance(cmd, str):
                return _deny("command must be a string", tier, role)
            if command_is_blocked(cmd):
                return _deny("command matches a blocked pattern", tier, role)
    for key, value in args.items():
        if key != "command" and isinstance(value, str) and not _TARGET_RE.match(value):
            return _deny(f"invalid value for argument {key!r}", tier, role)

    needed = policy.min_role.get(action, TIER_MIN_ROLE[tier])
    if role < needed:
        return _deny(f"{action} needs role {needed.name.lower()} or above", tier, role)

    if tier is Tier.DANGEROUS or action in policy.approval_overrides:
        return Decision(Verdict.NEEDS_APPROVAL, "approval required", tier, role)
    return Decision(Verdict.ALLOW, "allowed", tier, role)


def may_approve(
    policy: Policy,
    *,
    project: str,
    requester: str,
    approver: str,
    approver_is_human: bool,
    allow_requester: bool = False,
    second_person: bool = False,
) -> bool:
    """The owner may approve anything (including their own request); a maintainer
    may approve someone else's request. `allow_requester` lets the person an agent
    acted for confirm it themselves (their role was already checked at request time).
    `second_person` is for actions that always need someone other than the requester, owner or not."""
    if not approver_is_human:
        return False
    if second_person and approver == requester:
        return False
    if allow_requester and approver == requester:
        return True
    role = policy.members.get(project, {}).get(approver)
    if role is Role.OWNER:
        return True
    return role is Role.MAINTAINER and approver != requester
