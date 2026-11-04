"""Who has which role: the YAML says where we start, an overlay file keeps what the owner changed in the dashboard.

The overlay replaces a project's member list as a whole, is written atomically with owner-only permissions, and is
applied to the live policy at once. Every change is audited. The last owner can never be removed or demoted.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .policy import Policy, Role

IDENTITY = re.compile(r"^@switch-[a-z]+-[0-9a-f-]{36}-[^:\s]{1,80}:[^:\s]{1,80}$")
ROLE_NAMES = ("viewer", "deployer", "maintainer", "owner")
MAX_MEMBERS = 200


class MemberError(ValueError):
    """A change that is refused; the message is safe to show."""


def parse_role(name: Any) -> Role:
    if not isinstance(name, str) or name.lower() not in ROLE_NAMES:
        raise MemberError(f"unknown role {name!r}")
    return Role[name.upper()]


class MemberStore:
    def __init__(self, path: str | Path, policy: Policy, audit: AuditLog):
        self.path, self.policy, self.audit = Path(path), policy, audit
        self.lock = threading.RLock()

    # -- reading ----------------------------------------------------------------

    def load(self) -> None:
        """Apply the overlay, if there is one, on top of the YAML members. A damaged file is ignored loudly."""
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            parsed = {project: {ident: parse_role(role) for ident, role in members.items()} for project, members in data.items()}
        except (ValueError, AttributeError, MemberError) as exc:
            raise SystemExit(f"{self.path} is damaged ({exc}); fix or remove it") from None
        for project, members in parsed.items():
            if project in self.policy.members and any(r is Role.OWNER for r in members.values()):
                self.policy.members[project] = members                 # type: ignore[index]

    def members(self, project: str) -> dict[str, Role]:
        return dict(self.policy.members.get(project, {}))

    # -- changing ---------------------------------------------------------------

    def apply(self, project: str, actor: str, changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Each change is {identity, role} (add or change) or {identity, role: null} (remove). All or nothing."""
        with self.lock:
            if project not in self.policy.members:
                raise MemberError("unknown project")
            if self.policy.members[project].get(actor) is not Role.OWNER:
                raise MemberError("only an owner can change roles")
            if not isinstance(changes, list) or not changes or len(changes) > 50:
                raise MemberError("send between 1 and 50 changes")
            old = self.members(project)
            new, done = dict(old), []
            for c in changes:
                if not isinstance(c, dict) or set(c) - {"identity", "role"}:
                    raise MemberError("a change is {identity, role}")
                ident = c.get("identity")
                if not isinstance(ident, str) or not IDENTITY.match(ident):
                    raise MemberError("that is not a chat identity: paste the id that `@gatekeeper whoami` prints")
                if c.get("role") is None:
                    if ident not in new:
                        raise MemberError("that person is not a member")
                    del new[ident]
                    done.append({"identity": ident, "from": old.get(ident), "to": None})
                else:
                    role = parse_role(c["role"])
                    if new.get(ident) is not role:
                        done.append({"identity": ident, "from": new.get(ident), "to": role})
                    new[ident] = role
            if not any(r is Role.OWNER for r in new.values()):
                raise MemberError("a project must keep at least one owner")
            if len(new) > MAX_MEMBERS:
                raise MemberError("too many members")
            done = [d for d in done if d["from"] is not d["to"]]
            if not done:
                return []
            self._write(project, new)
            self.policy.members[project] = new                          # type: ignore[index]
            for d in done:
                self.audit.write(project=project, actor=actor, event="role_changed", action="roles.edit", target=d["identity"],
                                 before=d["from"].name.lower() if d["from"] else None, after=d["to"].name.lower() if d["to"] else None)
            return [{"identity": d["identity"], "from": d["from"].name.lower() if d["from"] else None,
                     "to": d["to"].name.lower() if d["to"] else None} for d in done]

    def _write(self, project: str, members: dict[str, Role]) -> None:
        data: dict[str, dict[str, str]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
        data[project] = {i: r.name.lower() for i, r in sorted(members.items())}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".members.")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
