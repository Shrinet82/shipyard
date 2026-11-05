"""Gatekeeper core: policy + approvals + audit. Transport-agnostic.

The Switch client, the Coolify adapter and the chat service plug in around this;
nothing here talks to the network.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .audit import AuditLog
from .policy import Decision, Policy, Role, Tier, Verdict, evaluate, may_approve

SECOND_PERSON = frozenset({"ticket.delete"})              # always approved by someone other than the person who asked

APPROVALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    requester TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    args_json TEXT NOT NULL DEFAULT '{}',
    room_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'command',
    expires REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
);
"""


SEEN_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_events (key TEXT PRIMARY KEY, ts REAL NOT NULL);
"""


@dataclass(frozen=True)
class Outcome:
    status: str  # allowed | denied | awaiting_approval | approved | expired
    reason: str
    approval_id: str | None = None
    request: dict[str, Any] | None = None  # the stored request, on approve


def args_hash(action: str, target: str, args: Mapping[str, Any]) -> str:
    blob = json.dumps([action, target, args], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class Gatekeeper:
    def __init__(self, policy: Policy, db: sqlite3.Connection, now: Callable[[], float] = time.time):
        self.policy = policy
        self.db = db
        self.now = now
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(APPROVALS_SCHEMA + SEEN_SCHEMA)
        self.audit = AuditLog(db, now)

    def first_time(self, key: str) -> bool:
        """True the first time `key` is seen (and remembers it); False for a replay."""
        with self.lock:
            cur = self.db.execute("INSERT OR IGNORE INTO seen_events (key, ts) VALUES (?, ?)", (key, self.now()))
            self.db.commit()
            return cur.rowcount == 1

    # -- requests -------------------------------------------------------------

    def request_action(
        self,
        *,
        project: str,
        identity: str,
        is_human: bool,
        action: str,
        target: str,
        args: Mapping[str, Any] | None = None,
        room_id: str = "",
        kind: str = "command",
        force_approval: bool = False,
        **detail: Any,
    ) -> Outcome:
        """Decide a request. `kind="agent_proposal"` with `force_approval` makes every
        non-read action wait for a human, whatever the role allows."""
        args = dict(args or {})
        d: Decision = evaluate(
            self.policy, project=project, identity=identity, is_human=is_human, action=action, target=target, args=args
        )
        if d.verdict is Verdict.DENY:
            self.audit.write(project=project, actor=identity, event="denied", action=action, target=target,
                             reason=d.reason, kind=kind, **detail)
            return Outcome("denied", d.reason)
        if d.verdict is Verdict.ALLOW and not (force_approval and d.tier is not Tier.READ):
            self.audit.write(project=project, actor=identity, event="allowed", action=action, target=target,
                             kind=kind, **detail)
            return Outcome("allowed", d.reason)

        approval_id = secrets.token_hex(4)
        with self.lock:
            self.db.execute(
                "INSERT INTO approvals (id, project, requester, action, target, args_hash, args_json, room_id, kind, expires)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (approval_id, project, identity, action, target, args_hash(action, target, args),
                 json.dumps(args, sort_keys=True), room_id, kind, self.now() + self.policy.approval_timeout_seconds),
            )
            self.db.commit()
        self.audit.write(project=project, actor=identity, event="approval_requested", action=action, target=target,
                         approval_id=approval_id, kind=kind, **detail)
        return Outcome("awaiting_approval", "approval required", approval_id)

    def _load(self, approval_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.db.execute(
                "SELECT project, requester, action, target, args_hash, args_json, room_id, kind, expires, state"
                " FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if row is None:
            return None
        keys = ("project", "requester", "action", "target", "args_hash", "args_json", "room_id", "kind", "expires", "state")
        r = dict(zip(keys, row))
        r["args"] = json.loads(r["args_json"])
        return r

    def pending_list(self, project: str) -> list[dict[str, Any]]:
        """Open requests of a project, oldest first (the dashboard's approvals page; it can only look)."""
        with self.lock:
            ids = [r[0] for r in self.db.execute(
                "SELECT id FROM approvals WHERE project=? AND state='pending' AND expires>=? ORDER BY expires", (project, self.now()))]
        return [{"id": i, **r} for i in ids if (r := self._load(i))]

    def pending(self, approval_id: str) -> dict[str, Any] | None:
        r = self._load(approval_id)
        return r if r and r["state"] == "pending" else None

    # -- approvals ------------------------------------------------------------

    def approve(
        self, *, approval_id: str, project: str, approver: str, approver_is_human: bool,
        action: str, target: str, args: Mapping[str, Any] | None = None,
    ) -> Outcome:
        """Approve exactly one pending request. The caller re-supplies the action,
        target and args it is about to execute; they must match what was requested."""
        r = self._load(approval_id)
        if r is None or r["project"] != project or r["state"] != "pending":
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=action, target=target,
                             approval_id=approval_id, reason="unknown or already used")
            return Outcome("denied", "unknown or already used approval")
        if self.now() > r["expires"]:
            self._set_state(approval_id, "expired")
            self.audit.write(project=project, actor=approver, event="approval_expired", action=r["action"],
                             target=r["target"], approval_id=approval_id)
            return Outcome("expired", "approval expired")
        if (action, target, args_hash(action, target, dict(args or {}))) != (r["action"], r["target"], r["args_hash"]):
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=action, target=target,
                             approval_id=approval_id, reason="does not match the original request")
            return Outcome("denied", "approval does not match the original request")
        if not may_approve(self.policy, project=project, requester=r["requester"], approver=approver,
                           approver_is_human=approver_is_human, allow_requester=r["kind"] == "agent_proposal" and r["action"] not in SECOND_PERSON,
                           second_person=r["action"] in SECOND_PERSON):
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=r["action"],
                             target=r["target"], approval_id=approval_id, reason="approver not authorized")
            return Outcome("denied", "approver not authorized")
        if r["args"].get("gate") and self.policy.members.get(project, {}).get(approver) is not Role.OWNER:
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=r["action"],
                             target=r["target"], approval_id=approval_id, reason="only an owner can override a security block")
            return Outcome("denied", "only an owner can override a security block")

        # Single use: only the first writer flips pending -> approved.
        with self.lock:
            cur = self.db.execute("UPDATE approvals SET state='approved' WHERE id=? AND state='pending'", (approval_id,))
            self.db.commit()
        if cur.rowcount != 1:
            return Outcome("denied", "unknown or already used approval")
        self.audit.write(project=project, actor=approver, event="approved", action=r["action"], target=r["target"],
                         approval_id=approval_id, requester=r["requester"])
        return Outcome("approved", "approved", approval_id, r)

    def approve_by_id(self, *, approval_id: str, project: str, approver: str, approver_is_human: bool) -> Outcome:
        """Approve using the stored request, as the chat flow does."""
        r = self._load(approval_id)
        if r is None or r["project"] != project:
            return self.approve(approval_id=approval_id, project=project, approver=approver,
                                approver_is_human=approver_is_human, action="?", target="?")
        return self.approve(approval_id=approval_id, project=project, approver=approver,
                            approver_is_human=approver_is_human, action=r["action"], target=r["target"], args=r["args"])

    def deny_by_id(self, *, approval_id: str, project: str, actor: str, actor_is_human: bool) -> Outcome:
        """Cancel a pending request: the requester, or anyone who could approve it."""
        r = self._load(approval_id)
        if r is None or r["project"] != project or r["state"] != "pending":
            return Outcome("denied", "unknown or already used approval")
        if not may_approve(self.policy, project=project, requester=r["requester"], approver=actor,
                           approver_is_human=actor_is_human, allow_requester=True):
            self.audit.write(project=project, actor=actor, event="approval_rejected", action=r["action"],
                             target=r["target"], approval_id=approval_id, reason="not allowed to cancel")
            return Outcome("denied", "not allowed to cancel this request")
        self._set_state(approval_id, "denied")
        self.audit.write(project=project, actor=actor, event="approval_denied", action=r["action"], target=r["target"],
                         approval_id=approval_id)
        return Outcome("approved", "cancelled", approval_id, r)

    def _set_state(self, approval_id: str, state: str) -> None:
        with self.lock:
            self.db.execute("UPDATE approvals SET state=? WHERE id=?", (state, approval_id))
            self.db.commit()

    def sweep_expired(self) -> list[dict[str, Any]]:
        """Mark overdue pending approvals expired; return them so the caller can say so."""
        with self.lock:
            ids = [row[0] for row in self.db.execute(
                "SELECT id FROM approvals WHERE state='pending' AND expires < ?", (self.now(),))]
        expired = []
        for approval_id in ids:
            r = self._load(approval_id)
            self._set_state(approval_id, "expired")
            self.audit.write(project=r["project"], actor="gatekeeper", event="approval_expired", action=r["action"],
                             target=r["target"], approval_id=approval_id)
            expired.append({"id": approval_id, **r})
        return expired
