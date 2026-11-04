"""Gatekeeper core: policy + approvals + audit. Transport-agnostic.

The Switch agent-protocol adapter and the backend adapters (Coolify, GitHub,
Kubernetes) plug in around this; nothing here talks to the network.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .audit import AuditLog
from .policy import Decision, Policy, Verdict, evaluate, may_approve

APPROVALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    requester TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    expires REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
);
"""


@dataclass(frozen=True)
class Outcome:
    status: str  # allowed | denied | awaiting_approval | approved | expired
    reason: str
    approval_id: str | None = None


def args_hash(action: str, target: str, args: Mapping[str, Any]) -> str:
    blob = json.dumps([action, target, args], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class Gatekeeper:
    def __init__(self, policy: Policy, db: sqlite3.Connection, now: Callable[[], float] = time.time):
        self.policy = policy
        self.db = db
        self.now = now
        self.db.executescript(APPROVALS_SCHEMA)
        self.audit = AuditLog(db, now)

    def request_action(
        self, *, project: str, identity: str, is_human: bool, action: str, target: str, args: Mapping[str, Any] | None = None
    ) -> Outcome:
        args = dict(args or {})
        d: Decision = evaluate(
            self.policy, project=project, identity=identity, is_human=is_human, action=action, target=target, args=args
        )
        if d.verdict is Verdict.DENY:
            self.audit.write(project=project, actor=identity, event="denied", action=action, target=target, reason=d.reason)
            return Outcome("denied", d.reason)
        if d.verdict is Verdict.ALLOW:
            self.audit.write(project=project, actor=identity, event="allowed", action=action, target=target)
            return Outcome("allowed", d.reason)

        approval_id = secrets.token_hex(4)
        self.db.execute(
            "INSERT INTO approvals (id, project, requester, action, target, args_hash, expires) VALUES (?,?,?,?,?,?,?)",
            (approval_id, project, identity, action, target, args_hash(action, target, args),
             self.now() + self.policy.approval_timeout_seconds),
        )
        self.db.commit()
        self.audit.write(project=project, actor=identity, event="approval_requested", action=action, target=target,
                         approval_id=approval_id)
        return Outcome("awaiting_approval", "approval required", approval_id)

    def approve(
        self, *, approval_id: str, project: str, approver: str, approver_is_human: bool,
        action: str, target: str, args: Mapping[str, Any] | None = None,
    ) -> Outcome:
        """Approve exactly one pending request. The caller re-supplies the action,
        target and args it is about to execute; they must match what was requested."""
        row = self.db.execute(
            "SELECT project, requester, action, target, args_hash, expires, state FROM approvals WHERE id=?",
            (approval_id,),
        ).fetchone()
        if row is None or row[0] != project or row[6] != "pending":
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=action, target=target,
                             approval_id=approval_id, reason="unknown or already used")
            return Outcome("denied", "unknown or already used approval")
        _, requester, r_action, r_target, r_hash, expires, _ = row
        if self.now() > expires:
            self.db.execute("UPDATE approvals SET state='expired' WHERE id=?", (approval_id,))
            self.db.commit()
            self.audit.write(project=project, actor=approver, event="approval_expired", action=r_action, target=r_target,
                             approval_id=approval_id)
            return Outcome("expired", "approval expired")
        if (action, target, args_hash(action, target, dict(args or {}))) != (r_action, r_target, r_hash):
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=action, target=target,
                             approval_id=approval_id, reason="does not match the original request")
            return Outcome("denied", "approval does not match the original request")
        if not may_approve(self.policy, project=project, requester=requester, approver=approver,
                           approver_is_human=approver_is_human):
            self.audit.write(project=project, actor=approver, event="approval_rejected", action=r_action, target=r_target,
                             approval_id=approval_id, reason="approver not authorized")
            return Outcome("denied", "approver not authorized")

        # Single use: only the first writer flips pending -> approved.
        cur = self.db.execute("UPDATE approvals SET state='approved' WHERE id=? AND state='pending'", (approval_id,))
        self.db.commit()
        if cur.rowcount != 1:
            return Outcome("denied", "unknown or already used approval")
        self.audit.write(project=project, actor=approver, event="approved", action=r_action, target=r_target,
                         approval_id=approval_id, requester=requester)
        return Outcome("approved", "approved", approval_id)
