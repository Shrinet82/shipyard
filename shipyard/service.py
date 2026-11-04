"""The Gatekeeper's chat service: commands, approvals, agent proposals, audit.

Transport-free: the caller feeds it Switch message events and gives it a `post`
function, so it is tested with fakes and run for real by shipyard.__main__.
"""
from __future__ import annotations

import datetime as dt
import threading
import time
from typing import Any, Callable

from .commands import USAGE, Command, arity_ok, parse
from .config import Config, Project
from .coolify import CoolifyError
from .gatekeeper import Gatekeeper

ACTION_FOR_VERB = {
    "status": "coolify.status",
    "deploy": "coolify.deploy",
    "restart": "coolify.restart",
    "rollback": "coolify.rollback",
    "audit": "audit.read",
}
MESSAGE_TTL = 300.0       # a proposal must cite a message this recent
CACHE_LIMIT = 500


class Service:
    def __init__(self, cfg: Config, gk: Gatekeeper, coolify: Any, post: Callable[[str, str], None],
                 agent_name: str = "gatekeeper", now: Callable[[], float] = time.time):
        self.cfg, self.gk, self.coolify, self.post = cfg, gk, coolify, post
        self.agent_name = agent_name
        self.now = now
        self.names: dict[str, str] = {}
        self.recent: dict[str, dict[str, Any]] = {}
        self.lock = threading.RLock()

    # -- helpers --------------------------------------------------------------

    def _name(self, sender: str) -> str:
        return self.names.get(sender, sender)

    def _remember(self, room: str, p: dict[str, Any]) -> None:
        with self.lock:
            self.names[p.get("sender", "")] = p.get("sender_name") or p.get("sender", "")
            self.recent[p["message_id"]] = {"room": room, "sender": p.get("sender", ""), "body": p.get("body") or "",
                                            "ts": self.now(), "used": False, "kind": p.get("sender_kind")}
            if len(self.recent) > CACHE_LIMIT:
                for mid in sorted(self.recent, key=lambda m: self.recent[m]["ts"])[: len(self.recent) - CACHE_LIMIT]:
                    del self.recent[mid]

    def _is_member(self, project: Project, sender: str) -> bool:
        return sender in self.cfg.policy.members.get(project.name, {})

    def _deny(self, project: Project, actor: str, action: str, target: str, reason: str, **detail: Any) -> str:
        self.gk.audit.write(project=project.name, actor=actor, event="denied", action=action, target=target,
                            reason=reason, **detail)
        return f"Denied: {reason}."

    # -- chat entry point -----------------------------------------------------

    def handle_event(self, ev: dict[str, Any]) -> None:
        if ev.get("type") != "message":
            return
        room, p = ev["room_id"], ev["payload"]
        self._remember(room, p)
        if p.get("sender_name") == self.agent_name:
            return
        project = self.cfg.project_for_room(room)
        cmd = parse(p.get("body"), bool(p.get("addressed")))
        if project is None or cmd is None:
            return
        sender = p.get("sender", "")
        if p.get("sender_kind") is not None:      # the Switch app itself, never a person
            return
        try:
            reply = self._dispatch(project, room, sender, cmd)
        except Exception as exc:                  # fail closed: say so, change nothing
            self.gk.audit.write(project=project.name, actor=sender, event="error", action=cmd.verb, target="",
                                error=repr(exc)[:200])
            reply = "Something went wrong and nothing was changed."
        if reply:
            self.post(room, reply)

    def _dispatch(self, project: Project, room: str, sender: str, cmd: Command) -> str | None:
        if cmd.verb == "unknown":
            return "I did not understand that. Try `help`."
        if cmd.verb == "help":
            return "Commands: " + ", ".join(USAGE[v] for v in USAGE) + ". Mention me first, e.g. `@gatekeeper deploy demo-app`."
        if not arity_ok(cmd):
            return f"Usage: {USAGE[cmd.verb]}"
        if cmd.verb == "whoami":
            role = self.cfg.policy.members.get(project.name, {}).get(sender)
            return f"Your id is `{sender}`. Your role in {project.name}: {role.name.lower() if role else 'none'}."
        if cmd.verb in ("approve", "deny"):
            return self._approval_reply(project, room, sender, cmd)
        if cmd.verb == "audit":
            return self._audit(project, sender, cmd)
        if cmd.verb == "status":
            return self._status(project, room, sender, cmd)
        return self._change(project, room, sender, cmd)

    # -- read commands --------------------------------------------------------

    def _guard(self, project: Project, sender: str, action: str, target: str) -> str | None:
        """Common checks before touching an app. Returns a refusal message, or None."""
        if not self._is_member(project, sender):
            return self._deny(project, sender, action, target, "you are not a member of this project")
        if action != "audit.read" and target not in project.apps:
            return self._deny(project, sender, action, target, f"unknown app {target!r}")
        return None

    def _status(self, project: Project, room: str, sender: str, cmd: Command) -> str:
        targets = list(cmd.args) or sorted(project.apps)
        lines = []
        for target in targets:
            refusal = self._guard(project, sender, "coolify.status", target)
            if refusal:
                return refusal
            out = self.gk.request_action(project=project.name, identity=sender, is_human=True, action="coolify.status",
                                         target=target, room_id=room, name=self._name(sender))
            if out.status != "allowed":
                return f"Denied: {out.reason}."
            lines.append(self._run(project, sender, "coolify.status", target, {}))
        return "\n".join(lines)

    def _audit(self, project: Project, sender: str, cmd: Command) -> str:
        if not self._is_member(project, sender):
            return self._deny(project, sender, "audit.read", project.name, "you are not a member of this project")
        out = self.gk.request_action(project=project.name, identity=sender, is_human=True, action="audit.read",
                                     target=project.name)
        if out.status != "allowed":
            return f"Denied: {out.reason}."
        n = 10
        if cmd.args:
            try:
                n = max(1, min(25, int(cmd.args[0])))
            except ValueError:
                return f"Usage: {USAGE['audit']}"
        rows = self.gk.audit.recent(project.name, n)
        if not rows:
            return "The audit log is empty."
        lines = []
        for r in reversed(rows):
            when = dt.datetime.fromtimestamp(r["ts"], dt.timezone.utc).strftime("%H:%M:%S")
            who = r["detail"].get("name") or self._name(r["actor"])
            extra = r["detail"].get("reason") or r["detail"].get("result") or r["detail"].get("error") or ""
            lines.append(f"{when} {who} {r['event']} {r['action']} {r['target']}" + (f" ({extra})" if extra else ""))
        return "Audit log (UTC):\n" + "\n".join(lines)

    # -- change commands ------------------------------------------------------

    def _change(self, project: Project, room: str, sender: str, cmd: Command) -> str:
        action = ACTION_FOR_VERB[cmd.verb]
        target = cmd.args[0]
        args = {"tag": cmd.args[1]} if len(cmd.args) > 1 else {}
        refusal = self._guard(project, sender, action, target)
        if refusal:
            return refusal
        out = self.gk.request_action(project=project.name, identity=sender, is_human=True, action=action, target=target,
                                     args=args, room_id=room, name=self._name(sender))
        if out.status == "denied":
            return f"Denied: {out.reason}."
        if out.status == "awaiting_approval":
            return self._prompt(out.approval_id, action, target, args, self._name(sender))
        return self._run(project, sender, action, target, args)

    def _prompt(self, approval_id: str | None, action: str, target: str, args: dict, who: str, agent: str | None = None) -> str:
        minutes = self.cfg.policy.approval_timeout_seconds // 60
        verb = action.split(".", 1)[1]
        what = f"{verb} {target}" + (f" {args['tag']}" if args.get("tag") else "")
        by = f"{agent} proposes, for {who}" if agent else f"requested by {who}"
        return (f"Approval needed (id {approval_id}): {what}, {by}. An owner, or another maintainer, can reply "
                f"`@gatekeeper approve {approval_id}`. `@gatekeeper deny {approval_id}` cancels. It expires in {minutes} minutes.")

    def _approval_reply(self, project: Project, room: str, sender: str, cmd: Command) -> str:
        approval_id = cmd.args[0].lower()
        if cmd.verb == "deny":
            out = self.gk.deny_by_id(approval_id=approval_id, project=project.name, actor=sender, actor_is_human=True)
            return f"Request {approval_id} cancelled." if out.status == "approved" else f"Denied: {out.reason}."
        out = self.gk.approve_by_id(approval_id=approval_id, project=project.name, approver=sender, approver_is_human=True)
        if out.status == "expired":
            return f"Request {approval_id} expired. Ask again."
        if out.status != "approved":
            return f"Denied: {out.reason}."
        r = out.request or {}
        return self._run(project, r["requester"], r["action"], r["target"], r["args"], approved_by=sender)

    # -- execution ------------------------------------------------------------

    def _run(self, project: Project, actor: str, action: str, target: str, args: dict[str, Any],
             approved_by: str | None = None) -> str:
        uuid = project.apps[target]
        try:
            if action == "coolify.status":
                result = self.coolify.status(uuid)
            elif action == "coolify.deploy":
                result = self.coolify.deploy(uuid)
            elif action == "coolify.restart":
                result = self.coolify.restart(uuid)
            elif action == "coolify.rollback":
                result = self.coolify.rollback(uuid, args.get("tag"))
            else:
                raise CoolifyError(f"no adapter for {action}")
        except CoolifyError as exc:
            self.gk.audit.write(project=project.name, actor=actor, event="failed", action=action, target=target,
                                error=str(exc), name=self._name(actor), approved_by=approved_by)
            return f"Failed: {action.split('.', 1)[1]} {target}: {exc}. Nothing was changed."
        self.gk.audit.write(project=project.name, actor=actor, event="executed", action=action, target=target,
                            result=result[:120], name=self._name(actor), approved_by=approved_by)
        if action == "coolify.status":
            return result
        by = f", approved by {self._name(approved_by)}" if approved_by else ""
        return f"Done: {action.split('.', 1)[1]} {target} for {self._name(actor)}{by}. {result}."

    # -- agent proposals (MCP tool request_action) ----------------------------

    def propose(self, *, action: str, target: str, args: dict[str, Any] | None, message_id: str,
                agent: str = "agent") -> dict[str, Any]:
        """An agent asks to act for the person who sent `message_id`. Anything beyond a
        read waits for a fresh human approval in chat."""
        args = dict(args or {})
        who = f"agent:{agent}"
        if not action.startswith("coolify."):
            return {"status": "denied", "reason": "unsupported action"}
        with self.lock:
            m = self.recent.get(message_id)
            reason = None
            if m is None:
                reason = "unknown message"
            elif self.now() - m["ts"] > MESSAGE_TTL:
                reason = "the cited message is too old"
            elif m["used"]:
                reason = "the cited message was already used"
            elif m["kind"] is not None:
                reason = "the cited message was not written by a person"
            project = self.cfg.project_for_room(m["room"]) if m else None
            if reason is None and project is None:
                reason = "the cited message is not in a Shipyard room"
            if reason is None and target.lower() not in m["body"].lower():
                reason = "the cited message does not mention the target"
            if reason is None and not self._is_member(project, m["sender"]):
                reason = "the person who wrote the message is not a project member"
            if reason is not None:
                if project is not None:
                    self.gk.audit.write(project=project.name, actor=who, event="denied", action=action, target=target,
                                        reason=reason, message_id=message_id)
                return {"status": "denied", "reason": reason}
            m["used"] = True
            requester, room = m["sender"], m["room"]
        if target not in project.apps and action != "audit.read":
            return {"status": "denied", "reason": f"unknown app {target!r}"}
        name = self._name(requester)
        out = self.gk.request_action(project=project.name, identity=requester, is_human=True, action=action,
                                     target=target, args=args, room_id=room, kind="agent_proposal",
                                     force_approval=True, via=agent, message_id=message_id, name=name)
        if out.status == "denied":
            self.post(room, f"Denied: {out.reason} ({agent} asked to {action.split('.')[-1]} {target} for {name}).")
            return {"status": "denied", "reason": out.reason}
        if out.status == "awaiting_approval":
            self.post(room, self._prompt(out.approval_id, action, target, args, name, agent=agent))
            return {"status": "awaiting_human_approval", "approval_id": out.approval_id,
                    "message": "A person must approve this in chat. Tell them the id; do not retry."}
        result = self._run(project, requester, action, target, args)
        return {"status": "done", "result": result}

    # -- housekeeping ---------------------------------------------------------

    def sweep(self) -> None:
        for r in self.gk.sweep_expired():
            if r["room_id"]:
                self.post(r["room_id"], f"Request {r['id']} ({r['action'].split('.', 1)[1]} {r['target']}) expired "
                                        f"without approval. Nothing was changed.")
