"""Shipyard Board: a small ticket tracker inside the Gatekeeper.

Tickets live in the Gatekeeper's SQLite database. People are the same chat identity strings the roles use. Every rule (who may do what,
which status can follow which, limits on every field) is enforced here, never by an agent, and every change is an audit row in the same
hash chain as everything else. Text in titles, bodies, comments and GitHub is data: nothing here ever passes it on as an instruction.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
import time
from typing import Any, Callable, Iterable

from .gatekeeper import Gatekeeper
from .policy import Role

SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, number INTEGER NOT NULL, key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'todo', priority TEXT NOT NULL DEFAULT 'medium',
    labels TEXT NOT NULL DEFAULT '[]', assignee TEXT, reporter TEXT NOT NULL, due_on TEXT, source TEXT NOT NULL DEFAULT 'chat',
    source_ref TEXT, room TEXT NOT NULL DEFAULT '', thread_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT,
    deleted_at TEXT, UNIQUE (project, number)
);
CREATE INDEX IF NOT EXISTS tickets_status ON tickets (project, status);
CREATE INDEX IF NOT EXISTS tickets_assignee ON tickets (project, assignee, status);
CREATE UNIQUE INDEX IF NOT EXISTS tickets_source_ref ON tickets (project, source, source_ref) WHERE source_ref IS NOT NULL AND closed_at IS NULL;
CREATE TABLE IF NOT EXISTS ticket_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, url TEXT, meta TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL, created_by TEXT NOT NULL, UNIQUE (ticket_id, kind, ref)
);
CREATE INDEX IF NOT EXISTS ticket_links_ref ON ticket_links (kind, ref);
CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, actor TEXT NOT NULL, type TEXT NOT NULL,
    from_value TEXT, to_value TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ticket_events_ticket ON ticket_events (ticket_id, id);
CREATE TABLE IF NOT EXISTS briefing_state (member TEXT NOT NULL, project TEXT NOT NULL, last_at TEXT NOT NULL, PRIMARY KEY (member, project));
CREATE TABLE IF NOT EXISTS ticket_notified (ticket_id INTEGER NOT NULL, kind TEXT NOT NULL, on_date TEXT NOT NULL, PRIMARY KEY (ticket_id, kind, on_date));
CREATE TABLE IF NOT EXISTS ticket_auto_log (project TEXT NOT NULL, ts REAL NOT NULL);
"""

STATUSES = ("todo", "doing", "review", "done", "cancelled")
PRIORITIES = ("low", "medium", "high", "urgent")
PRIORITY_RANK = {p: i for i, p in enumerate(reversed(PRIORITIES))}          # urgent = 0 sorts first
SOURCES = ("chat", "dashboard", "alert", "incident", "deploy_failed", "sbom_gate")
LINK_KINDS = ("pr", "commit", "deploy", "incident", "sbom_report", "alert", "ticket")
EVENT_TYPES = ("created", "assigned", "unassigned", "status_changed", "priority_changed", "labels_changed", "due_changed", "commented",
               "linked", "edited", "closed", "reopened")
TRANSITIONS = {
    "todo": ("doing", "cancelled"),
    "doing": ("review", "todo"),
    "review": ("done", "doing"),
    "done": ("todo",),
    "cancelled": ("todo",),
}
AUDIT_EVENT = {"created": "ticket_created", "assigned": "ticket_assigned", "unassigned": "ticket_assigned", "status_changed": "ticket_moved",
               "priority_changed": "ticket_edited", "labels_changed": "ticket_edited", "due_changed": "ticket_edited", "edited": "ticket_edited",
               "commented": "ticket_commented", "linked": "ticket_linked", "closed": "ticket_closed", "reopened": "ticket_reopened"}
TITLE_MAX, BODY_MAX, COMMENT_MAX, LABELS_MAX, LABEL_MAX = 120, 4000, 2000, 8, 24
LABEL = re.compile(r"^[a-z0-9-]{1,24}$")
KEY = re.compile(r"^[A-Z]{2,6}-\d{1,6}$")
REFERENCE = re.compile(r"\b(?i:fixes|closes|refs)\s+([A-Z]{2,6}-\d{1,6})\b")
CLOSING = re.compile(r"\b(?i:fixes|closes)\s+([A-Z]{2,6}-\d{1,6})\b")
MENTION = re.compile(r"@([A-Za-z0-9][A-Za-z0-9._-]{0,38})")
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
AUTO_PER_HOUR = 10


class TicketError(Exception):
    """A refused ticket action. `code` is one of the Board's error codes; `message` is plain words for chat."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def _now_iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_ist(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, IST).date().isoformat()


def keys_in(text: str) -> list[tuple[str, bool]]:
    """(ticket key, closes?) for each `Fixes|Closes|Refs KEY` in some text. The text is data; this fixed pattern is all that reads it."""
    seen: dict[str, bool] = {}
    for m in REFERENCE.finditer(text or ""):
        key = m.group(1)
        seen[key] = seen.get(key, False) or bool(CLOSING.search(m.group(0)))
    return list(seen.items())


class Tickets:
    def __init__(self, gk: Gatekeeper, projects: dict[str, Any], members: Callable[[str], dict[str, Role]], names: Callable[[str], str],
                 now: Callable[[], float] = time.time, post: Callable[[str, str], None] | None = None):
        """`projects` maps a project name to its config (ticket_prefix, rooms); `members` gives a project's identity -> role live (roles can change)."""
        self.gk, self.projects, self.members, self.names, self.now, self.post = gk, projects, members, names, now, post
        with gk.lock:
            gk.db.executescript(SCHEMA)

    # -- who ---------------------------------------------------------------------------------

    def _role(self, project: str, identity: str) -> Role | None:
        return self.members(project).get(identity)

    def resolve_person(self, project: str, who: str) -> str:
        """An identity from an identity or a name ("@anya", "anya.dev"). Only people who hold a role in the project count."""
        roles = self.members(project)
        text = (who or "").strip()
        if text in roles:
            return text
        want = text.lstrip("@").lower()
        hits = [i for i in roles if want and (self.names(i) or "").lower() == want]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise TicketError("invalid", f"more than one person is called {text!r}; use their full chat id")
        raise TicketError("unknown_member", f"{text.lstrip('@') or 'that person'} isn't a member of {project}. Add them on the Roles page.")

    # -- low level ---------------------------------------------------------------------------------

    def _ticket(self, project: str, key: str) -> dict[str, Any] | None:
        with self.gk.lock:
            cur = self.gk.db.execute("SELECT * FROM tickets WHERE key=? AND project=? AND deleted_at IS NULL", (key, project))
            row = cur.fetchone()
            cols = [c[0] for c in cur.description]
        return dict(zip(cols, row)) if row else None

    def _need(self, project: str, key: str) -> dict[str, Any]:
        if not isinstance(key, str) or not KEY.match(key):
            raise TicketError("invalid", "a ticket key looks like SY-12")
        t = self._ticket(project, key)
        if t is None:
            raise TicketError("not_found", f"I can't find {key} in {project}.")
        return t

    def _view(self, t: dict[str, Any]) -> dict[str, Any]:
        out = {k: t[k] for k in ("key", "title", "body", "status", "priority", "assignee", "reporter", "due_on", "source", "source_ref", "room",
                                 "thread_id", "created_at", "updated_at", "closed_at", "project", "number")}
        out["labels"] = json.loads(t["labels"])
        out["automatic"] = str(t["reporter"]).startswith("system:")
        out["assignee_name"] = self.names(t["assignee"]) if t["assignee"] else None
        out["reporter_name"] = self.names(t["reporter"]) if not out["automatic"] else t["reporter"]
        out["overdue"] = bool(t["due_on"] and t["due_on"] < today_ist(self.now()) and t["status"] not in ("done", "cancelled"))
        return out

    def _event(self, t: dict[str, Any], actor: str, etype: str, frm: Any = None, to: Any = None, **audit: Any) -> None:
        assert etype in EVENT_TYPES
        ts = _now_iso(self.now())
        with self.gk.lock:
            self.gk.db.execute("INSERT INTO ticket_events (ticket_id, actor, type, from_value, to_value, created_at) VALUES (?,?,?,?,?,?)",
                               (t["id"], actor, etype, None if frm is None else str(frm), None if to is None else str(to), ts))
            self.gk.db.execute("UPDATE tickets SET updated_at=? WHERE id=?", (ts, t["id"]))
            self.gk.db.commit()
        event = "ticket_auto_created" if etype == "created" and actor.startswith("system:") else AUDIT_EVENT[etype]
        self.gk.audit.write(project=t["project"], actor=actor, event=event, action=f"ticket.{etype}", target=t["key"],
                            frm=None if frm is None else str(frm)[:120], to=None if to is None else str(to)[:120], **audit)

    # -- validation -------------------------------------------------------------------------------

    @staticmethod
    def _title(v: Any) -> str:
        if not isinstance(v, str) or not 1 <= len(v.strip()) <= TITLE_MAX:
            raise TicketError("invalid", f"title must be 1 to {TITLE_MAX} characters")
        return v.strip()

    @staticmethod
    def _body(v: Any) -> str:
        if v is None:
            return ""
        if not isinstance(v, str) or len(v) > BODY_MAX:
            raise TicketError("invalid", f"body must be at most {BODY_MAX} characters")
        return v

    @staticmethod
    def _priority(v: Any) -> str:
        if v not in PRIORITIES:
            raise TicketError("invalid", f"priority must be one of {', '.join(PRIORITIES)}")
        return v

    @staticmethod
    def _labels(v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            v = [x for x in re.split(r"[,\s]+", v) if x]
        if not isinstance(v, list) or len(v) > LABELS_MAX or any(not isinstance(x, str) or not LABEL.match(x) for x in v):
            raise TicketError("invalid", f"labels: up to {LABELS_MAX}, each 1 to {LABEL_MAX} characters of a-z, 0-9 and -")
        out: list[str] = []
        for x in v:
            if x not in out:
                out.append(x)
        return out

    @staticmethod
    def _due(v: Any) -> str | None:
        if v in (None, "", "none"):
            return None
        try:
            return dt.date.fromisoformat(str(v)).isoformat()
        except ValueError:
            raise TicketError("invalid", "due date must look like 2026-11-07") from None

    # -- permissions (the matrix) ------------------------------------------------------------------

    def _check_role(self, project: str, caller: str) -> Role:
        role = self._role(project, caller)
        if role is None:
            raise TicketError("forbidden", "You are not a member of this project.")
        return role

    @staticmethod
    def _forbid(what: str, ask: str = "a maintainer") -> TicketError:
        return TicketError("forbidden", f"{what} Ask {ask}.")

    def can_edit(self, role: Role, caller: str, t: dict[str, Any]) -> bool:
        if str(t["reporter"]).startswith("system:"):
            return role >= Role.MAINTAINER                                       # automatic tickets: maintainers and owners only
        if role >= Role.MAINTAINER:
            return True
        if role is Role.DEPLOYER:
            return t["reporter"] == caller or t["assignee"] == caller
        return t["reporter"] == caller                                           # a viewer: their own tickets

    def _check_move(self, role: Role, caller: str, t: dict[str, Any], target: str) -> str | None:
        """None when allowed, else the refusal. Closing and reopening are moves with their own rows in the matrix."""
        frm = t["status"]
        reopen = frm in ("done", "cancelled") and target == "todo"
        if reopen:
            return None if role >= Role.MAINTAINER else "Viewers and deployers can't reopen tickets."
        if target == "done":
            if role >= Role.MAINTAINER or (role is Role.DEPLOYER and t["assignee"] == caller):
                return None
            return "Only the assignee (a deployer or above) or a maintainer can mark it done."
        if target == "cancelled":
            return None if role >= Role.MAINTAINER else "Only maintainers can cancel tickets."
        if role >= Role.MAINTAINER or (role is Role.DEPLOYER and t["assignee"] == caller):
            return None
        return "Viewers can't move tickets." if role is Role.VIEWER else "You can move tickets assigned to you; a maintainer can move any."

    # -- operations ---------------------------------------------------------------------------------

    def create(self, project: str, caller: str, *, title: Any, body: Any = None, priority: Any = "medium", labels: Any = None, assignee: Any = None,
               due_on: Any = None, room: str = "", thread_id: str | None = None, source: str = "chat") -> dict[str, Any]:
        role = self._check_role(project, caller)
        who = None
        if assignee not in (None, ""):
            who = self.resolve_person(project, str(assignee))
            if not (role >= Role.MAINTAINER or (who == caller and role >= Role.DEPLOYER)):
                raise self._forbid("Viewers can't assign tickets." if role is Role.VIEWER else "Deployers can only take tickets for themselves.")
        return self._insert(project, caller, title=title, body=body, priority=priority, labels=labels, assignee=who, due_on=due_on, room=room,
                            thread_id=thread_id, source=source, source_ref=None)

    def _insert(self, project: str, reporter: str, *, title: Any, body: Any, priority: Any, labels: Any, assignee: str | None, due_on: Any, room: str,
                thread_id: str | None, source: str, source_ref: str | None) -> dict[str, Any]:
        if project not in self.projects:
            raise TicketError("not_found", f"There is no project {project!r}.")
        title, body, priority, labels, due = self._title(title), self._body(body), self._priority(priority), self._labels(labels), self._due(due_on)
        prefix = getattr(self.projects[project], "ticket_prefix", "SY")
        ts = _now_iso(self.now())
        with self.gk.lock:
            n = (self.gk.db.execute("SELECT COALESCE(MAX(number), 0) + 1 FROM tickets WHERE project=?", (project,)).fetchone()[0])
            key = f"{prefix}-{n}"
            cur = self.gk.db.execute(
                "INSERT INTO tickets (project, number, key, title, body, status, priority, labels, assignee, reporter, due_on, source, source_ref, room,"
                " thread_id, created_at, updated_at) VALUES (?,?,?,?,?,'todo',?,?,?,?,?,?,?,?,?,?,?)",
                (project, n, key, title, body, priority, json.dumps(labels), assignee, reporter, due, source, source_ref, room[:200], thread_id, ts, ts))
            self.gk.db.commit()
        t = self._need(project, key)
        self._event(t, reporter, "created", None, key, source=source, priority=priority, assignee=assignee)
        if assignee:
            self._event(t, reporter, "assigned", None, assignee)
        return self._view(self._need(project, key))

    def get(self, project: str, caller: str, key: str) -> dict[str, Any]:
        self._check_role(project, caller)
        t = self._need(project, key)
        with self.gk.lock:
            links = self.gk.db.execute("SELECT kind, ref, url, meta, created_at, created_by FROM ticket_links WHERE ticket_id=? ORDER BY id", (t["id"],)).fetchall()
            events = self.gk.db.execute("SELECT actor, type, from_value, to_value, created_at FROM ticket_events WHERE ticket_id=? ORDER BY id DESC LIMIT 20",
                                        (t["id"],)).fetchall()
            comments = self.gk.db.execute("SELECT author, body, created_at FROM ticket_comments WHERE ticket_id=? ORDER BY id DESC LIMIT 50", (t["id"],)).fetchall()
        out = self._view(t)
        out["links"] = [{"kind": k, "ref": r, "url": u, "meta": json.loads(m), "created_at": c, "created_by": b} for k, r, u, m, c, b in links]
        out["events"] = [{"actor": a, "actor_name": self.names(a) if not a.startswith("system:") else a, "type": ty, "from": self._pretty(ty, f), "to": self._pretty(ty, to),
                          "created_at": c} for a, ty, f, to, c in events]
        out["comments"] = [{"author": a, "author_name": self.names(a) if not a.startswith("system:") else a, "body": b, "created_at": c} for a, b, c in comments]
        return out

    def _pretty(self, etype: str, value: str | None) -> str | None:
        """Assignment events store chat ids; people read names."""
        return (self.names(value) or value) if etype in ("assigned", "unassigned") and value else value

    def update(self, project: str, caller: str, key: str, fields: dict[str, Any]) -> dict[str, Any]:
        role = self._check_role(project, caller)
        t = self._need(project, key)
        if not isinstance(fields, dict) or not fields:
            raise TicketError("invalid", "say what to change: title, body, priority, labels or due_on")
        unknown = set(fields) - {"title", "body", "priority", "labels", "due_on"}
        if unknown:
            raise TicketError("invalid", f"{', '.join(sorted(unknown))} can't be edited this way")
        if not self.can_edit(role, caller, t):
            raise self._forbid("You can't edit this ticket." if not str(t["reporter"]).startswith("system:") else "Automatic tickets can only be edited by maintainers.")
        changes: list[tuple[str, str, Any, Any]] = []
        new: dict[str, Any] = {}
        if "title" in fields:
            new["title"] = self._title(fields["title"])
            changes.append(("edited", "title", t["title"], new["title"]))
        if "body" in fields:
            new["body"] = self._body(fields["body"])
            changes.append(("edited", "body", "…", "…"))
        if "priority" in fields:
            new["priority"] = self._priority(fields["priority"])
            changes.append(("priority_changed", "priority", t["priority"], new["priority"]))
        if "labels" in fields:
            new["labels"] = json.dumps(self._labels(fields["labels"]))
            changes.append(("labels_changed", "labels", ",".join(json.loads(t["labels"])), ",".join(json.loads(new["labels"]))))
        if "due_on" in fields:
            new["due_on"] = self._due(fields["due_on"])
            changes.append(("due_changed", "due_on", t["due_on"], new["due_on"]))
        changes = [c for c in changes if c[1] == "body" and new.get("body") != t["body"] or c[1] != "body" and c[2] != c[3]]
        if not changes:
            return self._view(t)
        with self.gk.lock:
            sets = ", ".join(f"{k}=?" for k in new)
            self.gk.db.execute(f"UPDATE tickets SET {sets} WHERE id=?", (*new.values(), t["id"]))
            self.gk.db.commit()
        for etype, _field, frm, to in changes:
            self._event(t, caller, etype, frm, to)
        return self._view(self._need(project, key))

    def assign(self, project: str, caller: str, key: str, assignee: Any) -> dict[str, Any]:
        role = self._check_role(project, caller)
        t = self._need(project, key)
        if t["status"] in ("done", "cancelled"):
            raise TicketError("bad_transition", f"{key} is {t['status']}; reopen it before assigning.")
        if assignee in (None, "", "none"):
            if not (role >= Role.MAINTAINER or (role >= Role.DEPLOYER and t["assignee"] == caller)):
                raise self._forbid("You can't unassign this ticket.")
            if t["assignee"] is None:
                return self._view(t)
            who = None
        else:
            who = self.resolve_person(project, str(assignee))
            take = who == caller and t["assignee"] is None and role >= Role.DEPLOYER
            if not (role >= Role.MAINTAINER or take):
                raise self._forbid("Viewers can't assign tickets." if role is Role.VIEWER else "You can take an unassigned ticket for yourself; reassigning needs a maintainer.")
            if who == t["assignee"]:
                return self._view(t)
        with self.gk.lock:
            self.gk.db.execute("UPDATE tickets SET assignee=? WHERE id=?", (who, t["id"]))
            self.gk.db.commit()
        self._event(t, caller, "assigned" if who else "unassigned", t["assignee"], who)
        return self._view(self._need(project, key))

    def move(self, project: str, caller: str, key: str, status: Any, *, actor_label: str | None = None) -> dict[str, Any]:
        role = self._check_role(project, caller)
        t = self._need(project, key)
        if status not in STATUSES:
            raise TicketError("invalid", f"status must be one of {', '.join(STATUSES)}")
        if status == t["status"]:
            return self._view(t)
        if status not in TRANSITIONS[t["status"]]:
            raise TicketError("bad_transition", f"{key} is in {t['status']}; it can go to {' or '.join(TRANSITIONS[t['status']])}.")
        why = self._check_move(role, caller, t, status)
        if why:
            raise self._forbid(why)
        return self._apply_move(t, caller, status)

    def _apply_move(self, t: dict[str, Any], actor: str, status: str) -> dict[str, Any]:
        frm, ts = t["status"], _now_iso(self.now())
        reopen = frm in ("done", "cancelled") and status == "todo"
        closed = status in ("done", "cancelled")
        with self.gk.lock:
            self.gk.db.execute("UPDATE tickets SET status=?, closed_at=? WHERE id=?", (status, ts if closed else None, t["id"]))
            self.gk.db.commit()
        self._event(t, actor, "status_changed", frm, status)
        if closed:
            self._event(t, actor, "closed", frm, status)
        if reopen:
            self._event(t, actor, "reopened", frm, status)
        return self._view(self._need(t["project"], t["key"]))

    def comment(self, project: str, caller: str, key: str, body: Any, *, author: str | None = None) -> dict[str, Any]:
        if author is None:
            self._check_role(project, caller)
        t = self._need(project, key)
        if not isinstance(body, str) or not 1 <= len(body.strip()) <= COMMENT_MAX:
            raise TicketError("invalid", f"a comment must be 1 to {COMMENT_MAX} characters")
        with self.gk.lock:
            self.gk.db.execute("INSERT INTO ticket_comments (ticket_id, author, body, created_at) VALUES (?,?,?,?)",
                               (t["id"], author or caller, body.strip(), _now_iso(self.now())))
            self.gk.db.commit()
        self._event(t, author or caller, "commented", None, body.strip()[:80])
        return self._view(self._need(project, key))

    def mentions(self, project: str, body: str) -> list[str]:
        """Identities of project members @-mentioned in some text (names are matched against members only)."""
        out: list[str] = []
        for m in MENTION.finditer(body or ""):
            try:
                who = self.resolve_person(project, m.group(1))
            except TicketError:
                continue
            if who not in out:
                out.append(who)
        return out

    def link(self, project: str, caller: str, key: str, kind: Any, ref: Any, url: str | None = None, *, system: bool = False, meta: dict[str, Any] | None = None) -> dict[str, Any]:
        t = self._need(project, key)
        if not system:
            role = self._check_role(project, caller)
            if not self.can_edit(role, caller, t):
                raise self._forbid("You can't link things to this ticket.")
        if kind not in LINK_KINDS:
            raise TicketError("invalid", f"a link is one of {', '.join(LINK_KINDS)}")
        ref = str(ref).strip().lstrip("#")
        if kind == "ticket" and not KEY.match(ref):
            raise TicketError("invalid", "link to another ticket by its key, like SY-3")
        if not ref or len(ref) > 120 or not re.fullmatch(r"[A-Za-z0-9._:/@#+-]+", ref):
            raise TicketError("invalid", "that reference has characters a link can't hold")
        if url is not None and not str(url).startswith("https://"):
            url = None
        with self.gk.lock:
            cur = self.gk.db.execute("INSERT OR IGNORE INTO ticket_links (ticket_id, kind, ref, url, meta, created_at, created_by) VALUES (?,?,?,?,?,?,?)",
                                     (t["id"], kind, ref, url, json.dumps(meta or {}), _now_iso(self.now()), caller))
            self.gk.db.commit()
            fresh = cur.rowcount == 1
        if fresh:
            self._event(t, caller, "linked", kind, ref)
        return self._view(self._need(project, key))

    def set_link_meta(self, ticket_id: int, kind: str, ref: str, meta: dict[str, Any]) -> bool:
        """Quietly update what a link shows (a PR's state and CI): no event, no audit row. True if it changed."""
        with self.gk.lock:
            row = self.gk.db.execute("SELECT meta FROM ticket_links WHERE ticket_id=? AND kind=? AND ref=?", (ticket_id, kind, ref)).fetchone()
            if row is None or json.loads(row[0]) == meta:
                return False
            self.gk.db.execute("UPDATE ticket_links SET meta=? WHERE ticket_id=? AND kind=? AND ref=?", (json.dumps(meta), ticket_id, kind, ref))
            self.gk.db.commit()
        return True

    def soft_delete(self, project: str, caller: str, key: str) -> dict[str, Any]:
        """The approved delete: the ticket becomes cancelled and is hidden. Its rows and audit entries stay."""
        t = self._need(project, key)
        ts = _now_iso(self.now())
        with self.gk.lock:
            self.gk.db.execute("UPDATE tickets SET status='cancelled', closed_at=COALESCE(closed_at, ?), deleted_at=? WHERE id=?", (ts, ts, t["id"]))
            self.gk.db.commit()
        self.gk.audit.write(project=project, actor=caller, event="ticket_deleted", action="ticket.delete", target=key)
        return {"key": key, "deleted": True}

    def check_delete(self, project: str, caller: str, key: str) -> dict[str, Any]:
        role = self._check_role(project, caller)
        t = self._need(project, key)
        if role < Role.OWNER:
            raise self._forbid("Only an owner can delete tickets.", "an owner")
        return t

    # -- lists --------------------------------------------------------------------------------------

    def list(self, project: str, caller: str, *, assignee: str | None = None, status: str | None = None, label: str | None = None,
             priority: str | None = None, source: str | None = None, overdue: bool = False, q: str | None = None, unassigned: bool = False,
             include_cancelled: bool = True, done_within_days: int | None = None, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        self._check_role(project, caller)
        where, args = ["project=?", "deleted_at IS NULL"], [project]
        if assignee:
            where.append("assignee=?")
            args.append(self.resolve_person(project, assignee))
        if unassigned:
            where.append("assignee IS NULL")
        if status:
            if status not in STATUSES and status != "open":
                raise TicketError("invalid", f"status must be one of {', '.join(STATUSES)} or open")
            where.append("status NOT IN ('done','cancelled')" if status == "open" else "status=?")
            if status != "open":
                args.append(status)
        if not include_cancelled:
            where.append("status!='cancelled'")
        if done_within_days:                                         # the board shows what was finished in the last few days, not the whole history
            where.append("(status!='done' OR closed_at >= ?)")
            args.append(_now_iso(self.now() - done_within_days * 86400))
        if priority:
            where.append("priority=?")
            args.append(self._priority(priority))
        if source:
            if source not in SOURCES:
                raise TicketError("invalid", f"source must be one of {', '.join(SOURCES)}")
            where.append("source=?")
            args.append(source)
        if label:
            if not LABEL.match(label):
                raise TicketError("invalid", "that is not a label")
            where.append("labels LIKE ?")
            args.append(f'%"{label}"%')
        if overdue:
            where.append("due_on IS NOT NULL AND due_on < ? AND status NOT IN ('done','cancelled')")
            args.append(today_ist(self.now()))
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\' OR key LIKE ? ESCAPE '\\')")
            args += [like, like, like]
        if cursor:
            m = re.fullmatch(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\|(\d+)", cursor)
            if not m:
                raise TicketError("invalid", "that cursor is not one this list gave you")
            where.append("(updated_at < ? OR (updated_at = ? AND id < ?))")
            args += [m.group(1), m.group(1), int(m.group(2))]
        limit = max(1, min(int(limit or 50), 50))
        with self.gk.lock:
            cur = self.gk.db.execute("SELECT * FROM tickets WHERE " + " AND ".join(where) + " ORDER BY updated_at DESC, id DESC LIMIT ?", (*args, limit + 1))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        more = len(rows) > limit
        rows = rows[:limit]
        return {"tickets": [self._view(r) for r in rows], "next": f"{rows[-1]['updated_at']}|{rows[-1]['id']}" if more else None}

    def pr_summaries(self, project: str, keys: list[str]) -> dict[str, dict[str, Any]]:
        """The newest linked pull request of each ticket (number, state, CI, url), for the board's cards."""
        if not keys:
            return {}
        with self.gk.lock:
            rows = self.gk.db.execute(
                "SELECT t.key, l.ref, l.url, l.meta FROM ticket_links l JOIN tickets t ON t.id = l.ticket_id WHERE t.project=? AND l.kind='pr' AND t.key IN (%s) ORDER BY l.id"
                % ",".join("?" * len(keys)), (project, *keys)).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for key, ref, url, meta in rows:
            m = json.loads(meta)
            out[key] = {"number": ref, "url": url, "state": m.get("state", "open"), "ci": m.get("ci", "none")}
        return out

    def summary(self, project: str, caller: str) -> dict[str, Any]:
        self._check_role(project, caller)
        with self.gk.lock:
            by = dict(self.gk.db.execute("SELECT status, COUNT(*) FROM tickets WHERE project=? AND deleted_at IS NULL GROUP BY status", (project,)).fetchall())
            overdue = self.gk.db.execute("SELECT COUNT(*) FROM tickets WHERE project=? AND deleted_at IS NULL AND due_on < ? AND status NOT IN ('done','cancelled')",
                                         (project, today_ist(self.now()))).fetchone()[0]
            unassigned = self.gk.db.execute("SELECT COUNT(*) FROM tickets WHERE project=? AND deleted_at IS NULL AND assignee IS NULL AND status NOT IN ('done','cancelled')",
                                            (project,)).fetchone()[0]
            mine = self.gk.db.execute("SELECT COUNT(*) FROM tickets WHERE project=? AND deleted_at IS NULL AND assignee=? AND status NOT IN ('done','cancelled')",
                                      (project, caller)).fetchone()[0]
        return {"by_status": {s: by.get(s, 0) for s in STATUSES}, "overdue": overdue, "unassigned": unassigned, "mine": mine,
                "open": sum(by.get(s, 0) for s in ("todo", "doing", "review"))}

    def all_open(self, project: str) -> list[dict[str, Any]]:
        """Every open ticket of a project, as plain dicts (for briefings; not a permission-checked read)."""
        with self.gk.lock:
            cur = self.gk.db.execute("SELECT * FROM tickets WHERE project=? AND deleted_at IS NULL AND status NOT IN ('done','cancelled')", (project,))
            cols = [c[0] for c in cur.description]
            return [self._view(dict(zip(cols, r))) for r in cur.fetchall()]

    # -- automatic tickets ----------------------------------------------------------------------------------

    def auto(self, project: str, *, source: str, source_ref: str, title: str, body: str = "", priority: str = "high", labels: Iterable[str] = (),
             assignee: str | None = None, room: str = "", again: str = "happened again") -> tuple[dict[str, Any] | None, str]:
        """(ticket, outcome). outcome: created | repeated (an open ticket with this source_ref got a comment) | limited (over 10 an hour: nothing made)."""
        if project not in self.projects:
            return None, "unknown_project"
        existing = self._open_by_ref(project, source, source_ref)
        if existing is not None:
            self.comment(project, f"system:{source}", existing["key"], f"{again} at {_now_iso(self.now())}", author=f"system:{source}")
            return self._view(self._need(project, existing["key"])), "repeated"
        cutoff = self.now() - 3600
        with self.gk.lock:
            self.gk.db.execute("DELETE FROM ticket_auto_log WHERE ts < ?", (cutoff,))
            n = self.gk.db.execute("SELECT COUNT(*) FROM ticket_auto_log WHERE project=?", (project,)).fetchone()[0]
            if n >= AUTO_PER_HOUR:
                self.gk.db.commit()
                return None, "limited"
            self.gk.db.execute("INSERT INTO ticket_auto_log (project, ts) VALUES (?, ?)", (project, self.now()))
            self.gk.db.commit()
        who = assignee if assignee and assignee in self.members(project) else None
        t = self._insert(project, f"system:{source}", title=title[:TITLE_MAX], body=body[:BODY_MAX], priority=priority, labels=list(labels), assignee=who, due_on=None,
                         room=room, thread_id=None, source=source, source_ref=source_ref)
        return t, "created"

    def _open_by_ref(self, project: str, source: str, source_ref: str) -> dict[str, Any] | None:
        with self.gk.lock:
            cur = self.gk.db.execute("SELECT * FROM tickets WHERE project=? AND source=? AND source_ref=? AND closed_at IS NULL AND deleted_at IS NULL",
                                     (project, source, source_ref))
            row = cur.fetchone()
            cols = [c[0] for c in cur.description]
        return dict(zip(cols, row)) if row else None

    def system(self, project: str, key: str) -> dict[str, Any] | None:
        """A ticket for the automation to act on, or None when the key is not this project's."""
        return self._ticket(project, key) if KEY.match(key or "") else None

    def system_move(self, project: str, key: str, status: str, actor: str) -> dict[str, Any] | None:
        t = self._ticket(project, key)
        if t is None or status not in TRANSITIONS.get(t["status"], ()):
            return None
        return self._apply_move(t, actor, status)

    def system_set_body(self, project: str, key: str, body: str, actor: str) -> bool:
        t = self._ticket(project, key)
        if t is None or t["body"] == body[:BODY_MAX]:
            return False
        with self.gk.lock:
            self.gk.db.execute("UPDATE tickets SET body=? WHERE id=?", (body[:BODY_MAX], t["id"]))
            self.gk.db.commit()
        self._event(t, actor, "edited", "body", "body")
        return True

    def system_note(self, project: str, key: str, actor: str, kind: str, text: str) -> None:
        """A timeline entry from the automation (for example "merged in PR #26"), recorded as a link event."""
        t = self._ticket(project, key)
        if t is not None:
            self._event(t, actor, "linked", kind, text[:120])

    def merged_awaiting_deploy(self, project: str) -> list[dict[str, Any]]:
        """Tickets in review whose closing PR has merged and whose deploy has not been seen yet."""
        with self.gk.lock:
            cur = self.gk.db.execute(
                "SELECT t.*, l.meta FROM tickets t JOIN ticket_links l ON l.ticket_id = t.id WHERE t.project=? AND l.kind='pr' AND t.status='review' AND t.deleted_at IS NULL",
                (project,))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        out = []
        for r in rows:
            meta = json.loads(r.pop("meta"))
            if meta.get("state") == "merged" and meta.get("closes"):
                out.append({**r, "merge_sha": meta.get("merge_sha", "")})
        return out

    def by_link(self, kind: str, ref: str, project: str) -> list[dict[str, Any]]:
        with self.gk.lock:
            cur = self.gk.db.execute(
                "SELECT t.* FROM tickets t JOIN ticket_links l ON l.ticket_id = t.id WHERE l.kind=? AND l.ref=? AND t.project=? AND t.deleted_at IS NULL",
                (kind, ref, project))
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def link_meta(self, ticket_id: int, kind: str, ref: str) -> dict[str, Any]:
        with self.gk.lock:
            row = self.gk.db.execute("SELECT meta FROM ticket_links WHERE ticket_id=? AND kind=? AND ref=?", (ticket_id, kind, ref)).fetchone()
        return json.loads(row[0]) if row else {}

    # -- notifications bookkeeping ----------------------------------------------------------------------------

    def mark_notified(self, ticket_id: int, kind: str, on_date: str) -> bool:
        """True the first time (ticket, kind, day) is recorded: a due-date notice goes out once a day."""
        with self.gk.lock:
            cur = self.gk.db.execute("INSERT OR IGNORE INTO ticket_notified (ticket_id, kind, on_date) VALUES (?,?,?)", (ticket_id, kind, on_date))
            self.gk.db.commit()
            return cur.rowcount == 1
