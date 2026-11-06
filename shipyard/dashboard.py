"""The dashboard: a small JSON API and a static page, inside the Gatekeeper, on loopback only.

It can show everything and change two things (roles, agent access), both for owners only and both audited. It cannot
approve or deny anything: approvals exist only in chat, where the sender's identity is verified. Every API call needs a
bearer session token (no cookies, so nothing for another site to ride on); responses carry a strict
Content-Security-Policy; the front end renders data as text only.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from .access import AccessError, AgentAccess, _SENDER
from .config import Config, Project
from .dashauth import DashAuth, TooManyCodes
from .evidence import redact
from .gatekeeper import Gatekeeper
from .health import Health
from .members import ROLE_NAMES, MemberError, MemberStore
from .policy import Role
from .sbom import gate_reasons, rebase
from .briefing import facts_for
from .sbomstore import FILES, SbomStore
from .tickets import KEY, TicketError

log = logging.getLogger("shipyard.dashboard")
WEB = Path(__file__).parent / "web"
TICKET_STATUS = {"not_found": 404, "forbidden": 403, "bad_transition": 422, "unknown_member": 422, "invalid": 400}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
MAX_BODY = 64 * 1024
SYSTEM_ACTORS = {"gatekeeper", "coolify", "ci", "github"}
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass
class Resp:
    status: int = 200
    body: bytes = b""
    ctype: str = "application/json"
    headers: dict[str, str] | None = None


def _json(data: Any, status: int = 200) -> Resp:
    return Resp(status, json.dumps(data, default=str).encode())


def _err(status: int, message: str) -> Resp:
    return _json({"error": message}, status)


class Dashboard:
    def __init__(self, cfg: Config, gk: Gatekeeper, auth: DashAuth, store: SbomStore | None, health: Health, members: MemberStore,
                 access: AgentAccess | None, names: Callable[[str], str], github_repo_url: str = "https://github.com",
                 now: Callable[[], float] = time.time, flow: Any = None, roomsync: Any = None):
        self.roomsync = roomsync                          # RoomSync, when Switch's admin login is set up
        self.cfg, self.gk, self.auth, self.store, self.health, self.members, self.access = cfg, gk, auth, store, health, members, access
        self.flow = flow                                  # the Board, when it is on
        self.tickets = flow.t if flow is not None else None
        self.names, self.now, self.gh_url = names, now, github_repo_url
        self._chain: tuple[float, dict[str, Any]] | None = None
        self.lock = threading.RLock()

    # -- people and places, for display only ------------------------------------------------

    def display(self, project: Project, identity: str) -> dict[str, Any]:
        role = self.cfg.policy.members.get(project.name, {}).get(identity)
        m = _SENDER.match(identity or "")
        if m:
            return {"id": identity, "name": self.names(identity) or m["name"], "platform": m["platform"], "role": role.name.lower() if role else None}
        base = identity.split(":", 1)[0] if identity else ""
        if role is not None:                                   # a member whose id is not in Switch's usual shape: the name we have for them
            return {"id": identity, "name": self.names(identity) or identity, "platform": "", "role": role.name.lower()}
        return {"id": identity, "name": identity, "platform": "system" if base in SYSTEM_ACTORS or identity.startswith("agent:") else "", "role": None}

    def room(self, project: Project, room_id: str) -> str:
        return project.room_names.get(room_id) or (room_id[:8] + "…" if len(room_id) > 12 else room_id)

    def chain(self) -> dict[str, Any]:
        with self.lock:
            if self._chain and self.now() - self._chain[0] < 30:
                return self._chain[1]
        ok = self.gk.audit.verify()
        rows, head = self.gk.audit.head()
        out = {"ok": ok, "rows": rows, "head": head[:4] + "…" + head[-4:] if head != "genesis" else "genesis"}
        with self.lock:
            self._chain = (self.now(), out)
        return out

    # -- entry point ---------------------------------------------------------------------------

    def handle(self, method: str, target: str, headers: dict[str, str], body: bytes = b"", host_ok: Callable[[str], bool] | None = None) -> Resp:
        h = {k.lower(): v for k, v in headers.items()}
        if host_ok is not None and not host_ok(h.get("host", "")):
            return _err(403, "unexpected host")
        try:
            url = urlparse(target)
            if len(url.query) > 2000:
                return _err(414, "query too long")
            path, query = url.path, {k: v[-1] for k, v in parse_qs(url.query, max_num_fields=20).items()}
        except ValueError:
            return _err(400, "bad request")
        if not path.startswith("/api/"):
            return self._static(method, path)
        if method == "POST":
            origin = h.get("origin")
            if origin and urlparse(origin).netloc != h.get("host"):
                return _err(403, "cross-origin request refused")
            if body and "application/json" not in h.get("content-type", ""):
                return _err(415, "send JSON")
        try:
            data = json.loads(body) if body else {}
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return _err(400, "the body is not a JSON object")
        try:
            return self._api(method, path, query, h, data)
        except MemberError as exc:
            return _err(422, str(exc))
        except TicketError as exc:
            return _json({"error": exc.message, "code": exc.code}, TICKET_STATUS.get(exc.code, 400))
        except AccessError as exc:
            return _err(502, str(exc))
        except Exception:
            log.exception("dashboard request failed")
            return _err(500, "Something went wrong")

    def _static(self, method: str, path: str) -> Resp:
        if method not in ("GET", "HEAD"):
            return _err(405, "method not allowed")
        entry = STATIC.get(path)
        if entry is None:
            return _err(404, "not found")
        return Resp(200, (WEB / entry[0]).read_bytes(), entry[1])

    # -- routing -------------------------------------------------------------------------------

    def _api(self, method: str, path: str, query: dict[str, str], h: dict[str, str], data: dict[str, Any]) -> Resp:
        if path == "/api/login/start" and method == "POST":
            try:
                return _json(self.auth.start())
            except TooManyCodes:
                return _err(429, "too many sign-in codes are waiting; try again in a few minutes")
        if path == "/api/login/poll" and method == "POST":
            state, token = self.auth.poll(str(data.get("code", "")), str(data.get("secret", "")))
            return _json({"state": state, **({"token": token} if token else {})}, 200 if state != "denied" else 403)
        bearer = h.get("authorization", "")
        token = bearer[7:] if bearer.lower().startswith("bearer ") else None
        session = self.auth.check(token)
        project = self.cfg.projects.get(session["project"]) if session else None
        role = self.cfg.policy.members.get(project.name, {}).get(session["identity"]) if project else None
        if session is None or project is None or role is None:
            return _err(401, "sign in again")
        ctx = {"identity": session["identity"], "project": project, "role": role, "token": token, "expires": session["expires"]}
        route = f"{method} {path}"
        simple = {
            "GET /api/me": self._me, "POST /api/logout": self._logout, "GET /api/overview": self._overview,
            "GET /api/approvals": self._approvals, "GET /api/backends": self._backends, "GET /api/roles": self._roles,
            "GET /api/agents": self._agents, "GET /api/rooms": self._rooms_page,
        }
        if route in simple:
            return simple[route](ctx)
        if route == "GET /api/audit":
            return self._audit(ctx, query)
        if route == "GET /api/sbom":
            return self._sbom_list(ctx, query)
        if route == "POST /api/backends/refresh":
            return self._refresh(ctx, data)
        owner_only = {"POST /api/roles": lambda: self._roles_save(ctx, data),
                      "POST /api/agents/preview": lambda: self._agents_preview(ctx),
                      "POST /api/agents/sync": lambda: self._agents_sync(ctx),
                      "POST /api/rooms/preview": lambda: self._rooms_preview(ctx),
                      "POST /api/rooms/sync": lambda: self._rooms_sync(ctx)}
        if route in owner_only:
            if role is not Role.OWNER:
                return _err(403, "only an owner can do that")
            return owner_only[route]()
        if self.tickets is not None:
            if route == "GET /api/tickets":
                return self._tickets_list(ctx, query)
            if route == "GET /api/tickets/summary":
                return _json(self.tickets.summary(project.name, ctx["identity"]))
            if route == "GET /api/members":
                return self._members_list(ctx)
            if (m := re.fullmatch(r"/api/tickets/([A-Z]{2,6}-\d{1,6})", path)) and method == "GET":
                t = self.tickets.get(project.name, ctx["identity"], m[1])
                return _json({**self._ticket_out(ctx, t), "room_url": self._room_url(t.get("room"))})
            if (m := re.fullmatch(r"/api/tickets/([A-Z]{2,6}-\d{1,6})/move", path)) and method == "POST":
                return self._ticket_move(ctx, m[1], data)
        if (m := re.fullmatch(r"/api/sbom/([0-9a-f]{7,40})", path)) and method == "GET":
            return self._sbom_detail(ctx, m[1])
        if (m := re.fullmatch(r"/api/sbom/([0-9a-f]{7,40})/file/([a-z]+)", path)) and method == "GET":
            return self._sbom_file(ctx, m[1], m[2])
        known = {p.split(" ", 1)[1] for p in [*simple, *owner_only, "GET /api/audit", "GET /api/sbom", "POST /api/backends/refresh"]}
        return _err(405 if path in known else 404, "method not allowed" if path in known else "not found")

    # -- pages -----------------------------------------------------------------------------------

    def _me(self, c) -> Resp:
        p: Project = c["project"]
        return _json({"identity": self.display(p, c["identity"]), "project": p.name, "role": c["role"].name.lower(),
                      "owner": c["role"] is Role.OWNER, "tz": self.cfg.digest.timezone, "now": self.now(), "expires": c["expires"],
                      "sbom": self.store is not None, "agents": self.access is not None, "board": self.tickets is not None, "roomsync": self.roomsync is not None})

    def _logout(self, c) -> Resp:
        self.auth.revoke(c["token"])
        return _json({"ok": True})

    def _audit_row(self, p: Project, r: dict[str, Any]) -> dict[str, Any]:
        detail = json.loads(redact(json.dumps(r["detail"], default=str)))
        reason = (detail.get("reason") or detail.get("error") or detail.get("result")
                  or (", ".join(map(str, detail["cves"])) if isinstance(detail.get("cves"), list) else "")
                  or (f"{detail.get('before') or 'none'} → {detail.get('after') or 'removed'}" if "after" in detail else ""))
        return {"id": r["id"], "ts": r["ts"], "who": self.display(p, r["actor"]), "event": r["event"], "action": r["action"],
                "target": r["target"], "summary": str(reason)[:200], "detail": detail, "hash": r["hash"][:8] + "…" + r["hash"][-8:]}

    def _overview(self, c) -> Resp:
        p: Project = c["project"]
        rows, _ = self.gk.audit.page(p.name, limit=8)
        pend = self.gk.pending_list(p.name)
        gated = [a for a in pend if a["args"].get("gate")]
        release = None
        if self.store is not None and p.repo and p.repo.app:
            rel = self.store.last_release(p.name, p.repo.app)
            rep = self.store.get(rel["report_commit"]) if rel else None
            if rel and rep:
                release = {"label": f"{p.repo.app} {rep.get('ref') or rel['commit'][:7]}", "commit": rel["commit"], "counts": rep["counts"],
                           "decision": rep["decision"], "ts": rel["ts"]}
        return _json({
            "project": p.name, "apps": p.app_names, "repo": p.repo.name if p.repo else None,
            "rooms": [self.room(p, r) for r in sorted(p.rooms)], "chain": self.chain(),
            "health": [{k: i[k] for k in ("key", "title", "state", "headline", "checked")} for i in self.health.snapshot()],
            "approvals": {"count": len(pend), "next_expires": min((a["expires"] for a in pend), default=None),
                          "room": self.room(p, sorted(p.ops_rooms)[0]) if p.ops_rooms else ""},
            "gate": {"blocked": len(gated), "items": [{"id": a["id"], "target": a["target"], "action": a["action"], "cves": a["args"]["gate"]} for a in gated][:5]},
            "release": release, "recent": [self._audit_row(p, r) for r in rows], "board": self._board_block(c),
            "sbom_enabled": self.store is not None})

    def _board_block(self, c) -> dict[str, Any] | None:
        """The "My tickets" block of the Overview: the caller's open tickets (at most 5) and the first step the briefing rule picks."""
        if self.tickets is None:
            return None
        p: Project = c["project"]
        facts = facts_for(self.tickets, p, c["identity"], github=None, pending=self.gk.pending_list(p.name), now=self.now())
        mine = [{k: t[k] for k in ("key", "title", "status", "priority", "due_on", "overdue")} for t in facts["tickets"][:5]]
        own = facts["tickets"]
        free = next((t["key"] for t in sorted(self.tickets.all_open(p.name), key=lambda t: t["number"]) if t["assignee"] is None), None)      # an example for "take one in chat"
        return {"mine": mine, "mine_total": len(own), "mine_overdue": sum(1 for t in own if t["overdue"]), "mine_review": sum(1 for t in own if t["status"] == "review"),
                "unassigned_key": free, "first_step": facts["first_step"], "summary": self.tickets.summary(p.name, c["identity"])}

    def _audit(self, c, q: dict[str, str]) -> Resp:
        p: Project = c["project"]
        rows, more = self.gk.audit.page(p.name, limit=int(q.get("limit", 50) or 50) if str(q.get("limit", "50")).isdigit() else 50,
                                        before=int(q["before"]) if q.get("before", "").isdigit() else None,
                                        q=q.get("q", "")[:100], event=q.get("event", "")[:40], actor=q.get("actor", "")[:200], action=q.get("action", "")[:60])
        facets = self.gk.audit.facets(p.name)
        return _json({"rows": [self._audit_row(p, r) for r in rows], "more": more, "chain": self.chain(),
                      "facets": {"events": facets["events"], "actions": facets["actions"],
                                 "actors": [self.display(p, a) for a in facets["actors"]]}})

    def _approvals(self, c) -> Resp:
        p: Project = c["project"]
        out = []
        for a in self.gk.pending_list(p.name):
            args = a["args"]
            tier = self.cfg.policy.actions.get(a["action"])
            report = self.store.get(args["sha"]) if self.store is not None and isinstance(args.get("sha"), str) and _COMMIT.match(args["sha"]) else None
            out.append({"id": a["id"], "action": a["action"], "target": a["target"], "kind": a["kind"], "tier": tier.value if tier else "",
                        "args": {k: v for k, v in args.items() if k not in ("gate",)}, "gate": args.get("gate") or [],
                        "requester": self.display(p, a["requester"]), "room": self.room(p, a["room_id"]) if a["room_id"] else "",
                        "expires": a["expires"], "needs": "owner" if args.get("gate") else "a second person" if a["action"] in {"repo.merge"} or (tier and tier.value == "dangerous") else "approval",
                        "report": args["sha"] if report else None})
        return _json({"approvals": out, "timeout_minutes": self.cfg.policy.approval_timeout_seconds // 60,
                      "room": self.room(p, sorted(p.ops_rooms)[0]) if p.ops_rooms else "", "now": self.now()})

    # -- the Board ------------------------------------------------------------------------------------------

    def _person(self, p: Project, ident: str | None) -> dict[str, Any] | None:
        if not ident:
            return None
        if ident.startswith("system:"):
            return {"id": ident, "name": ident, "platform": "system", "role": None}
        return self.display(p, ident)

    def _room_url(self, room_id: str | None) -> str | None:
        """The chat app's own link to a room (for "Open in chat"), from Switch, kept for a minute. None when Switch is not set up or has no link."""
        if not room_id or self.access is None:
            return None
        with self.lock:
            cached = getattr(self, "_room_urls", None)
        if cached is None or self.now() - cached[0] > 60:
            try:
                urls = self.access.room_urls()
            except Exception:                                  # Switch unreachable: the page just has no link
                urls = {}
            cached = (self.now(), urls)
            with self.lock:
                self._room_urls = cached
        url = cached[1].get(room_id)
        return url if isinstance(url, str) and url.startswith("https://") else None

    def _ticket_out(self, c, t: dict[str, Any]) -> dict[str, Any]:
        p: Project = c["project"]
        out = {k: t[k] for k in ("key", "title", "body", "status", "priority", "due_on", "labels", "source", "automatic", "overdue", "created_at", "updated_at", "closed_at")}
        out["assignee"] = self._person(p, t["assignee"])
        out["reporter"] = self._person(p, t["reporter"])
        out["room"] = self.room(p, t["room"]) if t.get("room") else ""
        out["can_move"] = self._moves_for(c, t)
        for k in ("links", "events", "comments"):
            if k in t:
                out[k] = t[k]
        if "events" in t:
            out["events"] = [{**e, "actor": self._person(p, e["actor"])} for e in t["events"]]
            out["comments"] = [{**cm, "author": self._person(p, cm["author"])} for cm in t["comments"]]
        return out

    def _moves_for(self, c, t: dict[str, Any]) -> list[str]:
        """The statuses this person may move the ticket to, so a board can disable the rest with a reason."""
        from .tickets import TRANSITIONS
        role, ident = c["role"], c["identity"]
        raw = self.tickets._ticket(c["project"].name, t["key"]) or {}
        return [s for s in TRANSITIONS[t["status"]] if raw and self.tickets._check_move(role, ident, raw, s) is None]

    def _tickets_list(self, c, q: dict[str, str]) -> Resp:
        p: Project = c["project"]
        who = c["identity"] if q.get("assignee", "").lower() == "me" else (q.get("assignee") or None)
        res = self.tickets.list(p.name, c["identity"], assignee=who, status=q.get("status") or None, label=q.get("label") or None, priority=q.get("priority") or None,
                                source=q.get("source") or None, q=q.get("q", "")[:100] or None, overdue=q.get("overdue") == "1", unassigned=q.get("unassigned") == "1",
                                include_cancelled=q.get("board") != "1", done_within_days=7 if q.get("board") == "1" else None, cursor=q.get("cursor") or None, limit=50)
        prs = self.tickets.pr_summaries(p.name, [t["key"] for t in res["tickets"]])
        return _json({"tickets": [{**self._ticket_out(c, t), "pr": prs.get(t["key"])} for t in res["tickets"]], "next": res["next"]})

    def _members_list(self, c) -> Resp:
        p: Project = c["project"]
        roles = self.members.members(p.name)
        return _json({"members": [{**self.display(p, i), "role": r.name.lower()} for i, r in sorted(roles.items(), key=lambda kv: self.names(kv[0]) or kv[0])]})

    def _ticket_move(self, c, key: str, data: dict[str, Any]) -> Resp:
        p: Project = c["project"]
        before = self.tickets.get(p.name, c["identity"], key)
        t = self.tickets.move(p.name, c["identity"], key, data.get("status"))
        if self.flow is not None and before["status"] != t["status"]:
            self.flow._tell(t["room"], t["assignee"], c["identity"], f"{key} moved {before['status']} → {t['status']} by {self.display(p, c['identity'])['name']} on the dashboard")
        return _json(self._ticket_out(c, self.tickets.get(p.name, c["identity"], key)))

    # -- SBOM --------------------------------------------------------------------------------------

    def _overridden(self, p: Project) -> set[str]:
        rows, _ = self.gk.audit.page(p.name, limit=200, event="gate_override")
        return {str(r["detail"].get("commit", "")) for r in rows}

    def _decision(self, report_decision: str, commit: str, overridden: set[str]) -> str:
        return "overridden" if report_decision in ("blocked", "unverified", "no_sbom") and commit[:12] in overridden else report_decision

    def _sbom_list(self, c, q: dict[str, str]) -> Resp:
        if self.store is None:
            return _json({"rows": [], "total": 0, "more": False})
        p: Project = c["project"]
        rows, _ = self.store.list(limit=200)
        rows = [r for r in rows if not p.repo or r["repo"] == p.repo.name]
        live = self.store.last_release(p.name, p.repo.app) if p.repo and p.repo.app else None
        over = self._overridden(p)
        for r in rows:
            r["decision"] = self._decision(r["decision"], r["commit"], over)
            r["live"] = bool(live and r["commit"] in (live["commit"], live["report_commit"]))
        want = q.get("decision", "")
        if want:
            rows = [r for r in rows if r["decision"] == want]
        offset = int(q["offset"]) if q.get("offset", "").isdigit() else 0
        page = rows[offset:offset + 25]
        return _json({"rows": page, "total": len(rows), "more": offset + 25 < len(rows)})

    def _report(self, c, commit: str) -> dict[str, Any] | None:
        p: Project = c["project"]
        full = self.store.resolve(commit) if self.store is not None else None
        report = self.store.get(full) if full else None
        if report is None:
            return None
        if p.repo and report["repo"] != p.repo.name:
            return None
        return report

    def _sbom_detail(self, c, commit: str) -> Resp:
        p: Project = c["project"]
        report = self._report(c, commit)
        if report is None:
            return _err(404, "no such report")
        stored = report
        if p.repo and p.repo.app:
            report = rebase(report, self.store.baseline(p.name, p.repo.app))
        d = report["diff"]
        decision = self._decision(report["decision"], report["commit"], self._overridden(p))
        pending = next((a["id"] for a in self.gk.pending_list(p.name) if a["args"].get("sha") == report["commit"]), None)
        repo = report["repo"]
        findings = report["findings"]
        return _json({
            "commit": report["commit"], "ref": report.get("ref") or "", "pr": report.get("pr"), "repo": repo, "format": report["format"],
            "package_count": report["package_count"], "counts": report["counts"], "fixable": report["fixable"],
            "decision": decision, "stored_decision": stored["decision"], "why": gate_reasons(report) if decision != "overridden" else [],
            "baseline": report["baseline"], "collected_at": report["collected_at"], "pending_approval": pending,
            "diff": {"added": d["added"][:300], "removed": d["removed"][:300], "upgraded": d["upgraded"][:300],
                     "total": len(d["added"]) + len(d["removed"]) + len(d["upgraded"])},
            "findings": findings[:300], "findings_total": len(findings), "licence_flags": report.get("licence_flags", [])[:200],
            "trust": report["trust"], "workflow": report["workflow"], "run_id": report.get("run_id"),
            "links": {"run": f"{self.gh_url}/{repo}/actions/runs/{report['run_id']}" if report.get("run_id") else None,
                      "commit": f"{self.gh_url}/{repo}/commit/{report['commit']}",
                      "pr": f"{self.gh_url}/{repo}/pull/{report['pr']}" if report.get("pr") else None},
            "files": [k for k in FILES if self.store.file_path(report["commit"], k)]})

    def _sbom_file(self, c, commit: str, kind: str) -> Resp:
        report = self._report(c, commit)
        path = self.store.file_path(report["commit"], kind) if report else None
        if path is None:
            return _err(404, "no such file")
        html = kind == "html"
        name = f"sbom-{report['commit'][:7]}-{kind}." + ("html" if html else "json")
        return Resp(200, path.read_bytes(), "text/html; charset=utf-8" if html else "application/json",
                    {"Content-Disposition": f'attachment; filename="{name}"', "Content-Security-Policy": REPORT_CSP})

    # -- backends ------------------------------------------------------------------------------------

    def _backends(self, c) -> Resp:
        items = self.health.snapshot()
        bad = sum(1 for i in items if i["state"] in ("warn", "bad"))
        return _json({"items": items, "healthy": sum(1 for i in items if i["state"] == "ok"), "attention": bad, "now": self.now()})

    def _refresh(self, c, data: dict[str, Any]) -> Resp:
        key = data.get("key")
        self.health.refresh(key if isinstance(key, str) else None)
        return self._backends(c)

    # -- roles and agent access ------------------------------------------------------------------------

    def _roles(self, c) -> Resp:
        p: Project = c["project"]
        members = self.members.members(p.name)
        owners = sum(1 for r in members.values() if r is Role.OWNER)
        rows = [{**self.display(p, i), "role": r.name.lower(), "last_owner": r is Role.OWNER and owners == 1}
                for i, r in sorted(members.items(), key=lambda kv: (-kv[1], kv[0]))]
        return _json({"project": p.name, "editable": c["role"] is Role.OWNER, "roles": list(ROLE_NAMES), "members": rows})

    def _roles_save(self, c, data: dict[str, Any]) -> Resp:
        p: Project = c["project"]
        done = self.members.apply(p.name, c["identity"], data.get("changes"))          # type: ignore[arg-type]
        for d in done:
            if d["to"] is None:
                self.auth.revoke_identity(d["identity"])           # a removed member's sessions end now
        return _json({"changed": done, "audited": len(done)})

    def _rooms_page(self, c) -> Resp:
        if self.access is None:
            return _err(404, "Switch is not configured")
        return _json({"rooms": self.access.rooms(c["project"]), "project": c["project"].name})

    def _agents(self, c) -> Resp:
        if self.access is None:
            return _err(404, "agent access is not configured")
        p: Project = c["project"]
        return _json(self.access.state(p, lambda i: self.display(p, i), lambda r: self.room(p, r)) | {"editable": c["role"] is Role.OWNER})

    def _rooms_preview(self, c) -> Resp:
        if self.roomsync is None:
            return _err(404, "room sync is not configured")
        try:
            return _json({"changes": self.roomsync.preview(c["project"])})
        except Exception as exc:                                     # Switch unreachable or refusing: the message is safe to show
            return _err(502, str(exc)[:200])

    def _rooms_sync(self, c) -> Resp:
        if self.roomsync is None:
            return _err(404, "room sync is not configured")
        try:
            return _json(self.roomsync.apply(c["project"], c["identity"]))
        except Exception as exc:
            return _err(502, str(exc)[:200])

    def _agents_preview(self, c) -> Resp:
        if self.access is None:
            return _err(404, "agent access is not configured")
        p: Project = c["project"]
        return _json({"changes": self.access.preview(p, lambda i: self.display(p, i), lambda r: self.room(p, r))})

    def _agents_sync(self, c) -> Resp:
        if self.access is None:
            return _err(404, "agent access is not configured")
        return _json(self.access.apply(c["project"], c["identity"]))


# --- the server --------------------------------------------------------------------------------------

_LOCAL_HOST = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?$")


def _loopback_host(port: int, public_url: str = "") -> Callable[[str], bool]:
    """Only a loopback Host header, plus the one address the owner chose to publish (`public_url`): a web page on another domain that rebinds its name
    to this machine carries its own Host, which matches neither."""
    extra = urlparse(public_url).netloc.lower() if public_url else ""
    return lambda host: bool(_LOCAL_HOST.match(host)) or (bool(extra) and host.lower() == extra)


def serve(dash: Dashboard, bind: str, port: int, allow_remote: bool = False, public_url: str = "") -> ThreadingHTTPServer:
    if bind not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise SystemExit("dashboard.bind must be a loopback address: reach it through an SSH tunnel. To listen on the network address on purpose "
                         "(plain HTTP: allow the port for your own address only in the firewall) run `python3 -m shipyard expose`, or set dashboard.allow_remote: true")
    host_ok = _loopback_host(port, public_url if allow_remote else "")

    class Handler(BaseHTTPRequestHandler):
        server_version = "Shipyard"
        sys_version = ""
        timeout = 15

        def _go(self) -> None:
            length = self.headers.get("Content-Length", "0")
            if not length.isdigit() or int(length) > MAX_BODY:
                self._send(Resp(413, b'{"error":"too large"}'))
                return
            body = self.rfile.read(int(length)) if int(length) else b""
            self._send(dash.handle(self.command, self.path, dict(self.headers), body, host_ok))

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = _go

        def _send(self, r: Resp) -> None:
            self.send_response(r.status)
            self.send_header("Content-Type", r.ctype)
            self.send_header("Content-Length", str(len(r.body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            for k, v in {"Content-Security-Policy": CSP, **(r.headers or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(r.body)

        def log_message(self, fmt: str, *args: Any) -> None:       # never log URLs with query strings from here
            log.debug("%s", fmt % args)

    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("dashboard on http://%s:%d (%s)", bind, port, "loopback only" if bind in ("127.0.0.1", "localhost", "::1") else "reachable on the network: plain HTTP, keep the port closed to everyone but you")
    return srv
