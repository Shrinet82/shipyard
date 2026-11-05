"""Briefings for the Board: facts first, words second.

`facts_for` builds a structured report of what one person should know, using only what they are allowed to see. The Repo Agent may
turn it into friendlier prose, but `render` already gives a complete, deterministic text of at most twelve lines, and the one line that
says where to start comes from a fixed rule, not from a model.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from .evidence import defuse, redact
from .github import GitHubError
from .gatekeeper import SECOND_PERSON
from .policy import Role, may_approve
from .tickets import IST, PRIORITY_RANK, Tickets, _now_iso

MAX_LINES = 12
STALE_DAYS = 3
WATCH_TYPES = ("assigned", "unassigned", "status_changed", "commented", "priority_changed", "due_changed")


def _t(text: Any, n: int = 70) -> str:
    return defuse(redact(str(text)))[:n]


def _sort_key(t: dict[str, Any]) -> tuple:
    return (0 if t["overdue"] else 1, PRIORITY_RANK[t["priority"]], t["due_on"] or "9999-99-99", t["number"])


def first_step(facts: dict[str, Any]) -> str:
    """The one line that says where to start. A fixed order: overdue urgent ticket, failing CI on your own PR, a review asked of you,
    your highest-priority ticket in doing, then in todo."""
    tickets = facts["tickets"]
    for t in tickets:
        if t["overdue"] and t["priority"] == "urgent" and t["status"] not in ("done", "cancelled"):
            return f"Start with {t['key']}: it is urgent and overdue ({_t(t['title'])})."
    for p in facts["prs"] or []:
        if p["ci"] == "red":
            return f"Fix the failing CI on your PR #{p['number']}: {_t(p['title'])}."
    for p in facts["review_requests"] or []:
        return f"Review PR #{p['number']}: {_t(p['title'])}."
    for status, verb in (("doing", "Keep going on"), ("todo", "Pick up")):
        mine = sorted((t for t in tickets if t["status"] == status), key=_sort_key)
        if mine:
            return f"{verb} {mine[0]['key']}: {_t(mine[0]['title'])}."
    return "Nothing is waiting on you."


def facts_for(tix: Tickets, project, who: str, *, github=None, pending=None, now: float, since: str | None = None) -> dict[str, Any]:
    """Everything one person may be told about their own work. `who` is a chat identity; the caller has already decided they may see it."""
    name = tix.names(who)
    own = sorted((t for t in tix.all_open(project.name) if t["assignee"] == who), key=_sort_key)
    since = since or _now_iso(now - 24 * 3600)
    changes: list[dict[str, Any]] = []
    with tix.gk.lock:
        rows = tix.gk.db.execute(
            "SELECT t.key, t.title, e.actor, e.type, e.from_value, e.to_value, e.created_at FROM ticket_events e JOIN tickets t ON t.id = e.ticket_id "
            "WHERE t.project=? AND t.assignee=? AND e.actor != ? AND e.created_at > ? AND e.type IN (%s) AND t.deleted_at IS NULL ORDER BY e.id DESC LIMIT 8"
            % ",".join("?" * len(WATCH_TYPES)), (project.name, who, who, since, *WATCH_TYPES)).fetchall()
        mention_rows = tix.gk.db.execute(
            "SELECT t.key, t.title, c.author, c.body, c.created_at FROM ticket_comments c JOIN tickets t ON t.id = c.ticket_id "
            "WHERE t.project=? AND c.author != ? AND c.created_at > ? AND t.deleted_at IS NULL AND c.body LIKE ? ESCAPE '\\' ORDER BY c.id DESC LIMIT 5",
            (project.name, who, since, "%@" + (name or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")).fetchall() if name else []
    for key, title, actor, typ, frm, to, at in rows:
        actor_name = actor if actor.startswith("system:") else tix.names(actor)
        what = {"assigned": f"assigned to you by {actor_name}", "unassigned": "unassigned", "status_changed": f"moved {frm} → {to} by {actor_name}",
                "commented": f"new comment by {actor_name}", "priority_changed": f"priority {frm} → {to}", "due_changed": f"due date {frm or 'none'} → {to or 'none'}"}[typ]
        changes.append({"key": key, "title": title, "what": what, "at": at})
    for key, title, author, _body, at in mention_rows:
        changes.append({"key": key, "title": title, "what": f"{author if author.startswith('system:') else tix.names(author)} mentioned you", "at": at})

    prs: list[dict[str, Any]] | None = None
    reviews: list[dict[str, Any]] | None = None
    login = project.github_logins.get(who)
    if github is not None and project.repo is not None and login:
        try:
            prs, reviews = [], []
            for pr in github.list_open_prs(project.repo.name):
                checks = github.checks(project.repo.name, pr.head_sha, project.repo.required_checks)
                info = {"number": pr.number, "title": pr.title, "ci": checks.ci, "conflict": pr.mergeable is False, "url": pr.url, "reviewers": len(pr.requested_reviewers)}
                if pr.author == login:
                    prs.append(info)
                if login in pr.requested_reviewers:
                    reviews.append(info)
        except GitHubError:
            prs = reviews = None                                   # "unavailable" is shown, never guessed
    approvals = []
    for a in (pending or []):
        if a["requester"] != who and may_approve(tix.gk.policy, project=project.name, requester=a["requester"], approver=who, approver_is_human=True,
                                                allow_requester=a["kind"] == "agent_proposal" and a["action"] not in SECOND_PERSON,
                                                second_person=a["action"] in SECOND_PERSON):
            approvals.append({"id": a["id"], "action": a["action"], "target": a["target"]})
    ops = [{"key": t["key"], "title": t["title"], "source": t["source"]} for t in own
           if t["source"] in ("alert", "deploy_failed", "sbom_gate", "incident") and t["created_at"] > _now_iso(now - 24 * 3600)]
    facts = {"who": {"identity": who, "name": name}, "since": since, "tickets": own, "changes": changes[:10], "prs": prs, "review_requests": reviews,
             "approvals": approvals, "ops": ops}
    facts["first_step"] = first_step(facts)
    return facts


def render(facts: dict[str, Any], link: str = "") -> str:
    """At most twelve lines. Every number and ticket in it is in `facts`."""
    own, lines = facts["tickets"], []
    lines.append(f"Briefing for {_t(facts['who']['name'], 40)}:")
    if own:
        shown = [f"{t['key']} {t['priority']}" + (f" due {t['due_on']}" if t["due_on"] else "") + (" OVERDUE" if t["overdue"] else "") + f" {_t(t['title'], 40)}" for t in own[:3]]
        lines.append(f"Your tickets ({len(own)}): " + "; ".join(shown) + (f"; and {len(own) - 3} more" if len(own) > 3 else ""))
    else:
        lines.append("Your tickets: none open.")
    ch = facts["changes"]
    lines.append("Since your last briefing: " + ("; ".join(f"{c['key']} {c['what']}" for c in ch[:3]) + (f"; and {len(ch) - 3} more" if len(ch) > 3 else "") if ch else "nothing changed."))
    if facts["prs"] is None:
        lines.append("Your PRs: GitHub could not be reached, or no GitHub login is set for you.")
    else:
        lines.append("Your PRs: " + ("; ".join(f"#{p['number']} CI {p['ci']}" + (" conflict" if p["conflict"] else "") for p in facts["prs"][:4]) or "none open."))
    waiting = [f"review PR #{p['number']}" for p in (facts["review_requests"] or [])[:3]] + [f"approval {a['id']} ({a['action'].split('.')[-1]} {_t(a['target'], 20)})" for a in facts["approvals"][:3]]
    lines.append("Waiting on you: " + ("; ".join(waiting) if waiting else "nothing."))
    if facts["ops"]:
        lines.append("Related ops (24 h): " + "; ".join(f"{o['key']} ({o['source']})" for o in facts["ops"][:3]))
    lines.append("First step: " + facts["first_step"])
    if link:
        lines.append(f"Board: {link}")
    return "\n".join(lines[:MAX_LINES])


def team_facts(tix: Tickets, project, *, now: float) -> dict[str, Any]:
    open_t = tix.all_open(project.name)
    members = tix.members(project.name)
    per: list[dict[str, Any]] = []
    for ident, role in sorted(members.items(), key=lambda kv: tix.names(kv[0])):
        mine = [t for t in open_t if t["assignee"] == ident]
        doing = sorted((t for t in mine if t["status"] == "doing"), key=lambda t: t["updated_at"])
        per.append({"identity": ident, "name": tix.names(ident), "role": role.name.lower(), "open": {s: sum(1 for t in mine if t["status"] == s) for s in ("todo", "doing", "review")},
                    "overdue": sum(1 for t in mine if t["overdue"]), "oldest_doing": doing[0]["key"] if doing else None})
    per = [p for p in per if sum(p["open"].values()) or p["overdue"]]
    unassigned: dict[str, list[str]] = {p: [] for p in ("urgent", "high", "medium", "low")}
    for t in open_t:
        if t["assignee"] is None:
            unassigned[t["priority"]].append(t["key"])
    cutoff = _now_iso(now - STALE_DAYS * 86400)
    stale = [t["key"] for t in open_t if t["status"] in ("doing", "review") and t["updated_at"] < cutoff]
    since = _now_iso(now - 24 * 3600)
    auto = [t["key"] for t in open_t if t["automatic"] and t["created_at"] > since]
    return {"members": per, "unassigned": unassigned, "stale": stale, "auto_24h": auto}


def render_team(facts: dict[str, Any], names: Any = None) -> str:
    lines = ["Team status:"]
    for p in facts["members"][:8]:
        o = p["open"]
        lines.append(f"{_t(p['name'], 24)}: todo {o['todo']}, doing {o['doing']}, review {o['review']}" + (f", {p['overdue']} overdue" if p["overdue"] else "")
                     + (f", oldest doing {p['oldest_doing']}" if p["oldest_doing"] else ""))
    un = facts["unassigned"]
    lines.append("Unassigned: " + (", ".join(f"{p} {len(k)}" for p, k in un.items() if k) or "none"))
    lines.append("Stale (no change for 3 days): " + (", ".join(facts["stale"][:6]) or "none"))
    lines.append("Opened automatically in the last 24 h: " + (", ".join(facts["auto_24h"][:6]) or "none"))
    return "\n".join(lines[:MAX_LINES])


def standup_text(tix: Tickets, project, *, now: float) -> str:
    """Yesterday's done tickets, today's doing per person, blocked and overdue items, new automatic tickets."""
    since = _now_iso(now - 24 * 3600)
    with tix.gk.lock:
        done = [r[0] for r in tix.gk.db.execute("SELECT key FROM tickets WHERE project=? AND status='done' AND closed_at > ? AND deleted_at IS NULL ORDER BY closed_at",
                                                (project.name, since)).fetchall()]
    open_t = tix.all_open(project.name)
    lines = [f"Standup for {project.name} ({dt.datetime.fromtimestamp(now, IST).date().isoformat()}):"]
    lines.append("Done in the last day: " + (", ".join(done[:8]) or "nothing"))
    doing: dict[str, list[str]] = {}
    for t in open_t:
        if t["status"] == "doing":
            doing.setdefault(tix.names(t["assignee"]) if t["assignee"] else "unassigned", []).append(t["key"])
    lines.append("Doing today: " + ("; ".join(f"{_t(n, 20)}: {', '.join(k[:4])}" for n, k in sorted(doing.items())) or "nothing"))
    team = team_facts(tix, project, now=now)
    overdue = [t["key"] for t in open_t if t["overdue"]]
    lines.append("Overdue: " + (", ".join(overdue[:6]) or "none") + "; stale: " + (", ".join(team["stale"][:6]) or "none"))
    lines.append("New automatic tickets: " + (", ".join(team["auto_24h"][:6]) or "none"))
    return "\n".join(lines)
