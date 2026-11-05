"""Incidents: an alert opens one, a maintainer closes it, and the action items they name become a Board ticket.

An incident is one row per project and number (`INC-1`, `INC-2`, ...). The same alert on the same target while an incident is open
joins it instead of opening another. Opening and closing are audit rows in the same hash chain as everything else.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from typing import Any, Callable

from .audit import AuditLog

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    number INTEGER NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    room TEXT NOT NULL DEFAULT '',
    opened_at REAL NOT NULL,
    closed_at REAL,
    closed_by TEXT,
    UNIQUE (project, number)
);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open ON incidents (project, kind, target) WHERE closed_at IS NULL;
"""
KEY = re.compile(r"^INC-(\d{1,6})$", re.IGNORECASE)
MAX_ITEMS, ITEM_MAX = 12, 160
_BULLET = re.compile(r"^\s*(?:[-*•]\s*)?(?:\[\s?[xX ]?\s?\]\s*)?")


class IncidentError(Exception):
    """A refusal whose message is safe to show."""


def parse_items(text: str) -> list[str]:
    """Action items after `incident close INC-3`: one per line (a leading dash or checkbox is dropped), or separated by `;` on one line."""
    text = text.strip().lstrip(":").strip()
    if not text:
        return []
    parts = text.splitlines() if "\n" in text else text.split(";")
    items = [_BULLET.sub("", p).strip() for p in parts]
    return [i for i in items if i]


class Incidents:
    def __init__(self, db: sqlite3.Connection, lock: threading.RLock, audit: AuditLog, now: Callable[[], float]):
        self.db, self.lock, self.audit, self.now = db, lock, audit, now
        with self.lock:
            self.db.executescript(SCHEMA)
            self.db.commit()

    @staticmethod
    def _row(cur: sqlite3.Cursor, r: tuple) -> dict[str, Any]:
        d = dict(zip([c[0] for c in cur.description], r))
        d["key"] = f"INC-{d['number']}"
        return d

    def open(self, project: str, kind: str, target: str, title: str, room: str = "") -> tuple[dict[str, Any], bool]:
        """(incident, created). An open incident for the same alert and target is joined, not duplicated."""
        with self.lock:
            cur = self.db.execute("SELECT * FROM incidents WHERE project=? AND kind=? AND target=? AND closed_at IS NULL", (project, kind, target))
            row = cur.fetchone()
            if row:
                return self._row(cur, row), False
            number = (self.db.execute("SELECT COALESCE(MAX(number), 0) + 1 FROM incidents WHERE project=?", (project,)).fetchone()[0])
            self.db.execute("INSERT INTO incidents (project, number, kind, target, title, room, opened_at) VALUES (?,?,?,?,?,?,?)",
                            (project, number, kind, target, title[:200], room, self.now()))
            self.db.commit()
            cur = self.db.execute("SELECT * FROM incidents WHERE project=? AND number=?", (project, number))
            inc = self._row(cur, cur.fetchone())
        self.audit.write(project=project, actor="system:alert", event="incident_opened", action="incident.open", target=inc["key"], kind=kind, on=target)
        return inc, True

    def get(self, project: str, key: str) -> dict[str, Any] | None:
        m = KEY.match(key.strip())
        if not m:
            return None
        with self.lock:
            cur = self.db.execute("SELECT * FROM incidents WHERE project=? AND number=?", (project, int(m.group(1))))
            row = cur.fetchone()
            return self._row(cur, row) if row else None

    def open_list(self, project: str) -> list[dict[str, Any]]:
        with self.lock:
            cur = self.db.execute("SELECT * FROM incidents WHERE project=? AND closed_at IS NULL ORDER BY number", (project,))
            return [self._row(cur, r) for r in cur.fetchall()]

    def close(self, project: str, key: str, actor: str, items: list[str]) -> dict[str, Any]:
        inc = self.get(project, key)
        if inc is None:
            raise IncidentError(f"I can't find {key.upper()} in {project}.")
        if inc["closed_at"] is not None:
            raise IncidentError(f"{inc['key']} is already closed.")
        if len(items) > MAX_ITEMS or any(len(i) > ITEM_MAX for i in items):
            raise IncidentError(f"Name at most {MAX_ITEMS} action items of up to {ITEM_MAX} characters each.")
        with self.lock:
            cur = self.db.execute("UPDATE incidents SET closed_at=?, closed_by=? WHERE id=? AND closed_at IS NULL", (self.now(), actor, inc["id"]))
            self.db.commit()
        if cur.rowcount != 1:
            raise IncidentError(f"{inc['key']} is already closed.")
        self.audit.write(project=project, actor=actor, event="incident_closed", action="incident.close", target=inc["key"], items=len(items))
        return inc
