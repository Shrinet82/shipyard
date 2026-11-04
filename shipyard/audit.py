"""Append-only audit log in SQLite. Rows are hash-chained so edits are detectable."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any, Callable

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    project TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


class AuditLog:
    def __init__(self, db: sqlite3.Connection, now: Callable[[], float] = time.time):
        self.db = db
        self.now = now
        self.db.executescript(SCHEMA)

    def _last_hash(self) -> str:
        row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else "genesis"

    def write(self, *, project: str, actor: str, event: str, action: str, target: str, **detail: Any) -> int:
        ts = self.now()
        body = json.dumps(detail, sort_keys=True, default=str)
        prev = self._last_hash()
        digest = hashlib.sha256("|".join([prev, str(ts), project, actor, event, action, target, body]).encode()).hexdigest()
        cur = self.db.execute(
            "INSERT INTO audit (ts, project, actor, event, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (ts, project, actor, event, action, target, body, prev, digest),
        )
        self.db.commit()
        return cur.lastrowid

    def recent(self, project: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT ts, actor, event, action, target, detail FROM audit WHERE project=? ORDER BY id DESC LIMIT ?",
            (project, limit),
        ).fetchall()
        return [
            {"ts": r[0], "actor": r[1], "event": r[2], "action": r[3], "target": r[4], "detail": json.loads(r[5])}
            for r in rows
        ]

    def verify(self) -> bool:
        prev = "genesis"
        for row in self.db.execute(
            "SELECT ts, project, actor, event, action, target, detail, prev_hash, hash FROM audit ORDER BY id"
        ):
            ts, project, actor, event, action, target, body, prev_hash, digest = row
            expect = hashlib.sha256("|".join([prev, str(ts), project, actor, event, action, target, body]).encode()).hexdigest()
            if prev_hash != prev or digest != expect:
                return False
            prev = digest
        return True
