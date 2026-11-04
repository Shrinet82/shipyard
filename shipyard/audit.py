"""Append-only audit log in SQLite. Rows are hash-chained so edits are detectable."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
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


def _digest(prev: str, ts: float, project: str, actor: str, event: str, action: str, target: str, body: str) -> str:
    return hashlib.sha256("|".join([prev, str(ts), project, actor, event, action, target, body]).encode()).hexdigest()


class AuditLog:
    def __init__(self, db: sqlite3.Connection, now: Callable[[], float] = time.time):
        self.db = db
        self.now = now
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def _last_hash(self) -> str:
        row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else "genesis"

    def write(self, *, project: str, actor: str, event: str, action: str, target: str, **detail: Any) -> int:
        with self.lock:
            ts = self.now()
            body = json.dumps(detail, sort_keys=True, default=str)
            prev = self._last_hash()
            digest = _digest(prev, ts, project, actor, event, action, target, body)
            cur = self.db.execute(
                "INSERT INTO audit (ts, project, actor, event, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, project, actor, event, action, target, body, prev, digest),
            )
            self.db.commit()
            return cur.lastrowid

    def recent(self, project: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT ts, actor, event, action, target, detail FROM audit WHERE project=? ORDER BY id DESC LIMIT ?",
                (project, limit),
            ).fetchall()
        return [
            {"ts": r[0], "actor": r[1], "event": r[2], "action": r[3], "target": r[4], "detail": json.loads(r[5])}
            for r in rows
        ]

    def page(self, project: str, *, limit: int = 50, before: int | None = None, q: str = "", event: str = "",
             actor: str = "", action: str = "") -> tuple[list[dict[str, Any]], bool]:
        """Rows newest first, with their ids and hashes, filtered; and whether older rows remain."""
        limit = max(1, min(int(limit), 200))
        where, params = ["project=?"], [project]
        for col, val in (("event", event), ("actor", actor), ("action", action)):
            if val:
                where.append(f"{col}=?")
                params.append(val)
        if before:
            where.append("id<?")
            params.append(int(before))
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(target LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\')")
            params += [like, like, like]
        with self.lock:
            rows = self.db.execute(
                "SELECT id, ts, actor, event, action, target, detail, hash FROM audit WHERE " + " AND ".join(where) +
                " ORDER BY id DESC LIMIT ?", (*params, limit + 1)).fetchall()
        out = [{"id": r[0], "ts": r[1], "actor": r[2], "event": r[3], "action": r[4], "target": r[5],
                "detail": json.loads(r[6]), "hash": r[7]} for r in rows[:limit]]
        return out, len(rows) > limit

    def facets(self, project: str) -> dict[str, list[str]]:
        with self.lock:
            return {col + "s": [r[0] for r in self.db.execute(f"SELECT DISTINCT {col} FROM audit WHERE project=? ORDER BY {col}", (project,))]
                    for col in ("event", "actor", "action")}

    def head(self, project: str | None = None) -> tuple[int, str]:
        """(rows, hash of the newest row): the chain's head, to show next to the verification result."""
        with self.lock:
            n = self.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        return n, self._last_hash()

    def verify(self) -> bool:
        with self.lock:
            prev = "genesis"
            for row in self.db.execute(
                "SELECT ts, project, actor, event, action, target, detail, prev_hash, hash FROM audit ORDER BY id"
            ):
                ts, project, actor, event, action, target, body, prev_hash, digest = row
                if prev_hash != prev or digest != _digest(prev, ts, project, actor, event, action, target, body):
                    return False
                prev = digest
            return True
