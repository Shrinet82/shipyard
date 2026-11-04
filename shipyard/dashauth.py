"""Dashboard sign-in: short-lived bearer sessions, bound to a chat identity the Gatekeeper has verified.

Two ways in, neither puts a secret in chat:
  * device code: the dashboard shows a code, the person types `@gatekeeper dashboard-login <code>` in a Shipyard room
    (Switch tells us who sent it), and the browser that started the code collects the session;
  * a token printed on the VM by `python -m shipyard dashboard-token` (for whoever has a shell there).
Only hashes are stored. A session's role is looked up live, so removing a member ends their access at once.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable

SCHEMA = """
CREATE TABLE IF NOT EXISTS dash_sessions (
    hash TEXT PRIMARY KEY, identity TEXT NOT NULL, project TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS dash_codes (
    code TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', identity TEXT, project TEXT
);
"""
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"      # no 0/O/1/I/L: typed by hand into chat
CODE_TTL = 600.0
MAX_PENDING = 20
TOKEN_PREFIX = "sy_live_"


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def normalize_code(text: str) -> str:
    return (text or "").strip().upper()


class TooManyCodes(Exception):
    pass


class DashAuth:
    def __init__(self, db: sqlite3.Connection, lock: threading.RLock | None = None, now: Callable[[], float] = time.time,
                 session_hours: float = 8.0):
        self.db, self.lock, self.now, self.ttl = db, lock or threading.RLock(), now, session_hours * 3600
        with self.lock:
            self.db.executescript(SCHEMA)

    # -- sessions -------------------------------------------------------------

    def issue(self, identity: str, project: str, hours: float | None = None) -> str:
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = self.now()
        with self.lock:
            self.db.execute("INSERT INTO dash_sessions (hash, identity, project, created, expires) VALUES (?,?,?,?,?)",
                            (_h(token), identity, project, now, now + (hours * 3600 if hours else self.ttl)))
            self.db.commit()
        return token

    def check(self, token: str | None) -> dict[str, Any] | None:
        if not token or not token.startswith(TOKEN_PREFIX) or len(token) > 200:
            return None
        with self.lock:
            row = self.db.execute("SELECT identity, project, created, expires FROM dash_sessions WHERE hash=?", (_h(token),)).fetchone()
        if row is None or row[3] < self.now():
            return None
        return {"identity": row[0], "project": row[1], "created": row[2], "expires": row[3]}

    def revoke(self, token: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM dash_sessions WHERE hash=?", (_h(token or ""),))
            self.db.commit()

    def revoke_identity(self, identity: str) -> int:
        with self.lock:
            cur = self.db.execute("DELETE FROM dash_sessions WHERE identity=?", (identity,))
            self.db.commit()
            return cur.rowcount

    # -- device code ----------------------------------------------------------

    def start(self) -> dict[str, Any]:
        """A code for the person to type in chat and a secret only this browser holds."""
        now = self.now()
        with self.lock:
            self.db.execute("DELETE FROM dash_codes WHERE expires<?", (now - 3600,))
            pending = self.db.execute("SELECT COUNT(*) FROM dash_codes WHERE state='pending' AND expires>=?", (now,)).fetchone()[0]
            if pending >= MAX_PENDING:
                raise TooManyCodes()
            code = "SY-" + "".join(secrets.choice(ALPHABET) for _ in range(8))
            secret = secrets.token_urlsafe(24)
            self.db.execute("INSERT INTO dash_codes (code, secret_hash, created, expires) VALUES (?,?,?,?)",
                            (code, _h(secret), now, now + CODE_TTL))
            self.db.commit()
        return {"code": code, "secret": secret, "expires_in": int(CODE_TTL)}

    def approve(self, code: str, identity: str, project: str) -> bool:
        """Called from chat with the verified sender. Single use; False for an unknown, used or expired code."""
        with self.lock:
            cur = self.db.execute("UPDATE dash_codes SET state='approved', identity=?, project=? WHERE code=? AND state='pending' AND expires>=?",
                                  (identity, project, normalize_code(code), self.now()))
            self.db.commit()
            return cur.rowcount == 1

    def poll(self, code: str, secret: str) -> tuple[str, str | None]:
        """("pending"|"expired"|"denied"|"ok", token). The token is handed over once."""
        with self.lock:
            row = self.db.execute("SELECT secret_hash, expires, state, identity, project FROM dash_codes WHERE code=?",
                                  (normalize_code(code),)).fetchone()
            if row is None or not hmac.compare_digest(row[0], _h(secret or "")):
                return "denied", None
            if row[1] < self.now() and row[2] == "pending":
                return "expired", None
            if row[2] == "pending":
                return "pending", None
            if row[2] != "approved":
                return "denied", None
            self.db.execute("UPDATE dash_codes SET state='done' WHERE code=?", (normalize_code(code),))
            self.db.commit()
        return "ok", self.issue(row[3], row[4])

    def sweep(self) -> None:
        with self.lock:
            self.db.execute("DELETE FROM dash_sessions WHERE expires<?", (self.now(),))
            self.db.execute("DELETE FROM dash_codes WHERE expires<?", (self.now() - 3600,))
            self.db.commit()
