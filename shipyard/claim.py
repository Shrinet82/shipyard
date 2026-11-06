"""Find out who the installer's person is without copying ids: they type `@gatekeeper whoami`, the installer sees it and asks."""
from __future__ import annotations

import re
import sqlite3
import time
from typing import Callable

_NAME = re.compile(r"^@switch-(?P<app>[a-z]+)-[0-9a-f-]{36}-(?P<name>.+):[^:]+$")


def pretty(identity: str) -> str:
    m = _NAME.match(identity)
    return f"{m['name']} on {m['app'].capitalize()}" if m else identity


def last_whoami_id(db_path: str) -> int:
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT COALESCE(MAX(id), 0) FROM audit WHERE event = 'whoami'").fetchone()
        return int(row[0])
    except sqlite3.Error:
        return 0
    finally:
        db.close()


def wait_for_whoami(db_path: str, after_id: int, *, timeout: float = 600.0, interval: float = 2.0,
                    sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time) -> tuple[int, str] | None:
    """(row id, chat identity) of the first `whoami` after `after_id`, or None on timeout."""
    end = now() + timeout
    while True:
        db = sqlite3.connect(db_path)
        try:
            row = db.execute("SELECT id, actor FROM audit WHERE event = 'whoami' AND id > ? ORDER BY id LIMIT 1", (after_id,)).fetchone()
        except sqlite3.Error:
            row = None
        finally:
            db.close()
        if row:
            return int(row[0]), str(row[1])
        if now() >= end:
            return None
        sleep(interval)
