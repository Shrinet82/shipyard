"""Where SBOM reports live: files per commit on disk, an index and the release records in SQLite."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .sbom import COMMIT, _mark_new_licences, parse_licences, render_html

SCHEMA = """
CREATE TABLE IF NOT EXISTS sbom_reports (
    commit_sha TEXT PRIMARY KEY, repo TEXT NOT NULL, pr INTEGER, ref TEXT NOT NULL DEFAULT '', created REAL NOT NULL,
    packages INTEGER NOT NULL, critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL, low INTEGER NOT NULL,
    decision TEXT NOT NULL, baseline TEXT, run_id INTEGER
);
CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, app TEXT NOT NULL, commit_sha TEXT NOT NULL,
    report_commit TEXT NOT NULL, ts REAL NOT NULL
);
"""
FILES = {"spdx": "sbom.spdx.json", "cyclonedx": "sbom.cdx.json", "scan": "grype.json", "html": "report.html"}


class SbomStore:
    def __init__(self, root: str | Path, db: sqlite3.Connection, lock: threading.RLock | None = None,
                 now: Callable[[], float] = time.time):
        self.root, self.db, self.lock, self.now = Path(root), db, lock or threading.RLock(), now
        self.root.mkdir(parents=True, exist_ok=True)
        with self.lock:
            self.db.executescript(SCHEMA)

    # -- reports ----------------------------------------------------------------

    @staticmethod
    def _check(commit: str) -> str:
        if not COMMIT.match(commit or ""):
            raise ValueError("not a commit id")
        return commit

    def save(self, report: dict[str, Any], raw: dict[str, bytes] | None = None) -> None:
        sha = self._check(report["commit"])
        final = self.root / sha
        tmp = Path(tempfile.mkdtemp(prefix=f".{sha}.", dir=self.root))
        try:
            for kind, data in (raw or {}).items():
                (tmp / FILES[kind]).write_bytes(data)
            (tmp / "report.json").write_text(json.dumps(report, sort_keys=True))
            (tmp / FILES["html"]).write_text(render_html(report))
            if final.exists():
                shutil.rmtree(final)
            os.replace(tmp, final)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        c = report["counts"]
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO sbom_reports (commit_sha, repo, pr, ref, created, packages, critical, high, medium, low, decision, baseline, run_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sha, report["repo"], report.get("pr"), report.get("ref", ""), report["collected_at"], report["package_count"],
                 c["critical"], c["high"], c["medium"], c["low"], report["decision"], report.get("baseline"), report.get("run_id")))
            self.db.commit()

    def get(self, commit: str) -> dict[str, Any] | None:
        try:
            path = self.root / self._check(commit) / "report.json"
        except ValueError:
            return None
        if not path.is_file():
            return None
        report = json.loads(path.read_text())
        if "licence_flags" not in report:                       # reports stored before licence flagging: read them from the saved SPDX
            report = self._add_licences(commit, report)
        return report

    def _add_licences(self, commit: str, report: dict[str, Any]) -> dict[str, Any]:
        spdx = self.root / commit / FILES["spdx"]
        flags: list[dict[str, Any]] = []
        if spdx.is_file():
            try:
                flags = parse_licences(json.loads(spdx.read_text()))
            except (ValueError, RecursionError):
                flags = []
        base = self.get(report["baseline"]) if report.get("baseline") and report["baseline"] != commit else None
        _mark_new_licences(flags, base)
        report = {**report, "licence_flags": flags}
        (self.root / commit / "report.json").write_text(json.dumps(report, sort_keys=True))
        (self.root / commit / FILES["html"]).write_text(render_html(report))
        return report

    def resolve(self, prefix: str) -> str | None:
        """A full commit id from an abbreviation (7 to 40 hex characters), or None."""
        try:
            self._check(prefix)
        except ValueError:
            return None
        with self.lock:
            rows = self.db.execute("SELECT commit_sha FROM sbom_reports WHERE commit_sha LIKE ? LIMIT 2", (prefix + "%",)).fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def latest(self, pr: int | None = None) -> dict[str, Any] | None:
        with self.lock:
            row = (self.db.execute("SELECT commit_sha FROM sbom_reports WHERE pr=? ORDER BY created DESC, rowid DESC LIMIT 1", (pr,))
                   if pr is not None else self.db.execute("SELECT commit_sha FROM sbom_reports ORDER BY created DESC, rowid DESC LIMIT 1")).fetchone()
        return self.get(row[0]) if row else None

    def list(self, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        with self.lock:
            total = self.db.execute("SELECT COUNT(*) FROM sbom_reports").fetchone()[0]
            rows = self.db.execute(
                "SELECT commit_sha, repo, pr, ref, created, packages, critical, high, medium, low, decision, baseline FROM sbom_reports"
                " ORDER BY created DESC, rowid DESC LIMIT ? OFFSET ?", (max(1, min(limit, 200)), max(0, offset))).fetchall()
        keys = ("commit", "repo", "pr", "ref", "created", "packages", "critical", "high", "medium", "low", "decision", "baseline")
        out = [dict(zip(keys, r)) for r in rows]
        with self.lock:
            deployed = {r[0] for r in self.db.execute("SELECT report_commit FROM releases").fetchall()} | \
                       {r[0] for r in self.db.execute("SELECT commit_sha FROM releases").fetchall()}
        for r in out:
            r["deployed"] = r["commit"] in deployed
        return out, total

    def file_path(self, commit: str, kind: str) -> Path | None:
        if kind not in FILES:
            return None
        try:
            p = self.root / self._check(commit) / FILES[kind]
        except ValueError:
            return None
        return p if p.is_file() else None

    def set_decision(self, commit: str, decision: str) -> None:
        report = self.get(commit)
        if report is None:
            return
        report["decision"] = decision
        report_dir = self.root / self._check(commit)
        (report_dir / "report.json").write_text(json.dumps(report, sort_keys=True))
        (report_dir / FILES["html"]).write_text(render_html(report))
        with self.lock:
            self.db.execute("UPDATE sbom_reports SET decision=? WHERE commit_sha=?", (decision, commit))
            self.db.commit()

    # -- releases -----------------------------------------------------------------

    def record_release(self, project: str, app: str, commit: str, report_commit: str | None = None) -> None:
        with self.lock:
            self.db.execute("INSERT INTO releases (project, app, commit_sha, report_commit, ts) VALUES (?,?,?,?,?)",
                            (project, app, commit, report_commit or commit, self.now()))
            self.db.commit()

    def last_release(self, project: str, app: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.db.execute("SELECT commit_sha, report_commit, ts FROM releases WHERE project=? AND app=? ORDER BY id DESC LIMIT 1",
                                (project, app)).fetchone()
        return {"commit": r[0], "report_commit": r[1], "ts": r[2]} if r else None

    def baseline(self, project: str, app: str | None) -> dict[str, Any] | None:
        """The report of the last release we deployed: what a new commit is compared with."""
        if not app:
            return None
        rel = self.last_release(project, app)
        if rel is None:
            return None
        return self.get(rel["report_commit"]) or self.get(rel["commit"])
