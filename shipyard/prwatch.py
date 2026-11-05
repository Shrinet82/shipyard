"""Poll GitHub and announce pull request changes once each: opened, CI result, conflict, stale, closed.

GitHub cannot reach the VM (no public port), so we ask it. State lives in SQLite, so a restart
never repeats an announcement.
"""
from __future__ import annotations

import logging
import time
from typing import Callable

from .config import Config, Project
from .gatekeeper import Gatekeeper
from .github import GitHubError, PR

log = logging.getLogger("shipyard.prwatch")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pr_state (
    repo TEXT NOT NULL, number INTEGER NOT NULL,
    ci_key TEXT NOT NULL DEFAULT '',        -- "<sha>:<green|red>" last announced
    conflict INTEGER NOT NULL DEFAULT 0,
    stale_at REAL NOT NULL DEFAULT 0,
    closed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo, number)
);
CREATE TABLE IF NOT EXISTS digest_sent (day TEXT PRIMARY KEY);
"""
STALE_REPEAT = 24 * 3600.0


class PrWatcher:
    def __init__(self, cfg: Config, gk: Gatekeeper, github, post: Callable[[str, str], None], now: Callable[[], float] = time.time, flow=None):
        self.cfg, self.gk, self.github, self.post, self.now = cfg, gk, github, post, now
        self.flow = flow                       # the Board, when it is on: pull requests that say "Fixes SY-12" are linked to their tickets
        with gk.lock:
            gk.db.executescript(SCHEMA)

    def _state(self, repo: str, n: int) -> dict | None:
        with self.gk.lock:
            r = self.gk.db.execute("SELECT ci_key, conflict, stale_at, closed FROM pr_state WHERE repo=? AND number=?", (repo, n)).fetchone()
        return dict(zip(("ci_key", "conflict", "stale_at", "closed"), r)) if r else None

    def _save(self, repo: str, n: int, **fields) -> None:
        with self.gk.lock:
            self.gk.db.execute("INSERT OR IGNORE INTO pr_state (repo, number) VALUES (?, ?)", (repo, n))
            for k, v in fields.items():
                self.gk.db.execute(f"UPDATE pr_state SET {k}=? WHERE repo=? AND number=?", (v, repo, n))
            self.gk.db.commit()

    def _announce(self, project: Project, pr_number: int, kind: str, text: str) -> None:
        self.gk.audit.write(project=project.name, actor="github", event="pr_alert", action=kind, target=str(pr_number))
        for room in sorted(project.maintainer_rooms or project.ops_rooms):
            self.post(room, text)

    def poll_once(self) -> None:
        for project in self.cfg.projects.values():
            if project.repo is None:
                continue
            try:
                self._poll_project(project)
            except GitHubError as exc:
                log.warning("poll of %s failed: %s", project.repo.name, exc)   # fail quietly, try again next time

    def _poll_project(self, project: Project) -> None:
        repo = project.repo
        open_prs = self.github.list_open_prs(repo.name)
        for pr in open_prs:
            self._one(project, pr)
        # PRs we knew about that are no longer open
        open_numbers = {p.number for p in open_prs}
        with self.gk.lock:
            known = [r[0] for r in self.gk.db.execute("SELECT number FROM pr_state WHERE repo=? AND closed=0", (repo.name,))]
        for n in known:
            if n not in open_numbers:
                pr = self.github.pr(repo.name, n)
                word = "merged" if pr.state == "merged" else "closed"
                self._announce(project, n, f"pr_{word}", f"PR #{n} {word}: {pr.title} {pr.url}")
                self._save(repo.name, n, closed=1)
                if self.flow is not None:
                    self.flow.on_pr_finished(project, n, pr.state == "merged", pr.title)

    def _one(self, project: Project, pr: PR) -> None:
        repo = project.repo
        st = self._state(repo.name, pr.number)
        if st is None:
            self._announce(project, pr.number, "pr_opened", f"PR #{pr.number} opened by {pr.author}: {pr.title} {pr.url}")
            self._save(repo.name, pr.number)
            st = self._state(repo.name, pr.number)

        checks = self.github.checks(repo.name, pr.head_sha, repo.required_checks)
        if self.flow is not None:
            self.flow.on_pr(project, pr, checks.ci)
        if checks.ci in ("green", "red"):
            key = f"{pr.head_sha}:{checks.ci}"
            if st["ci_key"] != key:
                if checks.ci == "green":
                    text = f"CI passed on PR #{pr.number}: {pr.title}"
                else:
                    text = f"CI failed on PR #{pr.number} ({', '.join(checks.failing)}): {pr.title} {pr.url}"
                self._announce(project, pr.number, f"ci_{checks.ci}", text)
                self._save(repo.name, pr.number, ci_key=key)

        if pr.mergeable is False and not st["conflict"]:
            self._announce(project, pr.number, "pr_conflict", f"PR #{pr.number} conflicts with {pr.base}: {pr.title} {pr.url}")
            self._save(repo.name, pr.number, conflict=1)
        elif pr.mergeable is True and st["conflict"]:
            self._save(repo.name, pr.number, conflict=0)

        idle = self.now() - pr.updated_at
        if idle > self.cfg.github.stale_hours * 3600 and self.now() - st["stale_at"] > STALE_REPEAT:
            hours = int(idle // 3600)
            self._announce(project, pr.number, "pr_stale", f"PR #{pr.number} has had no activity for {hours} hours: {pr.title} {pr.url}")
            self._save(repo.name, pr.number, stale_at=self.now())
