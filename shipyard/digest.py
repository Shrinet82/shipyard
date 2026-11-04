"""Daily maintainer digest: review queue, assigned issues, your pull requests that need attention."""
from __future__ import annotations

import datetime as dt
import logging
import time
import zoneinfo
from typing import Callable

from .config import Config, Project
from .gatekeeper import Gatekeeper
from .github import GitHubError
from .policy import Role

log = logging.getLogger("shipyard.digest")


def build_digest(github, project: Project, login: str, name: str, when: dt.datetime) -> str:
    repo = project.repo
    prs = github.list_open_prs(repo.name)
    queue, attention = [], []
    for pr in prs:
        checks = github.checks(repo.name, pr.head_sha, repo.required_checks)
        if login in pr.requested_reviewers:
            queue.append(f"#{pr.number} {pr.title} (CI {checks.ci}) {pr.url}")
        if pr.author == login:
            problems = []
            if checks.ci == "red":
                problems.append("CI failed: " + ", ".join(checks.failing))
            if pr.mergeable is False:
                problems.append("merge conflict")
            if problems:
                attention.append(f"#{pr.number} {pr.title}: {'; '.join(problems)}")
    issues = [f"#{i['number']} {i['title']} {i['html_url']}" for i in github.assigned_issues(repo.name, login)]

    def section(title: str, rows: list[str]) -> str:
        return f"{title}: none" if not rows else f"{title}:\n  - " + "\n  - ".join(rows)

    return "\n".join([f"Digest for {name}, {when.strftime('%a %d %b')} ({repo.name})",
                      section("Review queue", queue), section("Assigned issues", issues),
                      section("Your pull requests that need attention", attention)])


class DigestScheduler:
    """Sends each maintainer's digest once a day at the configured local time; catches up after downtime."""

    def __init__(self, cfg: Config, gk: Gatekeeper, github, post: Callable[[str, str], None],
                 name_of: Callable[[str], str], now: Callable[[], float] = time.time):
        self.cfg, self.gk, self.github, self.post, self.name_of, self.now = cfg, gk, github, post, name_of, now
        self.tz = zoneinfo.ZoneInfo(cfg.digest.timezone)
        with gk.lock:
            gk.db.execute("CREATE TABLE IF NOT EXISTS digest_sent (day TEXT PRIMARY KEY)")

    def _local(self) -> dt.datetime:
        return dt.datetime.fromtimestamp(self.now(), self.tz)

    def tick(self) -> bool:
        """Send today's digests if it is time and they have not gone out. Returns True if they were sent."""
        local = self._local()
        due = local.replace(hour=self.cfg.digest.hour, minute=self.cfg.digest.minute, second=0, microsecond=0)
        day = local.strftime("%Y-%m-%d")
        if local < due:
            return False
        with self.gk.lock:
            cur = self.gk.db.execute("INSERT OR IGNORE INTO digest_sent (day) VALUES (?)", (day,))
            self.gk.db.commit()
        if cur.rowcount != 1:
            return False
        for project in self.cfg.projects.values():
            self.send_all(project, local)
        return True

    def send_all(self, project: Project, local: dt.datetime | None = None) -> None:
        if project.repo is None:
            return
        local = local or self._local()
        roles = self.cfg.policy.members.get(project.name, {})
        for sender, login in sorted(project.github_logins.items()):
            if roles.get(sender, Role.VIEWER) < Role.MAINTAINER:
                continue
            try:
                text = build_digest(self.github, project, login, self.name_of(sender), local)
            except GitHubError as exc:
                log.warning("digest for %s failed: %s", login, exc)
                continue
            self.gk.audit.write(project=project.name, actor="scheduler", event="digest", action="repo.digest", target=login)
            for room in sorted(project.maintainer_rooms or project.ops_rooms):
                self.post(room, text)
