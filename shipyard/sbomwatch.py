"""Collect each commit's SBOM and scan from CI, store a report, and tell the maintainers.

Polling, like the PR watcher: GitHub cannot reach the VM. A commit is collected once its CI run has finished;
until then there is simply no report (and a deploy of it is gated).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable

from .config import Config, Project
from .gatekeeper import Gatekeeper
from .github import GitHubError
from .sbom import EXPECTED_ARTIFACTS, SbomError, build_report, evaluate_trust, load_json, read_artifact_json, summary
from .sbomstore import SbomStore

log = logging.getLogger("shipyard.sbom")


class SbomCollector:
    def __init__(self, cfg: Config, gk: Gatekeeper, github, store: SbomStore, post: Callable[[str, str], None],
                 now: Callable[[], float] = time.time):
        self.cfg, self.gk, self.github, self.store, self.post, self.now = cfg, gk, github, store, post, now

    # -- one commit ------------------------------------------------------------

    def collect(self, project: Project, commit: str, pr: int | None = None, ref: str = "") -> dict[str, Any] | None:
        """The report for `commit`: stored, or built now if its CI run has finished. None means "not yet" or "no CI run"."""
        existing = self.store.get(commit)
        if existing is not None:
            return existing
        repo, workflow = project.repo, self.cfg.sbom.workflow
        runs = [r for r in self.github.workflow_runs(repo.name, commit) if str(r.get("path", "")).startswith(workflow)]
        if not runs:
            return None
        run = max(runs, key=lambda r: r.get("run_number", 0))
        if run.get("status") != "completed":
            return None
        arts = {a["name"]: a for a in self.github.run_artifacts(repo.name, run["id"]) if not a.get("expired")}
        pr_files = self.github.pr_files(repo.name, pr) if pr else None
        trust = evaluate_trust(run=run, repo=repo.name, sha=commit, workflow=workflow, artifacts=set(arts), pr_files=pr_files)
        raw: dict[str, bytes] = {}
        try:
            if "sbom-spdx" not in arts or "grype-report" not in arts:
                raise SbomError("CI did not produce the SBOM and scan artifacts")
            docs: dict[str, Any] = {}
            for name, kind in EXPECTED_ARTIFACTS.items():
                if name in arts:
                    raw[kind] = read_artifact_json(self.github.download_artifact(repo.name, arts[name]["id"]))
                    if kind != "cyclonedx":                  # kept for download; the report is built from SPDX and the scan
                        docs[kind] = load_json(raw[kind])
            baseline = self.store.baseline(project.name, repo.app)
            report = build_report(commit=commit, repo=repo.name, pr=pr, ref=ref, run=run, workflow=workflow, sbom_doc=docs["spdx"],
                                  grype_doc=docs["scan"], baseline=baseline, trust=trust, now=self.now())
        except SbomError as exc:
            report = {"commit": commit, "repo": repo.name, "pr": pr, "ref": ref, "run_id": run.get("id"), "workflow": workflow,
                      "collected_at": self.now(), "format": "", "package_count": 0, "packages": {}, "findings": [],
                      "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "fixable": 0, "baseline": None,
                      "diff": {"added": [], "removed": [], "upgraded": []}, "trust": {"ok": False, "reasons": [str(exc)]},
                      "blocking": [], "reasons": [str(exc)], "decision": "no_sbom"}
            raw = {}
        self.store.save(report, raw)
        self.gk.audit.write(project=project.name, actor="ci", event="sbom_collected", action="sbom.read", target=commit[:7],
                            decision=report["decision"], critical=report["counts"]["critical"], pr=pr)
        return report

    # -- the loop --------------------------------------------------------------

    def poll_once(self) -> None:
        for project in self.cfg.projects.values():
            if project.repo is None:
                continue
            try:
                self._poll_project(project)
            except GitHubError as exc:
                log.warning("SBOM poll of %s failed: %s", project.repo.name, exc)

    def _poll_project(self, project: Project) -> None:
        repo = project.repo
        targets: list[tuple[str, int | None, str]] = [(p.head_sha, p.number, f"PR #{p.number}") for p in self.github.list_open_prs(repo.name)]
        targets.append((self.github.branch_head(repo.name, repo.branch), None, repo.branch))
        for sha, pr, ref in targets:
            if self.store.get(sha) is not None:
                continue
            report = self.collect(project, sha, pr, ref)
            if report is not None:
                self._announce(project, report, ref)

    def _announce(self, project: Project, report: dict[str, Any], ref: str) -> None:
        if report["decision"] == "no_sbom":
            text = f"No SBOM for {ref} (commit {report['commit'][:7]}): {report['reasons'][0]}"
        else:
            text = summary(report, ref if ref.startswith("PR #") else f"{ref} branch")
        for room in sorted(project.maintainer_rooms or project.ops_rooms):
            self.post(room, text)
