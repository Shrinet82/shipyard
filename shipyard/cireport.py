"""What CI the repository has and what it produced, for the `ci` command and the agents. Read-only; every line comes from GitHub."""
from __future__ import annotations

from typing import Any

MAX_RUNS = 8                                  # runs whose artifacts are listed (one GitHub call each)


def _verdict(row: dict[str, Any]) -> str:
    return row.get("conclusion") or row.get("status") or "unknown"


def _size(n: Any) -> str:
    n = int(n or 0)
    return f"{n / 1_048_576:.1f} MB" if n >= 1_048_576 else f"{max(n // 1024, 1)} KB" if n else "0 KB"


def _actor(run: dict[str, Any]) -> str:
    return ((run.get("triggering_actor") or run.get("actor") or {}).get("login")) or "unknown"


def repo_overview(github: Any, repo: str, required: tuple[str, ...], workflow: str) -> str:
    """Every workflow in the repository with its latest run, and what Shipyard does with it."""
    flows = github.workflows(repo)
    if not flows:
        return f"{repo} has no GitHub Actions workflows. Shipyard reads CI from GitHub; add one under .github/workflows/."
    latest: dict[int, dict[str, Any]] = {}
    for run in github.recent_runs(repo):                    # newest first
        latest.setdefault(run.get("workflow_id"), run)
    lines = [f"CI in {repo}: {len(flows)} workflow(s)"]
    for f in flows:
        run = latest.get(f.get("id"))
        last = (f"latest run: {_verdict(run)} on {run.get('head_branch')} ({run.get('event')}, by {_actor(run)}) {run.get('html_url')}"
                if run else "no runs yet")
        role = "feeds the SBOM gate" if str(f.get("path", "")).startswith(workflow) else "not read for the SBOM gate"
        lines.append(f"- {f.get('name')} [{f.get('path')}, {f.get('state')}]: {last}; {role}")
    lines.append(f"Merge checks count only: {', '.join(required) or 'every check'}. Ask `ci <pr-number>` to see the checks and artifacts of one pull request.")
    return "\n".join(lines)


def commit_report(github: Any, repo: str, sha: str, label: str, required: tuple[str, ...], workflow: str) -> str:
    """The checks, the workflow runs (who started them, what they produced) and which of them Shipyard trusts, for one commit."""
    checks = github.check_runs(repo, sha)
    runs = github.workflow_runs(repo, sha)
    lines = [f"CI for {label} (commit {sha[:7]}): {len(checks)} check(s), {len(runs)} workflow run(s)"]
    seen = {c.get("name") for c in checks}
    for c in sorted(checks, key=lambda c: str(c.get("name"))):
        note = "required for merge" if c.get("name") in required else "not required, so merge ignores it"
        lines.append(f"- check {c.get('name')}: {_verdict(c)} ({note})")
    for name in required:
        if name not in seen:
            lines.append(f"- check {name}: missing (required for merge, but no CI reported it on this commit)")
    for r in runs[:MAX_RUNS]:
        arts = github.run_artifacts(repo, r["id"]) if r.get("id") else []
        names = {a.get("name") for a in arts if not a.get("expired")}
        trusted = str(r.get("path", "")).startswith(workflow) and r.get("event") in ("pull_request", "push")
        if trusted and {"sbom-spdx", "grype-report"} <= names:
            gate = "its SBOM is read by the gate"
        elif trusted:
            gate = "the gate expects artifacts sbom-spdx and grype-report here and they are missing"
        else:
            gate = "not the SBOM workflow, so the gate does not read it"
        listed = ", ".join(f"{a.get('name')} ({_size(a.get('size_in_bytes'))}{', expired' if a.get('expired') else ''})" for a in arts) or "none"
        lines.append(f"- run {r.get('name')} [{r.get('path')}]: {_verdict(r)}, {r.get('event')} on {r.get('head_branch')}, started by {_actor(r)}, "
                     f"{r.get('html_url')}\n    artifacts: {listed}; {gate}")
    if len(runs) > MAX_RUNS:
        lines.append(f"({len(runs) - MAX_RUNS} more run(s) not listed)")
    if not checks and not runs:
        lines.append("Nothing has reported on this commit yet.")
    return "\n".join(lines)

