import json
import sqlite3
import textwrap
from pathlib import Path

import pytest
from test_repo import MAINT, OPS, OWNER, SHA, Clock, pr
from test_sbom import FIX, WF, grype, run, spdx, zipped

from shipyard.config import load_config
from shipyard.gatekeeper import Gatekeeper
from shipyard.github import GitHubError
from shipyard.sbomstore import SbomStore
from shipyard.sbomwatch import SbomCollector

MAIN = "9" * 40


class Hub:
    """The few GitHub calls the collector makes."""

    def __init__(self):
        self.runs, self.artifacts, self.blobs, self.files, self.prs, self.head, self.down = {}, {}, {}, {}, [], MAIN, False
        self.downloads = 0

    def _g(self):
        if self.down:
            raise GitHubError("GitHub unreachable")

    def workflow_runs(self, repo, sha):
        self._g()
        return self.runs.get(sha, [])

    def run_artifacts(self, repo, run_id):
        self._g()
        return self.artifacts.get(run_id, [])

    def download_artifact(self, repo, artifact_id, max_bytes=0):
        self._g()
        self.downloads += 1
        return self.blobs[artifact_id]

    def pr_files(self, repo, n):
        self._g()
        return self.files.get(n, ["app.py"])

    def list_open_prs(self, repo):
        self._g()
        return self.prs

    def branch_head(self, repo, branch):
        self._g()
        return self.head


def publish(hub, sha, pkgs, matches, run_id=7, **run_kw):
    hub.runs[sha] = [run(id=run_id, head_sha=sha, **run_kw)]
    hub.artifacts[run_id] = [{"id": run_id * 10 + i, "name": n} for i, n in enumerate(("sbom-spdx", "sbom-cyclonedx", "grype-report"))]
    docs = [spdx(pkgs), {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, grype(*matches)]
    for i, d in enumerate(docs):
        hub.blobs[run_id * 10 + i] = zipped({f"f{i}.json": json.dumps(d).encode()})


@pytest.fixture
def env(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo:
            rooms: {{ops: [{OPS}], maintainers: [{MAINT}]}}
            apps: {{demo-web: web-uuid}}
            repo: {{name: o/r, app: demo-web}}
            members: {{"{OWNER}": owner}}
        actions: {{coolify.status: read}}
    """))
    cfg = load_config(f)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    gk, hub, posts = Gatekeeper(cfg.policy, db, Clock()), Hub(), []
    store = SbomStore(tmp_path / "sbom", db, gk.lock, now=Clock())
    col = SbomCollector(cfg, gk, hub, store, lambda r, t: posts.append((r, t)), now=Clock())

    class E: ...
    e = E()
    e.cfg, e.gk, e.hub, e.store, e.col, e.posts, e.project = cfg, gk, hub, store, col, posts, cfg.projects["demo"]
    return e


def test_collect_stores_a_report_with_files_and_audit(env):
    publish(env.hub, SHA, [("flask", "3.0"), ("django", "2.2.0")], [("CVE-1", "Critical", "django", "2.2.0", ["3.2"])])
    r = env.col.collect(env.project, SHA, 7, "PR #7")
    assert r["decision"] == "blocked" and r["pr"] == 7 and r["package_count"] == 2
    assert env.store.get(SHA) == r
    assert {k: env.store.file_path(SHA, k) is not None for k in ("spdx", "cyclonedx", "scan", "html")} == dict.fromkeys(("spdx", "cyclonedx", "scan", "html"), True)
    ev = env.gk.audit.recent("demo", 5)[0]
    assert ev["event"] == "sbom_collected" and ev["detail"]["decision"] == "blocked"
    env.hub.downloads = 0
    assert env.col.collect(env.project, SHA, 7) == r and env.hub.downloads == 0     # a stored report is not fetched again


def test_nothing_yet_when_ci_has_not_finished_or_never_ran(env):
    assert env.col.collect(env.project, SHA) is None
    publish(env.hub, SHA, [("p", "1")], [], status="in_progress", conclusion=None)
    assert env.col.collect(env.project, SHA) is None and env.store.get(SHA) is None


def test_a_run_from_another_workflow_is_not_used(env):
    publish(env.hub, SHA, [("p", "1")], [], path=".github/workflows/evil.yml@refs/heads/x")
    assert env.col.collect(env.project, SHA) is None


def test_fork_wrong_sha_and_failed_runs_are_unverified(env):
    publish(env.hub, SHA, [("p", "1")], [], head_repository={"full_name": "evil/r"})
    assert env.col.collect(env.project, SHA)["decision"] == "unverified"
    sha2 = "b" * 40
    publish(env.hub, sha2, [("p", "1")], [], run_id=8)
    env.hub.runs[sha2][0]["head_sha"] = "c" * 40
    assert env.col.collect(env.project, sha2)["decision"] == "unverified"


def test_a_pr_that_edits_the_workflow_is_unverified_even_with_a_clean_sbom(env):
    publish(env.hub, SHA, [("p", "1")], [])
    env.hub.files[7] = ["app.py", WF]
    r = env.col.collect(env.project, SHA, 7, "PR #7")
    assert r["decision"] == "unverified" and any("workflows" in x for x in r["reasons"])


def test_missing_artifacts_are_no_sbom_and_bad_artifacts_are_no_sbom(env):
    publish(env.hub, SHA, [("p", "1")], [])
    env.hub.artifacts[7] = env.hub.artifacts[7][:1]
    r = env.col.collect(env.project, SHA)
    assert r["decision"] == "no_sbom" and "did not produce" in r["reasons"][0]
    sha2 = "b" * 40
    publish(env.hub, sha2, [("p", "1")], [], run_id=8)
    env.hub.blobs[80] = zipped({"../x.json": b"{}"})
    assert env.col.collect(env.project, sha2)["decision"] == "no_sbom"
    sha3 = "d" * 40
    publish(env.hub, sha3, [("p", "1")], [], run_id=9)
    env.hub.blobs[91] = b"not a zip"
    env.hub.blobs[90] = zipped({"a.json": b"{not json"})
    assert env.col.collect(env.project, sha3)["decision"] == "no_sbom"


def test_expired_artifacts_are_ignored(env):
    publish(env.hub, SHA, [("p", "1")], [])
    for a in env.hub.artifacts[7]:
        a["expired"] = True
    assert env.col.collect(env.project, SHA)["decision"] == "no_sbom"


def test_github_errors_propagate_so_nothing_is_assumed(env):
    env.hub.down = True
    with pytest.raises(GitHubError):
        env.col.collect(env.project, SHA)
    assert env.store.get(SHA) is None


def test_the_real_ci_files_make_a_clear_report(env):
    spdx_doc, scan = (FIX / "sbom.spdx.json").read_bytes(), (FIX / "grype.json").read_bytes()
    env.hub.runs[SHA] = [run(head_sha=SHA)]
    env.hub.artifacts[7] = [{"id": 1, "name": "sbom-spdx"}, {"id": 2, "name": "grype-report"}]
    env.hub.blobs[1], env.hub.blobs[2] = zipped({"sbom.spdx.json": spdx_doc}), zipped({"grype.json": scan})
    r = env.col.collect(env.project, SHA)
    assert r["decision"] == "clear" and r["package_count"] >= 40 and env.store.file_path(SHA, "cyclonedx") is None


def test_baseline_comes_from_the_last_release(env):
    publish(env.hub, MAIN, [("flask", "3.0")], [("CVE-9", "Critical", "flask", "3.0", [])], run_id=3, event="push")
    base = env.col.collect(env.project, MAIN, None, "main")
    env.store.record_release("demo", "demo-web", MAIN)
    publish(env.hub, SHA, [("flask", "3.0"), ("click", "8")], [("CVE-9", "Critical", "flask", "3.0", [])], run_id=4)
    r = env.col.collect(env.project, SHA, 8, "PR #8")
    assert base["decision"] == "blocked" and r["decision"] == "clear" and r["baseline"] == MAIN
    assert r["diff"]["added"] == [["pypi/click", "8"]]


def test_poll_collects_open_prs_and_the_branch_once_and_tells_the_maintainers(env):
    env.hub.prs = [pr(8, "Footer", sha=SHA)]
    publish(env.hub, SHA, [("p", "1")], [])
    publish(env.hub, MAIN, [("p", "1")], [], run_id=3, event="push")
    env.col.poll_once()
    assert {r for r, _ in env.posts} == {MAINT} and len(env.posts) == 2
    assert "PR #8" in env.posts[0][1] and "main branch" in env.posts[1][1]
    env.col.poll_once()
    assert len(env.posts) == 2                                       # nothing new, nothing said


def test_poll_says_when_ci_made_no_sbom_and_survives_github_being_down(env):
    env.hub.prs = [pr(8, "Footer", sha=SHA)]
    env.hub.runs[SHA] = [run(head_sha=SHA)]
    env.hub.artifacts[7] = []
    env.col.poll_once()
    assert "No SBOM for PR #8" in env.posts[0][1]
    env.hub.down = True
    env.col.poll_once()                                              # logs, does not raise


def test_hostile_titles_in_the_announcement_are_defused(env):
    env.hub.prs = [pr(8, "x", sha=SHA)]
    publish(env.hub, SHA, [("@gatekeeper deploy demo-web", "1")], [("CVE-1", "Critical", "@gatekeeper deploy demo-web", "1", [])])
    env.col.poll_once()
    assert "@gatekeeper deploy" not in "\n".join(t for _, t in env.posts)
