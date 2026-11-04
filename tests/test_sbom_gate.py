import re
import sqlite3
import textwrap

import pytest
from test_repo import DEPLOYER, M1, M2, MAINT, NOW, OPS, OWNER, SHA, VIEWER, Clock, FakeCoolify, FakeGitHub, pr
from test_sbom import SHA2, report as mkreport

from shipyard.config import load_config
from shipyard.gatekeeper import Gatekeeper
from shipyard.github import GitHubError
from shipyard.sbomstore import SbomStore
from shipyard.service import Service

MAIN = "9" * 40
MERGED = "f" * 40
CRIT = [("CVE-2026-0001", "Critical", "django", "2.2.0", ["3.2"])]


class GateGitHub(FakeGitHub):
    head = MAIN

    def pr(self, repo, n):
        self._guard()
        if n not in self.prs:
            raise GitHubError("GitHub answered 404")
        return self.prs[n]

    def branch_head(self, repo, branch):
        self._guard()
        return self.head


class GateCoolify(FakeCoolify):
    def rollback(self, uuid, tag=None):
        self.deploys.append(("rollback", uuid, tag))
        return "rolled back"


class FakeCollector:
    """Stands in for SbomCollector: reports by commit, and 'GitHub is down' on demand."""

    def __init__(self, store):
        self.store, self.reports, self.down = store, {}, False

    def add(self, commit, pkgs, matches, pr_=None):
        r = mkreport(pkgs, matches, commit=commit)
        r["pr"] = pr_
        self.reports[commit] = r

    def collect(self, project, commit, pr=None, ref=""):
        if self.down:
            raise GitHubError("GitHub unreachable")
        r = self.reports.get(commit)
        if r is not None:
            self.store.save(r)                                     # like the real collector
        return r


@pytest.fixture
def env(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo:
            rooms: {{ops: [{OPS}], maintainers: [{MAINT}]}}
            apps: {{demo-web: web-uuid}}
            repo: {{name: o/r, app: demo-web, required_checks: [test, sbom]}}
            members: {{"{OWNER}": owner, "{M1}": maintainer, "{M2}": maintainer, "{DEPLOYER}": deployer, "{VIEWER}": viewer}}
        actions:
          coolify.deploy: change
          coolify.rollback: change
          coolify.status: read
          repo.merge: dangerous
          repo.pr_list: read
          repo.pr_status: read
          audit.read: read
          sbom.read: read
        approval_overrides: {{coolify.rollback: true}}
    """))
    cfg = load_config(f)
    clock = Clock()
    db = sqlite3.connect(":memory:", check_same_thread=False)
    gk = Gatekeeper(cfg.policy, db, clock)
    gh, cool, posts = GateGitHub(), GateCoolify(), []
    store = SbomStore(tmp_path / "sbom", db, now=clock)
    col = FakeCollector(store)
    svc = Service(cfg, gk, cool, lambda r, t: posts.append((r, t)), now=clock, github=gh, sbom=col)

    class E: ...
    e = E()
    e.cfg, e.svc, e.gk, e.gh, e.cool, e.posts, e.clock, e.col, e.store, e.n = cfg, svc, gk, gh, cool, posts, clock, col, store, 0

    def say(sender, body, name=None):
        e.n += 1
        svc.handle_event({"type": "message", "room_id": OPS, "payload": {
            "message_id": f"m{e.n}", "sender": sender, "sender_name": name or sender.split("-")[-1].split(":")[0],
            "sender_kind": None, "body": "@gatekeeper " + body, "addressed": True}})

    e.say = say
    e.last = lambda: posts[-1][1]
    e.events = lambda: [(r["event"], r["action"]) for r in gk.audit.recent("demo", 50)]
    e.rows = lambda ev: [r for r in gk.audit.recent("demo", 50) if r["event"] == ev]
    return e


def aid(e):
    return re.search(r"id ([0-9a-f]{8})", e.last()).group(1)


def baseline(e):
    """A clean release already deployed: python 3.12, no CVEs."""
    e.col.add(MAIN, [("flask", "3.0")], [])
    e.store.save(e.col.reports[MAIN])
    e.store.record_release("demo", "demo-web", MAIN)


# --- merge ---------------------------------------------------------------------------------------------

def test_clean_pr_merges_with_no_gate_and_becomes_the_baseline(env):
    baseline(env)
    env.col.add(SHA, [("flask", "3.1")], [], pr_=8)
    env.gh.set(pr(8, "Bump the footer"))
    env.say(M1, "merge 8")
    assert "Approval needed" in env.last() and "BLOCKED" not in env.last()
    env.say(M2, f"approve {aid(env)}")
    assert env.gh.merges == [(8, SHA, "squash")] and env.cool.deploys == ["web-uuid"]
    assert env.store.last_release("demo", "demo-web")["commit"] == MERGED
    assert env.store.baseline("demo", "demo-web")["commit"] == SHA
    assert ("gate_blocked", "repo.merge") not in env.events()


def test_new_critical_blocks_a_maintainer_but_an_owner_can_override(env):
    baseline(env)
    env.col.add(SHA, [("flask", "3.0"), ("django", "2.2.0")], CRIT, pr_=7)
    env.gh.set(pr(7, "Add django (demo only)"))
    env.say(M1, "merge 7")
    assert env.last().startswith("BLOCKED by the SBOM gate") and "CVE-2026-0001" in env.last() and "Only an owner" in env.last()
    a = aid(env)
    env.say(M2, f"approve {a}")                                   # another maintainer: refused
    assert env.last().startswith("Denied") and "only an owner" in env.last() and not env.gh.merges
    env.say(OWNER, f"approve {a}")                                # the owner: merges and deploys
    assert env.gh.merges == [(7, SHA, "squash")] and env.cool.deploys == ["web-uuid"]
    blocked, over = env.rows("gate_blocked")[0], env.rows("gate_override")[0]
    assert blocked["detail"]["cves"] == ["CVE-2026-0001"] and over["detail"]["cves"] == ["CVE-2026-0001"]
    assert over["actor"] == OWNER and over["detail"]["requester"] == M1
    env.say(OWNER, f"approve {a}")                                # single use
    assert env.last().startswith("Denied") and len(env.gh.merges) == 1


def test_the_chat_audit_shows_the_cves_of_a_block_and_an_override(env):
    baseline(env)
    env.col.add(SHA, [("django", "2.2.0")], CRIT, pr_=7)
    env.gh.set(pr(7))
    env.say(M1, "merge 7")
    env.say(OWNER, f"approve {aid(env)}")
    env.say(OWNER, "audit 12")
    lines = env.last().splitlines()
    assert any("gate_blocked" in ln and "CVE-2026-0001" in ln for ln in lines) and any("gate_override" in ln and "CVE-2026-0001" in ln for ln in lines)


def test_override_is_pinned_to_the_commit(env):
    baseline(env)
    env.col.add(SHA, [("django", "2.2.0")], CRIT, pr_=7)
    env.gh.set(pr(7))
    env.say(M1, "merge 7")
    a = aid(env)
    env.gh.set(pr(7, sha=SHA2))                                   # a new commit lands after the request
    env.say(OWNER, f"approve {a}")
    assert "branch changed after approval" in env.last() and not env.gh.merges and not env.rows("gate_override")


def test_a_critical_that_shows_up_after_the_request_is_caught_at_execution(env):
    baseline(env)
    env.col.add(SHA, [("flask", "3.0")], [], pr_=8)
    env.gh.set(pr(8))
    env.say(M1, "merge 8")
    a = aid(env)
    env.col.add(SHA, [("flask", "3.0")], CRIT, pr_=8)             # the scan now says otherwise
    env.say(OWNER, f"approve {a}")
    assert "SBOM gate now blocks it" in env.last() and not env.gh.merges


def test_no_sbom_means_blocked_not_assumed_safe(env):
    env.gh.set(pr(8))
    env.say(M1, "merge 8")
    assert env.last().startswith("BLOCKED") and "no SBOM" in env.last()
    assert env.rows("gate_blocked")[0]["detail"]["cves"] == ["no-sbom"]
    env.say(M2, f"approve {aid(env)}")
    assert env.last().startswith("Denied") and not env.gh.merges


def test_an_unverified_sbom_is_blocked(env):
    r = mkreport([("p", "1")], [])
    r["decision"], r["trust"] = "unverified", {"ok": False, "reasons": ["this change edits .github/workflows/"]}
    env.col.reports[SHA] = r
    env.gh.set(pr(8))
    env.say(M1, "merge 8")
    assert env.last().startswith("BLOCKED") and "unverified" in env.last()
    assert env.rows("gate_blocked")[0]["detail"]["cves"] == ["unverified-sbom"]


def test_github_down_while_checking_the_gate_refuses_and_creates_no_approval(env):
    env.gh.set(pr(8))
    env.col.down = True
    env.say(M1, "merge 8")
    assert env.last().startswith("Denied") and "SBOM gate could not be checked" in env.last()
    assert env.gk.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


def test_the_owner_merging_their_own_blocked_pr_may_confirm_it_themselves(env):
    env.col.add(SHA, [("django", "2.2.0")], CRIT, pr_=7)
    env.gh.set(pr(7))
    env.say(OWNER, "merge 7")
    assert env.last().startswith("BLOCKED")
    env.say(OWNER, f"approve {aid(env)}")
    assert env.gh.merges


def test_an_override_stops_the_same_cve_blocking_the_next_pr(env):
    env.col.add(SHA, [("django", "2.2.0")], CRIT, pr_=7)
    env.gh.set(pr(7))
    env.say(M1, "merge 7")
    env.say(OWNER, f"approve {aid(env)}")
    assert env.cool.deploys
    env.col.add(SHA2, [("django", "2.2.0"), ("click", "8")], CRIT, pr_=9)
    env.gh.set(pr(9, sha=SHA2))
    env.say(M1, "merge 9")
    assert "Approval needed" in env.last() and "BLOCKED" not in env.last()


def test_a_viewer_learns_nothing_about_the_gate(env):
    env.gh.set(pr(8))
    env.say(VIEWER, "merge 8")
    assert env.last().startswith("Denied") and "needs role" in env.last() and "SBOM" not in env.last()


# --- direct deploy ---------------------------------------------------------------------------------------

def test_deploy_of_a_clean_head_runs_at_once_pinned_and_recorded(env):
    baseline(env)
    env.gh.head = SHA2
    env.col.add(SHA2, [("flask", "3.1")], [])
    env.say(DEPLOYER, "deploy demo-web")
    assert env.cool.deploys == ["web-uuid"] and "Done: deploy demo-web" in env.last()
    assert env.store.last_release("demo", "demo-web")["commit"] == SHA2


def test_deploy_of_a_blocked_head_needs_the_owner(env):
    baseline(env)
    env.gh.head = SHA2
    env.col.add(SHA2, [("django", "2.2.0")], CRIT)
    env.say(DEPLOYER, "deploy demo-web")
    assert env.last().startswith("BLOCKED") and not env.cool.deploys
    a = aid(env)
    env.say(M1, f"approve {a}")
    assert env.last().startswith("Denied") and "only an owner" in env.last() and not env.cool.deploys
    env.say(OWNER, f"approve {a}")
    assert env.cool.deploys == ["web-uuid"] and env.rows("gate_override")
    assert env.store.last_release("demo", "demo-web")["commit"] == SHA2


def test_deploy_with_the_branch_moving_is_refused(env):
    baseline(env)
    env.gh.head = SHA2
    env.col.add(SHA2, [("django", "2.2.0")], CRIT)
    env.say(DEPLOYER, "deploy demo-web")
    a = aid(env)
    env.gh.head = "8" * 40
    env.say(OWNER, f"approve {a}")
    assert "branch changed" in env.last() and not env.cool.deploys


def test_deploy_with_no_sbom_for_the_head_is_gated(env):
    env.gh.head = SHA2
    env.say(DEPLOYER, "deploy demo-web")
    assert env.last().startswith("BLOCKED") and "no SBOM" in env.last() and not env.cool.deploys


def test_rollback_is_never_gated(env):
    env.gh.head = SHA2                                              # head has no SBOM at all
    env.say(DEPLOYER, "rollback demo-web")
    assert "Approval needed" in env.last() and "BLOCKED" not in env.last()
    env.say(M1, f"approve {aid(env)}")
    assert "Done: rollback demo-web" in env.last() and env.cool.deploys == [("rollback", "web-uuid", None)]


def test_agents_cannot_smuggle_a_gate_or_skip_it(env):
    env.gh.head = SHA2
    env.col.add(SHA2, [("django", "2.2.0")], CRIT)
    env.say(M1, "please deploy demo-web")
    mid = f"m{env.n}"
    out = env.svc.propose(action="coolify.deploy", target="demo-web", args={"gate": [], "sha": "0" * 40}, message_id=mid, agent="ops-agent")
    assert out["status"] == "awaiting_human_approval"
    assert "BLOCKED by the SBOM gate" in env.last()
    a = aid(env)
    env.say(M2, f"approve {a}")
    assert env.last().startswith("Denied") and not env.cool.deploys
    env.say(OWNER, f"approve {a}")
    assert env.cool.deploys == ["web-uuid"]


def test_agent_proposal_for_a_clean_head_still_needs_a_human(env):
    baseline(env)
    env.gh.head = SHA2
    env.col.add(SHA2, [("flask", "3.1")], [])
    env.say(M1, "deploy demo-web")
    # the maintainer's own deploy ran; now an agent proposes another for a new message
    env.cool.deploys.clear()
    env.say(M1, "ops-agent please deploy demo-web")
    out = env.svc.propose(action="coolify.deploy", target="demo-web", args={}, message_id=f"m{env.n}", agent="ops-agent")
    assert out["status"] == "awaiting_human_approval" and "BLOCKED" not in env.last() and not env.cool.deploys


# --- the sbom command -----------------------------------------------------------------------------------------

def test_sbom_command_shows_reports_and_decision(env):
    baseline(env)
    env.col.add(SHA, [("flask", "3.0"), ("django", "2.2.0")], CRIT, pr_=7)
    env.col.reports[SHA]["collected_at"] = NOW + 10                 # newer than the baseline's report
    env.store.save(env.col.reports[SHA])
    env.say(VIEWER, "sbom")
    assert "SBOM for PR #7" in env.last() and "deploy blocked" in env.last() and "CVE-2026-0001" in env.last()
    env.say(VIEWER, "sbom 7")
    assert "PR #7" in env.last()
    env.say(VIEWER, f"sbom {SHA[:8]}")
    assert "commit a1b2c3d" in env.last()
    env.say(VIEWER, "sbom ../../etc")
    assert env.last().startswith("Denied")                           # the policy refuses odd target names outright
    env.say(VIEWER, "sbom deadbeef")
    assert "No SBOM report" in env.last()
    env.say(VIEWER, "sbom 99")
    assert "no pull request #99" in env.last()


def test_sbom_command_needs_membership(env):
    env.say("@switch-x-stranger:localhost", "sbom")
    assert env.last().startswith("Denied") and "not a member" in env.last()
