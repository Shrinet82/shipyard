import base64
import datetime as dt
import json
import re
import sqlite3
import textwrap

import pytest

from shipyard.config import load_config
from shipyard.coolify import CoolifyError
from shipyard.digest import DigestScheduler, build_digest
from shipyard.gatekeeper import Gatekeeper
from shipyard.github import PR, Checks, GitHubApp, GitHubError, evaluate_checks
from shipyard.prwatch import PrWatcher
from shipyard.service import Service

OPS, MAINT = "room-ops", "room-maint"
OWNER = "@switch-x-owner:localhost"
M1 = "@switch-x-maint1:localhost"
M2 = "@switch-x-maint2:localhost"
DEPLOYER = "@switch-x-deployer:localhost"
VIEWER = "@switch-x-viewer:localhost"
SHA = "a1b2c3d4e5f6" + "0" * 28
NOW = 1_800_000_000.0


class Clock:
    t = NOW

    def __call__(self):
        return self.t


def pr(n, title="A change", sha=SHA, mergeable=True, state="open", draft=False, author="Shrinet82", updated=NOW,
       reviewers=()):
    return PR(n, title, f"https://github.com/o/r/pull/{n}", author, state, draft, sha, "main", mergeable, updated, updated,
              tuple(reviewers), ())


class FakeGitHub:
    def __init__(self):
        self.prs: dict[int, PR] = {}
        self.ci: dict[str, Checks] = {}
        self.issues: dict[str, list] = {}
        self.merges: list = []
        self.down = False

    def _guard(self):
        if self.down:
            raise GitHubError("GitHub unreachable")

    def set(self, p: PR, ci="green", failing=()):
        self.prs[p.number] = p
        self.ci[p.head_sha] = Checks(ci, tuple(failing))

    def pr(self, repo, n):
        self._guard()
        return self.prs[n]

    def list_open_prs(self, repo):
        self._guard()
        return [p for p in self.prs.values() if p.state == "open"]

    def checks(self, repo, sha, required):
        self._guard()
        return self.ci.get(sha, Checks("none"))

    def assigned_issues(self, repo, login):
        self._guard()
        return self.issues.get(login, [])

    def merge(self, repo, n, sha, method="squash"):
        self._guard()
        if self.prs[n].head_sha != sha:
            raise GitHubError("GitHub answered 409: Head branch was modified")
        self.merges.append((n, sha, method))
        self.prs[n] = PR(**{**self.prs[n].__dict__, "state": "merged"})
        return "f" * 40


class FakeCoolify:
    def __init__(self):
        self.deploys, self.fail = [], False

    def deploy(self, uuid):
        if self.fail:
            raise CoolifyError("Coolify unreachable")
        self.deploys.append(uuid)
        return "deployment queued"


@pytest.fixture
def env(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo:
            rooms: {{ops: [{OPS}], maintainers: [{MAINT}]}}
            apps: {{demo-web: web-uuid}}
            repo: {{name: o/r, app: demo-web, required_checks: [test]}}
            members: {{"{OWNER}": owner, "{M1}": maintainer, "{M2}": maintainer, "{DEPLOYER}": deployer, "{VIEWER}": viewer}}
            github_logins: {{"{OWNER}": Shrinet82, "{M1}": maint1, "{DEPLOYER}": dep, "{VIEWER}": vw}}
        actions:
          coolify.deploy: change
          coolify.status: read
          repo.merge: dangerous
          repo.pr_list: read
          repo.pr_status: read
          repo.digest: read
          audit.read: read
        github: {{stale_hours: 48}}
    """))
    cfg = load_config(f)
    clock = Clock()
    gk = Gatekeeper(cfg.policy, sqlite3.connect(":memory:", check_same_thread=False), clock)
    gh, cool, posts = FakeGitHub(), FakeCoolify(), []
    svc = Service(cfg, gk, cool, lambda r, t: posts.append((r, t)), now=clock, github=gh)

    class E: ...
    e = E()
    e.cfg, e.svc, e.gk, e.gh, e.cool, e.posts, e.clock, e.n = cfg, svc, gk, gh, cool, posts, clock, 0

    def say(sender, body, name=None):
        e.n += 1
        svc.handle_event({"type": "message", "room_id": OPS, "payload": {
            "message_id": f"m{e.n}", "sender": sender, "sender_name": name or sender.split("-")[-1].split(":")[0],
            "sender_kind": None, "body": "@gatekeeper " + body, "addressed": True}})

    e.say = say
    e.last = lambda: posts[-1][1]
    return e


def approval_id(e):
    return re.search(r"id ([0-9a-f]{8})", e.last()).group(1)


# --- merge ----------------------------------------------------------------------

def test_merge_checks_asks_approves_merges_then_deploys(env):
    env.gh.set(pr(6, "Bump the footer"))
    env.say(M1, "merge 6")
    assert "Approval needed" in env.last() and "PR #6" in env.last() and "CI green" in env.last() and "a1b2c3d" in env.last()
    assert not env.gh.merges
    aid = approval_id(env)
    env.say(M1, f"approve {aid}")                                   # a maintainer cannot approve their own merge
    assert env.last().startswith("Denied") and not env.gh.merges
    env.say(OWNER, f"approve {aid}")
    assert env.gh.merges == [(6, SHA, "squash")]
    assert env.cool.deploys == ["web-uuid"]
    assert "merged PR #6" in env.last() and "Deploy of demo-web queued" in env.last()
    audit = {(r["event"], r["action"]) for r in env.gk.audit.recent("demo", 20)}
    assert {("executed", "repo.merge"), ("executed", "coolify.deploy")} <= audit


def test_another_maintainer_may_approve(env):
    env.gh.set(pr(6))
    env.say(M1, "merge 6")
    env.say(M2, f"approve {approval_id(env)}")
    assert env.gh.merges


@pytest.mark.parametrize("sender,why", [(DEPLOYER, "needs role"), (VIEWER, "needs role")])
def test_only_maintainers_and_owners_can_ask_to_merge(env, sender, why):
    env.gh.set(pr(6))
    env.say(sender, "merge 6")
    assert env.last().startswith("Denied") and why in env.last() and not env.gh.merges
    assert env.gk.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


@pytest.mark.parametrize("make,reason", [
    (lambda: (pr(4, sha="b" * 40), "red", ("test",)), "CI failed (test)"),
    (lambda: (pr(5, mergeable=False), "green", ()), "conflicts with main"),
    (lambda: (pr(12, mergeable=False), "none", ()), "conflicts with main"),     # CI never ran: still say conflict
    (lambda: (pr(7), "pending", ()), "still running"),
    (lambda: (pr(8), "none", ()), "no CI result"),
    (lambda: (pr(9, draft=True), "green", ()), "draft"),
    (lambda: (pr(10, mergeable=None), "green", ()), "not finished checking"),
    (lambda: (pr(11, state="merged"), "green", ()), "is merged"),
])
def test_unmergeable_prs_are_refused_with_the_reason_and_no_approval_is_created(env, make, reason):
    p, ci, failing = make()
    env.gh.set(p, ci, failing)
    env.say(OWNER, f"merge {p.number}")
    assert env.last().startswith("Denied") and reason in env.last()
    assert env.gk.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0 and not env.gh.merges


def test_branch_that_moves_after_the_request_is_not_merged(env):
    env.gh.set(pr(6))
    env.say(M1, "merge 6")
    aid = approval_id(env)
    env.gh.set(pr(6, sha="c" * 40))                                  # someone pushed a new commit
    env.say(OWNER, f"approve {aid}")
    assert "branch changed after approval" in env.last() and not env.gh.merges and not env.cool.deploys


def test_ci_turning_red_after_the_request_is_caught_at_the_second_check(env):
    env.gh.set(pr(6))
    env.say(M1, "merge 6")
    aid = approval_id(env)
    env.gh.ci[SHA] = Checks("red", ("test",))
    env.say(OWNER, f"approve {aid}")
    assert "Not merged: CI failed" in env.last() and not env.gh.merges


def test_github_down_at_approval_changes_nothing(env):
    env.gh.set(pr(6))
    env.say(M1, "merge 6")
    aid = approval_id(env)
    env.gh.down = True
    env.say(OWNER, f"approve {aid}")
    assert env.last().startswith("Failed") and "Nothing was changed" in env.last() and not env.cool.deploys
    assert any(r["event"] == "failed" for r in env.gk.audit.recent("demo", 5))


def test_github_down_when_asking_is_a_refusal_not_a_crash(env):
    env.gh.down = True
    env.say(OWNER, "merge 6")
    assert env.last().startswith("Denied") and "GitHub" in env.last()


def test_merge_succeeds_but_deploy_fails_is_reported_honestly(env):
    env.gh.set(pr(6))
    env.say(M1, "merge 6")
    env.cool.fail = True
    env.say(OWNER, f"approve {approval_id(env)}")
    assert env.gh.merges and "merge succeeded but the deploy failed" in env.last() and "deploy demo-web" in env.last()
    assert not any("Deploy of demo-web queued" in t for _, t in env.posts)


def test_merge_usage_and_non_members(env):
    env.say(OWNER, "merge six")
    assert env.last().startswith("Usage")
    env.say("@switch-x-stranger:localhost", "merge 6")
    assert "not a member" in env.last()


def test_agents_cannot_merge_even_by_proposal(env):
    env.gh.set(pr(6))
    mid = "m_owner"
    env.svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": mid, "sender": OWNER, "sender_name": "owner",
                                                                       "sender_kind": None, "body": "merge 6 please", "addressed": False}})
    out = env.svc.propose(action="repo.merge", target="6", args={}, message_id=mid, agent="repo-agent")
    assert out["status"] == "denied" and "unsupported" in out["reason"] and not env.gh.merges


# --- repo reads ------------------------------------------------------------------

def test_prs_pr_and_agent_reads(env):
    env.gh.set(pr(4, "Add footer check", sha="b" * 40), "red", ("test",))
    env.gh.set(pr(5, "Reword", sha="d" * 40, mergeable=False))
    env.say(VIEWER, "prs")
    assert "#4 Add footer check" in env.last() and "CI red" in env.last() and "conflict" in env.last()
    env.say(VIEWER, "pr 4")
    assert env.last().startswith("#4") and "CI red" in env.last()
    env.svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": "q1", "sender": VIEWER, "sender_name": "vw",
                                                                       "sender_kind": None, "body": "what is up with the PRs?", "addressed": False}})
    out = env.svc.propose(action="repo.pr_status", target="4", args={}, message_id="q1", agent="repo-agent")
    assert out["status"] == "done" and "CI red" in out["result"]
    assert not env.gh.merges


def test_digest_on_demand_needs_a_github_login(env):
    env.gh.set(pr(4, "Add footer check", sha="b" * 40), "red", ("test",))
    env.gh.issues["Shrinet82"] = [{"number": 2, "title": "Docs", "html_url": "u"}]
    env.say(OWNER, "digest")
    assert "Digest for owner" in env.last() and "#4 Add footer check: CI failed: test" in env.last() and "#2 Docs" in env.last()
    env.say(M2, "digest")
    assert "No GitHub login" in env.last()


# --- PR watcher ------------------------------------------------------------------

@pytest.fixture
def watch(env):
    w = PrWatcher(env.cfg, env.gk, env.gh, lambda r, t: env.posts.append((r, t)), env.clock)
    env.watch = w
    return w


def texts(env):
    return [t for r, t in env.posts if r == MAINT]


def test_each_event_is_announced_once_to_the_maintainers_room(env, watch):
    env.gh.set(pr(1, "Health", sha="1" * 40))
    env.gh.set(pr(4, "Footer test", sha="4" * 40), "red", ("test",))
    env.gh.set(pr(5, "Reword", sha="5" * 40, mergeable=False))
    watch.poll_once()
    out = texts(env)
    assert any("PR #1 opened" in t for t in out) and any("CI passed on PR #1" in t for t in out)
    assert any("CI failed on PR #4 (test)" in t for t in out) and any("PR #5 conflicts with main" in t for t in out)
    assert all(r == MAINT for r, _ in env.posts)
    before = len(env.posts)
    watch.poll_once()
    watch.poll_once()
    assert len(env.posts) == before                                   # nothing repeats, even across polls


def test_a_new_commit_and_a_new_result_are_announced_again(env, watch):
    env.gh.set(pr(1, sha="1" * 40), "red", ("test",))
    watch.poll_once()
    env.gh.set(pr(1, sha="2" * 40), "green")
    watch.poll_once()
    out = texts(env)
    assert sum("CI failed on PR #1" in t for t in out) == 1 and sum("CI passed on PR #1" in t for t in out) == 1


def test_pending_ci_is_not_announced_until_it_finishes(env, watch):
    env.gh.set(pr(1), "pending")
    watch.poll_once()
    assert not any("CI " in t for t in texts(env))
    env.gh.ci[SHA] = Checks("green")
    watch.poll_once()
    assert any("CI passed on PR #1" in t for t in texts(env))


def test_conflict_is_announced_once_and_again_if_it_recurs(env, watch):
    env.gh.set(pr(5, mergeable=False))
    watch.poll_once()
    watch.poll_once()
    env.gh.set(pr(5, mergeable=True))
    watch.poll_once()
    env.gh.set(pr(5, mergeable=False))
    watch.poll_once()
    assert sum("conflicts with main" in t for t in texts(env)) == 2


def test_stale_prs_are_announced_after_the_threshold_and_then_daily(env, watch):
    env.gh.set(pr(1, updated=NOW - 49 * 3600))
    watch.poll_once()
    assert sum("no activity for 49 hours" in t for t in texts(env)) == 1
    watch.poll_once()
    env.clock.t += 23 * 3600
    watch.poll_once()
    assert sum("no activity" in t for t in texts(env)) == 1
    env.clock.t += 2 * 3600
    watch.poll_once()
    assert sum("no activity" in t for t in texts(env)) == 2


def test_fresh_prs_are_not_stale(env, watch):
    env.gh.set(pr(1, updated=NOW - 3600))
    watch.poll_once()
    assert not any("no activity" in t for t in texts(env))


def test_a_merged_pr_is_announced_once(env, watch):
    env.gh.set(pr(1))
    watch.poll_once()
    env.gh.prs[1] = pr(1, state="merged")
    watch.poll_once()
    watch.poll_once()
    assert sum("PR #1 merged" in t for t in texts(env)) == 1


def test_github_errors_do_not_crash_or_post(env, watch):
    env.gh.down = True
    watch.poll_once()
    assert not env.posts


def test_state_survives_a_restart(env):
    env.gh.set(pr(1))
    PrWatcher(env.cfg, env.gk, env.gh, lambda r, t: env.posts.append((r, t)), env.clock).poll_once()
    n = len(env.posts)
    PrWatcher(env.cfg, env.gk, env.gh, lambda r, t: env.posts.append((r, t)), env.clock).poll_once()   # a fresh process
    assert len(env.posts) == n


# --- digest ----------------------------------------------------------------------

def test_build_digest_sections(env):
    env.gh.set(pr(4, "Footer test", sha="4" * 40), "red", ("test",))
    env.gh.set(pr(5, "Reword", sha="5" * 40, mergeable=False, author="maint1", reviewers=["Shrinet82"]))
    env.gh.issues["Shrinet82"] = [{"number": 9, "title": "Fix docs", "html_url": "https://x/9"}]
    text = build_digest(env.gh, env.cfg.projects["demo"], "Shrinet82", "shrinet82", dt.datetime(2026, 11, 5, 9, 0))
    assert "Review queue:\n  - #5 Reword" in text
    assert "Assigned issues:\n  - #9 Fix docs" in text
    assert "#4 Footer test: CI failed: test" in text
    other = build_digest(env.gh, env.cfg.projects["demo"], "maint1", "maint1", dt.datetime(2026, 11, 5, 9, 0))
    assert "#5 Reword: merge conflict" in other


def test_scheduler_sends_once_a_day_at_nine_ist_only_to_maintainers(env):
    # 08:59 IST is 03:29 UTC; 09:00 IST is 03:30 UTC
    base = dt.datetime(2026, 11, 5, 3, 29, tzinfo=dt.timezone.utc).timestamp()
    env.clock.t = base
    sched = DigestScheduler(env.cfg, env.gk, env.gh, lambda r, t: env.posts.append((r, t)), lambda s: s.split("-")[-1].split(":")[0], env.clock)
    assert sched.tick() is False and not env.posts
    env.clock.t = base + 60
    assert sched.tick() is True
    names = [t.split(",")[0] for _, t in env.posts]
    assert names == ["Digest for maint1" , "Digest for owner"] or sorted(names) == ["Digest for maint1", "Digest for owner"]
    assert all(r == MAINT for r, _ in env.posts)
    n = len(env.posts)
    env.clock.t = base + 3600
    assert sched.tick() is False and len(env.posts) == n               # not twice the same day
    env.clock.t = base + 86400 + 60
    assert sched.tick() is True and len(env.posts) == 2 * n            # and again tomorrow


def test_scheduler_catches_up_after_downtime(env):
    env.clock.t = dt.datetime(2026, 11, 5, 6, 0, tzinfo=dt.timezone.utc).timestamp()     # 11:30 IST, service just started
    sched = DigestScheduler(env.cfg, env.gk, env.gh, lambda r, t: env.posts.append((r, t)), lambda s: s, env.clock)
    assert sched.tick() is True and env.posts


# --- GitHub App client -------------------------------------------------------------

def test_check_evaluation():
    runs = [{"name": "test", "status": "completed", "conclusion": "success"}, {"name": "lint", "status": "completed", "conclusion": "failure"}]
    assert evaluate_checks(runs, ("test",)).ci == "green"
    assert evaluate_checks(runs, ("test", "lint")) == Checks("red", ("lint",))
    assert evaluate_checks(runs, ("deploy",)).ci == "none"
    assert evaluate_checks([], ()).ci == "none"
    assert evaluate_checks([{"name": "test", "status": "in_progress", "conclusion": None}], ("test",)).ci == "pending"
    assert evaluate_checks([{"name": "test", "status": "completed", "conclusion": "skipped"}], ("test",)).ci == "green"
    assert evaluate_checks([{"name": "test", "status": "completed", "conclusion": "cancelled"}], ("test",)).ci == "red"


class Http:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers["Authorization"].removeprefix("Bearer "), body))
        if url.endswith("/access_tokens"):
            return 201, {"token": f"inst-{len(self.calls)}", "expires_at": "2027-01-15T09:30:00Z"}
        if url.endswith("/installation"):
            return 200, {"id": 4242}
        if url.endswith("/merge"):
            return (409, {"message": "Head branch was modified"}) if body["sha"] == "stale" else (200, {"sha": "abc123", "merged": True})
        return 200, {"check_runs": []}


def test_jwt_shape_and_token_use():
    http, clock = Http(), Clock()
    clock.t = 1_800_000_000
    app = GitHubApp("123", "key.pem", now=clock, http=http, sign=lambda m: b"sig")
    assert app.installation_for("o/r") == "4242"
    jwt = http.calls[-1][2]
    head, body, sig = jwt.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    assert json.loads(base64.urlsafe_b64decode(pad(head))) == {"alg": "RS256", "typ": "JWT"}
    claims = json.loads(base64.urlsafe_b64decode(pad(body)))
    assert claims["iss"] == "123" and 0 < claims["exp"] - claims["iat"] <= 600
    assert base64.urlsafe_b64decode(pad(sig)) == b"sig"
    app.checks("o/r", "sha", ("test",))                       # an installation call uses the installation token
    assert http.calls[-1][2].startswith("inst-")
    assert [c[1] for c in http.calls].count("https://api.github.com/app/installations/4242/access_tokens") == 1
    app.checks("o/r", "sha", ("test",))
    assert [c[1] for c in http.calls].count("https://api.github.com/app/installations/4242/access_tokens") == 1   # cached


def test_installation_token_is_renewed_before_it_expires():
    http, clock = Http(), Clock()
    clock.t = dt.datetime(2027, 1, 15, 9, 0, tzinfo=dt.timezone.utc).timestamp()
    app = GitHubApp("1", "k", installation_id="9", now=clock, http=http, sign=lambda m: b"s")
    app.checks("o/r", "s", ())
    clock.t += 29 * 60 + 30                                  # inside the 2-minute safety margin
    app.checks("o/r", "s", ())
    assert sum(c[1].endswith("/access_tokens") for c in http.calls) == 2


def test_merge_pins_the_sha_and_surfaces_refusals():
    http = Http()
    app = GitHubApp("1", "k", installation_id="9", http=http, sign=lambda m: b"s")
    assert app.merge("o/r", 6, "abc", "squash") == "abc123"
    assert http.calls[-1][3] == {"sha": "abc", "merge_method": "squash"}
    with pytest.raises(GitHubError, match="409"):
        app.merge("o/r", 6, "stale")


def test_missing_installation_is_an_error_not_a_guess():
    app = GitHubApp("1", "k", http=Http(), sign=lambda m: b"s")
    with pytest.raises(GitHubError):
        app.checks("o/r", "s", ())
