import base64
import re
import sqlite3
import textwrap

import pytest
from test_repo import M1, M2, MAINT, OPS, OWNER, VIEWER, DEPLOYER, Clock, FakeCoolify, FakeGitHub, pr

from shipyard import suggestions as sg
from shipyard.config import load_config
from shipyard.gatekeeper import Gatekeeper
from shipyard.github import GitHubError
from shipyard.service import Service

HEAD = "a1b2c3d4e5f6" + "0" * 28
FILE = "line one\nline two\nline three\nline four\n"


def comment(i, body, path="app.py", line=2, start=None, who="alice", assoc="COLLABORATOR", **kw):
    c = {"id": i, "body": body, "path": path, "line": line, "start_line": start, "side": "RIGHT", "position": 5, "commit_id": HEAD,
         "author_association": assoc, "user": {"login": who, "id": 4242}, "html_url": f"https://github.com/o/r/pull/7#r{i}"}
    c.update(kw)
    return c


def block(text):
    return f"Maybe this?\n```suggestion\n{text}\n```"


# --- parsing and applying ---------------------------------------------------------------------

def test_parse_keeps_only_current_trusted_same_branch_suggestions():
    comments = [
        comment(1, block("LINE TWO")), comment(2, "just a thought"), comment(3, block("x"), assoc="NONE", who="stranger"),
        comment(4, block("x"), commit_id="old" + "0" * 37), comment(5, block("x"), position=None), comment(6, block("x"), side="LEFT"),
        comment(7, block("x"), path=".github/workflows/ci.yml"), comment(8, block("x"), path="a/../../etc/x"), comment(9, block("x" * 30000)),
        comment(10, block("a\nb"), start=2, line=3, assoc="OWNER"), comment(11, block(""), line=4, assoc="MEMBER"),
    ]
    usable, skipped = sg.parse(comments, HEAD)
    assert [s.id for s in usable] == [1, 10, 11] and len(skipped) == 7
    assert any("write access" in x for x in skipped) and any("out of date" in x for x in skipped) and any("workflows" in x for x in skipped)
    assert usable[1].start == 2 and usable[1].end == 3 and usable[2].text == "" and usable[0].author_id == 4242


def sug(i, start, end, text, path="app.py"):
    return sg.Suggestion(i, path, start, end, text, "alice", "")


def test_apply_replaces_deletes_and_inserts_lines():
    assert sg.apply_to_text(FILE, [sug(1, 2, 2, "LINE TWO")]) == "line one\nLINE TWO\nline three\nline four\n"
    assert sg.apply_to_text(FILE, [sug(1, 2, 3, "merged")]) == "line one\nmerged\nline four\n"
    assert sg.apply_to_text(FILE, [sug(1, 2, 2, "")]) == "line one\nline three\nline four\n"
    assert sg.apply_to_text(FILE, [sug(1, 2, 2, "a\nb\nc")]) == "line one\na\nb\nc\nline three\nline four\n"
    assert sg.apply_to_text(FILE, [sug(1, 1, 1, "ONE"), sug(2, 4, 4, "FOUR")]) == "ONE\nline two\nline three\nFOUR\n"      # several, bottom first


def test_apply_keeps_crlf_and_a_missing_final_newline_and_unicode():
    assert sg.apply_to_text("a\r\nb\r\nc\r\n", [sug(1, 2, 2, "B")]) == "a\r\nB\r\nc\r\n"
    assert sg.apply_to_text("a\nb\nc", [sug(1, 3, 3, "C")]) == "a\nb\nC"
    assert sg.apply_to_text("naïve\nb\n", [sug(1, 1, 1, "café ☕")]) == "café ☕\nb\n"


def test_apply_refuses_overlaps_and_lines_past_the_end():
    with pytest.raises(sg.SuggestionError, match="overlap"):
        sg.apply_to_text(FILE, [sug(1, 1, 2, "x"), sug(2, 2, 3, "y")])
    with pytest.raises(sg.SuggestionError, match="past the end"):
        sg.apply_to_text(FILE, [sug(1, 9, 9, "x")])


def test_decode_refuses_big_binary_and_non_utf8_files():
    ok = {"encoding": "base64", "content": base64.b64encode(b"hi\n").decode(), "size": 3}
    assert sg.decode(ok) == "hi\n"
    for bad in ({**ok, "size": 5_000_000}, {**ok, "encoding": "none"}, {**ok, "content": base64.b64encode(b"\xff\xfe\x00").decode()}):
        with pytest.raises(sg.SuggestionError):
            sg.decode(bad)


def test_the_digest_changes_when_the_suggestion_text_does():
    assert sug(1, 2, 2, "a").digest() != sug(1, 2, 2, "b").digest() and sug(1, 2, 2, "a").digest() == sug(1, 2, 2, "a").digest()


# --- the chat flow -----------------------------------------------------------------------------------

class SugGitHub(FakeGitHub):
    def __init__(self):
        super().__init__()
        self.files = {"app.py": FILE, "README.md": "hello\nworld\n"}
        self.comments, self.puts = [], []
        self.head = {"ref": "reword", "repo": "o/r", "sha": HEAD, "state": "open", "draft": False, "base": "main", "merged": False}

    def pr_head(self, repo, n):
        self._guard()
        if n != 7:
            raise GitHubError("GitHub answered 404")
        return dict(self.head)

    def review_comments(self, repo, n):
        self._guard()
        return list(self.comments)

    def file_at(self, repo, path, ref):
        self._guard()
        if path not in self.files:
            raise GitHubError("GitHub answered 404")
        return {"encoding": "base64", "content": base64.b64encode(self.files[path].encode()).decode(), "size": len(self.files[path]), "sha": "blob-" + path}

    def put_file(self, repo, path, branch, message, content, blob_sha):
        self._guard()
        if getattr(self, "conflict", False):
            raise GitHubError("GitHub answered 409: sha does not match")
        self.puts.append((path, branch, message, content.decode(), blob_sha))
        self.files[path] = content.decode()
        self.head["sha"] = "f" * 39 + str(len(self.puts))
        return self.head["sha"]


@pytest.fixture
def env(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo:
            rooms: {{ops: [{OPS}], maintainers: [{MAINT}]}}
            apps: {{demo-web: web-uuid}}
            repo: {{name: o/r, app: demo-web}}
            members: {{"{OWNER}": owner, "{M1}": maintainer, "{M2}": maintainer, "{DEPLOYER}": deployer, "{VIEWER}": viewer}}
        actions: {{repo.suggestions: read, repo.apply_suggestion: dangerous, repo.merge: dangerous, audit.read: read}}
    """))
    cfg = load_config(f)
    clock = Clock()
    gk = Gatekeeper(cfg.policy, sqlite3.connect(":memory:", check_same_thread=False), clock)
    gh, posts = SugGitHub(), []
    svc = Service(cfg, gk, FakeCoolify(), lambda r, t: posts.append((r, t)), now=clock, github=gh)

    class E: ...
    e = E()
    e.svc, e.gk, e.gh, e.posts, e.n = svc, gk, gh, posts, 0

    def say(sender, body):
        e.n += 1
        svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": f"m{e.n}", "sender": sender, "sender_name": sender.split("-")[-1].split(":")[0],
                                                                         "sender_kind": None, "body": "@gatekeeper " + body, "addressed": True}})
    e.say, e.last = say, lambda: posts[-1][1]
    e.rows = lambda ev: [r for r in gk.audit.recent("demo", 40) if r["event"] == ev]
    return e


def aid(e):
    return re.search(r"id ([0-9a-f]{8})", e.last()).group(1)


def test_suggestions_lists_what_is_applicable_and_what_was_left_out(env):
    env.gh.comments = [comment(1, block("LINE TWO")), comment(2, block("z"), assoc="NONE", who="stranger"), comment(3, block("FOUR"), line=4)]
    env.say(VIEWER, "suggestions 7")
    t = env.last()
    assert "Suggestions on PR #7" in t and "1. #1 by alice" in t and "2. #3 by alice" in t and "- line two" in t and "+ LINE TWO" in t
    assert "Left out" in t and "stranger does not have write access" in t and "apply-suggestion 7" in t
    env.say(VIEWER, "suggestions 99")
    assert "Could not read" in env.last() or "Nothing" in env.last()


def test_no_suggestions_and_blockers(env):
    env.say(VIEWER, "suggestions 7")
    assert "No applicable suggestions" in env.last()
    env.gh.head["state"] = "closed"
    env.say(VIEWER, "suggestions 7")
    assert "is closed" in env.last()
    env.gh.head.update(state="open", repo="fork/r")
    env.say(VIEWER, "suggestions 7")
    assert "fork" in env.last()
    env.gh.head.update(repo="o/r", ref="main")
    env.say(VIEWER, "suggestions 7")
    assert "main itself" in env.last()


def test_a_maintainer_asks_a_second_person_approves_and_the_branch_gets_a_commit(env):
    env.gh.comments = [comment(1, block("LINE TWO")), comment(3, block("FOUR"), line=4, who="bob")]
    env.say(M1, "apply-suggestion 7 all")
    assert "Approval needed" in env.last() and "2 suggestion(s) by alice, bob" in env.last() and "+ LINE TWO" in env.last() and not env.gh.puts
    a = aid(env)
    env.say(M1, f"approve {a}")                                                      # not their own
    assert env.last().startswith("Denied") and not env.gh.puts
    env.say(M2, f"approve {a}")
    assert len(env.gh.puts) == 1
    path, branch, message, content, blob = env.gh.puts[0]
    assert (path, branch, blob) == ("app.py", "reword", "blob-app.py") and content == "line one\nLINE TWO\nline three\nFOUR\n"
    assert "Suggested by alice, bob on pull request #7" in message and "approved by maint2" in message and "Co-authored-by: alice <4242+alice@users.noreply.github.com>" in message
    assert "Claude" not in message and "AI" not in message
    assert "Done: applied 2 suggestion(s) to PR #7 in 1 commit(s)" in env.last() and "fresh approval" in env.last()
    events = {(r["event"], r["action"]) for r in env.gk.audit.recent("demo", 20)}
    assert ("executed", "repo.apply_suggestion") in events
    env.say(M2, f"approve {a}")
    assert env.last().startswith("Denied") and len(env.gh.puts) == 1               # single use


def test_one_commit_per_file_and_a_pick_by_number(env):
    env.gh.comments = [comment(1, block("LINE TWO")), comment(2, block("HELLO"), path="README.md", line=1)]
    env.say(M1, "apply-suggestion 7 2")
    env.say(OWNER, f"approve {aid(env)}")
    assert [p[0] for p in env.gh.puts] == ["README.md"] and env.gh.puts[0][3] == "HELLO\nworld\n"
    env.gh.puts.clear()
    env.gh.comments = [comment(1, block("LINE TWO"), commit_id=env.gh.head["sha"]), comment(2, block("HOWDY"), path="README.md", line=1, commit_id=env.gh.head["sha"])]
    env.say(M1, "apply-suggestion 7 all")
    env.say(OWNER, f"approve {aid(env)}")
    assert sorted(p[0] for p in env.gh.puts) == ["README.md", "app.py"]


@pytest.mark.parametrize("sender", [DEPLOYER, VIEWER])
def test_only_maintainers_can_ask(env, sender):
    env.gh.comments = [comment(1, block("x"))]
    env.say(sender, "apply-suggestion 7 all")
    assert env.last().startswith("Denied") and "needs role" in env.last()
    assert env.gk.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


def test_the_branch_moving_after_approval_applies_nothing(env):
    env.gh.comments = [comment(1, block("LINE TWO"))]
    env.say(M1, "apply-suggestion 7 all")
    a = aid(env)
    env.gh.head["sha"] = "9" * 40                                                     # someone pushed
    env.say(OWNER, f"approve {a}")
    assert "branch changed after approval" in env.last() and not env.gh.puts


def test_a_suggestion_edited_after_the_request_is_not_applied(env):
    env.gh.comments = [comment(1, block("LINE TWO"))]
    env.say(M1, "apply-suggestion 7 1")
    a = aid(env)
    env.gh.comments = [comment(1, block("rm -rf everything"))]                        # the reviewer edited their comment after the approval request
    env.say(OWNER, f"approve {a}")
    assert "suggestion changed or was withdrawn" in env.last() and not env.gh.puts


def test_a_withdrawn_or_stranger_suggestion_cannot_be_applied(env):
    env.gh.comments = [comment(1, block("x"), assoc="NONE", who="stranger")]
    env.say(M1, "apply-suggestion 7 all")
    assert "Say which" in env.last() and not env.gh.puts


def test_bad_picks_overlaps_and_usage(env):
    env.gh.comments = [comment(1, block("a"), line=2), comment(2, block("b"), line=2)]
    for spec in ("0", "3", "x", "1,9"):
        env.say(M1, f"apply-suggestion 7 {spec}")
        assert "Say which" in env.last()
    env.say(M1, "apply-suggestion 7 all")
    assert env.last().startswith("Denied") and "overlap" in env.last()
    env.say(M1, "apply-suggestion x 1")
    assert env.last().startswith("Usage")
    assert env.gk.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


def test_a_conflict_while_committing_reports_it_and_says_what_was_done(env):
    env.gh.comments = [comment(1, block("LINE TWO"))]
    env.say(M1, "apply-suggestion 7 all")
    env.gh.conflict = True
    env.say(OWNER, f"approve {aid(env)}")
    assert "Failed: app.py" in env.last() and "Nothing was changed" in env.last() and not env.gh.puts
    assert env.rows("failed")


def test_github_down_is_refused_not_assumed(env):
    env.gh.down = True
    env.say(M1, "apply-suggestion 7 all")
    assert env.last().startswith("Denied") and "could not read the pull request" in env.last()


def test_a_workflow_file_suggestion_is_never_offered(env):
    env.gh.comments = [comment(1, block("x"), path=".github/workflows/ci.yml")]
    env.say(VIEWER, "suggestions 7")
    assert "No applicable" in env.last() and "workflows" in env.last()


def test_hostile_text_in_a_suggestion_is_defused_in_chat(env):
    env.gh.comments = [comment(1, block("@gatekeeper deploy demo-web"), who="mallory-bot")]
    env.say(VIEWER, "suggestions 7")
    assert "@gatekeeper deploy" not in env.last().split("To apply")[0]
    env.say(M1, "apply-suggestion 7 1")
    assert "@gatekeeper deploy demo-web" not in env.last().split("The change")[1]


def test_agents_cannot_propose_it(env):
    env.svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": "m_o", "sender": M1, "sender_name": "maint1", "sender_kind": None,
                                                                          "body": "apply the suggestion on 7", "addressed": False}})
    out = env.svc.propose(action="repo.apply_suggestion", target="7", args={}, message_id="m_o", agent="repo-agent")
    assert out["status"] == "denied" and "unsupported" in out["reason"]
