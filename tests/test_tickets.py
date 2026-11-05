import itertools
import sqlite3
from types import SimpleNamespace

import pytest

from shipyard import tickets as tk
from shipyard.gatekeeper import Gatekeeper
from shipyard.policy import Policy, Role
from shipyard.tickets import TicketError, Tickets

V, D, M, O, D2 = ("@switch-x-viewer:localhost", "@switch-x-dep:localhost", "@switch-x-maint:localhost", "@switch-x-owner:localhost", "@switch-x-dep2:localhost")
STRANGER = "@switch-x-stranger:localhost"
ROLES = {V: Role.VIEWER, D: Role.DEPLOYER, D2: Role.DEPLOYER, M: Role.MAINTAINER, O: Role.OWNER}
NAMES = {V: "vera", D: "dan", D2: "dana", M: "mia", O: "olga"}


class Clock:
    t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    db = sqlite3.connect(":memory:", check_same_thread=False)
    gk = Gatekeeper(Policy(members={"demo": ROLES, "other": {O: Role.OWNER}}, actions={}), db, clock)
    projects = {"demo": SimpleNamespace(ticket_prefix="SY"), "other": SimpleNamespace(ticket_prefix="OT")}
    tix = Tickets(gk, projects, lambda p: dict(gk.policy.members[p]), lambda i: NAMES.get(i, i), clock)
    return SimpleNamespace(t=tix, gk=gk, clock=clock, db=db)


def code(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return "ok"
    except TicketError as e:
        return e.code


# --- permission matrix: every role x action --------------------------------------------------------------

def scenario(env):
    """Tickets: A reported by the viewer, assigned to deployer D; B by the maintainer, unassigned; AUTO by the system."""
    a = env.t.create("demo", V, title="A: viewer's ticket")
    env.t.assign("demo", M, a["key"], D)
    b = env.t.create("demo", M, title="B: maintainer's ticket")
    auto, _ = env.t.auto("demo", source="alert", source_ref="alert:web:crash", title="Investigate: crash")
    return a["key"], b["key"], auto["key"]


# (role, action) -> expected for the matrix rows that depend only on role
@pytest.mark.parametrize("role_id,expect", [(V, "ok"), (D, "ok"), (M, "ok"), (O, "ok")])
def test_everyone_may_see_create_and_comment(env, role_id, expect):
    a, b, _ = scenario(env)
    assert code(env.t.get, "demo", role_id, a) == expect
    assert code(env.t.create, "demo", role_id, title="new") == expect
    assert code(env.t.comment, "demo", role_id, b, "hello") == expect
    assert code(env.t.list, "demo", role_id) == expect and code(env.t.summary, "demo", role_id) == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "ok"), (D2, "forbidden"), (M, "ok"), (O, "ok")])
def test_move_a_ticket_assigned_to_the_deployer(env, caller, expect):
    a, _, _ = scenario(env)
    assert code(env.t.move, "demo", caller, a, "doing") == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "forbidden"), (M, "ok"), (O, "ok")])
def test_move_any_ticket(env, caller, expect):
    _, b, _ = scenario(env)
    assert code(env.t.move, "demo", caller, b, "doing") == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "ok"), (M, "ok"), (O, "ok")])
def test_take_an_unassigned_ticket(env, caller, expect):
    _, b, _ = scenario(env)
    assert code(env.t.assign, "demo", caller, b, caller) == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "forbidden"), (M, "ok"), (O, "ok")])
def test_assign_or_reassign_anyone(env, caller, expect):
    a, b, _ = scenario(env)
    assert code(env.t.assign, "demo", caller, b, D2) == expect
    assert code(env.t.assign, "demo", caller, a, D2) == expect


def test_a_deployer_cannot_take_a_ticket_that_already_has_an_owner_or_hand_one_to_someone_else(env):
    a, b, _ = scenario(env)
    assert code(env.t.assign, "demo", D2, a, D2) == "forbidden"                    # A is assigned to D
    assert code(env.t.assign, "demo", D, b, D2) == "forbidden"                     # reassigning to someone else


@pytest.mark.parametrize("caller,ticket,expect", [
    (V, "A", "ok"), (V, "B", "forbidden"), (V, "AUTO", "forbidden"),                # a viewer edits only what they reported
    (D, "A", "ok"), (D, "B", "forbidden"), (D, "AUTO", "forbidden"),                # a deployer: reported or assigned
    (D2, "A", "forbidden"), (M, "A", "ok"), (M, "B", "ok"), (M, "AUTO", "ok"),
    (O, "A", "ok"), (O, "AUTO", "ok"),
])
def test_edit_title_body_priority_labels_due(env, caller, ticket, expect):
    keys = dict(zip(("A", "B", "AUTO"), scenario(env)))
    for fields in ({"title": "t2"}, {"body": "b"}, {"priority": "low"}, {"labels": ["x"]}, {"due_on": "2026-12-01"}):
        assert code(env.t.update, "demo", caller, keys[ticket], fields) == expect, fields


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "ok"), (D2, "forbidden"), (M, "ok"), (O, "ok")])
def test_close_as_done(env, caller, expect):
    a, _, _ = scenario(env)
    env.t.move("demo", M, a, "doing"); env.t.move("demo", M, a, "review")
    assert code(env.t.move, "demo", caller, a, "done") == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "forbidden"), (M, "ok"), (O, "ok")])
def test_cancel_and_reopen_need_a_maintainer(env, caller, expect):
    a, b, _ = scenario(env)
    assert code(env.t.move, "demo", caller, a, "cancelled") == expect
    env.t.move("demo", M, b, "cancelled")
    assert code(env.t.move, "demo", caller, b, "todo") == expect


@pytest.mark.parametrize("caller,expect", [(V, "forbidden"), (D, "forbidden"), (M, "forbidden"), (O, "ok")])
def test_delete_is_the_owners_alone(env, caller, expect):
    a, _, _ = scenario(env)
    assert code(env.t.check_delete, "demo", caller, a) == expect


def test_a_stranger_can_do_nothing_and_cross_project_tickets_are_invisible(env):
    a, _, _ = scenario(env)
    for fn, args in ((env.t.get, (a,)), (env.t.list, ()), (env.t.summary, ()), (env.t.create, ()), (env.t.comment, (a, "x"))):
        kw = {"title": "x"} if fn == env.t.create else {}
        assert code(fn, "demo", STRANGER, *args, **kw) == "forbidden"
    assert code(env.t.get, "other", O, a) == "not_found"                           # SY-1 is not a ticket of project "other"
    other = env.t.create("other", O, title="in other")
    assert other["key"] == "OT-1" and env.t.list("demo", M)["tickets"][0]["key"] != "OT-1"


# --- the workflow: every transition --------------------------------------------------------------------

@pytest.mark.parametrize("frm,to", [p for p in itertools.product(tk.STATUSES, tk.STATUSES) if p[0] != p[1]])
def test_only_the_listed_transitions_are_allowed(env, frm, to):
    t = env.t.create("demo", M, title="walker")
    path = {"todo": [], "doing": ["doing"], "review": ["doing", "review"], "done": ["doing", "review", "done"], "cancelled": ["cancelled"]}[frm]
    for step in path:
        env.t.move("demo", O, t["key"], step)
    want = "ok" if to in tk.TRANSITIONS[frm] else "bad_transition"
    assert code(env.t.move, "demo", O, t["key"], to) == want


def test_closing_sets_closed_at_and_reopening_clears_it_with_both_events(env):
    t = env.t.create("demo", M, title="x")
    for s in ("doing", "review", "done"):
        env.t.move("demo", M, t["key"], s)
    done = env.t.get("demo", M, t["key"])
    assert done["closed_at"] and {e["type"] for e in done["events"]} >= {"closed", "status_changed"}
    env.t.move("demo", M, t["key"], "todo")
    back = env.t.get("demo", M, t["key"])
    assert back["closed_at"] is None and back["events"][0]["type"] == "reopened" or "reopened" in [e["type"] for e in back["events"]]


def test_a_done_ticket_cannot_be_assigned_until_reopened(env):
    t = env.t.create("demo", M, title="x")
    for s in ("doing", "review", "done"):
        env.t.move("demo", M, t["key"], s)
    assert code(env.t.assign, "demo", M, t["key"], D) == "bad_transition"


def test_bad_transition_message_names_the_options(env):
    t = env.t.create("demo", M, title="x")
    with pytest.raises(TicketError) as e:
        env.t.move("demo", M, t["key"], "done")
    assert e.value.code == "bad_transition" and "can go to doing or cancelled" in e.value.message


# --- limits: rejected, never truncated -----------------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    {"title": ""}, {"title": "   "}, {"title": "x" * 121}, {"title": 5}, {"title": "ok", "body": "b" * 4001}, {"title": "ok", "priority": "critical"},
    {"title": "ok", "labels": ["a"] * 9}, {"title": "ok", "labels": ["UPPER"]}, {"title": "ok", "labels": ["has space"]}, {"title": "ok", "labels": ["x" * 25]},
    {"title": "ok", "labels": [1]}, {"title": "ok", "due_on": "tomorrow"}, {"title": "ok", "due_on": "2026-13-45"},
])
def test_invalid_input_is_refused(env, kw):
    assert code(env.t.create, "demo", M, **kw) == "invalid"
    assert env.t.list("demo", M)["tickets"] == []


def test_valid_edge_values_are_accepted_and_trimmed(env):
    t = env.t.create("demo", M, title="  " + "x" * 120 + "  ", body="b" * 4000, labels="ui, mobile  ui", priority="urgent", due_on="2026-11-07")
    assert t["title"] == "x" * 120 and len(t["body"]) == 4000 and t["labels"] == ["ui", "mobile"] and t["due_on"] == "2026-11-07"
    assert code(env.t.comment, "demo", M, t["key"], "c" * 2000) == "ok" and code(env.t.comment, "demo", M, t["key"], "c" * 2001) == "invalid"
    assert code(env.t.comment, "demo", M, t["key"], "  ") == "invalid"


def test_assignee_must_hold_a_role_and_can_be_named_by_name(env):
    t = env.t.create("demo", M, title="x")
    assert code(env.t.assign, "demo", M, t["key"], "nobody") == "unknown_member" and code(env.t.assign, "demo", M, t["key"], STRANGER) == "unknown_member"
    assert env.t.assign("demo", M, t["key"], "@dan")["assignee"] == D and env.t.assign("demo", M, t["key"], "DANA")["assignee"] == D2
    assert env.t.assign("demo", M, t["key"], None)["assignee"] is None
    assert code(env.t.create, "demo", V, title="x", assignee=D) == "forbidden" and code(env.t.create, "demo", D, title="x", assignee=D2) == "forbidden"
    assert env.t.create("demo", D, title="mine", assignee=D)["assignee"] == D


def test_unknown_fields_keys_and_statuses(env):
    t = env.t.create("demo", M, title="x")
    assert code(env.t.update, "demo", M, t["key"], {"status": "done"}) == "invalid" and code(env.t.update, "demo", M, t["key"], {}) == "invalid"
    assert code(env.t.get, "demo", M, "SY-99") == "not_found" and code(env.t.get, "demo", M, "nonsense") == "invalid"
    assert code(env.t.get, "demo", M, "SY-1; DROP TABLE tickets") == "invalid" and code(env.t.move, "demo", M, t["key"], "blocked") == "invalid"


def test_edits_record_old_and_new_values_and_no_op_edits_record_nothing(env):
    t = env.t.create("demo", M, title="x", priority="low")
    env.t.update("demo", M, t["key"], {"priority": "high", "labels": ["a", "b"], "due_on": "2026-12-01", "title": "y"})
    env.t.update("demo", M, t["key"], {"priority": "high"})
    ev = {e["type"]: (e["from"], e["to"]) for e in env.t.get("demo", M, t["key"])["events"]}
    assert ev["priority_changed"] == ("low", "high") and ev["labels_changed"] == ("", "a,b") and ev["due_changed"] == (None, "2026-12-01") and ev["edited"] == ("x", "y")
    assert sum(1 for e in env.t.get("demo", M, t["key"])["events"] if e["type"] == "priority_changed") == 1


# --- numbering, keys, soft delete -------------------------------------------------------------------------------

def test_numbers_are_per_project_and_never_reused_after_a_delete(env):
    a = env.t.create("demo", M, title="a")
    b = env.t.create("demo", M, title="b")
    assert (a["key"], b["key"]) == ("SY-1", "SY-2")
    env.t.soft_delete("demo", O, b["key"])
    assert env.t.create("demo", M, title="c")["key"] == "SY-3"
    assert code(env.t.get, "demo", M, "SY-2") == "not_found"
    assert "SY-2" not in [x["key"] for x in env.t.list("demo", M)["tickets"]]
    with env.gk.lock:
        row = env.db.execute("SELECT status, deleted_at FROM tickets WHERE key='SY-2'").fetchone()
    assert row[0] == "cancelled" and row[1]                                          # the row stays


def test_keys_in_text_are_parsed_by_the_fixed_pattern_only():
    assert tk.keys_in("Fixes SY-12 and refs ab-3, closes OTHER-9, fixes sy-4, Closes  SY-7.") is not None
    got = dict(tk.keys_in("Fixes SY-12\nRefs SY-3\nCLOSES SY-9\nfixes   SY-12"))
    assert got == {"SY-12": True, "SY-3": False, "SY-9": True}
    assert tk.keys_in("see SY-12, no verb") == [] and tk.keys_in("prefixes SY-12") == [] and tk.keys_in("Fixes sy-12") == []
    assert tk.keys_in("Fixes TOOLONGPREFIX-1") == [] and tk.keys_in("Fixes SY-1234567") == [] and tk.keys_in("") == [] and tk.keys_in(None) == []


# --- automatic tickets: dedupe and the rate limit -----------------------------------------------------------------

def test_a_repeat_becomes_a_comment_until_the_ticket_is_closed(env):
    t1, o1 = env.t.auto("demo", source="alert", source_ref="alert:web:crash", title="Investigate: crash on web", labels=["ops"])
    t2, o2 = env.t.auto("demo", source="alert", source_ref="alert:web:crash", title="Investigate: crash on web")
    assert (o1, o2) == ("created", "repeated") and t1["key"] == t2["key"]
    got = env.t.get("demo", M, t1["key"])
    assert got["comments"][0]["body"].startswith("happened again at") and got["comments"][0]["author"] == "system:alert" and got["automatic"]
    for s in ("doing", "review", "done"):
        env.t.system_move("demo", t1["key"], s, "system:test")
    t3, o3 = env.t.auto("demo", source="alert", source_ref="alert:web:crash", title="Investigate: crash on web")
    assert o3 == "created" and t3["key"] != t1["key"]                                  # closed: a new ticket


def test_fifty_alerts_in_a_minute_make_ten_tickets_then_stop_until_the_next_hour(env):
    outcomes = [env.t.auto("demo", source="alert", source_ref=f"alert:svc{i}:crash", title=f"crash {i}")[1] for i in range(50)]
    assert outcomes.count("created") == 10 and outcomes.count("limited") == 40
    assert len(env.t.list("demo", M, source="alert")["tickets"]) == 10
    env.clock.t += 3601
    assert env.t.auto("demo", source="alert", source_ref="alert:new:crash", title="later")[1] == "created"


def test_automatic_tickets_default_and_unknown_assignees_are_dropped(env):
    t, _ = env.t.auto("demo", source="sbom_gate", source_ref="cve:CVE-1:web", title="Fix CVE-1", priority="urgent", labels=["security"], assignee="@switch-x-gone:localhost")
    assert t["priority"] == "urgent" and t["labels"] == ["security"] and t["assignee"] is None and t["reporter"] == "system:sbom_gate" and t["source"] == "sbom_gate"
    t2, _ = env.t.auto("demo", source="deploy_failed", source_ref="deploy:web:1", title="Fix failed deploy", assignee=D)
    assert t2["assignee"] == D


# --- the audit chain -------------------------------------------------------------------------------------------------

def test_every_change_is_an_audit_row_and_the_hash_chain_stays_intact(env):
    t = env.t.create("demo", M, title="x", assignee=D)
    env.t.update("demo", M, t["key"], {"priority": "urgent"})
    for s in ("doing", "review", "done"):
        env.t.move("demo", M, t["key"], s)
    env.t.comment("demo", V, t["key"], "hi")
    env.t.link("demo", M, t["key"], "pr", "26", "https://github.com/o/r/pull/26")
    env.t.move("demo", M, t["key"], "todo")
    env.t.soft_delete("demo", O, t["key"])
    env.t.auto("demo", source="alert", source_ref="a", title="auto")
    names = [r["event"] for r in env.gk.audit.recent("demo", 100)]
    for want in ("ticket_created", "ticket_assigned", "ticket_edited", "ticket_moved", "ticket_closed", "ticket_commented", "ticket_linked", "ticket_reopened",
                 "ticket_deleted", "ticket_auto_created"):
        assert want in names, want
    assert env.gk.audit.verify()


def test_links_validate_dedupe_and_drop_unsafe_urls(env):
    t = env.t.create("demo", M, title="x")
    env.t.link("demo", M, t["key"], "pr", "#26", "https://github.com/o/r/pull/26")
    env.t.link("demo", M, t["key"], "pr", "26")
    env.t.link("demo", M, t["key"], "commit", "a1b2c3d", "javascript:alert(1)")
    g = env.t.get("demo", M, t["key"])
    assert [(l["kind"], l["ref"]) for l in g["links"]] == [("pr", "26"), ("commit", "a1b2c3d")] and g["links"][1]["url"] is None
    assert code(env.t.link, "demo", M, t["key"], "wiki", "x") == "invalid" and code(env.t.link, "demo", M, t["key"], "pr", "a b<c>") == "invalid"
    assert code(env.t.link, "demo", M, t["key"], "ticket", "nope") == "invalid" and code(env.t.link, "demo", V, t["key"], "pr", "1") == "forbidden"


# --- lists -------------------------------------------------------------------------------------------------------------

def test_list_filters_search_and_cursor(env):
    for i in range(7):
        env.clock.t += 1
        env.t.create("demo", M, title=f"ticket {i} 100%_x", labels=["ui"] if i % 2 else ["api"], priority="high" if i < 3 else "low", assignee=D if i == 0 else None)
    assert len(env.t.list("demo", V, label="ui")["tickets"]) == 3 and len(env.t.list("demo", V, priority="high")["tickets"]) == 3
    assert [x["title"] for x in env.t.list("demo", V, assignee="dan")["tickets"]] == ["ticket 0 100%_x"] and len(env.t.list("demo", V, unassigned=True)["tickets"]) == 6
    assert len(env.t.list("demo", V, q="100%_x")["tickets"]) == 7 and env.t.list("demo", V, q="%")["tickets"] != [] and len(env.t.list("demo", V, q="nomatch")["tickets"]) == 0
    first = env.t.list("demo", V, limit=3)
    assert [x["key"] for x in first["tickets"]] == ["SY-7", "SY-6", "SY-5"] and first["next"]
    second = env.t.list("demo", V, limit=3, cursor=first["next"])
    assert [x["key"] for x in second["tickets"]] == ["SY-4", "SY-3", "SY-2"]
    last = env.t.list("demo", V, limit=3, cursor=second["next"])
    assert [x["key"] for x in last["tickets"]] == ["SY-1"] and last["next"] is None
    for bad in ({"cursor": "x'; DROP"}, {"label": "Bad Label"}, {"source": "magic"}, {"status": "blocked"}):
        assert code(env.t.list, "demo", V, **bad) == "invalid"
    assert len(env.t.list("demo", V, limit=500)["tickets"]) == 7


def test_overdue_uses_the_ist_date_and_ignores_closed_tickets(env):
    env.t.create("demo", M, title="late", due_on="2026-01-01")
    ok = env.t.create("demo", M, title="fine", due_on="2999-01-01")
    done = env.t.create("demo", M, title="done late", due_on="2026-01-01")
    for s in ("doing", "review", "done"):
        env.t.move("demo", M, done["key"], s)
    assert [x["title"] for x in env.t.list("demo", V, overdue=True)["tickets"]] == ["late"]
    s = env.t.summary("demo", M)
    assert s["overdue"] == 1 and s["by_status"]["done"] == 1 and s["open"] == 2 and s["unassigned"] == 2 and ok["overdue"] is False


def test_mentions_resolve_only_members(env):
    assert env.t.mentions("demo", "ping @dan and @nobody and @mia, also user@example.com") == [D, M]
