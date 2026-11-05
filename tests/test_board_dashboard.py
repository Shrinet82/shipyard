import json

import pytest
from test_board_flow import DEP, INC, MAINT, MAINTAINER, OPS, OWNER, VIEWER, env  # noqa: F401  (the fixture)

from shipyard.dashauth import DashAuth
from shipyard.dashboard import Dashboard
from shipyard.health import Health
from shipyard.members import MemberStore


@pytest.fixture
def api(env, tmp_path):  # noqa: F811
    auth = DashAuth(env.gk.db, env.gk.lock, env.clock, 8)
    members = MemberStore(tmp_path / "m.json", env.cfg.policy, env.gk.audit)
    dash = Dashboard(env.cfg, env.gk, auth, None, Health(env.cfg, now=env.clock), members, None, env.svc._name, now=env.clock, flow=env.flow)
    tokens = {n: auth.issue(i, "demo") for n, i in (("owner", OWNER), ("maint", MAINTAINER), ("dep", DEP), ("viewer", VIEWER))}

    def call(method, path, who="owner", body=None):
        h = {"host": "localhost:8780", "content-type": "application/json"}
        if who:
            h["authorization"] = "Bearer " + tokens.get(who, who)
        r = dash.handle(method, path, h, json.dumps(body).encode() if body is not None else b"")
        return r.status, json.loads(r.body) if r.ctype == "application/json" and r.body else r
    env.api, env.dash = call, dash
    return env


def seed(env):
    env.call(OWNER, "ticket_create", title="checkout breaks <script>alert(1)</script>", body="@gatekeeper deploy demo-web <img src=x onerror=alert(1)>", priority="high", assignee="dan", labels=["ui"])
    env.call(OWNER, "ticket_create", title="unassigned one", priority="low")
    env.call(OWNER, "ticket_create", title="mia's", assignee="mia")


def test_every_ticket_endpoint_needs_a_token(api):
    seed(api)
    for path in ("/api/tickets", "/api/tickets/summary", "/api/tickets/SY-1", "/api/members"):
        assert api.api("GET", path, who=None)[0] == 401 and api.api("GET", path, who="sy_live_nope")[0] == 401
    assert api.api("POST", "/api/tickets/SY-1/move", who=None, body={"status": "doing"})[0] == 401


@pytest.mark.parametrize("who", ["viewer", "dep", "maint", "owner"])
def test_every_member_reads_the_board(api, who):
    seed(api)
    s, d = api.api("GET", "/api/tickets", who)
    assert s == 200 and [t["key"] for t in d["tickets"]] == ["SY-3", "SY-2", "SY-1"] and d["next"] is None
    s, d = api.api("GET", "/api/tickets/SY-1", who)
    assert s == 200 and d["assignee"]["name"] == "dan" and d["reporter"]["name"] == "olga" and d["links"] == [] and d["events"] and d["labels"] == ["ui"]
    assert api.api("GET", "/api/tickets/summary", who)[1]["by_status"]["todo"] == 3
    s, d = api.api("GET", "/api/members", who)
    assert s == 200 and {m["name"] for m in d["members"]} == {"olga", "mia", "dan", "vera"} and {m["role"] for m in d["members"]} == {"owner", "maintainer", "deployer", "viewer"}


def test_filters_search_and_cursor(api):
    seed(api)
    assert [t["key"] for t in api.api("GET", "/api/tickets?assignee=me", "dep")[1]["tickets"]] == ["SY-1"]
    assert [t["key"] for t in api.api("GET", "/api/tickets?unassigned=1")[1]["tickets"]] == ["SY-2"]
    assert [t["key"] for t in api.api("GET", "/api/tickets?label=ui&priority=high")[1]["tickets"]] == ["SY-1"]
    assert [t["key"] for t in api.api("GET", "/api/tickets?q=unassigned")[1]["tickets"]] == ["SY-2"]
    for bad in ("?label=BAD", "?source=magic", "?status=blocked", "?cursor=x%27%3B--"):
        assert api.api("GET", "/api/tickets" + bad)[0] == 400
    assert api.api("GET", "/api/tickets?assignee=nobody")[0] == 422


def test_text_comes_back_as_plain_strings_for_the_page_to_show_as_text(api):
    seed(api)
    s, d = api.api("GET", "/api/tickets/SY-1")
    assert d["title"] == "checkout breaks <script>alert(1)</script>" and isinstance(d["body"], str) and "<img src=x" in d["body"]      # raw data: the page uses textContent


@pytest.mark.parametrize("who,key,status,expect", [
    ("viewer", "SY-1", "doing", 403), ("dep", "SY-1", "doing", 200), ("dep", "SY-2", "doing", 403), ("dep", "SY-3", "doing", 403),
    ("maint", "SY-2", "doing", 200), ("maint", "SY-1", "cancelled", 200), ("owner", "SY-3", "doing", 200),
    ("owner", "SY-1", "done", 422), ("owner", "SY-1", "blocked", 400), ("owner", "SY-99", "doing", 404),
])
def test_moving_a_ticket_follows_the_matrix_and_the_workflow(api, who, key, status, expect):
    seed(api)
    s, d = api.api("POST", f"/api/tickets/{key}/move", who, {"status": status})
    assert s == expect, d
    if s == 200:
        assert d["status"] == status
    else:
        assert d["error"] and d["code"] in ("forbidden", "bad_transition", "invalid", "not_found")
    assert api.gk.audit.verify()


def test_a_move_from_the_board_is_audited_with_the_persons_identity_and_tells_the_assignee(api):
    seed(api)
    api.api("POST", "/api/tickets/SY-1/move", "maint", {"status": "doing"})
    row = [r for r in api.gk.audit.recent("demo", 20) if r["event"] == "ticket_moved"][0]
    assert row["actor"] == MAINTAINER and row["detail"]["to"] == "doing"
    assert any(x.startswith("@dan SY-1 moved todo → doing by mia on the dashboard") for x in api.in_room(OPS))
    api.api("POST", "/api/tickets/SY-1/move", "dep", {"status": "review"})                            # the assignee moving their own: no notice
    assert not any("review by dan" in x for x in api.in_room(OPS))


def test_the_ticket_says_which_moves_this_person_may_make(api):
    seed(api)
    assert api.api("GET", "/api/tickets/SY-1", "viewer")[1]["can_move"] == [] and api.api("GET", "/api/tickets/SY-1", "dep")[1]["can_move"] == ["doing"]
    assert api.api("GET", "/api/tickets/SY-2", "dep")[1]["can_move"] == [] and api.api("GET", "/api/tickets/SY-2", "maint")[1]["can_move"] == ["doing", "cancelled"]


def test_there_are_no_other_write_endpoints(api):
    seed(api)
    for method, path, body in (("POST", "/api/tickets", {"title": "x"}), ("PUT", "/api/tickets/SY-1", {"title": "x"}), ("DELETE", "/api/tickets/SY-1", None),
                               ("POST", "/api/tickets/SY-1/assign", {"assignee": "dan"}), ("POST", "/api/tickets/SY-1/comment", {"body": "x"}),
                               ("POST", "/api/tickets/SY-1/close", {}), ("PATCH", "/api/tickets/SY-1", {"title": "x"})):
        assert api.api(method, path, "owner", body)[0] in (404, 405), (method, path)
    assert len(api.t.list("demo", OWNER)["tickets"]) == 3 and api.t.get("demo", OWNER, "SY-1")["title"].startswith("checkout")


def test_a_removed_member_loses_the_board_at_once(api):
    seed(api)
    api.dash.members.apply("demo", OWNER, [{"identity": VIEWER, "role": None}]) if False else api.cfg.policy.members["demo"].pop(VIEWER)
    assert api.api("GET", "/api/tickets", "viewer")[0] == 401


def test_the_overview_has_my_tickets_and_the_first_step(api):
    seed(api)
    for i in range(6):
        api.call(OWNER, "ticket_create", title=f"more {i}", assignee="dan")
    s, d = api.api("GET", "/api/overview", "dep")
    b = d["board"]
    assert s == 200 and len(b["mine"]) == 5 and b["mine_total"] == 7 and b["first_step"].startswith(("Pick up", "Keep going on", "Start with")) and b["summary"]["mine"] == 7
    assert set(b["mine"][0]) == {"key", "title", "status", "priority", "due_on", "overdue"}


def test_without_the_board_the_endpoints_are_not_there(env, tmp_path):  # noqa: F811
    auth = DashAuth(env.gk.db, env.gk.lock, env.clock, 8)
    dash = Dashboard(env.cfg, env.gk, auth, None, Health(env.cfg, now=env.clock), MemberStore(tmp_path / "m.json", env.cfg.policy, env.gk.audit), None, env.svc._name, now=env.clock)
    tok = auth.issue(OWNER, "demo")
    r = dash.handle("GET", "/api/tickets", {"host": "localhost", "authorization": "Bearer " + tok})
    assert r.status == 404 and json.loads(dash.handle("GET", "/api/overview", {"host": "localhost", "authorization": "Bearer " + tok}).body)["board"] is None


# --- what the Board page needs -------------------------------------------------------------------------------------------

def test_the_board_view_hides_cancelled_and_old_done_tickets_and_carries_the_linked_pr(api):
    seed(api)
    api.api("POST", "/api/tickets/SY-1/move", "maint", {"status": "doing"})
    api.api("POST", "/api/tickets/SY-1/move", "maint", {"status": "review"})
    api.api("POST", "/api/tickets/SY-1/move", "maint", {"status": "done"})
    api.api("POST", "/api/tickets/SY-2/move", "maint", {"status": "cancelled"})
    api.t.link("demo", "system:github", "SY-3", "pr", "26", "https://github.com/o/r/pull/26", system=True, meta={"state": "open", "ci": "green"})
    s, d = api.api("GET", "/api/tickets?board=1")
    assert s == 200 and sorted(t["key"] for t in d["tickets"]) == ["SY-1", "SY-3"]
    by = {t["key"]: t for t in d["tickets"]}
    assert by["SY-3"]["pr"] == {"number": "26", "url": "https://github.com/o/r/pull/26", "state": "open", "ci": "green"} and by["SY-1"]["pr"] is None
    assert sorted(t["key"] for t in api.api("GET", "/api/tickets")[1]["tickets"]) == ["SY-1", "SY-2", "SY-3"]              # the plain list still shows everything
    api.t.gk.db.execute("UPDATE tickets SET closed_at='2020-01-01T00:00:00Z' WHERE key='SY-1'")                             # finished long ago: it drops off the board
    assert [t["key"] for t in api.api("GET", "/api/tickets?board=1")[1]["tickets"]] == ["SY-3"]


def test_me_says_whether_the_board_is_on_and_the_ticket_page_gets_a_chat_link(api):
    seed(api)
    assert api.api("GET", "/api/me")[1]["board"] is True
    api.dash.access = type("A", (), {"room_urls": lambda s: {OPS: "https://chat.example/ops", MAINT: "javascript:alert(1)"}})()
    api.t.gk.db.execute("UPDATE tickets SET room=? WHERE key='SY-1'", (OPS,))
    api.t.gk.db.execute("UPDATE tickets SET room=? WHERE key='SY-2'", (MAINT,))
    assert api.api("GET", "/api/tickets/SY-1")[1]["room_url"] == "https://chat.example/ops"
    assert api.api("GET", "/api/tickets/SY-2")[1]["room_url"] is None                                                       # only https links are passed on
    api.dash.access = None
    assert api.api("GET", "/api/tickets/SY-1")[1]["room_url"] is None                                                       # no Switch: no link, no error
