import json
import re
import sqlite3
import textwrap

import pytest
from test_repo import DEPLOYER, M1, MAINT, NOW, OPS, OWNER, SHA, VIEWER, Clock
from test_sbom import SHA2, report as mkreport

from shipyard.access import AccessError, AgentAccess
from shipyard.config import load_config
from shipyard.dashauth import DashAuth, TooManyCodes
from shipyard.dashboard import CSP, Dashboard, serve
from shipyard.gatekeeper import Gatekeeper
from shipyard.health import Health
from shipyard.members import MemberError, MemberStore
from shipyard.policy import Role
from shipyard.sbomstore import SbomStore

UUID = "11111111-2222-3333-4444-555555555555"
def who(name):
    return f"@switch-discord-{UUID}-{name}:localhost"
OWN, MAIN2, DEP, VIEW, NEW = who("owner"), who("maint"), who("dep"), who("view"), who("newbie")


class FakeGateway:
    def __init__(self):
        self.puts, self.policy, self.code = [], None, 200

    def call(self, method, path, body=None):
        if method == "GET" and path == "/agents":
            return 200, [{"id": "a1", "name": "ops-agent", "addressing_policy": self.policy},
                         {"id": "a2", "name": "repo-agent", "addressing_policy": None}, {"id": "g", "name": "gatekeeper", "addressing_policy": None}]
        if method == "GET" and path == "/rooms":
            return 200, [{"id": OPS, "name": "demo-ops", "bridge_display_name": "Discord", "group_name": "demo", "connected_user_count": 3,
                          "external_channel_url": "https://discord.com/channels/1/2"},
                         {"id": MAINT, "name": "demo-maintainers", "bridge_display_name": "Discord", "group_name": "demo", "connected_user_count": 2,
                          "external_channel_url": "javascript:alert(1)"}, {"id": "other", "name": "someone-elses"}]
        if method == "GET" and path.startswith("/rooms/"):
            return 200, {"agent_ids": ["a1", "g"] if path.endswith(OPS) else ["a2", "g"]}
        if method == "GET" and path == "/collaborations":
            return 200, [{"bridge_id": UUID, "bridge_type": "discord"}]
        if method == "GET" and path.endswith("/users"):
            return 200, [{"id": "u-owner", "external_username": "owner"}, {"id": "u-maint", "external_username": "maint"},
                         {"id": "u-dep", "external_username": "dep"}, {"id": "u-view", "external_username": "view"}]
        if method == "PUT":
            self.puts.append((path, body))
            return self.code, {}
        return 404, None


class FakeCool:
    def status(self, uuid):
        return "demo-web: running"


@pytest.fixture
def env(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo:
            rooms: {{ops: [{OPS}], maintainers: [{MAINT}]}}
            room_names: {{{OPS}: "#demo-ops"}}
            apps: {{demo-web: web-uuid}}
            repo: {{name: o/r, app: demo-web}}
            members: {{"{OWN}": owner, "{MAIN2}": maintainer, "{DEP}": deployer, "{VIEW}": viewer}}
        actions: {{coolify.status: read, coolify.deploy: change, repo.merge: dangerous, audit.read: read, sbom.read: read}}
    """))
    cfg = load_config(f)
    clock = Clock()
    db = sqlite3.connect(":memory:", check_same_thread=False)
    gk = Gatekeeper(cfg.policy, db, clock)
    auth = DashAuth(db, gk.lock, clock, 8)
    store = SbomStore(tmp_path / "sbom", db, gk.lock, now=clock)
    gw = FakeGateway()
    members = MemberStore(tmp_path / "members.json", cfg.policy, gk.audit)
    health = Health(cfg, coolify=FakeCool(), gateway=lambda: gw, runner_active=lambda: True, now=clock)
    access = AgentAccess(cfg, lambda: gw, db, gk.lock, gk.audit, clock)
    names = {OWN: "Owner Person"}
    dash = Dashboard(cfg, gk, auth, store, health, members, access, lambda i: names.get(i, ""), now=clock)

    class E: ...
    e = E()
    e.cfg, e.gk, e.auth, e.store, e.gw, e.members, e.health, e.dash, e.clock, e.names, e.tmp = cfg, gk, auth, store, gw, members, health, dash, clock, names, tmp_path
    e.tok = {n: auth.issue(i, "demo") for n, i in (("owner", OWN), ("maint", MAIN2), ("dep", DEP), ("view", VIEW))}

    def call(method, path, who_="owner", body=None, headers=None):
        h = {"host": "localhost:8780", "content-type": "application/json", **(headers or {})}
        if who_:
            h["authorization"] = "Bearer " + (e.tok.get(who_) or who_)
        r = dash.handle(method, path, h, json.dumps(body).encode() if body is not None else b"")
        return r.status, (json.loads(r.body) if r.ctype == "application/json" and r.body else r)

    e.call = call
    return e


# --- sign-in -------------------------------------------------------------------------------------------

def test_no_or_wrong_token_is_401_everywhere(env):
    for path in ("/api/me", "/api/overview", "/api/audit", "/api/approvals", "/api/sbom", "/api/backends", "/api/roles", "/api/agents"):
        assert env.call("GET", path, who_=None)[0] == 401
        assert env.call("GET", path, who_="sy_live_nope")[0] == 401
        assert env.call("GET", path, who_="not-even-a-token")[0] == 401


def test_device_code_flow_binds_the_session_to_the_chat_sender(env):
    s, start = env.call("POST", "/api/login/start", who_=None, body={})
    assert s == 200 and re.fullmatch(r"SY-[A-Z2-9]{8}", start["code"])
    assert env.call("POST", "/api/login/poll", who_=None, body={"code": start["code"], "secret": start["secret"]})[1]["state"] == "pending"
    assert env.call("POST", "/api/login/poll", who_=None, body={"code": start["code"], "secret": "wrong"})[0] == 403
    assert env.auth.approve(start["code"].lower(), DEP, "demo")
    assert not env.auth.approve(start["code"], OWN, "demo")                      # single use
    s, done = env.call("POST", "/api/login/poll", who_=None, body={"code": start["code"], "secret": start["secret"]})
    assert done["state"] == "ok" and done["token"].startswith("sy_live_")
    assert env.call("POST", "/api/login/poll", who_=None, body={"code": start["code"], "secret": start["secret"]})[1]["state"] != "ok"   # the token is handed over once
    s, me = env.call("GET", "/api/me", who_=done["token"])
    assert me["role"] == "deployer" and me["identity"]["name"] == "dep" and me["owner"] is False


def test_codes_expire_and_are_limited(env):
    code = env.auth.start()
    env.clock.t += 601
    assert not env.auth.approve(code["code"], OWN, "demo") and env.auth.poll(code["code"], code["secret"])[0] == "expired"
    for _ in range(20):
        env.auth.start()
    with pytest.raises(TooManyCodes):
        env.auth.start()


def test_sessions_expire_logout_and_removal_end_access(env):
    assert env.call("GET", "/api/me")[0] == 200
    env.clock.t += 9 * 3600
    assert env.call("GET", "/api/me")[0] == 401
    tok = env.auth.issue(DEP, "demo")
    assert env.call("POST", "/api/logout", who_=tok, body={})[0] == 200 and env.call("GET", "/api/me", who_=tok)[0] == 401
    tok2 = env.auth.issue(DEP, "demo")
    env.members.apply("demo", OWN, [{"identity": DEP, "role": None}])               # removed: the live role lookup fails at once
    assert env.call("GET", "/api/me", who_=tok2)[0] == 401


def test_a_session_for_a_non_member_is_refused(env):
    assert env.call("GET", "/api/me", who_=env.auth.issue(NEW, "demo"))[0] == 401


# --- request hygiene -----------------------------------------------------------------------------------

def test_static_files_unknown_paths_and_methods(env):
    r = env.dash.handle("GET", "/", {"host": "127.0.0.1:8780"})
    assert r.status == 200 and b"/app.js" in r.body and r.ctype.startswith("text/html")
    assert env.dash.handle("GET", "/app.js", {"host": "127.0.0.1:8780"}).status == 200
    assert env.dash.handle("GET", "/../shipyard.yaml", {"host": "127.0.0.1:8780"}).status == 404
    assert env.dash.handle("GET", "/app.js/../../config.py", {"host": "127.0.0.1:8780"}).status == 404
    assert env.dash.handle("DELETE", "/app.js", {"host": "127.0.0.1:8780"}).status == 405
    assert env.call("GET", "/api/nope")[0] == 404
    assert env.call("DELETE", "/api/roles")[0] == 405


def test_host_header_must_be_loopback_and_posts_must_be_same_origin_json(env):
    ok = lambda host: host.split(":")[0] in ("127.0.0.1", "localhost", "[::1]")          # noqa: E731
    assert env.dash.handle("GET", "/api/me", {"host": "evil.example:8780"}, host_ok=lambda h: bool(__import__("re").match(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", h))).status == 403
    assert env.call("POST", "/api/roles", body={"changes": []}, headers={"origin": "https://evil.example"})[0] == 403
    assert env.call("POST", "/api/roles", body={"changes": []}, headers={"content-type": "text/plain"})[0] == 415
    r = env.dash.handle("POST", "/api/roles", {"host": "localhost:8780", "content-type": "application/json", "authorization": "Bearer " + env.tok["owner"]}, b"[1]")
    assert r.status == 400


def test_the_server_refuses_a_non_loopback_bind(env):
    with pytest.raises(SystemExit):
        serve(env.dash, "0.0.0.0", 0)


def test_csp_is_strict_and_the_front_end_never_uses_innerhtml():
    assert "script-src 'self'" in CSP and "unsafe" not in CSP and "default-src 'none'" in CSP
    from pathlib import Path
    js = (Path(__file__).parent.parent / "shipyard" / "web" / "app.js").read_text()
    code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)                # the header comment says there is none
    code = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", "", code)            # strings may mention the words in the guard
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in code.replace("k === 'html'", ""), bad
    assert "style=" not in (Path(__file__).parent.parent / "shipyard" / "web" / "index.html").read_text()


def test_there_is_no_endpoint_that_approves_or_denies(env):
    for path in ("/api/approve", "/api/approvals/abc/approve", "/api/approvals/approve", "/api/deny", "/api/approvals"):
        for method in ("POST", "PUT", "DELETE"):
            assert env.call(method, path)[0] in (404, 405), (method, path)


# --- overview, audit, approvals --------------------------------------------------------------------------

def test_overview_has_health_chain_and_recent_activity(env):
    env.gk.audit.write(project="demo", actor=OWN, event="executed", action="coolify.deploy", target="demo-web", result="queued")
    s, d = env.call("GET", "/api/overview", who_="view")
    assert s == 200 and d["project"] == "demo" and d["chain"]["ok"] and d["chain"]["rows"] >= 1
    assert [h["key"] for h in d["health"]][:2] == ["coolify", "kubernetes"] and d["recent"][0]["target"] == "demo-web"
    assert sorted(d["rooms"]) == sorted(["#demo-ops", MAINT])
    assert d["recent"][0]["who"]["name"] == "Owner Person" and d["recent"][0]["who"]["role"] == "owner"


def test_audit_paging_filters_and_redaction(env):
    for i in range(7):
        env.gk.audit.write(project="demo", actor=OWN, event="executed" if i % 2 else "denied", action="coolify.deploy", target=f"app{i}",
                           error="token=sk-abcdefghijklmnopqrstuvwxyz0123456789 failed")
    env.gk.audit.write(project="other", actor=OWN, event="denied", action="x", target="secret-other-project")
    s, d = env.call("GET", "/api/audit?limit=3")
    assert len(d["rows"]) == 3 and d["more"] and "sk-abcdefghij" not in json.dumps(d)
    s, d2 = env.call("GET", f"/api/audit?limit=3&before={d['rows'][-1]['id']}")
    assert d2["rows"][0]["id"] < d["rows"][-1]["id"]
    assert all(r["event"] == "denied" for r in env.call("GET", "/api/audit?event=denied")[1]["rows"])
    assert [r["target"] for r in env.call("GET", "/api/audit?q=app3")[1]["rows"]] == ["app3"]
    assert "secret-other-project" not in json.dumps(env.call("GET", "/api/audit?limit=200")[1])
    assert env.call("GET", "/api/audit?limit=abc&before=x")[0] == 200
    assert env.call("GET", "/api/audit?q=" + "a" * 5000)[0] == 414


def test_audit_shows_script_tags_as_data_not_html(env):
    env.gk.audit.write(project="demo", actor=OWN, event="denied", action="deploy", target="<script>alert(1)</script>", reason="<img src=x onerror=alert(1)>")
    rows = env.call("GET", "/api/audit")[1]["rows"]
    assert rows[0]["target"] == "<script>alert(1)</script>"            # raw text: the page renders it with textContent


def test_a_tampered_audit_row_breaks_the_chain_badge(env):
    env.gk.audit.write(project="demo", actor=OWN, event="executed", action="a", target="t")
    assert env.call("GET", "/api/overview")[1]["chain"]["ok"]
    env.gk.db.execute("UPDATE audit SET target='edited'")
    env.clock.t += 31
    assert env.call("GET", "/api/overview")[1]["chain"]["ok"] is False


def test_approvals_list_is_read_only_and_marks_gates(env):
    env.gk.request_action(project="demo", identity=DEP, is_human=True, action="coolify.deploy", target="demo-web",
                          args={"sha": SHA, "gate": ["CVE-2026-0001"]}, room_id=OPS, force_approval=True)
    env.gk.request_action(project="demo", identity=MAIN2, is_human=True, action="repo.merge", target="7", args={"sha": SHA2}, room_id=OPS)
    s, d = env.call("GET", "/api/approvals", who_="view")
    assert s == 200 and len(d["approvals"]) == 2
    gated = next(a for a in d["approvals"] if a["gate"])
    assert gated["needs"] == "owner" and gated["gate"] == ["CVE-2026-0001"] and gated["room"] == "#demo-ops"
    assert next(a for a in d["approvals"] if a["action"] == "repo.merge")["needs"] == "a second person"
    env.clock.t += 700
    assert env.call("GET", "/api/approvals")[1]["approvals"] == []                # expired ones leave the list


# --- SBOM ------------------------------------------------------------------------------------------------

def put_report(env, commit, pkgs, matches, pr=None, ref="main", raw=None):
    r = mkreport(pkgs, matches, commit=commit)
    r["pr"], r["ref"] = pr, ref
    env.store.save(r, raw or {"spdx": b'{"spdx":1}', "scan": b"{}"})
    return r


def test_sbom_list_detail_downloads_and_overrides(env):
    base = put_report(env, SHA, [("flask", "3.0")], [])
    env.store.record_release("demo", "demo-web", SHA)
    put_report(env, SHA2, [("flask", "3.0"), ("django", "2.2.0")], [("CVE-2026-0001", "Critical", "django", "2.2.0", [])], pr=7, ref="PR #7")
    s, d = env.call("GET", "/api/sbom", who_="view")
    assert s == 200 and d["total"] == 2
    by = {r["commit"]: r for r in d["rows"]}
    assert by[SHA]["live"] is True and by[SHA2]["live"] is False and by[SHA2]["pr"] == 7
    assert env.call("GET", "/api/sbom?decision=blocked")[1]["total"] == 1 and env.call("GET", "/api/sbom?decision=clear")[1]["rows"][0]["commit"] == SHA
    s, det = env.call("GET", f"/api/sbom/{SHA2}")
    assert s == 200 and det["decision"] == "blocked" and det["findings"][0]["new"] is True and det["diff"]["added"] == [["pypi/django", "2.2.0"]]
    assert det["links"]["commit"].endswith(f"/o/r/commit/{SHA2}") and det["files"] == ["spdx", "scan", "html"]
    assert env.call("GET", f"/api/sbom/{SHA2[:9]}")[0] == 200                      # abbreviations work
    r = env.dash.handle("GET", f"/api/sbom/{SHA2}/file/spdx", {"host": "localhost", "authorization": "Bearer " + env.tok["view"]})
    assert r.status == 200 and r.body == b'{"spdx":1}' and "attachment" in r.headers["Content-Disposition"]
    html = env.dash.handle("GET", f"/api/sbom/{SHA2}/file/html", {"host": "localhost", "authorization": "Bearer " + env.tok["view"]})
    assert html.status == 200 and "sandbox" in html.headers["Content-Security-Policy"] and b"CVE-2026-0001" in html.body
    env.gk.audit.write(project="demo", actor=OWN, event="gate_override", action="repo.merge", target="7", cves=["CVE-2026-0001"], commit=SHA2[:12])
    assert env.call("GET", f"/api/sbom/{SHA2}")[1]["decision"] == "overridden"
    assert env.call("GET", "/api/sbom?decision=overridden")[1]["total"] == 1


def test_sbom_paths_cannot_escape(env):
    put_report(env, SHA, [("p", "1")], [])
    for path in ("/api/sbom/../../etc/passwd", f"/api/sbom/{SHA}/file/../../report", f"/api/sbom/{SHA}/file/report.json",
                 "/api/sbom/ZZZZZZZ", f"/api/sbom/{SHA}/file/cyclonedx", "/api/sbom/" + "a" * 41):
        assert env.call("GET", path)[0] == 404, path


def test_sbom_of_another_repo_is_not_shown(env):
    r = mkreport([("p", "1")], [], commit=SHA)
    r["repo"] = "someone/else"
    env.store.save(r)
    assert env.call("GET", f"/api/sbom/{SHA}")[0] == 404 and env.call("GET", "/api/sbom")[1]["total"] == 0


# --- backends --------------------------------------------------------------------------------------------

def test_backends_are_cached_and_a_failing_probe_is_a_finding(env):
    s, d = env.call("GET", "/api/backends")
    keys = {i["key"]: i for i in d["items"]}
    assert keys["coolify"]["state"] == "ok" and keys["kubernetes"]["state"] == "off" and keys["switch"]["state"] == "ok" and keys["agents"]["headline"] == "2/2 ready"
    env.health.coolify = type("Broken", (), {"status": lambda self, u: (_ for _ in ()).throw(RuntimeError("Coolify down"))})()
    assert env.call("GET", "/api/backends")[1]["items"][0]["state"] == "ok"                          # cached
    s, d = env.call("POST", "/api/backends/refresh", body={"key": "coolify"})
    c = next(i for i in d["items"] if i["key"] == "coolify")
    assert c["state"] == "bad" and "Coolify down" in c["detail"] and d["attention"] >= 1


# --- roles -----------------------------------------------------------------------------------------------

def test_everyone_reads_roles_only_owners_write(env):
    s, d = env.call("GET", "/api/roles", who_="view")
    assert s == 200 and d["editable"] is False and [m["role"] for m in d["members"]] == ["owner", "maintainer", "deployer", "viewer"]
    assert next(m for m in d["members"] if m["id"] == OWN)["last_owner"] is True
    for who_ in ("maint", "dep", "view"):
        assert env.call("POST", "/api/roles", who_=who_, body={"changes": [{"identity": VIEW, "role": "owner"}]})[0] == 403
    assert env.cfg.policy.members["demo"][VIEW] is Role.VIEWER


def test_owner_changes_a_role_live_with_an_audit_row_and_a_persisted_overlay(env):
    s, d = env.call("POST", "/api/roles", body={"changes": [{"identity": DEP, "role": "maintainer"}, {"identity": NEW, "role": "viewer"}]})
    assert s == 200 and d["audited"] == 2
    assert env.cfg.policy.members["demo"][DEP] is Role.MAINTAINER and env.cfg.policy.members["demo"][NEW] is Role.VIEWER
    rows = [r for r in env.gk.audit.recent("demo", 5) if r["event"] == "role_changed"]
    assert {(r["target"], r["detail"]["before"], r["detail"]["after"]) for r in rows} == {(DEP, "deployer", "maintainer"), (NEW, None, "viewer")}
    data = json.loads((env.tmp / "members.json").read_text())
    assert data["demo"][DEP] == "maintainer" and oct((env.tmp / "members.json").stat().st_mode & 0o777) == "0o600"
    again = MemberStore(env.tmp / "members.json", env.cfg.policy, env.gk.audit)
    env.cfg.policy.members["demo"].pop(NEW)
    again.load()
    assert env.cfg.policy.members["demo"][NEW] is Role.VIEWER                                         # overlay wins after a restart


@pytest.mark.parametrize("changes,why", [
    ([{"identity": OWN, "role": "viewer"}], "at least one owner"),
    ([{"identity": OWN, "role": None}], "at least one owner"),
    ([{"identity": "anya", "role": "viewer"}], "not a chat identity"),
    ([{"identity": who("x"), "role": "superuser"}], "unknown role"),
    ([{"identity": who("ghost"), "role": None}], "not a member"),
    ([], "between 1 and 50"),
    ([{"identity": who("x"), "role": "viewer", "extra": 1}], "{identity, role}"),
    ("nope", "between 1 and 50"),
    ([{"identity": "@switch-discord-x-y:localhost", "role": "viewer"}], "not a chat identity"),
])
def test_bad_role_changes_are_refused_and_change_nothing(env, changes, why):
    before = dict(env.cfg.policy.members["demo"])
    s, d = env.call("POST", "/api/roles", body={"changes": changes})
    assert s == 422 and why in d["error"] and env.cfg.policy.members["demo"] == before
    assert not (env.tmp / "members.json").exists()


def test_one_bad_change_in_a_batch_applies_none_and_a_second_owner_makes_demoting_possible(env):
    assert env.call("POST", "/api/roles", body={"changes": [{"identity": NEW, "role": "viewer"}, {"identity": "bad", "role": "viewer"}]})[0] == 422
    assert NEW not in env.cfg.policy.members["demo"]
    assert env.call("POST", "/api/roles", body={"changes": [{"identity": MAIN2, "role": "owner"}]})[0] == 200
    assert env.call("POST", "/api/roles", body={"changes": [{"identity": OWN, "role": "viewer"}]})[0] == 200
    assert env.call("POST", "/api/roles", who_="owner", body={"changes": [{"identity": OWN, "role": "owner"}]})[0] == 403   # same session, now a viewer's rights


def test_a_no_op_change_writes_nothing(env):
    s, d = env.call("POST", "/api/roles", body={"changes": [{"identity": DEP, "role": "deployer"}]})
    assert s == 200 and d["changed"] == [] and not [r for r in env.gk.audit.recent("demo", 5) if r["event"] == "role_changed"]


def test_a_damaged_overlay_stops_startup_rather_than_guessing(env):
    (env.tmp / "members.json").write_text("{not json")
    with pytest.raises(SystemExit):
        MemberStore(env.tmp / "members.json", env.cfg.policy, env.gk.audit).load()
    (env.tmp / "members.json").write_text(json.dumps({"demo": {OWN: "viewer"}}))
    MemberStore(env.tmp / "members.json", env.cfg.policy, env.gk.audit).load()
    assert env.cfg.policy.members["demo"][OWN] is Role.OWNER                                          # an overlay with no owner is ignored


# --- agent access ----------------------------------------------------------------------------------------

def test_agent_access_state_preview_and_apply(env):
    s, d = env.call("GET", "/api/agents", who_="view")
    assert s == 200 and d["editable"] is False and [a["name"] for a in d["agents"]] == ["ops-agent", "repo-agent", "gatekeeper"]
    assert d["agents"][2]["status"] == "system" and d["agents"][2]["may_address"] is None
    assert env.call("POST", "/api/agents/preview", who_="maint", body={})[0] == 403 and env.call("POST", "/api/agents/sync", who_="dep", body={})[0] == 403
    s, p = env.call("POST", "/api/agents/preview", body={})
    assert s == 200 and {c["agent"] for c in p["changes"]} == {"ops-agent", "repo-agent"} and any("Owner Person may address it" in c["text"] for c in p["changes"])
    assert not env.gw.puts                                                    # a preview changes nothing
    s, r = env.call("POST", "/api/agents/sync", body={})
    assert s == 200 and r["agents"] == ["ops-agent", "repo-agent"] and len(env.gw.puts) == 2
    path, body = env.gw.puts[0]
    users = body["policy"]["rules"][0]["users"]
    assert path == "/agents/a1/addressing-policy" and sorted(users) == ["u-dep", "u-maint", "u-owner", "u-view"]
    assert body["policy"]["rules"][-1] == {"rooms": "*", "users": [], "agents": [], "owner": True, "platform": False}
    assert any(r["event"] == "executed" and r["action"] == "agents.sync" for r in env.gk.audit.recent("demo", 5))
    env.gw.policy = body["policy"]
    assert {c["agent"] for c in env.call("POST", "/api/agents/preview", body={})[1]["changes"]} == {"repo-agent"}   # ops-agent is in sync now


def test_agent_sync_follows_role_changes_and_reports_switch_refusal(env):
    env.gw.policy = {"rules": [{"rooms": [OPS, MAINT], "users": ["u-owner", "u-maint", "u-dep", "u-view"], "agents": [], "owner": False, "platform": False}]}
    env.call("POST", "/api/roles", body={"changes": [{"identity": VIEW, "role": None}]})
    p = env.call("POST", "/api/agents/preview", body={})[1]["changes"]
    assert any(c["op"] == "-" and "view" in c["text"] for c in p)
    env.gw.code = 403
    s, d = env.call("POST", "/api/agents/sync", body={})
    assert s == 502 and "403" in d["error"]
    assert any(r["event"] == "failed" and r["action"] == "agents.sync" for r in env.gk.audit.recent("demo", 5))


def test_unresolved_members_are_named_not_silently_dropped(env):
    env.call("POST", "/api/roles", body={"changes": [{"identity": NEW, "role": "viewer"}]})
    p = env.call("POST", "/api/agents/preview", body={})[1]["changes"]
    assert any(c["op"] == "!" and "newbie" in c["text"] for c in p)
    assert env.call("GET", "/api/agents")[1]["unresolved"][0]["name"] == "newbie"


# --- the chat side of sign-in ------------------------------------------------------------------------------

def test_dashboard_login_verb_in_chat(env):
    from shipyard.service import Service
    posts = []
    svc = Service(env.cfg, env.gk, None, lambda r, t: posts.append(t), now=env.clock, dashauth=env.auth)

    def say(sender, body):
        svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": f"m{len(posts)}{body[-3:]}", "sender": sender,
                          "sender_name": sender.split("-")[-1].split(":")[0], "sender_kind": None, "body": "@gatekeeper " + body, "addressed": True}})
    code = env.auth.start()
    say(NEW, f"dashboard-login {code['code']}")
    assert "not a member" in posts[-1]
    say(DEP, "dashboard-login SY-WRONGONE")
    assert "unknown, used or expired" in posts[-1]
    say(DEP, f"dashboard-login {code['code']}")
    assert "Signed in to the dashboard as dep (deployer)" in posts[-1]
    assert env.auth.poll(code["code"], code["secret"])[0] == "ok"
    say(DEP, f"dashboard-login {code['code']}")
    assert "unknown, used or expired" in posts[-1]
    events = {(r["event"], r["action"]) for r in env.gk.audit.recent("demo", 10)}
    assert ("allowed", "dashboard.login") in events and ("denied", "dashboard.login") in events


def test_switch_rooms_page_shows_only_the_projects_rooms_and_safe_links(env):
    s, d = env.call("GET", "/api/rooms", who_="view")
    assert s == 200 and [r["name"] for r in d["rooms"]] == ["demo-maintainers", "demo-ops"] or {r["name"] for r in d["rooms"]} == {"demo-ops", "demo-maintainers"}
    by = {r["name"]: r for r in d["rooms"]}
    assert by["demo-ops"]["agents"] == ["gatekeeper", "ops-agent"] and by["demo-ops"]["kind"] == "ops" and by["demo-ops"]["alerts"] is True
    assert by["demo-ops"]["url"] == "https://discord.com/channels/1/2" and by["demo-maintainers"]["url"] is None       # a javascript: link is dropped
    assert by["demo-maintainers"]["kind"] == "maintainers" and "someone-elses" not in json.dumps(d)
    assert env.call("GET", "/api/rooms", who_=None)[0] == 401


def test_a_network_bind_needs_the_explicit_opt_in_and_then_only_the_published_host_is_accepted(env):
    import socket
    from shipyard.dashboard import _loopback_host
    with pytest.raises(SystemExit, match="shipyard expose"):
        serve(env.dash, "0.0.0.0", 0)                                           # the default stays: loopback only
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = serve(env.dash, "0.0.0.0", port, allow_remote=True, public_url="http://13.126.17.66:8780")
    srv.shutdown()
    srv.server_close()
    ok = _loopback_host(8780, "http://13.126.17.66:8780")
    assert ok("localhost:8780") and ok("127.0.0.1:8780") and ok("13.126.17.66:8780") and ok("13.126.17.66:8780".upper())
    assert not ok("evil.example:8780") and not ok("13.126.17.66:9999") and not ok("13.126.17.67:8780")
    assert not _loopback_host(8780, "")("13.126.17.66:8780")                       # nothing published: loopback only, as before
