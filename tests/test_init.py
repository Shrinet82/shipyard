import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from test_dashboard import OWN

from shipyard.config import load_config
from shipyard.init import InitError, Installer, doctor
from shipyard.members import MemberError, MemberStore
from shipyard.policy import Role

ROOMS = [{"id": "r-ops-mm", "name": "demo-ops", "bridge_display_name": "Mattermost"}, {"id": "r-ops-dc", "name": "demo-ops", "bridge_display_name": "Discord"},
         {"id": "r-mt", "name": "demo-maintainers", "bridge_display_name": "Mattermost"}]


class FakeGw:
    rooms = ROOMS
    controllers = [{"id": "c1", "name": "build-vm"}]
    agents = ["ops-agent", "repo-agent"]
    template_status = 201

    def __init__(self, *a):
        self.calls = []

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/rooms":
            return 200, type(self).rooms
        if method == "POST" and path == "/rooms":
            if not body["agent_names"]:
                return 400, "Internal rooms require at least one agent"
            return 200, {"id": "new-" + body["name"]}
        if method == "GET" and path == "/management/controllers":
            return 200, type(self).controllers
        if method == "GET" and path == "/agents":
            return 200, [{"name": n} for n in type(self).agents]
        if method == "POST" and path == "/rooms/from-template-document":
            if type(self).template_status != 201:
                return 409, json.dumps({"detail": "x", "code": "agents_not_created", "problems": [{"slot": "ops_agent", "code": "provider_login_missing", "message": "Codex is not signed in"}]})
            p = body["inputs"]["project"]
            return 201, {"created_agents": [], "room": {"group_name": p, "rooms": [{"room_id": f"t-{k}", "room_name": f"{p}-{k}"} for k in ("ops", "incidents", "maintainers")], "errors": []}}
        return 200, {}


def http_fake(coolify_status=200, register_status=201):
    def http(method, url, headers=None, body=None, timeout=20):
        if url.endswith("/api/v1/applications"):
            return coolify_status, [{"uuid": "u-web", "name": "Demo Web"}, {"uuid": "u-api", "name": "demo api"}] if coolify_status == 200 else "no"
        if url.endswith("/agents") and method == "POST":
            return register_status, {"id": "gk-id", "api_key": "gk-secret-key"}
        return 200, "<html>"
    return http


@pytest.fixture
def home(tmp_path):
    (tmp_path / "switch").mkdir()
    (tmp_path / "switch/.env").write_text("GATEWAY_ADMIN_EMAIL=a@b.c\nGATEWAY_ADMIN_PASSWORD=pw\nAGENT_REGISTRATION_TOKEN=regtok\n")
    (tmp_path / "gh.pem").write_text("pem")
    os.chmod(tmp_path / "gh.pem", 0o644)
    return tmp_path


def answers(home, **over):
    a = {"project": "demo", "switch": {"url": "http://sw:8000", "env_file": str(home / "switch/.env")},
         "rooms": {"ops": ["demo-ops"], "maintainers": ["r-mt"]},
         "coolify": {"url": "http://cool:8000", "token": "cool-secret-token", "apps": ["demo-web"]},
         "github": {"app_id": "123", "private_key_file": str(home / "gh.pem"), "repo": "o/r", "deploy_app": "demo-web"},
         "agents": {"create": "no"}, "owner": OWN, "dashboard": True}
    a.update(over)
    return a


def installer(home, a, **kw):
    log, runs = [], []
    inst = Installer(a, home, interactive=False, say=log.append, gateway=FakeGw, http=kw.pop("http", http_fake()),
                     run=lambda argv, **k: runs.append(argv) or SimpleNamespace(returncode=0, stdout="active", stderr=""),
                     github_check=kw.pop("github_check", lambda *x: "inst-1"), python="/usr/bin/python3", workdir=Path(__file__).parent.parent, **kw)
    inst.log, inst.runs = log, runs
    return inst


def test_full_install_writes_a_config_the_gatekeeper_can_load_and_locks_the_secrets(home):
    inst = installer(home, answers(home))
    inst.install()
    cfg = load_config(home / "shipyard.yaml")
    p = cfg.projects["demo"]
    assert p.ops_rooms == {"r-ops-mm", "r-ops-dc"} and p.maintainer_rooms == {"r-mt"}            # a name selects every room of that name
    assert p.apps == {"demo-web": "u-web"} and p.repo.name == "o/r" and p.repo.app == "demo-web" and p.repo.required_checks == ("test", "sbom")
    assert cfg.policy.members["demo"][OWN] is Role.OWNER and cfg.github.installation_id == "inst-1"
    assert cfg.dashboard.port == 8780 and cfg.sbom.enabled and cfg.policy.actions["repo.merge"].value == "dangerous"
    for name in ("config", "gatekeeper", "mcp", "coolify"):
        assert oct(inst.paths[name].stat().st_mode & 0o777) == "0o600", name
    assert json.loads(inst.paths["gatekeeper"].read_text()) == {"id": "gk-id", "api_key": "gk-secret-key", "name": "gatekeeper"}
    assert "cool-secret-token" not in "\n".join(inst.log) and "gk-secret-key" not in "\n".join(inst.log)
    assert oct((home / "gh.pem").stat().st_mode & 0o777) == "0o600"                              # a loose key file is tightened
    unit = inst.paths["unit"].read_text()
    assert "ExecStart=/usr/bin/python3 -m shipyard run --config" in unit and "shipyard.yaml" in unit
    assert ["systemctl", "--user", "enable", "--now", "shipyard-gatekeeper"] in inst.runs


def test_the_gatekeeper_is_added_to_every_room_and_its_addressing_opened(home):
    gws = []
    inst = installer(home, answers(home))
    inst.gateway = lambda *a: gws.append(FakeGw()) or gws[-1]
    inst.install()
    calls = gws[0].calls
    assert ("PUT", "/agents/gk-id/addressing-policy", {"policy": None}) in calls
    assert sorted(c[1] for c in calls if c[0] == "POST") == ["/rooms/r-mt/agents", "/rooms/r-ops-dc/agents", "/rooms/r-ops-mm/agents"]


def test_dry_run_checks_everything_and_writes_nothing(home):
    inst = installer(home, answers(home))
    cfg = inst.install(dry_run=True)
    assert cfg["projects"]["demo"]["apps"] == {"demo-web": "u-web"}
    assert not (home / "shipyard.yaml").exists() and not (home / "gatekeeper.json").exists() and not inst.runs


def test_rerunning_replaces_its_own_files(home):
    installer(home, answers(home)).install()
    installer(home, answers(home, owner="")).install()
    assert load_config(home / "shipyard.yaml").projects["demo"].apps == {"demo-web": "u-web"}


@pytest.mark.parametrize("change,why", [
    ({"rooms": {"ops": ["nowhere"], "maintainers": []}}, "no room called 'nowhere'"),
    ({"rooms": {"ops": [], "maintainers": []}}, "at least one room"),
    ({"coolify": {"url": "http://cool:8000", "token": "t", "apps": ["ghost"]}}, "no application called ghost"),
    ({"github": {"app_id": "1", "private_key_file": "/nonexistent.pem", "repo": "o/r"}}, "does not exist"),
    ({"github": {"app_id": "1", "private_key_file": "KEY", "repo": "o/r", "deploy_app": "ghost"}}, "not one of the Coolify apps"),
    ({"switch": {"url": "http://sw", "env_file": "/nonexistent/.env"}}, "does not exist"),
])
def test_bad_answers_stop_before_anything_is_written(home, change, why):
    if "github" in change:
        change["github"]["private_key_file"] = change["github"]["private_key_file"].replace("KEY", str(home / "gh.pem"))
    with pytest.raises(InitError, match=why):
        installer(home, answers(home, **change)).install()
    assert not (home / "shipyard.yaml").exists() and not (home / "gatekeeper.json").exists()


def test_a_missing_answer_in_non_interactive_mode_is_named(home):
    a = answers(home)
    del a["github"]["repo"]
    with pytest.raises(InitError, match="missing answer: github.repo"):
        installer(home, a).install()


def test_coolify_refusing_the_token_and_github_not_installed_are_explained(home):
    with pytest.raises(InitError, match="Coolify refused"):
        installer(home, answers(home), http=http_fake(coolify_status=401)).install()

    def no_install(*a):
        raise RuntimeError("404 Not Found")
    with pytest.raises(InitError, match="cannot see o/r"):
        installer(home, answers(home), github_check=no_install).install()


def test_switch_refusing_registration_is_explained_and_leaves_no_service(home):
    inst = installer(home, answers(home), http=http_fake(register_status=401))
    with pytest.raises(InitError, match="AGENT_REGISTRATION_TOKEN"):
        inst.install()
    assert not inst.paths["unit"].exists() and not inst.runs


def test_skipping_coolify_and_github_still_gives_a_working_install(home):
    a = answers(home)
    a["coolify"], a["github"] = {"url": ""}, {"app_id": ""}
    inst = installer(home, a)
    inst.install()
    cfg = load_config(home / "shipyard.yaml")
    assert cfg.projects["demo"].apps == {} and cfg.projects["demo"].repo is None and cfg.github.app_id == ""


def test_the_switch_template_creates_rooms_incidents_and_links_and_reuses_existing_agents(home):
    a = answers(home)
    del a["rooms"]
    a["agents"] = {"create": "yes", "codex_config": str(home / "codex.toml")}
    gws = []
    inst = installer(home, a)
    inst.gateway = lambda *x: gws.append(EmptyGw()) or gws[-1]
    inst.install()
    run = next(c for c in gws[0].calls if c[1] == "/rooms/from-template-document")[2]
    assert run["inputs"] == {"project": "demo"} and run["filled"] == {"ops_agent": "ops-agent", "repo_agent": "repo-agent"} and run["template_name"] == "shipyard"
    assert "version: 2" in run["template"] and "links:" in run["template"]
    p = load_config(home / "shipyard.yaml").projects["demo"]
    assert p.ops_rooms == {"t-ops"} and p.incident_rooms == {"t-incidents"} and p.maintainer_rooms == {"t-maintainers"}
    assert p.alert_rooms == {"t-incidents", "t-ops"} and p.room_names["t-incidents"] == "#demo-incidents"
    # the Gatekeeper is registered before the template runs, so the template can name it
    assert [c[0] for c in gws[0].calls].index("PUT") < [c[1] for c in gws[0].calls].index("/rooms/from-template-document")
    toml = (home / "codex.toml").read_text()
    assert toml.count("[mcp_servers") == 1 and "apps = false" in toml and "COOLIFY_TOKEN" not in toml and oct((home / "codex.toml").stat().st_mode & 0o777) == "0o600"


def test_without_agents_or_a_machine_it_falls_back_to_plain_rooms_and_says_why(home):
    class Bare(EmptyGw):
        controllers = []
        agents = []
    a = answers(home, agents={"create": "yes", "codex_config": str(home / "codex.toml")})
    del a["rooms"]
    inst = installer(home, a)
    inst.gateway = lambda *x: Bare()
    inst.install()
    assert any("not using the Switch template" in l and "controller" in l for l in inst.log)
    assert load_config(home / "shipyard.yaml").projects["demo"].ops_rooms == {"new-demo-ops"}


def test_a_refused_template_run_names_the_problem(home):
    class Refusing(EmptyGw):
        template_status = 409
    a = answers(home, agents={"create": "yes", "codex_config": str(home / "codex.toml")})
    del a["rooms"]
    inst = installer(home, a)
    inst.gateway = lambda *x: Refusing()
    with pytest.raises(InitError, match="Codex is not signed in"):
        inst.install()


def test_interactive_mode_asks_lists_rooms_and_hides_the_token(home):
    asked, secrets_ = [], []
    replies = iter(["", "", "1,3", "", "demo-web", "", "", "", "no"])           # project? switch url, env, ops rooms, maint rooms, ...
    def ask(q, d=""):
        asked.append(q)
        return next(replies, "") or d
    a = {"switch": {"env_file": str(home / "switch/.env")}, "coolify": {"url": "http://cool:8000"}, "github": {"app_id": "", "create": "no"}, "agents": {"create": "no"}, "owner": ""}
    inst = Installer(a, home, interactive=True, whoami_waiter=lambda db, start: None, ask=ask, secret=lambda q: secrets_.append(q) or "typed-token", say=lambda s: None, gateway=FakeGw, http=http_fake(),
                     run=lambda *x, **k: SimpleNamespace(returncode=0, stdout="", stderr=""), github_check=lambda *x: "i", workdir=Path(__file__).parent.parent)
    os.environ.pop("COOLIFY_TOKEN", None)
    inst.install()
    assert secrets_ and "token" in secrets_[0].lower()                          # asked through the hidden prompt
    cfg = load_config(home / "shipyard.yaml")
    assert cfg.projects["demo"].ops_rooms == {"r-ops-mm", "r-mt"} or "r-ops-mm" in cfg.projects["demo"].rooms


def test_doctor_reports_what_is_wrong_and_what_is_right(home):
    installer(home, answers(home)).install()
    out = []
    ok = doctor(home / "shipyard.yaml", say=out.append, http=lambda *a, **k: (200, "x"), gateway=FakeGw,
                run=lambda argv: SimpleNamespace(stdout="active"), wait=0)
    text = "\n".join(out)
    print(text)
    assert ok and "Switch admin login works" in text and "service shipyard-gatekeeper is active" in text and "dashboard answers" in text
    out.clear()
    ok = doctor(home / "shipyard.yaml", say=out.append, http=lambda *a, **k: (500, "x"), gateway=FakeGw, run=lambda argv: SimpleNamespace(stdout="failed"), wait=0)
    assert not ok and sum(1 for l in out if "FAIL" in l) == 3
    assert not doctor(home / "missing.yaml", say=out.append)


def test_doctor_tells_a_new_install_how_to_get_an_owner(home):
    installer(home, answers(home, owner="")).install()
    out = []
    doctor(home / "shipyard.yaml", say=out.append, http=lambda *a, **k: (200, "x"), gateway=FakeGw, run=lambda argv: SimpleNamespace(stdout="active"), wait=0)
    assert any("add-owner" in l and "whoami" in l for l in out)


def test_add_owner_bootstraps_a_new_install_and_validates_the_identity(home):
    installer(home, answers(home, owner="")).install()
    cfg = load_config(home / "shipyard.yaml")
    store = MemberStore(home / "shipyard-members.json", cfg.policy, None)
    with pytest.raises(MemberError):
        store.add_owner("demo", "someone")
    with pytest.raises(MemberError):
        store.add_owner("nope", OWN)
    store.add_owner("demo", OWN)
    assert cfg.policy.members["demo"][OWN] is Role.OWNER
    fresh = load_config(home / "shipyard.yaml")
    MemberStore(home / "shipyard-members.json", fresh.policy, None).load()
    assert fresh.policy.members["demo"][OWN] is Role.OWNER                          # survives a restart


class EmptyGw(FakeGw):
    rooms = []


def test_a_brand_new_switch_gets_its_rooms_created_with_the_gatekeeper_in_them(home):
    a = answers(home)
    del a["rooms"]
    gws = []
    inst = installer(home, a)
    inst.gateway = lambda *x: gws.append(EmptyGw()) or gws[-1]
    inst.install()
    creates = [c[2] for c in gws[0].calls if c[0] == "POST" and c[1] == "/rooms"]
    assert [c["name"] for c in creates] == ["demo-ops", "demo-maintainers"] and all(c["agent_names"] == ["gatekeeper"] for c in creates)
    p = load_config(home / "shipyard.yaml").projects["demo"]
    assert p.ops_rooms == {"new-demo-ops"} and p.maintainer_rooms == {"new-demo-maintainers"}
    assert p.room_names["new-demo-ops"] == "#demo-ops"


def test_a_named_room_that_does_not_exist_is_created_only_when_asked(home):
    a = answers(home, rooms={"ops": ["alerts"], "maintainers": ["r-mt"]})
    with pytest.raises(InitError, match="create: true"):
        installer(home, a).install()
    a = answers(home, rooms={"ops": ["alerts"], "maintainers": ["r-mt"], "create": True})
    inst = installer(home, a)
    inst.install()
    assert load_config(home / "shipyard.yaml").projects["demo"].ops_rooms == {"new-alerts"}


def test_dry_run_says_which_rooms_it_would_create(home):
    a = answers(home)
    del a["rooms"]
    inst = installer(home, a)
    inst.gateway = lambda *x: EmptyGw()
    cfg = inst.install(dry_run=True)
    assert cfg["projects"]["demo"]["rooms"]["ops"] == ["<new: demo-ops>"] and not (home / "gatekeeper.json").exists()


def test_the_real_http_helper_copes_with_html_and_json_and_errors():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from shipyard.init import _http

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body, ctype, code = {"/": (b"<html>hi</html>", "text/html", 200), "/j": (b'{"a": 1}', "application/json", 200), "/no": (b"nope", "text/plain", 401)}[self.path]
            self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    assert _http("GET", base + "/") == (200, "<html>hi</html>") and _http("GET", base + "/j") == (200, {"a": 1}) and _http("GET", base + "/no")[0] == 401
    srv.shutdown()
    with pytest.raises(InitError, match="cannot reach"):
        _http("GET", "http://127.0.0.1:1/", timeout=1)


def test_rerunning_without_room_answers_reuses_the_conventional_rooms(home):
    class Existing(FakeGw):
        rooms = [{"id": "e-ops", "name": "demo-ops", "bridge_display_name": "Mattermost"}, {"id": "e-mt", "name": "demo-maintainers", "bridge_display_name": "Mattermost"}]
    a = answers(home)
    del a["rooms"]
    inst = installer(home, a)
    inst.gateway = lambda *x: Existing()
    inst.install()
    p = load_config(home / "shipyard.yaml").projects["demo"]
    assert p.ops_rooms == {"e-ops"} and p.maintainer_rooms == {"e-mt"}


def test_rerunning_keeps_the_incidents_room_the_template_made(home):
    class Existing(FakeGw):
        rooms = [{"id": "e-ops", "name": "demo-ops", "bridge_display_name": "Mattermost"}, {"id": "e-mt", "name": "demo-maintainers", "bridge_display_name": "Mattermost"},
                 {"id": "e-inc", "name": "demo-incidents", "bridge_display_name": "Mattermost"}]
    a = answers(home)
    del a["rooms"]
    inst = installer(home, a)
    inst.gateway = lambda *x: Existing()
    inst.install()
    assert load_config(home / "shipyard.yaml").projects["demo"].incident_rooms == {"e-inc"}                 # a second run no longer drops it


def test_agents_that_run_as_another_user_get_their_tool_config_in_that_users_home(home, monkeypatch):
    """The isolated controller runs the agents as `agentrun`: Codex reads that user's home, so the config must be written there, as that user."""
    import pwd
    import subprocess
    from types import SimpleNamespace
    seen = {}
    monkeypatch.setattr(pwd, "getpwnam", lambda name: SimpleNamespace(pw_dir="/home/agentrun") if name == "agentrun" else (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.update(argv=argv, text=kw["input"]) or SimpleNamespace(returncode=0, stderr=""))
    a = answers(home)
    a["agents"] = {"create": "no"}                                            # no explicit codex_config: the isolated user's home is the default
    inst = installer(home, a)
    inst.paths["mcp"].parent.mkdir(parents=True, exist_ok=True)
    inst.paths["mcp"].write_text("t" * 32)
    inst.write_codex_config()
    assert seen["argv"][:5] == ["sudo", "-n", "-u", "agentrun", "-H"] and "[mcp_servers.gatekeeper]" in seen["text"] and "apps = false" in seen["text"]
    assert not (home / ".codex/config.toml").exists()
    a2 = answers(home)
    a2["agents"] = {"codex_config": str(home / "own.toml")}                    # an explicit path always wins
    inst2 = installer(home, a2)
    inst2.paths["mcp"].write_text("t" * 32)
    inst2.write_codex_config()
    assert (home / "own.toml").exists()


def test_doctor_counts_roles_from_the_dashboard_file_and_checks_the_audit_chain(home):
    import sqlite3
    from shipyard.audit import AuditLog
    installer(home, answers(home, owner="")).install()
    cfg = load_config(home / "shipyard.yaml")
    MemberStore(home / "shipyard-members.json", cfg.policy, None).add_owner("demo", OWN)
    db = sqlite3.connect(home / "shipyard.db")
    AuditLog(db).write(project="demo", actor="a", event="x", action="y", target="z")
    db.commit(); db.close()
    out = []
    ok = doctor(home / "shipyard.yaml", say=out.append, http=lambda *a, **k: (200, "x"), gateway=FakeGw, run=lambda argv: SimpleNamespace(stdout="active"), wait=0)
    assert ok and any("audit chain verifies (1 rows" in l for l in out) and not any("no owner yet" in l for l in out)
    db = sqlite3.connect(home / "shipyard.db")
    db.execute("UPDATE audit SET actor = 'tampered'"); db.commit(); db.close()
    out.clear()
    assert not doctor(home / "shipyard.yaml", say=out.append, http=lambda *a, **k: (200, "x"), gateway=FakeGw, run=lambda argv: SimpleNamespace(stdout="active"), wait=0)
    assert any("FAIL" in l and "audit chain" in l for l in out)


def test_a_missing_github_app_is_created_with_the_two_click_flow(home):
    made = []

    def fake_creator(h, repo, **kw):
        made.append((h, repo, kw["org"]))
        return {"app_id": "555", "slug": "shipyard-x", "key_file": str(home / "gh.pem"), "installation": "909", "repo": repo}

    a = answers(home, github={"app_id": "", "repo": "o/r", "org": "acme", "port": "8800", "create": "yes", "deploy_app": "demo-web"})
    inst = Installer(a, home, interactive=True, ask=lambda q, d: d, secret=lambda q: "x", say=lambda s: None, gateway=FakeGw, http=http_fake(),
                     run=lambda *x, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
                     github_check=lambda *x: (_ for _ in ()).throw(AssertionError("an App just created must not be looked up again")),
                     app_creator=fake_creator, workdir=Path(__file__).parent.parent)
    gh = inst.github({"demo-web": "u-web"})
    assert made == [(home, "o/r", "acme")]
    assert gh["app_id"] == "555" and gh["installation"] == "909" and gh["repo"] == "o/r" and gh["deploy"] == "demo-web"


def test_declining_the_github_app_skips_repo_features(home):
    a = answers(home, github={"app_id": "", "create": "no"})
    inst = Installer(a, home, interactive=True, ask=lambda q, d: d, secret=lambda q: "x", say=lambda s: None, gateway=FakeGw, http=http_fake(),
                     run=lambda *x, **k: SimpleNamespace(returncode=0, stdout="", stderr=""), workdir=Path(__file__).parent.parent)
    assert inst.github({"demo-web": "u-web"}) is None
