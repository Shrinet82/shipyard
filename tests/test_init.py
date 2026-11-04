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
    def __init__(self, *a):
        self.calls = []

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/rooms":
            return 200, ROOMS
        if method == "GET" and path == "/management/controllers":
            return 200, [{"id": "c1", "name": "build-vm"}]
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


def test_agents_are_created_from_the_templates_and_get_only_the_gatekeeper_tool(home):
    a = answers(home, agents={"create": "yes", "home": str(home / "agenthome"), "controller": "build-vm", "codex_config": str(home / "codex.toml")})
    gws = []
    inst = installer(home, a)
    inst.gateway = lambda *x: gws.append(FakeGw()) or gws[-1]
    inst.install()
    posts = [c for c in gws[0].calls if c[1] == "/management/agents"]
    assert [p[2]["name"] for p in posts] == ["ops-agent", "repo-agent"] and posts[0][2]["controller_id"] == "c1"
    assert posts[0][2]["definition"]["directory"] == str(home / "agenthome/agents/ops-agent") and (home / "agenthome/agents/ops-agent").is_dir()
    assert "request_action" in posts[0][2]["definition"]["instructions"]
    toml = (home / "codex.toml").read_text()
    assert toml.count("[mcp_servers") == 1 and "[mcp_servers.gatekeeper]" in toml and "COOLIFY_TOKEN" not in toml and "cool-secret-token" not in toml
    assert oct((home / "codex.toml").stat().st_mode & 0o777) == "0o600"


def test_interactive_mode_asks_lists_rooms_and_hides_the_token(home):
    asked, secrets_ = [], []
    replies = iter(["", "", "1,3", "", "demo-web", "", "", "", "no"])           # project? switch url, env, ops rooms, maint rooms, ...
    def ask(q, d=""):
        asked.append(q)
        return next(replies, "") or d
    a = {"switch": {"env_file": str(home / "switch/.env")}, "coolify": {"url": "http://cool:8000"}, "github": {"app_id": ""}, "agents": {"create": "no"}, "owner": ""}
    inst = Installer(a, home, interactive=True, ask=ask, secret=lambda q: secrets_.append(q) or "typed-token", say=lambda s: None, gateway=FakeGw, http=http_fake(),
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
