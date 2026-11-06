from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from test_claim import FakeGw, answers, home, http_fake  # noqa: F401

from shipyard.confedit import edit_config
from shipyard.expose import OVERRIDE, PARTS, PORTS, ExposeError, Exposer, detect_host, on_cloud, override_text, switch_unit
from shipyard.init import Installer

BASE = "projects:\n  demo:\n    rooms: {ops: [r1], maintainers: [r2]}\n    apps: {}\n    members: {}\nactions: {coolify.status: read}\ndashboard: {port: 8780, bind: 127.0.0.1}\n"


def doc(text):
    return yaml.safe_load(text.replace("!override", ""))          # the tag only matters to docker compose


def test_the_override_opens_only_the_pages_asked_for_and_never_the_database():
    d = doc(override_text("13.126.17.66", PARTS))
    assert d["services"]["mattermost"]["ports"] == ["0.0.0.0:8065:8065"] and d["services"]["switch"]["ports"] == ["0.0.0.0:8000:8000"]
    assert set(d["services"]) == {"mattermost", "switch"}                          # no postgres, no gateway
    origins = d["services"]["mattermost"]["environment"]["MM_SERVICESETTINGS_ALLOWCORSFROM"].split()
    assert origins == ["http://localhost:8065", "http://13.126.17.66:8065"]        # the live connection works from both addresses: the tunnel keeps working
    assert "!override" in override_text("h", PARTS)
    only = doc(override_text("h", ("mattermost",)))
    assert set(only["services"]) == {"mattermost"}
    assert doc(override_text("h", ())) == {"services": {}}


def test_the_unit_reads_the_override_every_boot():
    u = switch_unit(Path("/home/anya/switch"))
    assert "WorkingDirectory=/home/anya/switch" in u and u.count("-f shipyard-expose.yml") == 2 and "up -d" in u and " stop" in u


class Machine:
    def __init__(self, tmp_path, fail=None, healthy=True):
        self.calls, self.fail, self.healthy = [], fail, healthy
        (tmp_path / "switch").mkdir(exist_ok=True)
        self.config = tmp_path / "shipyard.yaml"
        self.config.write_text(BASE)

    def run(self, argv, **kw):
        self.calls.append((list(argv), kw.get("input")))
        return SimpleNamespace(returncode=1 if self.fail and self.fail in " ".join(argv) else 0, stderr="no", stdout="")

    def exposer(self, tmp_path, said=None, **kw):
        return Exposer(tmp_path, run=self.run, say=(said if said is not None else []).append, sleep=lambda n: None, health=lambda url: self.healthy,
                       host_finder=lambda: "13.126.17.66", cloud=lambda: True, **kw)


def test_enable_writes_the_override_the_unit_the_dashboard_bind_and_restarts_in_order(tmp_path):
    m, said = Machine(tmp_path), []
    out = m.exposer(tmp_path, said).enable(config=m.config)
    assert out["urls"] == {"mattermost": "http://13.126.17.66:8065", "console": "http://13.126.17.66:8000", "dashboard": "http://13.126.17.66:8780"}
    assert "13.126.17.66:8065" in (tmp_path / "switch" / OVERRIDE).read_text()
    cmds = [" ".join(c[0]) for c in m.calls]
    assert cmds == ["sudo -n tee /etc/systemd/system/switch-stack.service", "sudo -n systemctl daemon-reload", "sudo -n systemctl restart switch-stack",
                    "systemctl --user restart shipyard-gatekeeper"]
    assert "WorkingDirectory=" in m.calls[0][1]
    d = yaml.safe_load(m.config.read_text())["dashboard"]
    assert d["bind"] == "0.0.0.0" and d["allow_remote"] is True and d["public_url"] == "http://13.126.17.66:8780" and d["port"] == 8780
    text = "\n".join(said)
    assert "TCP 8065, 8000, 8780" in text and "YOUR address only" in text and "tunnel still works" in text


def test_only_some_pages_and_a_bad_choice(tmp_path):
    m = Machine(tmp_path)
    out = m.exposer(tmp_path).enable(parts=("mattermost",), config=m.config)
    assert list(out["urls"]) == ["mattermost"]
    assert yaml.safe_load(m.config.read_text())["dashboard"]["bind"] == "127.0.0.1" and "public_url" not in yaml.safe_load(m.config.read_text())["dashboard"]
    with pytest.raises(ExposeError, match="choose from"):
        m.exposer(tmp_path).enable(parts=("database",))
    with pytest.raises(ExposeError, match="public address"):
        Exposer(tmp_path, run=m.run, say=lambda s: None, host_finder=lambda: "").enable()


def test_off_puts_everything_back_to_this_machine_only(tmp_path):
    m = Machine(tmp_path)
    ex = m.exposer(tmp_path)
    ex.enable(config=m.config)
    ex.disable(m.config)
    assert doc((tmp_path / "switch" / OVERRIDE).read_text()) == {"services": {}}
    d = yaml.safe_load(m.config.read_text())["dashboard"]
    assert d["bind"] == "127.0.0.1" and "public_url" not in d and "allow_remote" not in d


def test_failures_are_reported_and_a_missing_switch_is_refused(tmp_path):
    m = Machine(tmp_path, fail="restart switch-stack")
    with pytest.raises(ExposeError, match="systemctl restart"):
        m.exposer(tmp_path).enable(config=m.config)
    with pytest.raises(ExposeError, match="did not come back"):
        Machine(tmp_path, healthy=False).exposer(tmp_path).enable(config=Machine(tmp_path).config)
    with pytest.raises(ExposeError, match="Switch is not installed"):
        Exposer(tmp_path / "nowhere", run=lambda *a, **k: None, say=lambda s: None, host_finder=lambda: "1.2.3.4").enable()


def test_the_address_comes_from_the_cloud_metadata_then_an_outside_lookup():
    seen = []

    def aws(url, headers, method):
        seen.append(url)
        return "tok" if url.endswith("/token") else "13.126.17.66"
    assert detect_host(aws) == "13.126.17.66" and on_cloud(aws) is True

    def elsewhere(url, headers, method):
        if "169.254" in url:
            raise OSError("no route")
        return "203.0.113.9"
    assert detect_host(elsewhere) == "203.0.113.9" and on_cloud(elsewhere) is False
    assert detect_host(lambda *a: (_ for _ in ()).throw(OSError("offline"))) == "" and detect_host(lambda u, h, m: "not an address!") == ""


def installer(home, ask, exposer, said):
    return Installer(answers(home, owner=""), home, interactive=True, ask=ask, secret=lambda q: "x", say=said.append, gateway=FakeGw, http=http_fake(),
                     whoami_waiter=lambda *a: None, login_maker=lambda p, n: {"username": n, "password": "pw", "rooms": [f"{p}-ops"], "team": "t"}, exposer=exposer,
                     run=lambda *x, **k: SimpleNamespace(returncode=0, stdout="active", stderr=""), github_check=lambda *a: "i", workdir=Path(__file__).parent.parent)


class FakeExposer:
    def __init__(self, cloud, fail=False):
        self.cloud_now, self.fail, self.enabled = cloud, fail, []

    def cloud(self):
        return self.cloud_now

    def enable(self, config=None):
        if self.fail:
            raise ExposeError("no sudo")
        self.enabled.append(config)
        return {"host": "13.126.17.66", "urls": {}}


def test_on_a_cloud_machine_the_installer_offers_it_with_yes_as_the_default_and_signs_you_in_at_that_address(home):
    ex, said = FakeExposer(cloud=True), []
    installer(home, lambda q, d: d, ex, said).install()
    assert ex.enabled and any("Sign in at http://13.126.17.66:8065" in s for s in said)


def test_elsewhere_the_default_is_no_and_the_tunnel_text_stays(home):
    ex, said = FakeExposer(cloud=False), []
    installer(home, lambda q, d: d, ex, said).install()
    assert not ex.enabled and any("ssh -L 8065:localhost:8065" in s for s in said)
    ex2, said2 = FakeExposer(cloud=False), []
    installer(home, lambda q, d: "yes" if "without a tunnel" in q else d, ex2, said2).install()
    assert ex2.enabled                                                                  # a conscious yes works anywhere


def test_a_failure_to_expose_does_not_stop_the_install(home):
    said = []
    installer(home, lambda q, d: d, FakeExposer(cloud=True, fail=True), said).install()
    assert any("could not do it: no sudo" in s for s in said) and any("ssh -L 8065:localhost:8065" in s for s in said)
