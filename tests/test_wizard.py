from pathlib import Path

from shipyard.wizard import Wizard


class Machine:
    """A pretend machine: what is installed, and what the wizard asked it to run."""
    def __init__(self, switch=True, controller=True, codex=True, installed=False, passwordless=True):
        self.switch, self.controller, self.codex, self.installed, self.passwordless = switch, controller, codex, installed, passwordless
        self.streamed, self.quieted, self.installs, self.doctors = [], [], [], 0
        self.fail_streams: set[str] = set()

    def probe(self, url):
        return self.switch

    def quiet(self, argv):
        self.quieted.append(argv)
        if argv[:3] == ["systemctl", "is-active", "--quiet"]:
            return 0 if argv[3] == "switch-agents" and self.controller else 1
        if argv[:2] == ["systemctl", "--user"]:
            return 0 if self.installed else 1
        if argv[:3] == ["sudo", "-n", "true"]:
            return 0 if self.passwordless else 1
        if "login" in argv and "status" in argv:
            return 0 if self.codex else 1
        return 0

    def stream(self, argv):
        self.streamed.append(argv)
        name = Path(argv[1]).name if argv[0] == "bash" else " ".join(argv[-2:])
        if name in self.fail_streams:
            return 1
        if name == "install-switch.sh":
            self.switch = True
        if name == "install-controller.sh":
            self.controller = True
        if "--device-auth" in argv:
            self.codex = True
        return 0

    def installer(self, answers, home, interactive=True):
        m = self

        class I:
            def install(self_inner):
                m.installs.append(dict(answers))
                (home / "shipyard.yaml").write_text("x")
        return I()

    def doctor(self, path, say=print):
        self.doctors += 1
        return True


def wizard(tmp_path, machine, replies=()):
    it = iter(replies)
    said = []
    w = Wizard(tmp_path, repo_dir=Path("/repo"), ask=lambda q, d: next(it, d), say=said.append, probe=machine.probe, quiet=machine.quiet,
               stream=machine.stream, installer=machine.installer, run_doctor=machine.doctor)
    w.said = said
    return w


def test_a_machine_that_is_ready_is_not_touched(tmp_path):
    m = Machine(installed=True)
    (tmp_path / "shipyard.yaml").write_text("x")
    w = wizard(tmp_path, m)
    assert w.run() is True
    assert m.streamed == [] and m.installs == [] and m.doctors == 1
    assert any("already installed" in s for s in w.said) and any("Step 8/8" in s for s in w.said)


def test_a_blank_machine_is_installed_in_order_and_signed_in_to_codex(tmp_path):
    m = Machine(switch=False, controller=False, codex=False)
    w = wizard(tmp_path, m, replies=["1", "yes", "yes", "no"])                    # target Coolify, install Switch, use agents, no SigNoz
    assert w.run() is True
    names = [Path(a[1]).name if a[0] == "bash" else "codex login" for a in m.streamed]
    assert names == ["install-switch.sh", "install-controller.sh", "codex login"]
    assert ["sudo", "systemctl", "restart", "switch-agents"] in m.quieted
    assert m.installs == [{}] and m.doctors == 1                                       # Coolify chosen: nothing is skipped


def test_declining_switch_stops_with_a_clear_reason(tmp_path):
    m = Machine(switch=False)
    w = wizard(tmp_path, m, replies=["1", "no"])
    assert w.run() is False
    assert m.streamed == [] and m.installs == [] and m.doctors == 0
    assert any("needs a running Switch" in s for s in w.said)


def test_a_failed_switch_install_stops_and_says_to_run_again(tmp_path):
    m = Machine(switch=False)
    m.fail_streams = {"install-switch.sh"}
    w = wizard(tmp_path, m, replies=["1", "yes"])
    assert w.run() is False and any("did not finish" in s for s in w.said) and m.installs == []


def test_no_agents_and_no_coolify_are_passed_to_the_installer_as_answers(tmp_path):
    m = Machine()
    w = wizard(tmp_path, m, replies=["4", "no", "no"])                                  # neither target, no agents, no SigNoz
    assert w.run() is True
    assert m.installs == [{"coolify": {"skip": True}, "agents": {"create": "no"}}]


def test_a_codex_login_that_fails_continues_without_agents(tmp_path):
    m = Machine(codex=False)
    m.fail_streams = {"login --device-auth"}
    w = wizard(tmp_path, m, replies=["1", "yes", "no"])
    assert w.run() is True
    assert m.installs[0]["agents"] == {"create": "no"} and any("not signed in" in s for s in w.said)


def test_kubernetes_choice_runs_the_connector_after_shipyard_and_signoz_is_offered(tmp_path):
    m = Machine()
    w = wizard(tmp_path, m, replies=["3", "yes", "yes"])                                # both targets, agents, SigNoz yes
    assert w.run() is True
    connects = [a[4:5] for a in m.streamed if a[1:4] == ["-m", "shipyard", "connect"]]
    assert connects == [["kubernetes"], ["signoz"]]
    assert "--bootstrap" in [a for a in m.streamed if a[4:5] == ["signoz"]][0]
    assert all("--config" in a for a in m.streamed if a[1:4] == ["-m", "shipyard", "connect"])


def test_a_small_machine_is_refused_before_anything_is_installed(tmp_path, monkeypatch):
    m = Machine(switch=False)
    monkeypatch.setattr(Wizard, "_memory_gb", staticmethod(lambda: 1.0))
    w = wizard(tmp_path, m)
    assert w.run() is False and any("memory" in s for s in w.said) and m.streamed == []


def test_a_sudo_that_wants_a_password_is_asked_once_up_front(tmp_path):
    m = Machine(installed=True, passwordless=False)
    (tmp_path / "shipyard.yaml").write_text("x")
    w = wizard(tmp_path, m)
    assert w.run() is True
    assert m.streamed[0] == ["sudo", "-v"] and any("ask for your password once" in s for s in w.said)
    m2 = Machine(installed=True)                                               # cloud images: nothing to ask
    (tmp_path / "shipyard.yaml").write_text("x")
    wizard(tmp_path, m2).run()
    assert ["sudo", "-v"] not in m2.streamed


def test_signoz_falls_back_to_asking_for_a_key_when_the_automatic_key_fails(tmp_path):
    m = Machine()
    real = m.stream
    def failing_bootstrap(argv):
        if "--bootstrap" in argv:
            m.streamed.append(argv)
            return 1
        return real(argv)
    m.stream = failing_bootstrap
    w = wizard(tmp_path, m, replies=["1", "yes", "yes"])
    assert w.run() is True
    signoz_calls = [a for a in m.streamed if a[4:5] == ["signoz"]]
    assert ["--bootstrap" in a for a in signoz_calls] == [True, False] and any("Paste a Viewer key" in s for s in w.said)


def test_discord_is_offered_after_the_connectors_and_runs_the_connect_command(tmp_path):
    m = Machine()
    w = wizard(tmp_path, m, replies=["1", "yes", "no", "yes"])           # Coolify, agents, no SigNoz, yes Discord
    assert w.run() is True
    calls = [a for a in m.streamed if a[1:4] == ["-m", "shipyard", "connect"]]
    assert [a[4] for a in calls] == ["discord"] and "--config" in calls[0]
    assert any("Chat apps" in s for s in w.said)
    m2 = Machine()
    assert wizard(tmp_path, m2, replies=["1", "yes", "no"]).run() is True        # the default is no
    assert not [a for a in m2.streamed if a[4:5] == ["discord"]]
