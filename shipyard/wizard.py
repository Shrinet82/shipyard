"""`python3 -m shipyard install`: one guided run from a blank Ubuntu machine to a working Shipyard.

It looks at what is really there (it keeps no progress file), does what a machine can do by itself, and stops only for what a person has to do:
sign in to Codex, create the Coolify token, press two buttons on GitHub, type `@gatekeeper whoami`. Each stop says exactly where to go and what to
get, takes the value hidden, checks it at once, and goes on. Running it again after a failure continues from where things stand.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .init import InitError, Installer, REPO_DIR, doctor

AGENT_USER = "agentrun"


class WizardError(Exception):
    pass


def _probe(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _quiet(argv: list[str]) -> int:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 127


def _stream(argv: list[str]) -> int:
    try:
        return subprocess.call(argv)
    except OSError as exc:
        print(f"could not run {argv[0]}: {exc}")
        return 127


class Wizard:
    def __init__(self, home: Path, *, repo_dir: Path = REPO_DIR, ask: Callable[[str, str], str] | None = None,
                 say: Callable[[str], None] = print, probe: Callable[[str], bool] = _probe, quiet: Callable[[list[str]], int] = _quiet,
                 stream: Callable[[list[str]], int] = _stream, installer: Callable[..., Installer] = Installer,
                 run_doctor: Callable[..., bool] = doctor, python: str = "python3", switch_url: str = "http://localhost:8000"):
        self.home, self.repo, self.say, self.probe, self.quiet, self.stream = home, repo_dir, say, probe, quiet, stream
        self._ask, self.make_installer, self.run_doctor, self.python, self.switch_url = ask or self._input, installer, run_doctor, python, switch_url
        self.answers: dict[str, Any] = {}
        self.target = {"coolify": False, "kubernetes": False}

    @staticmethod
    def _input(question: str, default: str = "") -> str:
        got = input(f"{question}" + (f" [{default}]" if default else "") + ": ").strip()
        return got or default

    def yes(self, question: str, default: str = "yes") -> bool:
        return self._ask(question + " (yes/no)", default).strip().lower() in ("yes", "y")

    def step(self, n: int, total: int, title: str, why: str = "") -> None:
        self.say(f"\n== Step {n}/{total}: {title}" + (f"\n   {why}" if why else ""))

    # -- the steps --------------------------------------------------------------------------

    def preflight(self) -> None:
        problems = []
        if not Path("/etc/os-release").exists() or "ubuntu" not in Path("/etc/os-release").read_text().lower():
            self.say("   note: this installer is tested on Ubuntu 24.04; other systems may need the packages installed by hand")
        free = shutil.disk_usage(str(self.home)).free / 1e9
        if free < 15:
            problems.append(f"only {free:.0f} GB of disk is free; Switch, Mattermost and images need about 15 GB")
        mem = self._memory_gb()
        if mem and mem < 3.5:
            problems.append(f"only {mem:.1f} GB of memory; 4 GB is the minimum, 8 GB is comfortable")
        if shutil.which("sudo") is None:
            problems.append("sudo is missing; the Switch and agent installers need it")
        if problems:
            raise WizardError("; ".join(problems))
        self.say(f"   ok: {free:.0f} GB free" + (f", {mem:.0f} GB memory" if mem else ""))

    @staticmethod
    def _memory_gb() -> float:
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / 1048576
        except OSError:
            pass
        return 0.0

    def choose_target(self) -> None:
        self.say("   What does Shipyard deploy to?  1) Coolify  2) a Kubernetes cluster  3) both  4) neither for now (chat and repo only)")
        pick = self._ask("   Choose 1-4", "1").strip()
        self.target = {"coolify": pick in ("1", "3"), "kubernetes": pick in ("2", "3")}
        if not self.target["coolify"]:
            self.answers["coolify"] = {"skip": True}

    def switch(self) -> None:
        if self.probe(f"{self.switch_url}/health"):
            self.say("   found: Switch answers at " + self.switch_url)
            return
        if not self.yes("   Switch is not running here. Install Switch and Mattermost now (about 5 minutes, Docker)?"):
            raise WizardError("Shipyard needs a running Switch. Start yours, or run this again and say yes.")
        if self.stream(["bash", str(self.repo / "scripts/install-switch.sh")]) != 0 or not self.probe(f"{self.switch_url}/health"):
            raise WizardError("the Switch installer did not finish; the output above says why. Run this again after fixing it.")
        self.say("   Switch is up.")

    def agents(self) -> None:
        if not self.yes("   Use the Ops and Repo agents? They need a ChatGPT account for Codex, signed in once."):
            self.answers["agents"] = {"create": "no"}
            return
        controller = self.quiet(["systemctl", "is-active", "--quiet", "switch-agents"]) == 0
        if not controller:
            if self.stream(["bash", str(self.repo / "scripts/install-controller.sh")]) != 0:
                self.say("   the controller did not install; continuing without agents (run this again to retry)")
                self.answers["agents"] = {"create": "no"}
                return
        status = ["sudo", "-n", "-u", AGENT_USER, "-H", "codex", "login", "status"]
        if self.quiet(status) != 0:
            self.say("   Sign in to Codex: a link and a code appear below. Open the link on any device, enter the code, then come back.")
            if self.stream(["sudo", "-u", AGENT_USER, "-H", "codex", "login", "--device-auth"]) != 0 or self.quiet(status) != 0:
                self.say("   Codex is not signed in; continuing without agents (run this again to retry)")
                self.answers["agents"] = {"create": "no"}
                return
        self.quiet(["sudo", "systemctl", "restart", "switch-agents"])
        self.say("   agents are ready")

    def shipyard(self) -> None:
        config = self.home / "shipyard.yaml"
        if config.exists() and self.quiet(["systemctl", "--user", "is-active", "--quiet", "shipyard-gatekeeper"]) == 0:
            self.say("   Shipyard is already installed and running here; leaving it as it is (checks run at the end)")
            return
        self.say("   I will ask for your rooms, then for what is needed, one thing at a time.")
        try:
            self.make_installer(self.answers, self.home, interactive=True).install()
        except InitError as exc:
            raise WizardError(str(exc)) from None

    def connect(self, what: str) -> None:
        cmd = [self.python, "-m", "shipyard", "connect", what, "--config", str(self.home / "shipyard.yaml")]
        if self.stream(cmd) != 0:
            self.say(f"   connecting {what} did not finish; run it again any time: python3 -m shipyard connect {what}")

    def optional_connectors(self) -> None:
        if self.target["kubernetes"]:
            self.say("   Needs kubectl on this machine pointing at your cluster with admin rights (used once, never stored).")
            self.connect("kubernetes")
        if self.yes("   Connect SigNoz (read-only alerts and logs)?", "no"):
            self.connect("signoz")

    def finish(self) -> bool:
        ok = self.run_doctor(self.home / "shipyard.yaml", say=self.say)
        self.say("\nDone." if ok else "\nShipyard is installed but a check failed (above). Fix it and run `python3 -m shipyard doctor`.")
        self.say("Open the dashboard: ssh -L 8780:localhost:8780 <this machine>, then http://localhost:8780 (sign in with `@gatekeeper dashboard-login <code>` in chat).\n"
                 "Coolify alerts: python3 -m shipyard webhook-url --host <this machine's private address>, paste it in Coolify → Notifications → Webhook.")
        return ok

    def run(self) -> bool:
        steps: list[tuple[str, str, Callable[[], Any]]] = [
            ("Check this machine", "", self.preflight),
            ("Where does Shipyard deploy?", "", self.choose_target),
            ("Switch and Mattermost", "the chat layer everything runs in", self.switch),
            ("The agents", "Codex runs the Ops and Repo agents, sealed off from your secrets", self.agents),
            ("Shipyard", "rooms, Coolify, GitHub, then you", self.shipyard),
            ("Connectors", "Kubernetes and SigNoz, if you want them", self.optional_connectors),
        ]
        for i, (title, why, fn) in enumerate(steps, 1):
            self.step(i, len(steps) + 1, title, why)
            try:
                fn()
            except WizardError as exc:
                self.say(f"\nStopped: {exc}")
                return False
        self.step(len(steps) + 1, len(steps) + 1, "Check everything")
        return self.finish()
