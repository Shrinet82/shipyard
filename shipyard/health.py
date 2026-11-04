"""Backend health for the dashboard: small, read-only probes, cached for a minute so a page load never fans out."""
from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Any, Callable

from .config import Config
from .evidence import redact

CACHE_SECONDS = 60.0
_READY = re.compile(r"(\d+)/(\d+) ready")


def _item(key: str, title: str, state: str, headline: str, detail: str, now: float) -> dict[str, Any]:
    return {"key": key, "title": title, "state": state, "headline": headline[:60], "detail": redact(detail)[:200], "checked": now}


class Health:
    def __init__(self, cfg: Config, *, coolify: Any = None, kube: Any = None, github: Any = None, hostshell: Any = None,
                 gateway: Callable[[], Any] | None = None, runner_active: Callable[[], bool] | None = None,
                 now: Callable[[], float] = time.time):
        self.cfg, self.coolify, self.kube, self.github, self.hostshell, self.gateway = cfg, coolify, kube, github, hostshell, gateway
        self.runner_active, self.now = runner_active or _systemd_active, now
        self.items: dict[str, dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.checks: dict[str, Callable[[], dict[str, Any]]] = {
            "coolify": self._coolify, "kubernetes": self._kube, "github": self._github, "switch": self._switch,
            "host": self._host, "agents": self._agents}

    # -- the probes --------------------------------------------------------------------

    def _coolify(self) -> dict[str, Any]:
        apps = [u for p in self.cfg.projects.values() for u in p.apps.values()]
        if self.coolify is None or not apps:
            return _item("coolify", "Coolify", "off", "not configured", "", self.now())
        text = self.coolify.status(apps[0])
        return _item("coolify", "Coolify", "ok", "healthy", f"{len(apps)} app(s) · {text}", self.now())

    def _kube(self) -> dict[str, Any]:
        apps = [(p, a) for p in self.cfg.projects.values() for a in p.k8s_apps.values()]
        if self.kube is None or not apps:
            return _item("kubernetes", "Kubernetes", "off", "not configured", "", self.now())
        ready = total = 0
        notes = []
        for a in (a for _, a in apps):
            text = self.kube.status(a.namespace, a.deployment)
            m = _READY.search(text)
            if m:
                ready, total = ready + int(m[1]), total + int(m[2])
            notes.append(f"{a.deployment} in {a.namespace}")
        state = "ok" if total and ready == total else "warn"
        return _item("kubernetes", "Kubernetes", state, f"{ready}/{total} ready", ", ".join(notes), self.now())

    def _github(self) -> dict[str, Any]:
        repos = [p.repo.name for p in self.cfg.projects.values() if p.repo]
        if self.github is None:
            return _item("github", "GitHub App", "off", "not configured", "", self.now())
        rl = self.github.rate_limit()
        left, limit = int(rl.get("remaining", 0)), int(rl.get("limit", 0))
        state = "ok" if left > limit * 0.1 else "warn"
        return _item("github", "GitHub App", state, f"{left:,} calls left", f"{', '.join(repos)} · rate limit {left:,} / {limit:,} left", self.now())

    def _switch(self) -> dict[str, Any]:
        if self.gateway is None:
            return _item("switch", "Switch", "off", "not configured", "", self.now())
        gw = self.gateway()
        status, agents = gw.call("GET", "/agents")
        if status != 200:
            return _item("switch", "Switch", "bad", "unreachable", f"the Gateway answered {status}", self.now())
        n = len(agents if isinstance(agents, list) else agents.get("agents", []))
        rooms = sum(len(p.rooms) for p in self.cfg.projects.values())
        return _item("switch", "Switch", "ok", "connected", f"{n} agents · {rooms} Shipyard rooms", self.now())

    def _host(self) -> dict[str, Any]:
        if self.hostshell is None or not self.cfg.hosts:
            return _item("host", "Production host", "off", "not configured", "", self.now())
        name = sorted(self.cfg.hosts)[0]
        lines = self.hostshell.run(name, ["df", "-h", "/"])
        use = next((int(m[1]) for ln in lines if (m := re.search(r"(\d+)%", ln))), None)
        load = ""
        try:
            load = " · load " + self.hostshell.run(name, ["cat", "/proc/loadavg"])[0].split()[0]
        except Exception:                                     # the disk figure is the point; the load is a bonus
            pass
        if use is None:
            return _item("host", "Production host", "warn", "unreadable", f"{name}: no disk figure", self.now())
        state = "bad" if use >= 95 else "warn" if use >= 80 else "ok"
        return _item("host", "Production host", state, f"disk {use}%", f"{name} · disk {use}%{load}", self.now())

    def _agents(self) -> dict[str, Any]:
        names = self.cfg.managed_agents
        if self.gateway is None:
            return _item("agents", "Agents", "off", "not configured", "", self.now())
        status, agents = self.gateway().call("GET", "/agents")
        listed = {a["name"] for a in (agents if isinstance(agents, list) else (agents or {}).get("agents", []))} if status == 200 else set()
        ready = sum(1 for n in names if n in listed)
        active = self.runner_active()
        state = "ok" if ready == len(names) and active else "warn"
        return _item("agents", "Agents", state, f"{ready}/{len(names)} ready", f"{' · '.join(names)} · runner {'active' if active else 'not running'}", self.now())

    # -- cache -------------------------------------------------------------------------

    def refresh(self, key: str | None = None) -> None:
        for k in ([key] if key else list(self.checks)):
            if k not in self.checks:
                continue
            try:
                item = self.checks[k]()
            except Exception as exc:                          # a probe failing is the finding, not a crash
                item = _item(k, k.capitalize(), "bad", "unreachable", f"{type(exc).__name__}: {exc}", self.now())
            with self.lock:
                self.items[k] = item

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            stale = not self.items or self.now() - min(i["checked"] for i in self.items.values()) > CACHE_SECONDS * 2
        if stale:
            self.refresh()
        with self.lock:
            return [self.items[k] for k in self.checks if k in self.items]

    def loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.refresh()
            stop.wait(CACHE_SECONDS)


def _systemd_active() -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", "switch-agents.service"], timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
