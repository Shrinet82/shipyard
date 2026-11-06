"""Make the web pages reachable from your browser without an SSH tunnel (and take that away again).

By default the bundled Mattermost (8065), Switch Console (8000) and the Shipyard dashboard (8780) listen on the machine itself. `expose` makes them
listen on the machine's network address, so you can open them straight from a browser. It changes only those three; Postgres and the Switch gateway
stay on the machine. What it can NOT do is open your cloud firewall: you allow the three ports for YOUR address only, and the command says how.
The tunnel keeps working either way. The pages use plain HTTP, so never open the ports to everyone.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

import yaml

PORTS = {"mattermost": 8065, "console": 8000, "dashboard": 8780}
PARTS = tuple(PORTS)
OVERRIDE = "shipyard-expose.yml"
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class ExposeError(Exception):
    pass


def override_text(host: str, parts: tuple[str, ...]) -> str:
    """The docker compose override. `!override` replaces the loopback-only port mapping of just these services."""
    lines = ["# Written by `shipyard expose`. Delete the services below (or run `shipyard expose --off`) to listen on this machine only.", "services:"]
    if "mattermost" in parts:
        origins = f"http://localhost:{PORTS['mattermost']} http://{host}:{PORTS['mattermost']}"
        lines += ["  mattermost:", "    ports: !override", f'      - "0.0.0.0:{PORTS["mattermost"]}:8065"',
                  "    environment:", f'      MM_SERVICESETTINGS_ALLOWCORSFROM: "{origins}"']       # both addresses may open the live connection
    if "console" in parts:
        lines += ["  switch:", "    ports: !override", f'      - "0.0.0.0:{PORTS["console"]}:8000"']
    if len(lines) == 2:
        lines = ["# Written by `shipyard expose`: nothing is exposed.", "services: {}"]
    return "\n".join(lines) + "\n"


def switch_unit(switch_dir: Path) -> str:
    compose = "/usr/bin/docker compose --env-file .env -f deploy/local/standalone-docker-compose.yml -f shipyard-expose.yml --profile collab --profile gateway"
    return ("[Unit]\nDescription=Switch and Mattermost (docker compose)\nRequires=docker.service\nAfter=docker.service network-online.target\n\n"
            f"[Service]\nType=oneshot\nRemainAfterExit=yes\nWorkingDirectory={switch_dir}\nExecStart={compose} up -d\nExecStop={compose} stop\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def detect_host(fetch: Callable[[str, dict[str, str], str], str] | None = None) -> str:
    """This machine's public address: the cloud's own metadata first (AWS), then an outside lookup. Empty if neither answers."""
    def get(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> str:
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read().decode().strip()
    fetch = fetch or (lambda url, headers, method: get(url, headers, method))
    try:
        token = fetch("http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, "PUT")
        ip = fetch("http://169.254.169.254/latest/meta-data/public-ipv4", {"X-aws-ec2-metadata-token": token}, "GET")
        if HOST.match(ip):
            return ip
    except Exception:                                          # noqa: BLE001 - not on AWS
        pass
    try:
        ip = fetch("https://checkip.amazonaws.com", {}, "GET")
        return ip if HOST.match(ip) else ""
    except Exception:                                          # noqa: BLE001
        return ""


def on_cloud(fetch: Callable[[str, dict[str, str], str], str] | None = None) -> bool:
    """True on a machine whose cloud firewall blocks inbound traffic until you allow it (AWS: the instance metadata answers)."""
    def get(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> str:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}, method=method), timeout=2) as r:
            return r.read().decode().strip()
    try:
        (fetch or get)("http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, "PUT")
        return True
    except Exception:                                          # noqa: BLE001
        return False


class Exposer:
    def __init__(self, home: Path, *, switch_dir: Path | None = None, run: Callable[..., Any] | None = None, say: Callable[[str], None] = print,
                 sleep: Callable[[float], None] = time.sleep, health: Callable[[str], bool] | None = None, host_finder: Callable[[], str] = detect_host,
                 cloud: Callable[[], bool] = on_cloud):
        self.home, self.switch_dir, self.say, self.sleep, self.find_host, self.cloud = home, switch_dir or home / "switch", say, sleep, host_finder, cloud
        self.run = run or (lambda argv, **kw: subprocess.run(argv, capture_output=True, text=True, timeout=180, **kw))
        self.health = health or self._health

    @staticmethod
    def _health(url: str) -> bool:
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                return r.status == 200
        except Exception:                                      # noqa: BLE001
            return False

    def _sudo(self, argv: list[str], text: str | None = None) -> None:
        r = self.run(["sudo", "-n", *argv], **({"input": text} if text is not None else {}))
        if getattr(r, "returncode", 0) != 0:
            raise ExposeError(f"`sudo {' '.join(argv[:3])}` failed: {(getattr(r, 'stderr', '') or '').strip()[:200]}")

    def _wait_up(self) -> None:
        for _ in range(40):
            if self.health("http://127.0.0.1:8000/health") and self.health("http://127.0.0.1:8065/api/v4/system/ping"):
                return
            self.sleep(3)
        raise ExposeError("Switch or Mattermost did not come back after the restart; check: sudo systemctl status switch-stack")

    def _apply(self, host: str, parts: tuple[str, ...], config: Path | None) -> None:
        override = self.switch_dir / OVERRIDE
        if not self.switch_dir.is_dir():
            raise ExposeError(f"{self.switch_dir} does not exist: Switch is not installed here")
        override.write_text(override_text(host, parts))
        self._sudo(["tee", "/etc/systemd/system/switch-stack.service"], switch_unit(self.switch_dir))      # the unit must read the override on every boot
        self._sudo(["systemctl", "daemon-reload"])
        self._sudo(["systemctl", "restart", "switch-stack"])
        if config is not None and config.exists():
            from .confedit import edit_config

            def change(raw: dict[str, Any]) -> None:
                d = dict(raw.get("dashboard") or {})
                if "dashboard" in parts:
                    d.update({"bind": "0.0.0.0", "public_url": f"http://{host}:{PORTS['dashboard']}"})
                else:
                    d["bind"] = "127.0.0.1"
                    d.pop("public_url", None)
                raw["dashboard"] = d
            edit_config(config, change)
            self.run(["systemctl", "--user", "restart", "shipyard-gatekeeper"])
        self._wait_up()

    def enable(self, host: str = "", parts: tuple[str, ...] = PARTS, config: Path | None = None) -> dict[str, Any]:
        host = host or self.find_host()
        if not host or not HOST.match(host):
            raise ExposeError("I could not find this machine's public address; pass it with --host")
        bad = [p for p in parts if p not in PORTS]
        if bad or not parts:
            raise ExposeError(f"choose from: {', '.join(PARTS)}")
        self._apply(host, tuple(parts), config)
        urls = {p: f"http://{host}:{PORTS[p]}" for p in parts}
        self.say("  The pages now listen on this machine's address:")
        for p, u in urls.items():
            self.say(f"    {p:<10} {u}")
        self.say(f"  Last step, in your cloud provider's firewall: allow TCP {', '.join(str(PORTS[p]) for p in parts)} from YOUR address only "
                 "(AWS: EC2 → Security groups → Inbound rules → Add rule → Custom TCP, Source: My IP). Never from everyone: these pages use plain HTTP.")
        self.say("  The SSH tunnel still works as before (ssh -L 8065:localhost:8065 ...).")
        return {"host": host, "urls": urls}

    def disable(self, config: Path | None = None) -> None:
        self._apply("localhost", (), config)
        self.say("  The pages listen on this machine only again.")
