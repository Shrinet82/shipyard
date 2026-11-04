"""Run the Gatekeeper:  python -m shipyard run --config shipyard.yaml

Other commands:
  webhook-url --host <private ip>   print the URL to paste into Coolify (it contains a secret)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sqlite3
import threading

from . import webhook
from .config import Config, expand, load_config
from .coolify import CoolifyMcp
from .digest import DigestScheduler
from .gatekeeper import Gatekeeper
from .hostshell import HostShell
from .github import GitHubApp, GitHubError
from .kube import Kube
from .mcp_server import serve
from .prwatch import PrWatcher
from .service import Service
from .switch_client import SwitchClient

log = logging.getLogger("shipyard")


def _read_env_token(path: str, name: str) -> str:
    for line in open(expand(path)):
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip("'\"")
    raise SystemExit(f"{name} not found in {path}")


def _webhook_secret(cfg: Config) -> str:
    path = expand(cfg.alerts.secret_file)
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    return open(path).read().strip()


def _loop(stop: threading.Event, every: float, fn, what: str) -> None:
    while not stop.wait(every):
        try:
            fn()
        except Exception:
            log.exception("%s failed", what)


def run(config_path: str) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config(config_path)
    creds = json.load(open(expand(cfg.agent_credentials_file)))
    db = sqlite3.connect(expand(cfg.db_path), check_same_thread=False)
    gk = Gatekeeper(cfg.policy, db)
    switch = SwitchClient(cfg.switch_url, creds["id"], creds["api_key"])
    coolify = CoolifyMcp(cfg.coolify_url, _read_env_token(cfg.coolify_token_file, "COOLIFY_TOKEN"))

    github = None
    key = expand(cfg.github.private_key_file)
    if cfg.github.app_id and os.path.exists(key):
        github = GitHubApp(cfg.github.app_id, key, cfg.github.installation_id)
        repo = next((p.repo.name for p in cfg.projects.values() if p.repo), None)
        if repo and not cfg.github.installation_id:
            try:
                log.info("GitHub App installation %s on %s", github.installation_for(repo), repo)
            except GitHubError as exc:
                log.error("GitHub is not usable yet: %s", exc)
                github = None
    else:
        log.warning("GitHub is not configured (needs github.app_id and the private key file): repo features are off")

    kube = Kube({r: expand(f) for r, f in cfg.kube.kubeconfigs.items()}, cfg.kube.kubectl, cfg.kube.max_replicas,
                cfg.kube.timeout) if cfg.kube else None
    hostshell = HostShell({n: {"ssh": h.ssh, "key_file": expand(h.key_file), "port": h.port} for n, h in cfg.hosts.items()}) \
        if cfg.hosts else None
    service = Service(cfg, gk, coolify, switch.post, agent_name=creds.get("name", "gatekeeper"), github=github,
                      kube=kube, hostshell=hostshell)
    serve(service, cfg.mcp_port, open(expand(cfg.mcp_token_file)).read().strip())
    webhook.serve(_webhook_secret(cfg), service.on_coolify_event, cfg.alerts.bind, cfg.alerts.port)

    stop = switch.stop
    threading.Thread(target=_loop, args=(stop, 30, service.sweep, "sweep"), daemon=True).start()
    if github:
        watcher = PrWatcher(cfg, gk, github, switch.post)
        digest = DigestScheduler(cfg, gk, github, switch.post, service._name)
        threading.Thread(target=_loop, args=(stop, cfg.github.poll_seconds, watcher.poll_once, "PR poll"), daemon=True).start()
        threading.Thread(target=_loop, args=(stop, 30, digest.tick, "digest"), daemon=True).start()
        threading.Thread(target=watcher.poll_once, daemon=True).start()
    log.info("Gatekeeper up: %d project(s), GitHub %s, Kubernetes %s, %d host(s)", len(cfg.projects),
             "on" if github else "off", "on" if kube else "off", len(cfg.hosts))
    for ev in switch.events():
        try:
            service.handle_event(ev)
        except Exception:
            log.exception("event failed")


def main() -> None:
    ap = argparse.ArgumentParser(prog="shipyard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the Gatekeeper")
    r.add_argument("--config", default="shipyard.yaml")
    w = sub.add_parser("webhook-url", help="print the Coolify webhook URL (contains a secret)")
    w.add_argument("--config", default="shipyard.yaml")
    w.add_argument("--host", required=True, help="this machine's private address, as Coolify will reach it")
    args = ap.parse_args()
    if args.cmd == "run":
        run(args.config)
    else:
        cfg = load_config(args.config)
        print(f"http://{args.host}:{cfg.alerts.port}/hooks/coolify/{_webhook_secret(cfg)}")


if __name__ == "__main__":
    main()
