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
import subprocess
import threading
import time
from pathlib import Path

import yaml

from . import webhook
from .config import Config, expand, load_config
from .access import AgentAccess, Gateway, read_env
from .clusterwatch import ClusterWatcher
from .coolify import CoolifyMcp
from .desks import Desks
from .discordapi import Discord, token_from
from .roomsync import RoomSync
from .incidents import Incidents
from .dashauth import DashAuth
from .dashboard import Dashboard, serve as serve_dashboard
from .digest import DigestScheduler
from .gatekeeper import Gatekeeper
from .hostshell import HostShell
from .github import GitHubApp, GitHubError
from .health import Health
from .init import InitError, Installer, doctor
from .members import MemberError, MemberStore
from .kube import Kube
from .mcp_server import serve
from .prwatch import PrWatcher
from .ticketflow import StandupScheduler, TicketFlow
from .tickets import Tickets
from .sbomstore import SbomStore
from .sbomwatch import SbomCollector
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


def _gateway_factory(cfg: Config):
    path = expand(cfg.gateway_env_file)
    if not os.path.exists(path):
        return None

    def make() -> Gateway:
        env = read_env(path)
        return Gateway(cfg.switch_url, env["GATEWAY_ADMIN_EMAIL"], env["GATEWAY_ADMIN_PASSWORD"])
    return make


def _start_dashboard(cfg, gk, auth, collector, members, service, coolify, kube, github, hostshell, db, stop) -> None:
    gateway = _gateway_factory(cfg)
    health = Health(cfg, coolify=coolify, kube=kube, github=github, hostshell=hostshell, gateway=gateway)
    access = AgentAccess(cfg, gateway, db, gk.lock, gk.audit) if gateway else None
    dash = Dashboard(cfg, gk, auth, collector.store if collector else None, health, members, access, service._name, flow=service.flow, roomsync=service.roomsync)
    threading.Thread(target=health.loop, args=(stop,), daemon=True).start()
    serve_dashboard(dash, cfg.dashboard.bind, cfg.dashboard.port)


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
    collector = None
    if github and cfg.sbom.enabled and any(p.repo for p in cfg.projects.values()):
        collector = SbomCollector(cfg, gk, github, SbomStore(expand(cfg.sbom.data_dir), db, gk.lock), switch.post)
    else:
        log.warning("SBOM reports and the deploy gate are off (they need GitHub and sbom.enabled)")
    members = MemberStore(expand(cfg.dashboard.members_file), cfg.policy, gk.audit)
    members.load()
    auth = DashAuth(db, gk.lock, session_hours=cfg.dashboard.session_hours)
    service = Service(cfg, gk, coolify, switch.post, agent_name=creds.get("name", "gatekeeper"), github=github,
                      kube=kube, hostshell=hostshell, sbom=collector, dashauth=auth)
    tickets = Tickets(gk, cfg.projects, lambda p: dict(cfg.policy.members.get(p, {})), service._name, post=switch.post)
    service.flow = TicketFlow(service, tickets)
    service.incidents = Incidents(db, gk.lock, gk.audit, service.now)
    service.desks = Desks(cfg, expand(cfg.desks_file), gk.audit, _gateway_factory(cfg))
    service.desks.load()
    gateway = _gateway_factory(cfg)
    access_for_sync = AgentAccess(cfg, gateway, db, gk.lock, gk.audit) if gateway else None
    token = token_from(expand(cfg.discord_token_file)) if cfg.discord_token_file else ""
    discord = Discord(token) if token else None
    log.info("Discord channel list (read only) for the room sync: %s", "on" if discord else "off")
    service.roomsync = RoomSync(cfg, expand(cfg.rooms_file), gk.audit, gateway, service.desks, access_for_sync.apply if access_for_sync else None, discord) if gateway else None
    if service.roomsync:
        service.roomsync.load()
    serve(service, cfg.mcp_port, open(expand(cfg.mcp_token_file)).read().strip())
    gh_secret_file = expand(cfg.github.webhook_secret_file)
    gh_secret = open(gh_secret_file).read().strip().encode() if os.path.exists(gh_secret_file) else None
    webhook.serve(_webhook_secret(cfg), service.on_coolify_event, cfg.alerts.bind, cfg.alerts.port, gh_secret, service.on_github_hook if gh_secret else None)
    log.info("GitHub webhooks %s (polling stays on as the fallback)", "accepted at /hooks/github" if gh_secret else "off: no secret file")

    stop = switch.stop
    _start_dashboard(cfg, gk, auth, collector, members, service, coolify, kube, github, hostshell, db, stop)
    standup = StandupScheduler(service, service.flow)
    if kube and cfg.alerts.cluster_poll_seconds > 0 and any(p.k8s_apps for p in cfg.projects.values()):
        threading.Thread(target=_loop, args=(stop, cfg.alerts.cluster_poll_seconds, ClusterWatcher(service, kube).poll_once, "cluster alerts"), daemon=True).start()
    threading.Thread(target=_loop, args=(stop, 60, standup.tick, "standup"), daemon=True).start()
    threading.Thread(target=_loop, args=(stop, 900, service.flow.due_tick, "due dates"), daemon=True).start()
    threading.Thread(target=_loop, args=(stop, 30, service.sweep, "sweep"), daemon=True).start()
    if github:
        watcher = PrWatcher(cfg, gk, github, switch.post, flow=service.flow, settle=6.0)
        service.github_hooks.append(watcher.on_hook)
        digest = DigestScheduler(cfg, gk, github, switch.post, service._name)
        threading.Thread(target=_loop, args=(stop, cfg.github.poll_seconds, watcher.poll_once, "PR poll"), daemon=True).start()
        threading.Thread(target=_loop, args=(stop, 30, digest.tick, "digest"), daemon=True).start()
        threading.Thread(target=watcher.poll_once, daemon=True).start()
    if collector:
        service.github_hooks.append(lambda event, payload: collector.poll_once() if event == "workflow_run" else None)   # a finished CI run: look for its SBOM now
        threading.Thread(target=_loop, args=(stop, cfg.sbom.poll_seconds, collector.poll_once, "SBOM poll"), daemon=True).start()
        threading.Thread(target=collector.poll_once, daemon=True).start()
    log.info("Gatekeeper up: %d project(s), GitHub %s, SBOM gate %s, Kubernetes %s, %d host(s)", len(cfg.projects),
             "on" if github else "off", "on" if collector else "off", "on" if kube else "off", len(cfg.hosts))
    for ev in switch.events():
        try:
            service.handle_event(ev)
        except Exception:
            log.exception("event failed")


def _init(args) -> None:
    answers = yaml.safe_load(open(args.answers)) if args.answers else {}
    inst = Installer(answers or {}, Path(args.home), interactive=not args.answers)
    try:
        cfg = inst.install(dry_run=args.dry_run)
    except InitError as exc:
        raise SystemExit(f"\nStopped: {exc}\nNothing after this point was done. Fix it and run `python3 -m shipyard init` again.") from None
    if args.dry_run:
        print(yaml.safe_dump({k: v for k, v in cfg.items() if k != "_project"}, sort_keys=False))
        return
    print("\nChecking the install:")
    good = doctor(inst.paths["config"])
    print(f"\n{'Done' if good else 'Installed, with problems above'} in {int(time.time() - inst.t0)} s. Next:")
    print("  1. In a Shipyard room, type  @gatekeeper whoami  and copy the id it prints.")
    print("  2. python3 -m shipyard add-owner --identity '<that id>'   (then: systemctl --user restart shipyard-gatekeeper)")
    print("  3. @gatekeeper help   shows the commands. The dashboard: ssh -L 8780:localhost:8780 <this machine>, open http://localhost:8780")
    if cfg["coolify"]["url"]:
        print("  4. In Coolify, send notifications to:  python3 -m shipyard webhook-url --host <this machine's private address>")


def _add_owner(args) -> None:
    cfg = load_config(args.config)
    project = args.project or next(iter(cfg.projects))
    store = MemberStore(expand(cfg.dashboard.members_file), cfg.policy, None)
    store.load()
    try:
        store.add_owner(project, args.identity)
    except MemberError as exc:
        raise SystemExit(str(exc)) from None
    subprocess.run(["systemctl", "--user", "restart", "shipyard-gatekeeper"], check=False)
    print(f"{args.identity} is now an owner of {project}. The Gatekeeper was restarted.")


def main() -> None:
    ap = argparse.ArgumentParser(prog="shipyard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the Gatekeeper")
    r.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    w = sub.add_parser("webhook-url", help="print the Coolify webhook URL (contains a secret)")
    w.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    w.add_argument("--host", required=True, help="this machine's private address, as Coolify will reach it")
    g = sub.add_parser("github-webhook", help="create the GitHub webhook secret (once) and print what to paste into the GitHub App's webhook settings")
    g.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    g.add_argument("--host", required=True, help="the public address GitHub will reach, for example gatekeeper.example.com:8766")
    t = sub.add_parser("dashboard-token", help="print a dashboard sign-in token for a member (run on the VM; shown once)")
    t.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    t.add_argument("--identity", required=True, help="the member's chat id, as `@gatekeeper whoami` prints it")
    t.add_argument("--project", default=None)
    t.add_argument("--hours", type=float, default=8.0)
    i = sub.add_parser("init", help="set Shipyard up on this machine (needs a running Switch)")
    i.add_argument("--answers", help="a YAML file of answers: no questions are asked")
    i.add_argument("--home", default=os.path.expanduser("~"), help="where the config and secrets go (default: your home)")
    i.add_argument("--dry-run", action="store_true", help="check everything and print the config, write nothing")
    d = sub.add_parser("doctor", help="check the install and say what is wrong")
    d.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    o = sub.add_parser("add-owner", help="make a person the owner of a project (run once on a new install, on the machine)")
    o.add_argument("--config", default=os.path.expanduser("~/shipyard.yaml"))
    o.add_argument("--identity", required=True, help="the id that `@gatekeeper whoami` printed")
    o.add_argument("--project", default=None)
    args = ap.parse_args()
    if args.cmd == "init":
        _init(args)
    elif args.cmd == "doctor":
        raise SystemExit(0 if doctor(Path(args.config)) else 1)
    elif args.cmd == "add-owner":
        _add_owner(args)
    elif args.cmd == "run":
        run(args.config)
    elif args.cmd == "github-webhook":
        cfg = load_config(args.config)
        path = Path(expand(cfg.github.webhook_secret_file))
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(32))
        print(f"Webhook URL:    http://{args.host}/hooks/github\nContent type:  application/json\nSecret:        {path.read_text().strip()}\n"
              f"Events:         Pull requests, Pull request reviews, Check runs, Check suites, Workflow runs, Commit statuses\n"
              f"Then restart the Gatekeeper. GitHub signs every delivery; anything unsigned or wrongly signed is dropped.")
    elif args.cmd == "dashboard-token":
        cfg = load_config(args.config)
        project = args.project or next(iter(cfg.projects))
        members = MemberStore(expand(cfg.dashboard.members_file), cfg.policy, None)      # load() does not audit
        members.load()
        if args.identity not in cfg.policy.members.get(project, {}):
            raise SystemExit(f"{args.identity} is not a member of {project}")
        db = sqlite3.connect(expand(cfg.db_path))
        print(DashAuth(db, session_hours=cfg.dashboard.session_hours).issue(args.identity, project, args.hours))
    else:
        cfg = load_config(args.config)
        print(f"http://{args.host}:{cfg.alerts.port}/hooks/coolify/{_webhook_secret(cfg)}")


if __name__ == "__main__":
    main()
