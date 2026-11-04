"""Run the Gatekeeper:  python -m shipyard run --config shipyard.yaml"""
from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import threading

from .config import expand, load_config
from .coolify import CoolifyMcp
from .gatekeeper import Gatekeeper
from .mcp_server import serve
from .service import Service
from .switch_client import SwitchClient


def _read_env_token(path: str, name: str) -> str:
    for line in open(expand(path)):
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip().strip("'\"")
    raise SystemExit(f"{name} not found in {path}")


def run(config_path: str) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger("shipyard")
    cfg = load_config(config_path)
    creds = json.load(open(expand(cfg.agent_credentials_file)))
    db = sqlite3.connect(expand(cfg.db_path), check_same_thread=False)
    gk = Gatekeeper(cfg.policy, db)
    switch = SwitchClient(cfg.switch_url, creds["id"], creds["api_key"])
    coolify = CoolifyMcp(cfg.coolify_url, _read_env_token(cfg.coolify_token_file, "COOLIFY_TOKEN"))
    service = Service(cfg, gk, coolify, switch.post, agent_name=creds.get("name", "gatekeeper"))
    serve(service, cfg.mcp_port, open(expand(cfg.mcp_token_file)).read().strip())

    def sweeper() -> None:
        while not switch.stop.wait(30):
            try:
                service.sweep()
            except Exception:
                log.exception("sweep failed")

    threading.Thread(target=sweeper, daemon=True).start()
    log.info("Gatekeeper up: %d project(s)", len(cfg.projects))
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
    args = ap.parse_args()
    if args.cmd == "run":
        run(args.config)


if __name__ == "__main__":
    main()
