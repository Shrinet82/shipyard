#!/usr/bin/env python3
"""Limit who may address each agent to a project's members. Run by the owner. Stdlib + PyYAML.

  sync_addressing.py --config ~/shipyard.yaml --agent ops-agent [--agent repo-agent]

Uses the Gateway admin login. The agent's owner (the admin) always keeps access.
Re-run after changing members.
"""
import argparse
import http.cookiejar
import json
import os
import urllib.error
import urllib.request

import yaml


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="~/shipyard.yaml")
    ap.add_argument("--switch-env", default="~/switch/.env")
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--agent", action="append", required=True)
    ap.add_argument("--project", default=None, help="default: every project's members")
    ap.add_argument("--allow-agent", action="append", default=[],
                    help="another agent that may address these agents (e.g. gatekeeper, so alerts can wake the Ops Agent)")
    a = ap.parse_args()
    cfg = yaml.safe_load(open(os.path.expanduser(a.config)))
    env = dict(l.strip().split("=", 1) for l in open(os.path.expanduser(a.switch_env)) if "=" in l and not l.startswith("#"))
    members = sorted({m for name, p in cfg["projects"].items() if a.project in (None, name) for m in (p.get("members") or {})})
    def room_ids(v):          # a flat list (ops rooms) or {ops: [...], maintainers: [...]}
        return [*(v.get("ops") or []), *(v.get("maintainers") or [])] if isinstance(v, dict) else list(v or [])
    rooms = sorted({r for name, p in cfg["projects"].items() if a.project in (None, name) for r in room_ids(p.get("rooms"))})
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(method, path, body=None):
        req = urllib.request.Request(a.base + "/gateway" + path, method=method, headers={"Content-Type": "application/json"},
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with op.open(req, timeout=30) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]

    call("POST", "/auth/login", {"email": env["GATEWAY_ADMIN_EMAIL"], "password": env["GATEWAY_ADMIN_PASSWORD"]})
    # Switch's `users` dimension holds the ExternalUser row id of a platform account, not the
    # sender string, so translate each member through the Gateway's per-bridge user list.
    s, bridges = call("GET", "/collaborations")
    squash = lambda t: "".join(ch for ch in t.lower() if ch.isalnum())
    rows = {}
    for b in bridges:
        s, users = call("GET", f"/collaborations/{b['bridge_id']}/users")
        for u in users if s == 200 else []:
            rows[f"@switch-{b['bridge_type']}-{b['bridge_id']}-"] = rows.get(f"@switch-{b['bridge_type']}-{b['bridge_id']}-", []) + [u]
    user_ids = []
    for m in members:
        hit = None
        for prefix, us in rows.items():
            if m.startswith(prefix):
                name = squash(m[len(prefix):].rsplit(":", 1)[0])
                hit = next((u["id"] for u in us if squash(u["external_username"] or "") == name), None)
        if hit:
            user_ids.append(hit)
        else:
            print("  warning: no Switch record yet for", m, "(they have not posted in a bridged channel)")
    s, agents = call("GET", "/agents")
    ids = {x["name"]: x["id"] for x in (agents if isinstance(agents, list) else agents.get("agents", []))}
    for name in a.agent:
        # Only people in the project may address the agent, and only in the project's rooms;
        # the owner keeps access everywhere. Platform and agent senders are not admitted.
        policy = {"rules": [
            {"rooms": rooms, "users": user_ids, "agents": [], "owner": False, "platform": False},
            *([{"rooms": rooms, "users": [], "agents": [ids[n] for n in a.allow_agent], "owner": False, "platform": False}]
              if a.allow_agent else []),
            {"rooms": "*", "users": [], "agents": [], "owner": True, "platform": False}]}
        s, r = call("PUT", f"/agents/{ids[name]}/addressing-policy", {"policy": policy})
        print(name, "addressing policy:", s, f"({len(user_ids)} of {len(members)} members resolved, {len(rooms)} rooms)")


if __name__ == "__main__":
    main()
