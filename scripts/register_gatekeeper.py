#!/usr/bin/env python3
"""Register the Gatekeeper with a Switch server and put it in rooms. Stdlib only.

  register_gatekeeper.py --switch-env ~/switch/.env --room <room-id> [--room ...]

Writes ~/gatekeeper.json ({id, api_key, name}) and ~/gatekeeper-mcp.token, both mode 0600.
Uses the registration token (to create the agent) and the Gateway admin login (to open
the Gatekeeper's addressing and add it to rooms). Never prints a secret.
"""
import argparse
import http.cookiejar
import json
import os
import secrets
import urllib.error
import urllib.request


def env_file(path):
    return dict(l.strip().split("=", 1) for l in open(os.path.expanduser(path)) if "=" in l and not l.startswith("#"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--switch-env", default="~/switch/.env")
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--name", default="gatekeeper")
    ap.add_argument("--room", action="append", default=[])
    a = ap.parse_args()
    env = env_file(a.switch_env)

    def call(opener, method, url, body=None, headers=None):
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with opener.open(req, timeout=30) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]

    plain = urllib.request.build_opener()
    s, reg = call(plain, "POST", f"{a.base}/agents", {
        "name": a.name, "description": "Shipyard Gatekeeper: roles, approvals and audit for chat-driven ops",
        "connector_type": "custom", "overwrite": True,
        "integration_profile": {"connection_model": "always_on", "message_exchange": True,
                                "pre_invocation_mediation": [], "post_invocation_mediation": [], "event_reporting": []}},
        {"Authorization": f"Bearer {env['AGENT_REGISTRATION_TOKEN']}"})
    assert s in (200, 201), f"registration failed: {s} {reg}"
    out = os.path.expanduser("~/gatekeeper.json")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"id": reg["id"], "api_key": reg["api_key"], "name": a.name}, f)
    tok = os.path.expanduser("~/gatekeeper-mcp.token")
    if not os.path.exists(tok):
        fd = os.open(tok, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(24))
    print("registered", a.name, reg["id"])

    gw = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    s, _ = call(gw, "POST", f"{a.base}/gateway/auth/login",
                {"email": env["GATEWAY_ADMIN_EMAIL"], "password": env["GATEWAY_ADMIN_PASSWORD"]})
    assert s == 200, "gateway login failed"
    # The Gatekeeper does its own authorization, so Switch must let anyone address it.
    s, r = call(gw, "PUT", f"{a.base}/gateway/agents/{reg['id']}/addressing-policy", {"policy": None})
    print("addressing open:", s)
    for room in a.room:
        s, r = call(gw, "POST", f"{a.base}/gateway/rooms/{room}/agents", {"agent_ids": [reg["id"]]})
        print("added to room", room, s)


if __name__ == "__main__":
    main()
