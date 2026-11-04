#!/usr/bin/env python3
"""Test helper for the bundled Mattermost. Run on the build VM. Stdlib only.

  mm_test.py create            create test users owner/deployer/viewer (passwords in ~/mm-test-users.json)
  mm_test.py say <user> <text> [channel]   post as that user, then print the replies that follow
"""
import json
import os
import secrets
import sys
import time
import urllib.request

env = dict(l.strip().split("=", 1) for l in open(os.path.expanduser("~/switch/.env")) if "=" in l and not l.startswith("#"))
USERS = os.path.expanduser("~/mm-test-users.json")
BASE = "http://localhost:8065/api/v4"


def mm(method, path, body=None, tok=None):
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(BASE + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
        return (json.loads(raw) if raw else None), r.headers


def login(user, password):
    return mm("POST", "/users/login", {"login_id": user, "password": password})[1]["Token"]


def channel_id(tok, name):
    return mm("GET", f"/teams/name/{env['MATTERMOST_TEAM_NAME']}/channels/name/{name}", tok=tok)[0]["id"]


def create():
    admin = login(env["MATTERMOST_ADMIN_USER"], env["MATTERMOST_ADMIN_PASSWORD"])
    team = mm("GET", f"/teams/name/{env['MATTERMOST_TEAM_NAME']}", tok=admin)[0]["id"]
    chans = [channel_id(admin, c) for c in ("demo-ops", "demo-maintainers")]
    users = json.load(open(USERS)) if os.path.exists(USERS) else {}
    for name in ("owner", "maint", "deployer", "viewer", "guest"):
        uname = f"sy-{name}"
        if uname not in users:
            users[uname] = secrets.token_urlsafe(18)
            u = mm("POST", "/users", {"email": f"{uname}@shipyard.test", "username": uname, "password": users[uname]}, admin)[0]
        else:
            u = mm("GET", f"/users/username/{uname}", tok=admin)[0]
        mm("POST", f"/teams/{team}/members", {"team_id": team, "user_id": u["id"]}, admin)
        for ch in chans:
            mm("POST", f"/channels/{ch}/members", {"user_id": u["id"]}, admin)
        print("ready", uname)
    fd = os.open(USERS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(users, f)


def say(user, text, channel="demo-ops", wait=float(os.environ.get("WAIT", 25))):
    users = json.load(open(USERS))
    tok = login(user, users[user])
    ch = channel_id(tok, channel)
    me = mm("GET", "/users/me", tok=tok)[0]["id"]
    before = mm("GET", f"/channels/{ch}/posts?per_page=1", tok=tok)[0]
    mine = mm("POST", "/posts", {"channel_id": ch, "message": text}, tok)[0]["create_at"]
    start = time.time()
    seen = set(before["order"])
    quiet_since = time.time()
    while time.time() - start < wait:
        posts = mm("GET", f"/channels/{ch}/posts?per_page=15", tok=tok)[0]
        new = [i for i in reversed(posts["order"]) if i not in seen and posts["posts"][i]["create_at"] > mine
               and posts["posts"][i]["props"].get("from_bot") and "Working" not in posts["posts"][i]["message"]]
        for i in new:
            seen.add(i)
            print("  >", posts["posts"][i]["message"].replace("\n", "\n    "))
            quiet_since = time.time()
        if seen - set(before["order"]) and time.time() - quiet_since > 3:
            break
        time.sleep(1.5)


if __name__ == "__main__":
    if sys.argv[1] == "create":
        create()
    else:
        say(sys.argv[2], sys.argv[3], *(sys.argv[4:5]))
