"""Phase 0 spike: Q1/Q2/Q3/Q4/Q9 against a live Switch server. Stdlib only.

Run on the build VM:  python3 probe_gatekeeper.py
Needs /tmp/probe.json ({"id","api_key"}) and ~/switch/.env. Prints event structure,
never secrets.
"""
import http.client
import json
import os
import threading
import time
import urllib.request
import uuid

BASE = "localhost:8000"
MM = "localhost:8065"
probe = json.load(open("/tmp/probe.json"))
AGENT, KEY = probe["id"], probe["api_key"]
env = dict(l.strip().split("=", 1) for l in open(os.path.expanduser("~/switch/.env")) if "=" in l and not l.startswith("#"))
CID = str(uuid.uuid4())
events, state = [], {"cursor": 0, "stop": False}


def api(method, path, body=None, host=BASE, headers=None, tok=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if tok:
        h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(f"http://{host}{path}", method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300], {}


def op(name, body=None):
    return api("POST", f"/agents/{AGENT}/ops/{name}", body or {}, tok=KEY, headers={"X-Switch-Connection-Id": CID})


def stream():
    c = http.client.HTTPConnection(BASE, timeout=60)
    c.request("GET", f"/agents/{AGENT}/events?connection_id={CID}&scope=all&filter=all&start_from=head&protocol=1&client=shipyard-probe",
              headers={"Authorization": "Bearer " + KEY, "Accept": "text/event-stream"})
    r = c.getresponse()
    ev = {}
    for raw in r:
        line = raw.decode().rstrip("\n")
        if line.startswith("id:"):
            ev["id"] = line[3:].strip()
        elif line.startswith("event:"):
            ev["event"] = line[6:].strip()
        elif line.startswith("data:"):
            ev["data"] = json.loads(line[5:])
        elif line == "" and ev:
            events.append(ev)
            if "id" in ev:
                state["cursor"] = int(ev["id"])
            ev = {}
        if state["stop"]:
            break


def beat():
    while not state["stop"]:
        api("POST", f"/agents/{AGENT}/connection/beat", {"connection_id": CID, "cursor": state["cursor"]}, tok=KEY)
        time.sleep(2)


threading.Thread(target=stream, daemon=True).start()
time.sleep(1.5)
threading.Thread(target=beat, daemon=True).start()

rooms = {r["name"]: r["room_id"] for r in op("list_rooms")[1]["result"]}
ROOM = rooms["Mattermost: Town Square"]
print("invite:", op("invite_agent_to_room", {"room_id": ROOM, "agent_name": "gatekeeper-probe"})[:2])
print("connect:", str(op("connect_to_room", {"room_id": ROOM})[1])[:160].replace("\n", " "))
parts = op("list_participants")[1]
print("participants:", json.dumps(parts)[:700])

# Human posts in Mattermost as the bundled user
s, login, hdr = api("POST", "/api/v4/users/login", {"login_id": env["MATTERMOST_USER"], "password": env["MATTERMOST_USER_PASSWORD"]}, host=MM)
mmtok = hdr.get("Token")
mmh = {"Authorization": "Bearer " + mmtok}
_, ch, _ = api("GET", f"/api/v4/teams/name/{env['MATTERMOST_TEAM_NAME']}/channels/name/town-square", host=MM, headers=mmh)
for text in ["@gatekeeper-probe hello from a human, addressed", "a plain message with no mention"]:
    api("POST", "/api/v4/posts", {"channel_id": ch["id"], "message": text}, host=MM, headers=mmh)
time.sleep(6)

print("\n== events received:")
for e in events:
    d = e["data"]
    if e.get("event") == "message":
        print("message payload:", json.dumps(d["payload"], indent=None)[:600])
    else:
        print(e.get("event"), json.dumps({k: v for k, v in d.items() if k != "position"})[:200])

print("\npost_message:", str(op("post_message", {"body": "gatekeeper-probe online"})[:2])[:200])
time.sleep(2)
_, posts, _ = api("GET", f"/api/v4/channels/{ch['id']}/posts?per_page=4", host=MM, headers=mmh)
for pid in posts["order"]:
    p = posts["posts"][pid]
    print("MM post user_id=%s props=%s msg=%r" % (p["user_id"][:6], json.dumps(p.get("props", {}))[:160], p["message"][:60]))
state["stop"] = True
