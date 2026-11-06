import json
import socket
import sqlite3
import textwrap
import urllib.error
import urllib.request

import pytest

from shipyard.commands import parse
from shipyard.config import load_config
from shipyard.gatekeeper import Gatekeeper
from shipyard.mcp_server import serve
from shipyard.service import Service

DEPLOYER = "@switch-x-deployer:localhost"
ROOM = "r1"
TOKEN = "t" * 32


@pytest.fixture
def server(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent(f"""
        projects:
          demo: {{rooms: [{ROOM}], apps: {{demo-app: u1}}, members: {{"{DEPLOYER}": deployer}}}}
        actions: {{coolify.deploy: change, coolify.status: read}}
    """))
    cfg = load_config(f)
    gk = Gatekeeper(cfg.policy, sqlite3.connect(":memory:", check_same_thread=False))
    posts = []

    class C:
        def status(self, u): return "ok"

    svc = Service(cfg, gk, C(), lambda r, t: posts.append(t))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = serve(svc, port, TOKEN)
    yield svc, port, posts
    srv.shutdown()


def rpc(port, method, params=None, token=TOKEN, id=1):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "id": id, **({"params": params} if params else {})}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/mcp", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def test_mcp_requires_the_token(server):
    _, port, _ = server
    with pytest.raises(urllib.error.HTTPError) as e:
        rpc(port, "tools/list", token="wrong")
    assert e.value.code == 401


def test_mcp_lists_request_action_and_the_board_tools_and_none_can_approve(server):
    _, port, _ = server
    tools = rpc(port, "tools/list")["result"]["tools"]
    names = [t["name"] for t in tools]
    assert names[0] == "request_action" and set(names[1:]) == {"ticket_create", "ticket_update", "ticket_assign", "ticket_move", "ticket_comment", "ticket_link",
                                                              "ticket_get", "ticket_list", "ticket_delete", "briefing", "team_status"}
    assert not [n for n in names if "approve" in n or "deny" in n]
    assert all("approve" not in json.dumps(t["inputSchema"]) for t in tools)
    assert all("message_id" in t["inputSchema"]["required"] for t in tools)                   # every call cites the person's message


def test_mcp_call_waits_for_a_human(server):
    svc, port, posts = server
    svc.handle_event({"type": "message", "room_id": ROOM, "payload": {
        "message_id": "m1", "sender": DEPLOYER, "sender_name": "dep", "sender_kind": None,
        "body": "please deploy demo-app", "addressed": False}})
    out = rpc(port, "tools/call", {"name": "request_action", "arguments": {
        "action": "coolify.deploy", "target": "demo-app", "message_id": "m1", "agent": "ops-agent"}})
    payload = json.loads(out["result"]["content"][0]["text"])
    assert payload["status"] == "awaiting_human_approval" and "Approval needed" in posts[-1]


def test_mcp_rejects_actions_outside_the_allowed_set(server):
    _, port, _ = server
    out = rpc(port, "tools/call", {"name": "request_action", "arguments": {
        "action": "ops.shell", "target": "x", "message_id": "m"}})
    assert json.loads(out["result"]["content"][0]["text"])["reason"] == "unsupported action"
    assert out["result"]["isError"] is True


def test_example_config_loads():
    cfg = load_config("shipyard.example.yaml")
    assert "demo" in cfg.projects and cfg.policy.actions["coolify.rollback"].value == "change"


def test_a_room_cannot_belong_to_two_projects(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("projects: {a: {rooms: [r1]}, b: {rooms: [r1]}}\nactions: {}\n")
    with pytest.raises(ValueError):
        load_config(f)


@pytest.mark.parametrize("body,addressed,verb", [
    ("!deploy demo-app", False, None), ("@gatekeeper deploy demo-app", True, "deploy"),
    ("<@&99> status", True, "status"), ("<@!99>: rollback demo-app 1.2", True, "rollback"),
    ("deploy demo-app", False, None), ("@gatekeeper blah", True, "unknown"), ("!blah", True, "unknown"),
])
def test_parse(body, addressed, verb):
    cmd = parse(body, addressed)
    assert (cmd.verb if cmd else None) == verb


def test_an_install_without_coolify_starts_and_every_coolify_call_says_so(tmp_path):
    import pytest
    from shipyard.__main__ import _coolify_for
    from shipyard.config import load_config
    from shipyard.coolify import CoolifyError, NoCoolify
    f = tmp_path / "c.yaml"
    f.write_text("projects:\n  demo:\n    rooms: {ops: [r1], maintainers: [r2]}\n    apps: {}\n    members: {}\nactions:\n  coolify.status: read\ncoolify: {url: '', token_file: '/nonexistent/coolify.env'}\n")
    client = _coolify_for(load_config(f))
    assert isinstance(client, NoCoolify)
    with pytest.raises(CoolifyError, match="not connected"):
        client.status("uuid")
    with pytest.raises(CoolifyError):
        client.container_logs("uuid")
