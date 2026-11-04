import json

import pytest

from shipyard.coolify import CoolifyError, CoolifyMcp, _parse_rollback


def adapter(replies):
    """A CoolifyMcp whose tool() replays canned replies and records calls."""
    c = CoolifyMcp("http://x", "t")
    c.calls = []

    def tool(name, args):
        c.calls.append((name, args))
        return replies[name]

    c.tool = tool
    return c


# the exact payload the live server returned (Coolify 4.6.0)
LIVE = {"current": "1.27-alpine", "images": [
    {"tag": "alpine", "created_at": "2026-10-21", "is_current": False, "source": "local"},
    {"tag": "1.27-alpine", "created_at": "2025-04-16", "is_current": True, "source": "local"}]}


def test_parse_live_rollback_payload():
    assert _parse_rollback(LIVE) == ("1.27-alpine", ["alpine", "1.27-alpine"])


def test_rollback_defaults_to_the_newest_image_that_is_not_current():
    c = adapter({"list_rollback_images": LIVE, "rollback_application": {"message": "queued"}})
    assert "rollback to alpine queued" in c.rollback("u1")
    name, args = c.calls[-1]
    assert name == "rollback_application" and args == {"action": "rollback", "uuid": "u1", "data": {"commit": "alpine"}, "confirm": True}


def test_rollback_refuses_a_tag_that_is_not_offered_or_is_current():
    c = adapter({"list_rollback_images": LIVE})
    for tag in ("latest", "1.27-alpine", "alpine; rm -rf /"):
        with pytest.raises(CoolifyError):
            c.rollback("u1", tag)
    assert all(n != "rollback_application" for n, _ in c.calls)


def test_rollback_with_nothing_to_roll_back_to():
    c = adapter({"list_rollback_images": {"current": "a", "images": [{"tag": "a", "is_current": True}]}})
    with pytest.raises(CoolifyError):
        c.rollback("u1")


def test_status_reads_name_and_state():
    c = adapter({"get_application": {"name": "demo-app", "status": "running:unknown"}})
    assert c.status("u1") == "demo-app: running:unknown"


def test_deploy_and_restart_report_the_message():
    c = adapter({"deploy": {"ok": True, "message": "Deployment request queued."}, "control": {"message": "Restart queued"}})
    assert "Deployment request queued." in c.deploy("u1")
    assert c.calls[-1] == ("deploy", {"uuid": "u1"})
    assert "Restart queued" in c.restart("u1")
    assert c.calls[-1] == ("control", {"resource": "application", "action": "restart", "uuid": "u1"})


def test_data_wrapper_is_removed_from_real_replies(monkeypatch):
    c = CoolifyMcp("http://x", "t")
    monkeypatch.setattr(c, "_ensure", lambda: None)
    reply = {"result": {"content": [{"type": "text", "text": json.dumps({"data": {"name": "n", "status": "s"}})}]}}
    monkeypatch.setattr(c, "_rpc", lambda *a, **k: reply)
    assert c.tool("get_application", {"uuid": "u"}) == {"name": "n", "status": "s"}


def test_tool_errors_and_outages_raise(monkeypatch):
    c = CoolifyMcp("http://x", "t")
    monkeypatch.setattr(c, "_ensure", lambda: None)
    monkeypatch.setattr(c, "_rpc", lambda *a, **k: {"result": {"isError": True, "content": [{"type": "text", "text": "no"}]}})
    with pytest.raises(CoolifyError):
        c.tool("deploy", {})

    def boom(*a, **k):
        raise CoolifyError("Coolify unreachable")

    monkeypatch.setattr(c, "_rpc", boom)
    with pytest.raises(CoolifyError):
        c.tool("deploy", {})


def test_container_logs_unwrap_the_reply_and_an_empty_log_is_empty():
    c = adapter({"get_logs": {"ok": True, "resource": "application", "logs": "line 1\nline 2", "redacted": True}})
    assert c.container_logs("u1") == ["line 1", "line 2"]
    c = adapter({"get_logs": {"ok": True, "resource": "application", "uuid": "u", "lines": 63, "logs": "", "redacted": True}})
    assert c.container_logs("u1") == []
    c = adapter({"get_logs": "plain text\nlog"})
    assert c.container_logs("u1") == ["plain text", "log"]
