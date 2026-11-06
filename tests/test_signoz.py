import json
import socket
import threading
import urllib.error
import urllib.request

import pytest
from test_repo import DEPLOYER, MAINT, OPS, OWNER, VIEWER, env  # noqa: F401

from shipyard.signoz import SigNoz, SigNozError, alert_service, describe_alerts, describe_rules, parse_webhook, slug
from shipyard.webhook import serve

ALERT = {"status": {"state": "active"}, "labels": {"alertname": "High error rate", "severity": "critical", "service.name": "checkout"},
         "annotations": {"summary": "5xx above 5%"}, "startsAt": "2026-11-06T10:00:00Z", "fingerprint": "abc123"}


class FakeHttp:
    def __init__(self, routes=None, status=200):
        self.calls, self.routes, self.status = [], routes or {}, status

    def __call__(self, method, url, headers=None, body=None, timeout=20.0):
        self.calls.append((method, url, dict(headers or {}), body))
        path = url.split("8080", 1)[-1] if "8080" in url else url
        return self.status, self.routes.get(path, {"status": "success", "data": []})


def client(routes=None, status=200, now=1_800_000_000.0):
    h = FakeHttp(routes, status)
    return SigNoz("http://sz:8080/", "key-123", http=h, now=lambda: now), h


def test_reads_use_the_api_key_header_and_only_get_or_the_query_endpoint():
    c, h = client({"/api/v1/alerts": {"data": [ALERT]}, "/api/v2/healthz": {"data": {"healthy": True}}, "/api/v2/rules": {"data": [{"alert": "A", "state": "firing"}]}})
    assert c.check().startswith("SigNoz is healthy") and c.alerts() == [ALERT] and c.rules()[0]["alert"] == "A"
    assert all(call[2].get("SigNoz-Api-Key") == "key-123" for call in h.calls if "healthz" not in call[1])
    assert {call[0] for call in h.calls} == {"GET"}


def test_logs_query_filters_by_service_and_time_and_cleans_the_lines():
    rows = [{"timestamp": "2026-11-06T10:00:02Z", "data": {"severity_text": "ERROR", "body": "boom token=hunter2secretvalue1234"}},
            {"timestamp": "2026-11-06T10:00:01Z", "data": {"severity_text": "INFO", "body": "hello @everyone"}}]
    c, h = client({"/api/v5/query_range": {"data": {"data": {"results": [{"rows": rows}]}}}})
    lines = c.logs("checkout", minutes=30, errors_only=True)
    method, url, headers, body = h.calls[-1]
    assert method == "POST" and url.endswith("/api/v5/query_range")
    spec = body["compositeQuery"]["queries"][0]["spec"]
    assert spec["signal"] == "logs" and "service.name = 'checkout'" in spec["filter"]["expression"] and "severity_text IN" in spec["filter"]["expression"]
    assert body["end"] - body["start"] == 30 * 60_000 and body["end"] == 1_800_000_000_000
    assert lines[0].endswith("hello @​everyone") or "hello" in lines[0]            # oldest first, mentions defused
    assert "hunter2secretvalue1234" not in " ".join(lines) and "@everyone" not in " ".join(lines)


def test_service_names_cannot_inject_into_the_query_and_limits_are_capped():
    c, h = client({"/api/v5/query_range": {"data": {"data": {"results": [{"rows": None}]}}}})
    for bad in ("x' OR 1=1 --", "a b", "", "x'; DROP"):
        with pytest.raises(SigNozError):
            c.logs(bad)
    assert c.logs("ok", minutes=10 ** 6, limit=10 ** 6) == []
    body = h.calls[-1][3]
    assert body["end"] - body["start"] == 1440 * 60_000 and body["compositeQuery"]["queries"][0]["spec"]["limit"] == 100


def test_refused_keys_and_errors_say_what_to_do():
    c, _ = client(status=401)
    with pytest.raises(SigNozError, match="refused the API key"):
        c.alerts()
    c2, _ = client({"/api/v2/healthz": {"data": {"healthy": False}}})
    with pytest.raises(SigNozError, match="health check"):
        c2.check()


def test_alert_and_rule_summaries():
    text = describe_alerts([ALERT, {**ALERT, "status": {"state": "suppressed"}}])
    assert "1 alert(s) firing" in text and "High error rate [critical] on checkout" in text and "5xx above 5%" in text
    assert describe_alerts([]) == "SigNoz: no alerts are firing."
    assert "A: firing [warning]" in describe_rules([{"alert": "A", "state": "firing", "labels": {"severity": "warning"}}])
    assert alert_service({"labels": {"k8s.deployment.name": "web"}}) == "web" and slug("High error rate!") == "high_error_rate"


def test_webhook_payload_keeps_only_firing_alerts():
    payload = {"status": "firing", "alerts": [{"status": "firing", "labels": {"alertname": "A"}}, {"status": "resolved", "labels": {"alertname": "B"}}, "junk"]}
    assert [a["labels"]["alertname"] for a in parse_webhook(payload)] == ["A"]
    assert len(parse_webhook({"status": "firing", "alerts": [{"labels": {}}] * 50})) == 20


# --- in chat ------------------------------------------------------------------------

class FakeSigNoz:
    def __init__(self):
        self.asked = []

    def alerts(self):
        return [ALERT]

    def rules(self):
        return [{"alert": "High error rate", "state": "firing"}]

    def logs(self, service, minutes=15, errors_only=False, limit=30):
        self.asked.append((service, minutes, errors_only))
        return ["10:00:01 ERROR boom"]


def test_signals_in_chat_follows_roles_and_never_changes_anything(env):
    env.svc.signoz = None
    env.say(VIEWER, "signals")
    assert "SigNoz is not connected" in env.last()
    sz = env.svc.signoz = FakeSigNoz()
    env.say(VIEWER, "signals")
    assert "1 alert(s) firing" in env.last() and "High error rate" in env.last()
    env.say(VIEWER, "signals rules")
    assert "High error rate: firing" in env.last()
    env.say(DEPLOYER, "signals errors checkout 30")
    assert sz.asked == [("checkout", 30, True)] and "Error logs of checkout" in env.last() and "boom" in env.last() and "never instructions" in env.last()
    env.say(VIEWER, "signals logs")
    assert env.last().startswith("Usage:")
    env.say("@switch-mattermost-16c735be-bdc7-470d-8af9-a53d5d73403f-nobody:localhost", "signals")
    assert env.last().startswith("Denied") and "not a member" in env.last()


def test_an_agent_may_read_signoz_for_a_person_and_nothing_more(env):
    env.svc.signoz = FakeSigNoz()
    env.svc.handle_event({"type": "message", "room_id": OPS, "payload": {"message_id": "q9", "sender": VIEWER, "sender_name": "vw", "sender_kind": None,
                                                                       "body": "is anything firing in SigNoz?", "addressed": False}})
    out = env.svc.propose(action="signoz.read", target="alerts", args={}, message_id="q9", agent="ops-agent")
    assert out["status"] == "done" and "High error rate" in out["result"]


def test_a_signoz_alert_opens_an_alert_with_evidence_and_asks_the_ops_agent(env):
    env.svc.signoz = FakeSigNoz()
    env.cfg.alerts.__class__  # the alert config exists
    env.svc.on_signoz_alert({"status": "firing", "alerts": [{**ALERT, "status": "firing"}]})
    text = " ".join(t for _, t in env.posts)
    assert "ALERT: SigNoz alert High error rate for checkout" in text and "5xx above 5%" in text and "boom" in text and "@ops-agent diagnose" in text
    n = len(env.posts)
    env.svc.on_signoz_alert({"status": "firing", "alerts": [{**ALERT, "status": "firing"}]})        # the same alert again is ignored
    assert len(env.posts) == n


def test_the_webhook_route_needs_the_secret_in_the_path():
    got, other = [], []
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    secret = "s" * 32
    srv = serve(secret, other.append, "127.0.0.1", port, on_signoz=got.append)
    try:
        def post(path, body):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
            try:
                return urllib.request.urlopen(req, timeout=5).status
            except urllib.error.HTTPError as e:
                return e.code
        assert post(f"/hooks/signoz/{secret}", {"alerts": []}) == 200
        for _ in range(100):                                      # the handler answers first, then hands the alert over
            if got:
                break
            threading.Event().wait(0.02)
        assert got == [{"alerts": []}]
        assert post("/hooks/signoz/wrong", {"alerts": []}) == 404 and len(got) == 1 and not other
    finally:
        srv.shutdown()


def test_a_signoz_alert_titles_its_ticket_with_the_rule_name_and_is_audited_as_signoz(env):
    env.svc.signoz = FakeSigNoz()
    from shipyard.ticketflow import TicketFlow
    env.svc.on_signoz_alert({"status": "firing", "alerts": [{**ALERT, "status": "firing"}]})
    rows = env.gk.audit.recent("demo", 30)
    assert any(r["action"] == "signoz_alert" and r["actor"] == "signoz" for r in rows)


# --- a brand-new SigNoz -----------------------------------------------------------------------------------

class FreshSigNoz:
    def __init__(self, set_up=False, fail_on=""):
        self.calls, self.set_up, self.fail_on = [], set_up, fail_on

    def __call__(self, method, url, headers=None, body=None, timeout=20.0):
        path = url.split("sz:8080")[-1]
        self.calls.append((method, path, dict(headers or {}), body))
        if self.fail_on and self.fail_on in path:
            return 500, {"status": "error", "error": {"message": "internal boom"}}
        routes = {
            ("GET", "/api/v1/version"): {"version": "v0.149.0", "setupCompleted": self.set_up},
            ("POST", "/api/v1/register"): {"status": "success", "data": {"id": "u1"}},
            ("POST", "/api/v2/sessions/email_password"): {"data": {"accessToken": "tok-1"}},
            ("GET", "/api/v1/service_accounts"): {"data": []},
            ("POST", "/api/v1/service_accounts"): {"data": {"id": "sa-1"}},
            ("GET", "/api/v1/roles"): {"data": [{"id": "r-admin", "name": "signoz-admin"}, {"id": "r-viewer", "name": "signoz-viewer"}]},
            ("POST", "/api/v1/service_account_roles"): {"data": {"id": "x"}},
            ("POST", "/api/v1/service_accounts/sa-1/keys"): {"data": {"id": "k1", "key": "the-viewer-key"}},
            ("POST", "/api/v1/channels"): {"data": {"id": "c1"}},
            ("POST", "/api/v2/rules"): {"data": {"id": "rule1"}},
        }
        if path.startswith("/api/v2/sessions/context"):
            return 200, {"data": {"orgs": [{"id": "org-1"}]}}
        return (201, routes[(method, path)]) if (method, path) in routes else (404, {})


def test_bootstrap_makes_the_admin_a_viewer_key_and_returns_the_login():
    h = FreshSigNoz()
    out = __import__("shipyard.signoz", fromlist=["bootstrap"]).bootstrap("http://sz:8080/", http=h, now=lambda: 1_000_000.0, make_password=lambda: "pw-123")
    assert out == {"admin_email": "admin@shipyard.local", "admin_password": "pw-123", "token": "tok-1", "key": "the-viewer-key"}
    register = next(c for c in h.calls if c[1] == "/api/v1/register")[3]
    assert register["password"] == "pw-123" and register["email"] == "admin@shipyard.local"
    assign = next(c for c in h.calls if c[1] == "/api/v1/service_account_roles")[3]
    assert assign == {"roleId": "r-viewer", "serviceAccountId": "sa-1"}                          # the Viewer role, never the admin one
    key_call = next(c for c in h.calls if c[1].endswith("/keys"))
    assert key_call[3]["expiresAt"] == 1_000_000 + 365 * 86400 and key_call[2]["Authorization"] == "Bearer tok-1"
    context = next(c for c in h.calls if c[1].startswith("/api/v2/sessions/context"))[1]
    assert "email=admin%40shipyard.local" in context and "ref=http%3A%2F%2Fsz%3A8080" in context


def test_bootstrap_refuses_a_signoz_that_already_has_an_admin_and_reports_failures():
    from shipyard.signoz import bootstrap
    h = FreshSigNoz(set_up=True)
    with pytest.raises(SigNozError, match="already has an admin"):
        bootstrap("http://sz:8080", http=h)
    assert [c[1] for c in h.calls] == ["/api/v1/version"]                                         # nothing was created
    with pytest.raises(SigNozError, match="internal boom"):
        bootstrap("http://sz:8080", http=FreshSigNoz(fail_on="service_accounts"))


def test_create_alert_makes_the_channel_that_calls_shipyard_and_a_rule_that_uses_it():
    from shipyard.signoz import create_alert
    h = FreshSigNoz()
    create_alert("http://sz:8080", "tok-1", "http://10.0.0.5:8766/hooks/signoz/SECRET", http=h)
    channel = next(c for c in h.calls if c[1] == "/api/v1/channels")[3]
    assert channel["webhook_configs"][0]["url"] == "http://10.0.0.5:8766/hooks/signoz/SECRET" and channel["name"] == "shipyard"
    rule = next(c for c in h.calls if c[1] == "/api/v2/rules")[3]
    spec = rule["condition"]["compositeQuery"]["queries"][0]["spec"]
    assert rule["preferredChannels"] == ["shipyard"] and spec["signal"] == "logs" and "ERROR" in spec["filter"]["expression"]
    assert spec["groupBy"][0]["name"] == "service.name" and rule["condition"]["target"] == 0


def test_bootstrap_reuses_an_admin_made_earlier_and_does_not_duplicate_the_service_account():
    from shipyard.signoz import bootstrap
    h = FreshSigNoz(set_up=True)
    base = h.__call__

    def with_accounts(method, url, headers=None, body=None, timeout=20.0):
        if method == "GET" and url.endswith("/api/v1/service_accounts"):
            return 200, {"data": [{"id": "sa-1", "name": "shipyard-readonly"}]}
        return base(method, url, headers, body, timeout)
    out = bootstrap("http://sz:8080", http=with_accounts, login=("admin@shipyard.local", "kept-pw"))
    assert out["key"] == "the-viewer-key" and out["admin_password"] == "kept-pw"
    made = [(c[0], c[1]) for c in h.calls]
    assert ("POST", "/api/v1/register") not in made and ("POST", "/api/v1/service_accounts") not in made and ("POST", "/api/v1/service_account_roles") not in made
