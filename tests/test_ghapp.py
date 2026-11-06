import json
import os
import socket
import threading
import urllib.request
from pathlib import Path

import pytest

from shipyard.ghapp import AppSetup, AppSetupError, build_manifest, create_app, wait_for_installation

PEM = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"


def fake_http(status=201, data=None, calls=None):
    def http(method, url, headers=None, body=None, timeout=20.0):
        if calls is not None:
            calls.append((method, url))
        return status, data if data is not None else {"id": 4242, "slug": "shipyard-ab12", "pem": PEM, "webhook_secret": "whsec", "html_url": "https://github.com/apps/shipyard-ab12"}
    return http


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_manifest_asks_for_what_shipyard_reads_and_merges_with_webhooks_off_by_default():
    m = build_manifest("Shipyard-1", "http://localhost:8767/callback")
    assert m["default_permissions"] == {"contents": "write", "pull_requests": "write", "actions": "read", "checks": "read", "statuses": "read", "issues": "read"}
    assert {"pull_request", "check_run", "workflow_run"} <= set(m["default_events"])
    assert m["hook_attributes"]["active"] is False and m["public"] is False and m["redirect_url"].endswith("/callback")
    assert build_manifest("n", "r", "http://10.0.0.5:8766/hooks/github")["hook_attributes"] == {"url": "http://10.0.0.5:8766/hooks/github", "active": True}


def test_start_page_posts_the_manifest_to_github_with_the_state_and_escapes_it(tmp_path):
    s = AppSetup(tmp_path, name='Evil"><script>x</script>')
    status, page = s.handle("/")
    assert status == 200 and "https://github.com/settings/apps/new?state=" in page and s.state in page
    assert "<script>x</script>" not in page and "&quot;" in page
    org = AppSetup(tmp_path, org="acme-corp")
    assert "https://github.com/organizations/acme-corp/settings/apps/new" in org.handle("/")[1]
    with pytest.raises(AppSetupError):
        AppSetup(tmp_path, org="../evil")


def test_callback_exchanges_the_code_saves_the_keys_privately_and_only_once(tmp_path):
    calls = []
    s = AppSetup(tmp_path, http=fake_http(calls=calls))
    status, page = s.handle(f"/callback?code=abcdefgh1234&state={s.state}")
    assert status == 200 and "installations/new" in page and "shipyard-ab12" in page
    assert calls == [("POST", "https://api.github.com/app-manifests/abcdefgh1234/conversions")]
    assert (tmp_path / "shipyard-github.pem").read_text().startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert oct((tmp_path / "shipyard-github.pem").stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "shipyard-github-webhook.secret").read_text() == "whsec"
    assert s.result["app_id"] == "4242" and s.result["slug"] == "shipyard-ab12"
    assert s.handle(f"/callback?code=zzzzzzzz9999&state={s.state}")[0] == 409
    assert len(calls) == 1


def test_callback_refuses_a_wrong_state_a_bad_code_and_a_github_refusal(tmp_path):
    s = AppSetup(tmp_path, http=fake_http())
    assert s.handle("/callback?code=abcdefgh1234&state=nope")[0] == 400
    assert s.handle(f"/callback?code=../../x&state={s.state}")[0] == 502
    assert not (tmp_path / "shipyard-github.pem").exists()
    bad = AppSetup(tmp_path, http=fake_http(status=422, data={"message": "expired"}))
    status, page = bad.handle(f"/callback?code=abcdefgh1234&state={bad.state}")
    assert status == 502 and "refused the code" in page and bad.result is None
    nokey = AppSetup(tmp_path, http=fake_http(data={"id": 1, "slug": "x", "pem": "nope"}))
    assert nokey.handle(f"/callback?code=abcdefgh1234&state={nokey.state}")[0] == 502
    assert s.handle("/other")[0] == 404


def test_the_real_server_listens_on_loopback_only_and_finishes_when_the_callback_arrives(tmp_path):
    port = free_port()
    s = AppSetup(tmp_path, port=port, http=fake_http())
    out = {}
    t = threading.Thread(target=lambda: out.update(s.serve(timeout=10, poll=0.05)))
    t.start()
    for _ in range(100):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as r:
                assert b"Continue to GitHub" in r.read() and "default-src 'none'" in r.headers["Content-Security-Policy"]
            break
        except OSError:
            threading.Event().wait(0.05)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/callback?code=abcdefgh1234&state={s.state}", timeout=5) as r:
        assert r.status == 200
    t.join(10)
    assert out["app_id"] == "4242"


def test_a_busy_port_and_a_timeout_say_what_to_do(tmp_path):
    with socket.socket() as hold:
        hold.bind(("127.0.0.1", 0)); hold.listen()
        with pytest.raises(AppSetupError, match="busy"):
            AppSetup(tmp_path, port=hold.getsockname()[1]).serve(timeout=0.1)
    with pytest.raises(AppSetupError, match="timed out"):
        AppSetup(tmp_path, port=free_port()).serve(timeout=0.2, poll=0.05)


def test_wait_for_installation_polls_until_the_app_can_see_the_repo():
    tries, clock = [], [0.0]
    def check(app_id, key, repo):
        tries.append(repo)
        if len(tries) < 3:
            raise RuntimeError("GitHub answered 404")
        return "999"
    def sleep(n):
        clock[0] += n
    assert wait_for_installation(check, "1", "k", "o/r", sleep=sleep, now=lambda: clock[0]) == "999" and len(tries) == 3
    with pytest.raises(AppSetupError, match="still not installed"):
        wait_for_installation(lambda *a: (_ for _ in ()).throw(RuntimeError("404")), "1", "k", "o/r", timeout=5, interval=2, sleep=sleep, now=lambda: clock[0])


def test_create_app_runs_the_whole_flow_and_returns_what_init_needs(tmp_path, monkeypatch):
    port = free_port()
    seen = []
    import shipyard.ghapp as g
    real = g.AppSetup
    class Quick(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **{**k, "http": fake_http()})
            threading.Timer(0.3, lambda: urllib.request.urlopen(f"http://127.0.0.1:{self.port}/callback?code=abcdefgh1234&state={self.state}", timeout=5).read()).start()
    monkeypatch.setattr(g, "AppSetup", Quick)
    out = create_app(tmp_path, "o/r", port=port, say=seen.append, check=lambda *a: "777", timeout=10)
    assert out["installation"] == "777" and out["app_id"] == "4242" and out["repo"] == "o/r"
    assert any(f"localhost:{port}" in l for l in seen) and any("installations/new" in l for l in seen)
