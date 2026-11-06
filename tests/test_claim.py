import sqlite3
from types import SimpleNamespace

from test_init import FakeGw, answers, home, http_fake  # noqa: F401
from test_repo import OWNER, VIEWER, env  # noqa: F401

from pathlib import Path

from shipyard.audit import AuditLog
from shipyard.claim import last_whoami_id, pretty, wait_for_whoami
from shipyard.config import load_config
from shipyard.init import InitError, Installer
from shipyard.members import MemberStore
from shipyard.policy import Role

ID = "@switch-discord-7e1957d7-6572-4bec-9167-5de9300a93e4-anya:localhost"


def audit_db(tmp_path):
    db_file = str(tmp_path / "a.db")
    db = sqlite3.connect(db_file)
    return db_file, db, AuditLog(db)


def test_pretty_names_the_person_and_the_chat_app():
    assert pretty(ID) == "anya on Discord" and pretty("@odd:localhost") == "@odd:localhost"


def test_wait_for_whoami_finds_only_newer_requests_and_times_out(tmp_path):
    db_file, db, log = audit_db(tmp_path)
    log.write(project="demo", actor="@old:localhost", event="whoami", action="whoami", target="demo")
    db.commit()
    first = last_whoami_id(db_file)
    assert first == 1
    clock, slept = [0.0], []

    def sleep(n):
        slept.append(n)
        clock[0] += n
        if len(slept) == 2:                                                   # the person types it after a few seconds
            log.write(project="demo", actor=ID, event="whoami", action="whoami", target="demo")
            db.commit()
    assert wait_for_whoami(db_file, first, sleep=sleep, now=lambda: clock[0]) == (2, ID)
    assert wait_for_whoami(db_file, 2, timeout=5, interval=2, sleep=sleep, now=lambda: clock[0]) is None


def test_the_gatekeeper_records_who_asked_whoami(env):
    env.say(VIEWER, "whoami")
    rows = env.gk.audit.recent("demo", 5)
    assert any(r["event"] == "whoami" and r["actor"] == VIEWER for r in rows)


def make_installer(home, waiter, ask_reply="yes", **kw):
    said, runs = [], []
    inst = Installer(answers(home, owner=""), home, interactive=True, ask=lambda q, d: ask_reply if "owner" in q else d, secret=lambda q: "x", say=said.append,
                     gateway=FakeGw, http=http_fake(), whoami_waiter=waiter, github_check=lambda *a: "i",
                     run=lambda argv, **k: runs.append(argv) or SimpleNamespace(returncode=0, stdout="active", stderr=""), workdir=Path(__file__).parent.parent, **kw)
    inst.said, inst.runs = said, runs
    return inst


def test_install_waits_for_whoami_confirms_and_makes_the_person_owner(home):
    inst = make_installer(home, lambda db, start: (7, ID))
    inst.install()
    assert any("type:  @gatekeeper whoami" in s for s in inst.said) and any("anya on Discord" in s for s in inst.said)
    cfg = load_config(home / "shipyard.yaml")
    MemberStore(home / "shipyard-members.json", cfg.policy, None).load()
    assert cfg.policy.members["demo"][ID] is Role.OWNER
    assert ["systemctl", "--user", "restart", "shipyard-gatekeeper"] in inst.runs


def test_declining_or_timing_out_adds_nobody(home):
    inst = make_installer(home, lambda db, start: (7, ID), ask_reply="no")
    inst.install()
    assert ID not in load_config(home / "shipyard.yaml").policy.members["demo"] and any("not added" in s for s in inst.said)
    inst2 = make_installer(home, lambda db, start: None)
    inst2.install()
    assert any("Nothing arrived" in s for s in inst2.said)
    inst3 = make_installer(home, lambda db, start: (_ for _ in ()).throw(KeyboardInterrupt()))
    inst3.install()
    assert any("skipped" in s for s in inst3.said)


def test_an_owner_in_the_answers_skips_the_wait(home):
    called = []
    a = answers(home)
    inst = Installer(a, home, interactive=True, ask=lambda q, d: d, secret=lambda q: "x", say=lambda s: None, gateway=FakeGw, http=http_fake(),
                     whoami_waiter=lambda *x: called.append(x), github_check=lambda *a: "i",
                     run=lambda argv, **k: SimpleNamespace(returncode=0, stdout="active", stderr=""), workdir=Path(__file__).parent.parent)
    inst.install()
    assert not called


def test_a_wrong_coolify_token_is_asked_again_with_the_page_to_create_it(home):
    tokens = iter(["bad-token", "good-token"])
    seen = []

    def http(method, url, headers=None, body=None, timeout=20):
        if url.endswith("/api/v1/applications"):
            seen.append(headers["Authorization"])
            ok = headers["Authorization"] == "Bearer good-token"
            return (200, [{"uuid": "u-web", "name": "Demo Web"}]) if ok else (401, "no")
        return http_fake()(method, url, headers, body, timeout)
    said = []
    a = answers(home, coolify={"url": "http://cool:8000", "apps": ["demo-web"]})
    inst = Installer(a, home, interactive=True, ask=lambda q, d: d, secret=lambda q: next(tokens), say=said.append, gateway=FakeGw, http=http,
                     whoami_waiter=lambda *x: None, github_check=lambda *a: "i",
                     run=lambda argv, **k: SimpleNamespace(returncode=0, stdout="active", stderr=""), workdir=Path(__file__).parent.parent)
    import os
    os.environ.pop("COOLIFY_TOKEN", None)
    url, token, apps = inst.coolify()
    assert token == "good-token" and seen == ["Bearer bad-token", "Bearer good-token"]
    text = "\n".join(said)
    assert "http://cool:8000/security/api-tokens" in text and "refused that token (401)" in text
    # unattended runs do not loop: one try, then a clear error
    bad = Installer(answers(home, coolify={"url": "http://cool:8000", "token": "bad-token"}), home, interactive=False, say=lambda s: None, gateway=FakeGw, http=http)
    try:
        bad.coolify()
        raise AssertionError("should have refused")
    except InitError as exc:
        assert "refused the token" in str(exc) and "API Access" in str(exc)
