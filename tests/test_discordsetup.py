import pytest

from shipyard.discordapi import DiscordError
from shipyard.discordsetup import PERMISSIONS, DiscordSetup, DiscordSetupError, invite_url, missing_switches

CONTENT, MEMBERS = 1 << 18, 1 << 14


class FakeDiscord:
    def __init__(self, token, flags=(CONTENT | MEMBERS), guilds=None, bad=False):
        self.token, self.flags_now, self.queue, self.bad = token, flags, list(guilds or []), bad

    def application(self):
        if self.bad:
            raise DiscordError("Discord does not accept this bot token")
        return {"id": "555", "name": "ShipYard", "flags": self.flags_now}

    def guilds(self):
        return self.queue.pop(0) if self.queue else []


class FakeGateway:
    def __init__(self, existing=None, status=201):
        self.calls, self.existing, self.status = [], existing or [], status

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if (method, path) == ("GET", "/collaborations"):
            return 200, self.existing
        return self.status, {"bridge_id": "7e1957d7-6572-4bec"}


def setup(tmp_path, client, gateway=None, replies=(), tokens=("tok-1",), said=None, **kw):
    it, tk = iter(replies), iter(tokens)
    clock = [0.0]
    s = DiscordSetup(tmp_path, lambda: gateway or FakeGateway(), ask=lambda q, d: next(it, d), secret=lambda q: next(tk), say=(said if said is not None else []).append,
                     discord=lambda token: client, sleep=lambda n: clock.__setitem__(0, clock[0] + n), now=lambda: clock[0], **kw)
    return s


def test_the_invite_link_names_the_bot_and_asks_for_what_the_bridge_does():
    url = invite_url("555")
    assert "client_id=555" in url and "scope=bot%20applications.commands" in url and f"permissions={PERMISSIONS}" in url
    for bit in (10, 11, 38, 29, 4, 28, 16, 15, 6):                       # view, send, threads, webhooks, channels, roles, history, files, reactions
        assert PERMISSIONS & (1 << bit)
    assert not PERMISSIONS & (1 << 3)                                     # never Administrator


def test_the_privileged_switches_are_read_from_the_applications_flags():
    assert missing_switches(0) == ["Message Content Intent", "Server Members Intent"]
    assert missing_switches(CONTENT) == ["Server Members Intent"] and missing_switches((1 << 19) | (1 << 15)) == []         # the LIMITED forms count


def test_a_bot_already_in_one_server_is_connected_without_asking_for_a_server_id(tmp_path):
    g = FakeGateway()
    out = setup(tmp_path, FakeDiscord("t", guilds=[[{"id": "999", "name": "My Server"}]]), g).run("shop Discord")
    assert out["guild_id"] == "999" and out["bridge_id"] == "7e1957d7-6572-4bec" and out["guild_name"] == "My Server"
    post = next(c for c in g.calls if c[0] == "POST")
    assert post[1] == "/collaborations" and post[2] == {"bridge_type": "discord", "display_name": "shop Discord",
                                                       "connection_config": {"bot_token": "tok-1", "guild_id": "999", "agent_roles": True}}
    f = tmp_path / "discord.env"
    assert f.read_text() == "DISCORD_BOT_TOKEN=tok-1\n" and oct(f.stat().st_mode & 0o777) == "0o600"


def test_it_prints_the_invite_and_waits_for_the_bot_to_join(tmp_path):
    said = []
    out = setup(tmp_path, FakeDiscord("t", guilds=[[], [], [{"id": "999", "name": "S"}]]), said=said).run("x")
    assert out["guild_id"] == "999" and any("discord.com/oauth2/authorize?client_id=555" in s for s in said)


def test_it_gives_up_politely_if_the_bot_never_joins(tmp_path):
    with pytest.raises(DiscordSetupError, match="did not join"):
        setup(tmp_path, FakeDiscord("t"), wait=10).run("x")


def test_a_switch_that_is_off_is_named_and_rechecked(tmp_path):
    said, c = [], FakeDiscord("t", flags=CONTENT, guilds=[[{"id": "9", "name": "S"}]])
    real = c.application
    calls = []

    def application():
        calls.append(1)
        if len(calls) >= 3:                                      # the person switched it on between the checks
            c.flags_now = CONTENT | MEMBERS
        return real()
    c.application = application
    setup(tmp_path, c, said=said).run("x")
    assert any("switch ON: Server Members Intent" in s for s in said)
    with pytest.raises(DiscordSetupError, match="still off"):
        setup(tmp_path, FakeDiscord("t", flags=0, guilds=[[{"id": "9", "name": "S"}]])).run("x")


def test_a_wrong_token_is_asked_again_three_times_then_refused(tmp_path):
    said = []
    with pytest.raises(DiscordSetupError, match="did not accept"):
        setup(tmp_path, FakeDiscord("t", bad=True), tokens=("a", "b", "c"), said=said).run("x")
    assert sum("Check the token" in s for s in said) == 2 and not (tmp_path / "discord.env").exists()


def test_an_existing_bridge_is_reused_and_a_refusal_is_reported(tmp_path):
    g = FakeGateway(existing=[{"bridge_type": "discord", "display_name": "shop Discord", "bridge_id": "already-there"}])
    out = setup(tmp_path, FakeDiscord("t", guilds=[[{"id": "9", "name": "S"}]]), g).run("shop Discord")
    assert out["bridge_id"] == "already-there" and not any(c[0] == "POST" for c in g.calls)
    with pytest.raises(DiscordSetupError, match="would not connect Discord"):
        setup(tmp_path, FakeDiscord("t", guilds=[[{"id": "9", "name": "S"}]]), FakeGateway(status=400)).run("x")


def test_several_servers_ask_which(tmp_path):
    said = []
    out = setup(tmp_path, FakeDiscord("t", guilds=[[{"id": "1", "name": "A"}, {"id": "2", "name": "B"}]]), replies=["2"], said=said).run("x")
    assert out["guild_id"] == "2" and "  1. A" in said and "  2. B" in said


def test_the_discord_reads_are_gets_that_return_the_application_and_the_servers(monkeypatch):
    import io
    import json
    import urllib.request
    from shipyard.discordapi import Discord
    seen = []

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout=0):
        seen.append((req.get_method(), req.full_url, req.headers.get("Authorization")))
        body = {"/applications/@me": {"id": 555, "name": "ShipYard", "flags": 1 << 18}, "/users/@me/guilds": [{"id": 9, "name": "S"}]}[req.full_url.split("/api/v10")[-1]]
        return Resp(json.dumps(body).encode())
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    d = Discord("tok")
    assert d.application() == {"id": "555", "name": "ShipYard", "flags": 1 << 18} and d.guilds() == [{"id": "9", "name": "S"}]
    assert {s[0] for s in seen} == {"GET"} and all(s[2] == "Bot tok" for s in seen)
