from pathlib import Path
from types import SimpleNamespace

import pytest
from test_claim import FakeGw, answers, home, http_fake  # noqa: F401

from shipyard.init import Installer
from shipyard.mmuser import MattermostError, clean_username, create_user

ENV = {"MATTERMOST_ADMIN_USER": "admin", "MATTERMOST_ADMIN_PASSWORD": "adminpw", "MATTERMOST_TEAM_NAME": "switch", "MATTERMOST_HOST_PORT": "8065"}


class FakeMm:
    def __init__(self, login=200, team=200, taken=False, rooms=("shop-ops", "shop-maintainers"), create=201):
        self.calls, self.login, self.team, self.taken, self.rooms, self.create = [], login, team, taken, set(rooms), create

    def __call__(self, method, url, token="", body=None):
        path = url.split("/api/v4")[-1]
        self.calls.append((method, path, token, body))
        if path == "/users/login":
            return self.login, {}, ({"Token": "admin-tok"} if self.login == 200 else {})
        if path == "/teams/name/switch":
            return self.team, {"id": "team1", "name": "switch"}, {}
        if path.startswith("/users/username/"):
            return (200, {"id": "x"}, {}) if self.taken else (404, {}, {})
        if (method, path) == ("POST", "/users"):
            return self.create, {"id": "u1"}, {}
        if "/channels/name/" in path:
            name = path.rsplit("/", 1)[-1]
            return (200, {"id": "c-" + name}, {}) if name in self.rooms else (404, {}, {})
        return 201, {}, {}


def test_a_login_is_made_in_the_team_and_the_projects_rooms_with_a_password_returned_once():
    m = FakeMm()
    out = create_user(ENV, "shop", "Anya", http=m, make_password=lambda: "pw-1")
    assert out == {"username": "anya", "password": "pw-1", "rooms": ["shop-ops", "shop-maintainers"], "team": "switch"}
    made = next(c for c in m.calls if c[:2] == ("POST", "/users"))
    assert made[3] == {"email": "anya@shipyard.local", "username": "anya", "password": "pw-1"} and made[2] == "admin-tok"
    joined = [c[1] for c in m.calls if c[0] == "POST" and c[1].endswith("/members")]
    assert joined == ["/teams/team1/members", "/channels/c-shop-ops/members", "/channels/c-shop-maintainers/members"]      # no incidents room here: skipped


@pytest.mark.parametrize("fake,message", [(FakeMm(login=401), "admin login"), (FakeMm(team=404), "no team"), (FakeMm(taken=True), "already exists"), (FakeMm(create=400), "would not create")])
def test_failures_say_what_is_wrong_and_create_nothing_more(fake, message):
    with pytest.raises(MattermostError, match=message):
        create_user(ENV, "shop", "anya", http=fake)
    assert not any(c[1].endswith("/members") for c in fake.calls)


def test_usernames_are_cleaned_and_checked():
    assert clean_username("  Anya Singh!") == "anyasingh"
    for bad in ("ab", "9lives", "!!!"):
        with pytest.raises(MattermostError):
            create_user(ENV, "shop", bad, http=FakeMm())


def test_the_installer_offers_a_login_and_shows_the_password_once(home):
    said = []
    inst = Installer(answers(home, owner=""), home, interactive=True, ask=lambda q, d: "ravi" if q.startswith("  Choose a username") else d, secret=lambda q: "x", say=said.append,
                     gateway=FakeGw, http=http_fake(), whoami_waiter=lambda *a: None,
                     login_maker=lambda project, name: {"username": name, "password": "secret-pw", "rooms": [f"{project}-ops"], "team": "switch"},
                     run=lambda *x, **k: SimpleNamespace(returncode=0, stdout="active", stderr=""), github_check=lambda *a: "i", workdir=Path(__file__).parent.parent)
    inst.install()
    text = "\n".join(said)
    assert "username ravi, password secret-pw" in text and "demo-ops" in text
    assert text.index("Mattermost login created") < text.index("Last step: make yourself the owner")
