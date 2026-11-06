"""A Mattermost login for the person installing, so they can type `@gatekeeper whoami` without hunting for an account.

Switch's bundled Mattermost starts with only an admin account that Switch uses. This makes an ordinary user, puts them in the project's rooms,
and returns the password once. It talks to Mattermost on this machine with the admin login from Switch's .env.
"""
from __future__ import annotations

import json
import re
import secrets
import urllib.error
import urllib.request
from typing import Any, Callable

USERNAME = re.compile(r"^[a-z][a-z0-9._-]{2,21}$")


class MattermostError(Exception):
    pass


def _http(method: str, url: str, token: str = "", body: Any = None) -> tuple[int, Any, dict[str, str]]:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None, dict(r.headers)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}"), {}
        except ValueError:
            return exc.code, {}, {}
    except (urllib.error.URLError, OSError) as exc:
        raise MattermostError(f"cannot reach Mattermost at {url.split('/api')[0]}: {exc}") from None


def clean_username(typed: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "", typed.strip().lower())[:22]


def create_user(env: dict[str, str], project: str, username: str, *, base: str = "", http: Callable[..., tuple[int, Any, dict[str, str]]] = _http,
                make_password: Callable[[], str] | None = None) -> dict[str, Any]:
    """Make the user, add them to the team and to the project's rooms. Returns {username, password, rooms}."""
    username = clean_username(username)
    if not USERNAME.match(username):
        raise MattermostError("a username is 3 to 22 letters, digits, dots, dashes or underscores, starting with a letter")
    base = (base or f"http://localhost:{env.get('MATTERMOST_HOST_PORT', '8065')}").rstrip("/") + "/api/v4"
    status, _, headers = http("POST", base + "/users/login", "", {"login_id": env.get("MATTERMOST_ADMIN_USER", ""), "password": env.get("MATTERMOST_ADMIN_PASSWORD", "")})
    token = headers.get("Token", "")
    if status != 200 or not token:
        raise MattermostError("Mattermost would not accept Switch's admin login (is Switch's .env the one for this Mattermost?)")
    status, team, _ = http("GET", f"{base}/teams/name/{env.get('MATTERMOST_TEAM_NAME', '')}", token)
    if status != 200 or not isinstance(team, dict):
        raise MattermostError("Mattermost has no team with the name in Switch's .env")
    status, existing, _ = http("GET", f"{base}/users/username/{username}", token)
    if status == 200:
        raise MattermostError(f"{username} already exists in Mattermost; pick another name, or log in with the password you were given")
    password = (make_password or (lambda: secrets.token_urlsafe(18)))()
    status, user, _ = http("POST", base + "/users", token, {"email": f"{username}@shipyard.local", "username": username, "password": password})
    if status not in (200, 201) or not isinstance(user, dict):
        raise MattermostError(f"Mattermost would not create the user ({status})")
    http("POST", f"{base}/teams/{team['id']}/members", token, {"team_id": team["id"], "user_id": user["id"]})
    rooms = []
    for kind in ("ops", "maintainers", "incidents"):
        name = f"{project}-{kind}"
        status, channel, _ = http("GET", f"{base}/teams/{team['id']}/channels/name/{name}", token)
        if status == 200 and isinstance(channel, dict):
            http("POST", f"{base}/channels/{channel['id']}/members", token, {"user_id": user["id"]})
            rooms.append(name)
    return {"username": username, "password": password, "rooms": rooms, "team": team.get("name", "")}
