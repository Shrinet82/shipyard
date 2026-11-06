"""`shipyard init`: from a machine that already runs Switch to a working ops room.

It asks only what it cannot find out: it lists the rooms from Switch and the apps from Coolify, checks the GitHub App
before it writes anything, registers the Gatekeeper, optionally creates the Ops and Repo agents, installs a systemd user
service and finishes with `doctor`. Every secret goes into a file readable only by you; nothing secret is printed.
Run it again to repair or change things: it overwrites its own files and keeps the audit database.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

import yaml

from . import defaults
from .access import AccessError, Gateway, read_env
from .audit import AuditLog
from .config import load_config
from .members import MemberStore

REPO_DIR = Path(__file__).resolve().parent.parent
UNIT = """[Unit]
Description=Shipyard Gatekeeper
After=network-online.target

[Service]
WorkingDirectory={workdir}
ExecStart={python} -m shipyard run --config {config}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""


class InitError(Exception):
    """Something the person has to fix; the message says what."""


def _write_secret(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def _http(method: str, url: str, headers: dict[str, str] | None = None, body: Any = None, timeout: float = 20.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, method=method, headers={"Content-Type": "application/json", **(headers or {})},
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else None
            except ValueError:                                  # not JSON (the dashboard's page is HTML): the status is what matters
                return r.status, raw.decode(errors="replace")[:200]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:200]
    except (urllib.error.URLError, OSError) as exc:
        raise InitError(f"cannot reach {url.split('?')[0]}: {exc}") from None


class Installer:
    """All the effects go through injected pieces (`ask`, `say`, `gateway`, `http`, `run`), so the whole flow is testable."""

    def __init__(self, answers: dict[str, Any], home: Path, *, interactive: bool = True,
                 ask: Callable[[str, str], str] | None = None, secret: Callable[[str], str] | None = None,
                 say: Callable[[str], None] = print, gateway: Callable[[str, str, str], Any] = Gateway,
                 http: Callable[..., tuple[int, Any]] = _http, run: Callable[..., Any] | None = None,
                 github_check: Callable[[str, str, str], str] | None = None, python: str = sys.executable, workdir: Path = REPO_DIR,
                 app_creator: Callable[..., dict[str, Any]] | None = None, whoami_waiter: Callable[[str, int], Any] | None = None):
        self.a, self.home, self.interactive = answers, home, interactive
        self._ask, self._secret, self.say, self.gateway, self.http = ask or self._input, secret or getpass.getpass, say, gateway, http
        self.run = run or (lambda argv, **kw: subprocess.run(argv, capture_output=True, text=True, timeout=60, **kw))
        self.github_check, self.python, self.workdir = github_check or self._github_check, python, workdir
        self.app_creator = app_creator or self._create_app
        from .claim import wait_for_whoami
        self.whoami_waiter = whoami_waiter or wait_for_whoami
        self.t0 = time.time()
        self.created: dict[str, list[str]] = {"ops": [], "maintainers": [], "incidents": []}
        self.use_template, self.filled = False, {}
        self.to_create: dict[str, list[str]] = {"ops": [], "maintainers": [], "incidents": []}
        self.room_labels: dict[str, str] = {}
        self.paths = {"config": home / "shipyard.yaml", "gatekeeper": home / "gatekeeper.json", "mcp": home / "gatekeeper-mcp.token",
                      "coolify": home / "coolify.env", "unit": home / ".config/systemd/user/shipyard-gatekeeper.service"}

    # -- asking -------------------------------------------------------------------

    @staticmethod
    def _input(question: str, default: str = "") -> str:
        got = input(f"{question}" + (f" [{default}]" if default else "") + ": ").strip()
        return got or default

    def get(self, key: str, question: str, default: str = "", secret: bool = False, required: bool = False) -> str:
        """An answer from the answers file, else asked (interactive), else the default or an error."""
        cur: Any = self.a
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur not in (None, ""):
            return str(cur)
        if not question:
            return default
        if not self.interactive:
            if required:
                raise InitError(f"missing answer: {key}")
            return default
        return (self._secret(question + ": ") if secret else self._ask(question, default)).strip() or default

    # -- steps ---------------------------------------------------------------------

    def preflight(self) -> list[str]:
        problems = []
        if sys.version_info < (3, 10):
            problems.append("Python 3.10 or newer is needed")
        if shutil.which("openssl") is None:
            problems.append("openssl is needed (it signs the GitHub App token); install it with your package manager")
        if shutil.which("systemctl") is None:
            problems.append("systemctl was not found: the Gatekeeper is installed as a systemd user service")
        return problems

    def switch(self) -> tuple[Any, dict[str, str], str, str]:
        url = self.get("switch.url", "Switch URL", "http://localhost:8000").rstrip("/")
        env_file = self.get("switch.env_file", "Path to Switch's .env (it holds the admin login)", str(self.home / "switch/.env"))
        try:
            env = read_env(env_file)
            gw = self.gateway(url, env["GATEWAY_ADMIN_EMAIL"], env["GATEWAY_ADMIN_PASSWORD"])
        except FileNotFoundError:
            raise InitError(f"{env_file} does not exist: point at the .env of your Switch install") from None
        except KeyError as exc:
            raise InitError(f"{env_file} has no {exc.args[0]}") from None
        except AccessError as exc:
            raise InitError(str(exc)) from None
        self.say(f"  Switch answers at {url}")
        return gw, env, url, env_file

    def rooms(self, gw: Any, project: str) -> dict[str, list[str]]:
        """Existing rooms are chosen by id or name. Names that do not exist yet are created later (`self.to_create`), once the
        Gatekeeper is registered: Switch will not make a room without an agent in it."""
        status, rows = gw.call("GET", "/rooms")
        if status != 200 or not isinstance(rows, list):
            raise InitError(f"Switch would not list its rooms ({status})")
        label = lambda r: f"{r['name']} ({r.get('bridge_display_name') or 'room'})"  # noqa: E731
        chosen: dict[str, list[str]] = {"ops": [], "maintainers": [], "incidents": []}
        self.to_create: dict[str, list[str]] = {"ops": [], "maintainers": [], "incidents": []}
        create = str(self.a.get("rooms", {}).get("create", "")).lower() in ("true", "yes", "y")
        if "rooms" not in self.a and self.get("agents.create", "", "yes").lower() in ("yes", "y", "true") \
                and not any(r["name"].startswith(project + "-") for r in rows):
            filled, why = self.template_plan(gw)
            if why is None:
                if not self.interactive or self._ask(f"Create the {project} rooms, links and agents from the Shipyard Switch template? (yes/no)", "yes").lower() in ("yes", "y"):
                    self.use_template, self.filled = True, filled
                    self.room_labels = {}
                    return chosen
            else:
                self.say(f"  not using the Switch template: {why}")
        if not rows and self.interactive and "rooms" not in self.a:
            self.say("  Switch has no rooms yet.")
            if self._ask(f"Create {project}-ops and {project}-maintainers? (yes/no)", "yes").lower() in ("yes", "y"):
                self.to_create = {"ops": [f"{project}-ops"], "maintainers": [f"{project}-maintainers"]}
                self.room_labels = {}
                return chosen
        if not self.interactive and "rooms" not in self.a:         # the conventional names: use them if they exist, else make them
            for kind in ("ops", "maintainers", "incidents"):
                name = f"{project}-{kind}"
                hits = [r["id"] for r in rows if r["name"] == name]
                chosen[kind] += hits
                if not hits and kind != "incidents":                  # an incidents room is kept if there is one, never made here
                    self.to_create[kind].append(name)
            self.room_labels = {r["id"]: f"#{r['name']} ({r.get('bridge_display_name') or 'room'})" for r in rows}
            return chosen
        for kind, q in (("ops", "ops rooms (alerts, deploys)"), ("maintainers", "maintainers rooms (PRs, digest)")):
            want = self.a.get("rooms", {}).get(kind)
            if want is None and self.interactive:
                for i, r in enumerate(rows, 1):
                    self.say(f"    {i:2}. {label(r)}")
                picked = self._ask(f"Numbers of the {q}, comma separated, blank for none", "")
                want = [rows[int(n) - 1]["id"] for n in picked.replace(" ", "").split(",") if n.isdigit() and 0 < int(n) <= len(rows)]
            for item in want or []:
                hits = [r["id"] for r in rows if item in (r["id"], r["name"])]
                if not hits and create:
                    self.to_create[kind].append(item)
                elif not hits:
                    raise InitError(f"no room called {item!r} in Switch (add `rooms: {{create: true}}` to make it)")
                chosen[kind] += [h for h in hits if h not in chosen[kind]]
        if not any(chosen.values()) and not any(self.to_create.values()) and not self.use_template:
            raise InitError("pick at least one room")
        self.room_labels = {r["id"]: f"#{r['name']} ({r.get('bridge_display_name') or 'room'})" for r in rows}
        return chosen

    def coolify(self) -> tuple[str, str, dict[str, str]]:
        if self.a.get("coolify", {}).get("skip"):
            return "", "", {}
        url = self.get("coolify.url", "Coolify URL, e.g. http://10.0.0.5:8000 (blank to skip)", "").rstrip("/")
        if not url:
            return "", "", {}
        token = os.environ.get("COOLIFY_TOKEN") or str(self.a.get("coolify", {}).get("token") or "")
        tries = 3 if self.interactive and not token else 1
        for attempt in range(tries):
            if not token:
                if self.interactive:
                    self.say(f"  Create the token in Coolify: {url}/security/api-tokens → New token, tick read, read:sensitive, write and deploy.")
                token = self.get("coolify.token", "Coolify API token (input hidden)", secret=True, required=True)
            status, rows = self.http("GET", f"{url}/api/v1/applications", {"Authorization": f"Bearer {token}"})
            if status == 200 and isinstance(rows, list):
                break
            if attempt + 1 == tries:
                raise InitError(f"Coolify refused the token or the URL ({status}). Is the API enabled (Settings → API Access)?")
            self.say(f"  Coolify refused that token ({status}). Check the permissions and try again.")
            token = ""
        apps = {str(r["name"]).replace(" ", "-").lower(): str(r["uuid"]) for r in rows if r.get("uuid") and r.get("name")}
        want = self.a.get("coolify", {}).get("apps")
        if want is None and self.interactive and apps:
            self.say("  Coolify applications: " + ", ".join(apps))
            got = self._ask("Which ones may Shipyard manage (comma separated, blank for all)", "")
            want = [x.strip() for x in got.split(",") if x.strip()] or None
        if want:
            missing = [w for w in want if w not in apps]
            if missing:
                raise InitError(f"Coolify has no application called {', '.join(missing)} (it has: {', '.join(apps) or 'none'})")
            apps = {k: v for k, v in apps.items() if k in want}
        self.say(f"  Coolify answers; {len(apps)} application(s)")
        return url, token, apps

    @staticmethod
    def _github_check(app_id: str, key_file: str, repo: str) -> str:
        from .github import GitHubApp
        return GitHubApp(app_id, key_file).installation_for(repo)

    @staticmethod
    def _create_app(home: Path, repo: str, **kw: Any) -> dict[str, Any]:
        from .ghapp import create_app
        return create_app(home, repo, **kw)

    PROJECT = re.compile(r"^[a-z][a-z0-9-]{1,30}$")

    @staticmethod
    def clean_project_name(typed: str) -> str:
        """What Switch accepts: lowercase letters, digits and dashes, starting with a letter. Whatever was typed is turned into that."""
        return re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9]+", "-", typed.strip().lower())).strip("-")[:31].rstrip("-")

    def project_name(self) -> str:
        for attempt in range(3):
            typed = self.get("project", "Project name", "demo")
            name = self.clean_project_name(typed)
            if self.PROJECT.match(name):
                if name != typed:
                    self.say(f"  using the project name {name!r} (Switch allows lowercase letters, digits and dashes)")
                return name
            if not self.interactive or attempt == 2 or self.a.get("project"):
                raise InitError(f"{typed!r} cannot be made into a project name: use 2 to 31 letters or digits, starting with a letter (for example `shop-test`)")
            self.say(f"  {typed!r} will not do: it must start with a letter and have at least 2 characters.")
        raise InitError("no valid project name")

    def _earlier_github_app(self, repo: str) -> dict[str, Any]:
        """An App this tool created on an earlier run (the installer stopped after the clicks): offer it instead of making another."""
        f = self.home / "shipyard-github-app.json"
        if not f.exists():
            return {}
        try:
            saved = json.loads(f.read_text())
            inst = self.github_check(saved["app_id"], saved["key_file"], repo)
        except Exception:                                        # not installed on this repository, or unreadable: make a new one
            return {}
        if self.get("github.reuse", f"Found the GitHub App you created earlier ({saved.get('slug')}), installed on {repo}. Use it? (yes/no)", "yes").lower() not in ("yes", "y"):
            return {}
        return {**saved, "installation": inst, "repo": repo}

    def create_github_app(self) -> dict[str, Any]:
        """Offer the two-click manifest flow (see ghapp.py). Returns {} when the person skips it or this run cannot ask."""
        if not self.interactive or self.a.get("github", {}).get("create") == "no":
            return {}
        if self.get("github.create", "No GitHub App yet. Create it now with two clicks (no form to fill, no key to copy)? (yes/no)", "yes").lower() not in ("yes", "y"):
            return {}
        repo = self.get("github.repo", "Repository the App should work on, owner/name", required=True)
        if (earlier := self._earlier_github_app(repo)):
            return earlier
        org = self.get("github.org", "GitHub organisation that owns the App (blank for your own account)", "")
        try:
            host = self.get("github.public_host", "Address your browser uses to reach this machine, for the setup page (blank: localhost, through an SSH tunnel)", "")
            return self.app_creator(self.home, repo, org=org, port=int(self.get("github.port", "Local port for the setup page", "8767")), say=self.say, public_host=host)
        except Exception as exc:
            raise InitError(f"creating the GitHub App failed: {exc}") from None

    def github(self, apps: dict[str, str]) -> dict[str, Any] | None:
        app_id = self.get("github.app_id", "GitHub App id (the number on github.com/settings/apps/<your app>; blank to create one now, or skip repo features)", "")
        created: dict[str, Any] = {}
        if not app_id:
            created = self.create_github_app()
            if not created:
                return None
            app_id = created["app_id"]
        key = os.path.expanduser(created["key_file"] if created else self.get("github.private_key_file", "Path to the GitHub App's private key (.pem)", str(self.home / "shipyard-github.pem")))
        repo = created["repo"] if created else self.get("github.repo", "Repository, owner/name", required=True)
        if not os.path.exists(key):
            raise InitError(f"{key} does not exist")
        if oct(os.stat(key).st_mode & 0o077) != "0o0":
            os.chmod(key, 0o600)
            self.say("  tightened the key file to 0600")
        try:
            inst = created["installation"] if created else self.github_check(app_id, key, repo)
        except Exception as exc:
            raise InitError(f"the GitHub App cannot see {repo}: {exc}. Install the App on that repository first") from None
        deploy = self.get("github.deploy_app", "App to deploy after a merge (blank for none)", next(iter(apps), "") if len(apps) == 1 else "")
        if deploy and deploy not in apps:
            raise InitError(f"github.deploy_app {deploy!r} is not one of the Coolify apps")
        if not created:                                                        # remembered, so a re-run finds this App by itself
            try:
                _write_secret(self.home / "shipyard-github-app.json", json.dumps({"app_id": app_id, "slug": "", "key_file": key}))
            except OSError:
                pass
        self.say(f"  GitHub App installation {inst} on {repo}")
        return {"app_id": app_id, "key": key, "repo": repo, "deploy": deploy or None, "installation": inst}

    # -- the files -------------------------------------------------------------------

    def build_config(self, project: str, switch_url: str, env_file: str, rooms: dict[str, list[str]], coolify: tuple[str, str, dict[str, str]],
                     gh: dict[str, Any] | None, dashboard: bool) -> dict[str, Any]:
        cfg: dict[str, Any] = {
            "switch": {"url": switch_url, "credentials_file": str(self.paths["gatekeeper"]), "gateway_env_file": env_file,
                       "managed_agents": ["ops-agent", "repo-agent"], "allow_agents": ["gatekeeper"]},
            "coolify": {"url": coolify[0], "token_file": str(self.paths["coolify"])},
            "gatekeeper": {"mcp_port": 8765, "mcp_token_file": str(self.paths["mcp"]), "db_path": str(self.home / "shipyard.db")},
            "projects": {project: {
                "rooms": {"ops": rooms["ops"], "maintainers": rooms["maintainers"], **({"incidents": rooms["incidents"]} if rooms.get("incidents") else {})},
                "room_names": {k: v for k, v in self.room_labels.items() if k in sum(rooms.values(), [])},
                "apps": coolify[2], "members": {}}},
            "actions": dict(defaults.ACTIONS), "min_role": dict(defaults.MIN_ROLE), "approval_overrides": dict(defaults.APPROVAL_OVERRIDES),
            "approval_timeout_seconds": 600,
            "alerts": {"port": 8766, "evidence_lines": 40, "agent": "ops-agent"},
            "digest": {"hour": 9, "minute": 0, "timezone": self.get("digest.timezone", "", "Asia/Kolkata")},
            "sbom": {"workflow": ".github/workflows/ci.yml", "data_dir": str(self.home / "shipyard-sbom"), "poll_seconds": 90},
        }
        if dashboard:
            cfg["dashboard"] = {"port": 8780, "session_hours": 8, "members_file": str(self.home / "shipyard-members.json")}
        if gh:
            cfg["github"] = {"app_id": gh["app_id"], "installation_id": gh["installation"], "private_key_file": gh["key"], "poll_seconds": 60}
            cfg["projects"][project]["repo"] = {"name": gh["repo"], "required_checks": ["test", "sbom"], "merge_method": "squash", "branch": "main",
                                                **({"app": gh["deploy"]} if gh["deploy"] else {})}
        return cfg

    def register(self, gw: Any, env: dict[str, str], url: str) -> str:
        """Create (or replace) the Gatekeeper agent in Switch and open its addressing: it authorizes people itself."""
        status, reg = self.http("POST", f"{url}/agents", {"Authorization": f"Bearer {env.get('AGENT_REGISTRATION_TOKEN', '')}"}, {
            "name": "gatekeeper", "description": "Shipyard Gatekeeper: roles, approvals and audit for chat-driven ops",
            "connector_type": "custom", "overwrite": True,
            "integration_profile": {"connection_model": "always_on", "message_exchange": True,
                                    "pre_invocation_mediation": [], "post_invocation_mediation": [], "event_reporting": []}})
        if status not in (200, 201) or not isinstance(reg, dict):
            raise InitError(f"Switch would not register the Gatekeeper ({status}); is AGENT_REGISTRATION_TOKEN set in its .env?")
        _write_secret(self.paths["gatekeeper"], json.dumps({"id": reg["id"], "api_key": reg["api_key"], "name": "gatekeeper"}))
        if not self.paths["mcp"].exists():
            _write_secret(self.paths["mcp"], secrets.token_hex(24))
        gw.call("PUT", f"/agents/{reg['id']}/addressing-policy", {"policy": None})
        self.say("  registered the Gatekeeper in Switch")
        return str(reg["id"])

    # -- rooms and agents: through Switch's own template, or plain rooms when it cannot be used ------------------------

    def template_plan(self, gw: Any) -> tuple[dict[str, str], str | None]:
        """(slots filled by agents Switch already has, why the template cannot run or None). A slot with no agent needs a machine."""
        status, rows = gw.call("GET", "/agents")
        have = {a["name"] for a in (rows if isinstance(rows, list) else (rows or {}).get("agents", []))} if status == 200 else set()
        filled = {slot: name for slot, name in (("ops_agent", "ops-agent"), ("repo_agent", "repo-agent")) if name in have}
        if len(filled) < 2:
            status, ctrls = gw.call("GET", "/management/controllers")
            machines = (ctrls if isinstance(ctrls, list) else (ctrls or {}).get("controllers", [])) if status == 200 else []
            if not machines:
                return filled, "Switch has no agent controller on a machine, so the Ops and Repo agents cannot be created"
        return filled, None

    def run_template(self, gw: Any, project: str, filled: dict[str, str]) -> None:
        text = (self.workdir / "templates/shipyard.template.yaml").read_text()
        inputs: dict[str, Any] = {"project": project}
        machine = self.get("agents.machine", "", "")
        if machine:
            inputs["machine"] = machine
        status, r = gw.call("POST", "/rooms/from-template-document", {"template": text, "inputs": inputs, "filled": filled, "template_name": "shipyard"})
        if status not in (200, 201) or not isinstance(r, dict):
            problems = ""
            if isinstance(r, str) and "problems" in r:
                try:
                    problems = "; ".join(f"{p.get('slot')}: {p.get('message')}" for p in json.loads(r).get("problems", []))
                except ValueError:
                    problems = r[:200]
            raise InitError(f"Switch would not run the Shipyard template ({status}): {problems or str(r)[:200]}. "
                            "For agents it needs an online machine with Codex installed and signed in (`codex login`).")
        for room in (r.get("room") or {}).get("rooms", []):
            kind = next((k for k, suf in (("incidents", "-incidents"), ("maintainers", "-maintainers"), ("ops", "-ops")) if room["room_name"].endswith(suf)), None)
            if kind:
                self.created[kind].append(room["room_id"])
                self.room_labels[room["room_id"]] = f"#{room['room_name']}"
        made = ", ".join(sorted(self.room_labels.values()))
        self.say(f"  Switch template ran: group '{project}' with {made}; agents: " + (", ".join(f"{n} (existing)" for n in filled.values()) or "created") + "; rooms linked")

    def make_rooms(self, gw: Any, project: str, gk_id: str, existing: list[str]) -> None:
        if self.use_template:
            self.run_template(gw, project, self.filled)
        else:
            for kind, names in self.to_create.items():
                for name in names:
                    status, room = gw.call("POST", "/rooms", {"name": name, "description": f"Shipyard {kind} room", "agent_names": ["gatekeeper"]})
                    if status not in (200, 201) or not isinstance(room, dict) or "id" not in room:
                        raise InitError(f"Switch would not create the room {name!r} ({status}): {str(room)[:120]}")
                    self.created[kind].append(room["id"])
                    self.room_labels[room["id"]] = f"#{name}"
                    self.say(f"  created room #{name}")
        for room in existing:
            status, _ = gw.call("POST", f"/rooms/{room}/agents", {"agent_ids": [gk_id]})
            if status not in (200, 201, 204, 409):
                self.say(f"  warning: could not add the Gatekeeper to room {room} ({status})")

    def _agent_user(self) -> str | None:
        """The isolated Linux user the agents run as (`scripts/isolate_agents.sh` makes `agentrun`), if there is one other than whoever runs this."""
        import getpass
        import pwd
        name = str(self.a.get("agents", {}).get("user", "agentrun"))
        try:
            pwd.getpwnam(name)
        except KeyError:
            return None
        return None if name == getpass.getuser() else name

    def write_codex_config(self) -> None:
        """The agents' only tools: the Gatekeeper's request tool. No Coolify, GitHub or Switch credential."""
        token = self.paths["mcp"].read_text().strip()
        explicit = self.a.get("agents", {}).get("codex_config")
        text = ('# Written by `shipyard init`. The agents hold only the Gatekeeper\'s request tool: no Coolify, GitHub or Switch credential.\n'
                '[mcp_servers.gatekeeper]\nurl = "http://127.0.0.1:8765/mcp"\n'
                f'http_headers = {{ Authorization = "Bearer {token}" }}\n\n'
                '# Codex account connectors (GitHub, Figma, ...) belong to whoever signed in to Codex; the agents must not inherit them.\n'
                '[features]\napps = false\n')
        user = None if explicit else self._agent_user()
        if user:                                   # the agents run as another user: Codex reads that user's home, which only that user may write
            import pwd
            import subprocess
            path = f"{pwd.getpwnam(user).pw_dir}/.codex/config.toml"
            r = subprocess.run(["sudo", "-n", "-u", user, "-H", "sh", "-c", "umask 077; mkdir -p \"$HOME/.codex\" && cat > \"$HOME/.codex/config.toml\""],
                               input=text, text=True, capture_output=True)
            if r.returncode != 0:
                raise InitError(f"could not write the agents' tool config as {user}: {r.stderr.strip()[:200]}")
        else:
            path = Path(self.get("agents.codex_config", "", str(self.home / ".codex/config.toml")))
            _write_secret(path, text)
        self.say(f"  wrote the agents' tool config ({path})")

    def service(self) -> None:
        unit = self.paths["unit"]
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(UNIT.format(workdir=self.workdir, python=self.python, config=self.paths["config"]))
        for argv in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "shipyard-gatekeeper"]):
            r = self.run(argv)
            if getattr(r, "returncode", 0) != 0:
                raise InitError(f"`{' '.join(argv)}` failed: {(getattr(r, 'stderr', '') or '').strip()[:200]}")
        self.run(["systemctl", "--user", "restart", "shipyard-gatekeeper"])
        self.run(["loginctl", "enable-linger", os.environ.get("USER", "")])               # keeps it running after you log out
        self.say("  installed and started the systemd user service")

    # -- the whole thing ---------------------------------------------------------------------

    def install(self, dry_run: bool = False) -> dict[str, Any]:
        for p in self.preflight():
            raise InitError(p)
        self.say("1/5 Switch")
        gw, env, url, env_file = self.switch()
        project = self.project_name()
        rooms = self.rooms(gw, project)
        self.say("2/5 Coolify")
        cool = self.coolify()
        self.say("3/5 GitHub")
        gh = self.github(cool[2])
        if dry_run:
            planned = {k: rooms[k] + [f"<new: {n}>" for n in self.to_create[k]] for k in rooms}
            if self.use_template:
                planned = {"ops": [f"<new: {project}-ops>"], "maintainers": [f"<new: {project}-maintainers>"], "incidents": [f"<new: {project}-incidents>"]}
                self.say(f"  would run the Shipyard Switch template (agents already in Switch: {', '.join(self.filled.values()) or 'none, they would be created'})")
            cfg = self.build_config(project, url, env_file, planned, cool, gh, bool(self.a.get("dashboard", True)))
            self.say("dry run: nothing written")
            return cfg
        self.say("4/5 Writing files and registering")
        self.home.mkdir(parents=True, exist_ok=True)
        if cool[1]:
            _write_secret(self.paths["coolify"], f"COOLIFY_TOKEN={cool[1]}\n")
        gk_id = self.register(gw, env, url)
        self.make_rooms(gw, project, gk_id, rooms["ops"] + rooms["maintainers"] + rooms["incidents"])
        rooms = {k: rooms[k] + self.created[k] for k in rooms}
        cfg = self.build_config(project, url, env_file, rooms, cool, gh, bool(self.a.get("dashboard", True)))
        owner = self.get("owner", "", "")
        if owner:
            cfg["projects"][project]["members"][owner] = "owner"
        self.paths["config"].write_text(yaml.safe_dump(cfg, sort_keys=False))
        os.chmod(self.paths["config"], 0o600)
        load_config(self.paths["config"])                                                  # refuse to go on with a config we cannot read
        if self.get("agents.create", "Use the Ops and Repo agents (give them the Gatekeeper's tool)? (yes/no)", "yes").lower() in ("yes", "y", "true"):
            self.write_codex_config()
        self.say("5/5 Starting")
        self.service()
        cfg["_project"] = project
        if not owner and self.interactive:
            self.claim_owner(project)
        return cfg

    def claim_owner(self, project: str) -> None:
        """No owner yet: wait for the person to type `@gatekeeper whoami`, confirm it is them, make them the owner."""
        from .claim import last_whoami_id, pretty, wait_for_whoami
        db_path = str(self.home / "shipyard.db")
        start = last_whoami_id(db_path)
        self.say("  Last step: make yourself the owner. In any Shipyard room (Mattermost or Discord) type:  @gatekeeper whoami")
        self.say("  I am waiting for it (Ctrl-C to skip; `python3 -m shipyard add-owner` does the same later).")
        try:
            seen = self.whoami_waiter(db_path, start)
        except KeyboardInterrupt:
            self.say("  skipped")
            return
        if seen is None:
            self.say("  Nothing arrived in 10 minutes. Run `python3 -m shipyard add-owner` and type `@gatekeeper whoami`.")
            return
        _, identity = seen
        if self._ask(f"  Saw `whoami` from {pretty(identity)}. Make them the owner of {project}? (yes/no)", "yes").lower() not in ("yes", "y"):
            self.say("  not added")
            return
        from .members import MemberStore
        cfg = load_config(self.paths["config"])
        MemberStore(self.home / "shipyard-members.json", cfg.policy, None).add_owner(project, identity)
        self.run(["systemctl", "--user", "restart", "shipyard-gatekeeper"])
        self.say(f"  {pretty(identity)} is now the owner. Try `@gatekeeper status` in the room.")


def doctor(config_path: Path, say: Callable[[str], None] = print, http: Callable[..., tuple[int, Any]] = _http,
           gateway: Callable[..., Any] = Gateway, run: Callable[..., Any] | None = None, wait: float = 20.0) -> bool:
    """Every check says what it looked at. Returns False if any failed."""
    run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=15))
    ok = True

    def line(good: bool, text: str) -> None:
        nonlocal ok
        ok = ok and good
        say(("  ok   " if good else "  FAIL ") + text)
    try:
        cfg = load_config(config_path)
    except Exception as exc:                                  # noqa: BLE001 - any damage to the file is the finding
        line(False, f"{config_path} cannot be read: {exc}")
        return False
    line(True, f"config {config_path} reads ({len(cfg.projects)} project)")
    try:
        MemberStore(os.path.expanduser(cfg.dashboard.members_file), cfg.policy, None).load()    # roles edited on the dashboard
    except SystemExit as exc:
        line(False, str(exc))
    for name, p in cfg.projects.items():
        line(bool(p.rooms), f"project {name}: {len(p.ops_rooms)} ops room(s), {len(p.maintainer_rooms)} maintainers room(s), {len(cfg.policy.members.get(name, {}))} member(s)")
        if not cfg.policy.members.get(name):
            say("       no owner yet: run `python3 -m shipyard add-owner`, then type `@gatekeeper whoami` in a room (or pass --identity <the id it prints>)")
    try:
        env = read_env(cfg.gateway_env_file)
        gateway(cfg.switch_url, env["GATEWAY_ADMIN_EMAIL"], env["GATEWAY_ADMIN_PASSWORD"])
        line(True, f"Switch admin login works at {cfg.switch_url}")
    except Exception as exc:                                  # noqa: BLE001
        line(False, f"Switch: {exc}")
    if cfg.coolify_url:
        try:
            token = read_env(cfg.coolify_token_file)["COOLIFY_TOKEN"]
            status, _ = http("GET", f"{cfg.coolify_url}/api/v1/applications", {"Authorization": f"Bearer {token}"})
            line(status == 200, f"Coolify answers {status}")
        except Exception as exc:                              # noqa: BLE001
            line(False, f"Coolify: {exc}")
    db_file = os.path.expanduser(cfg.db_path)
    if os.path.exists(db_file):
        import sqlite3
        db = sqlite3.connect(db_file)
        try:
            rows, head = AuditLog(db).head()
            line(AuditLog(db).verify(), f"audit chain verifies ({rows} rows, head {head[:12]})")
        except sqlite3.Error as exc:
            line(False, f"audit log: {exc}")
        finally:
            db.close()
    r = run(["systemctl", "--user", "is-active", "shipyard-gatekeeper"])
    line(getattr(r, "stdout", "").strip() == "active", "systemd service shipyard-gatekeeper is active")
    if cfg.dashboard.bind:
        deadline = time.time() + wait
        status = 0
        while True:                                           # the service needs a few seconds to come up
            try:
                status, _ = http("GET", f"http://127.0.0.1:{cfg.dashboard.port}/", timeout=3)
            except InitError:
                status = 0
            if status == 200 or time.time() >= deadline:
                break
            time.sleep(1)
        line(status == 200, f"dashboard answers on 127.0.0.1:{cfg.dashboard.port} (reach it with an SSH tunnel)")
    return ok
