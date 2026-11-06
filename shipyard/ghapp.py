"""Create Shipyard's GitHub App with GitHub's manifest flow, so nobody fills in the App form or copies a key by hand.

  1. Shipyard serves a tiny local page. Opening it posts the App's definition (name, permissions, events) to GitHub.
  2. GitHub shows the form already filled in. One click on "Create GitHub App" sends the browser back to
     http://localhost:<port>/callback with a one-time code.
  3. Shipyard trades the code for the App id, the private key and the webhook secret and saves them (mode 0600).
  4. The person installs the App on the repository (second click); Shipyard waits until the App can see it.

The page listens on 127.0.0.1 only. On a remote machine, forward the port: ssh -L <port>:localhost:<port> <machine>.
"""
from __future__ import annotations

import hmac
import html
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

API = "https://api.github.com"
ORG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
CODE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

# the same permissions README lists: read CI and issues, write contents and pull requests (merge)
PERMISSIONS = {"contents": "write", "pull_requests": "write", "actions": "read", "checks": "read", "statuses": "read", "issues": "read"}
EVENTS = ["pull_request", "pull_request_review", "check_run", "check_suite", "workflow_run", "status"]


class AppSetupError(Exception):
    pass


def build_manifest(name: str, redirect_url: str, webhook_url: str = "") -> dict[str, Any]:
    """The App's definition. Webhooks stay off unless a public URL is given: Shipyard polls GitHub when it hears nothing."""
    return {
        "name": name,
        "url": "https://github.com/Shrinet82/shipyard",
        "description": "Shipyard: a chat-native ops room. Reads pull requests and CI, merges after a person approves.",
        "redirect_url": redirect_url,
        "public": False,
        "hook_attributes": {"url": webhook_url or "https://example.com/shipyard-webhook-off", "active": bool(webhook_url)},
        "default_permissions": dict(PERMISSIONS),
        "default_events": list(EVENTS),
    }


def _http(method: str, url: str, headers: dict[str, str] | None = None, body: Any = None, timeout: float = 20.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, method=method, data=json.dumps(body if body is not None else {}).encode() if method == "POST" else None,
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "shipyard", "X-GitHub-Api-Version": "2022-11-28",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, OSError) as exc:
        raise AppSetupError(f"cannot reach GitHub: {exc}") from None


def _write_secret(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


class AppSetup:
    def __init__(self, home: Path, *, org: str = "", port: int = 8767, webhook_url: str = "",
                 http: Callable[..., tuple[int, Any]] = _http, say: Callable[[str], None] = print, name: str = ""):
        if org and not ORG.match(org):
            raise AppSetupError(f"{org!r} is not a GitHub organisation name")
        self.home, self.org, self.port, self.webhook_url, self.http, self.say = home, org, port, webhook_url, http, say
        self.name = name or f"Shipyard-{secrets.token_hex(2)}"
        self.state = secrets.token_urlsafe(24)
        self.result: dict[str, Any] | None = None
        self.error = ""
        self.lock = threading.Lock()

    # -- addresses --------------------------------------------------------------------------

    @property
    def start_url(self) -> str:
        return f"http://localhost:{self.port}/"

    @property
    def redirect_url(self) -> str:
        return f"http://localhost:{self.port}/callback"

    @property
    def key_file(self) -> Path:
        return self.home / "shipyard-github.pem"

    @property
    def webhook_secret_file(self) -> Path:
        return self.home / "shipyard-github-webhook.secret"

    # -- the pages --------------------------------------------------------------------------

    def start_page(self) -> str:
        target = (f"https://github.com/organizations/{self.org}/settings/apps/new" if self.org else "https://github.com/settings/apps/new")
        manifest = html.escape(json.dumps(build_manifest(self.name, self.redirect_url, self.webhook_url)), quote=True)
        return ("<!doctype html><meta charset=utf-8><title>Shipyard: create the GitHub App</title>"
                "<body style='font:16px system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem'>"
                "<h1>Create the Shipyard GitHub App</h1><p>GitHub will show the App already filled in. Press <b>Create GitHub App</b> there.</p>"
                f"<form id=f method=post action='{html.escape(target, quote=True)}?state={urllib.parse.quote(self.state)}'>"
                f"<input type=hidden name=manifest value='{manifest}'><button>Continue to GitHub</button></form>"
                "<script>document.getElementById('f').submit()</script></body>")

    def _done_page(self, slug: str) -> str:
        install = f"https://github.com/apps/{urllib.parse.quote(slug)}/installations/new"
        return ("<!doctype html><meta charset=utf-8><title>Shipyard: install the App</title>"
                "<body style='font:16px system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem'>"
                "<h1>The App exists</h1><p>The keys are saved on the machine. Last click: install it on your repository.</p>"
                f"<p><a href='{html.escape(install, quote=True)}'>Install the App</a></p></body>")

    def _fail_page(self, text: str) -> str:
        return ("<!doctype html><meta charset=utf-8><title>Shipyard</title><body style='font:16px system-ui;max-width:34rem;margin:4rem auto'>"
                f"<h1>That did not work</h1><p>{html.escape(text)}</p></body>")

    # -- the exchange -----------------------------------------------------------------------

    def exchange(self, code: str) -> dict[str, Any]:
        if not CODE.match(code or ""):
            raise AppSetupError("GitHub sent an unexpected code")
        status, data = self.http("POST", f"{API}/app-manifests/{code}/conversions", None, None)
        if status >= 400 or not isinstance(data, dict):
            raise AppSetupError(f"GitHub refused the code ({status}); it is valid for one hour and works once")
        app_id, pem, slug = data.get("id"), data.get("pem"), data.get("slug")
        if not app_id or not isinstance(pem, str) or "PRIVATE KEY" not in pem or not slug:
            raise AppSetupError("GitHub's answer did not contain the App id and key")
        _write_secret(self.key_file, pem if pem.endswith("\n") else pem + "\n")
        if isinstance(data.get("webhook_secret"), str) and data["webhook_secret"]:
            _write_secret(self.webhook_secret_file, data["webhook_secret"])
        return {"app_id": str(app_id), "slug": str(slug), "key_file": str(self.key_file), "html_url": data.get("html_url", "")}

    def handle(self, path: str) -> tuple[int, str]:
        """(status, html) for a GET. All the logic is here so it can be tested without a socket."""
        parsed = urllib.parse.urlparse(path)
        if parsed.path == "/":
            return 200, self.start_page()
        if parsed.path != "/callback":
            return 404, self._fail_page("not found")
        q = urllib.parse.parse_qs(parsed.query)
        if not hmac.compare_digest((q.get("state") or [""])[0], self.state):
            return 400, self._fail_page("The state did not match: open the page Shipyard printed again.")
        with self.lock:
            if self.result is not None:
                return 409, self._fail_page("This code was already used.")
            try:
                self.result = self.exchange((q.get("code") or [""])[0])
            except AppSetupError as exc:
                self.error = str(exc)
                return 502, self._fail_page(str(exc))
            return 200, self._done_page(self.result["slug"])

    # -- running it -------------------------------------------------------------------------

    def serve(self, timeout: float = 900.0, poll: float = 0.3) -> dict[str, Any]:
        setup = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                status, page = setup.handle(self.path)
                body = page.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(body)

        try:
            server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        except OSError as exc:
            raise AppSetupError(f"port {self.port} is busy ({exc}); pick another with --port") from None
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            end = time.time() + timeout
            while time.time() < end:
                if self.result is not None:
                    return self.result
                time.sleep(poll)
            raise AppSetupError(self.error or "timed out waiting for the click on GitHub")
        finally:
            server.shutdown()
            server.server_close()

    def install_url(self) -> str:
        return f"https://github.com/apps/{urllib.parse.quote((self.result or {}).get('slug', ''))}/installations/new"


def wait_for_installation(check: Callable[[str, str, str], str], app_id: str, key_file: str, repo: str, *, timeout: float = 600.0,
                          interval: float = 3.0, sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time) -> str:
    """Poll until the App can see the repository; returns the installation id."""
    end, last = now() + timeout, ""
    while True:
        try:
            return check(app_id, key_file, repo)
        except Exception as exc:                       # not installed yet: GitHub answers 404
            last = str(exc)
        if now() >= end:
            raise AppSetupError(f"the App is still not installed on {repo} ({last})")
        sleep(interval)


def create_app(home: Path, repo: str, *, org: str = "", port: int = 8767, webhook_url: str = "", say: Callable[[str], None] = print,
               check: Callable[[str, str, str], str] | None = None, timeout: float = 900.0) -> dict[str, Any]:
    """The whole flow for a terminal: print one address, wait for the clicks, return what `init` needs."""
    from .github import GitHubApp
    check = check or (lambda app_id, key, r: GitHubApp(app_id, key).installation_for(r))
    setup = AppSetup(home, org=org, port=port, webhook_url=webhook_url, say=say)
    say(f"  1. Open {setup.start_url} in your browser (on a remote machine first run: ssh -L {port}:localhost:{port} <this machine>).")
    say("  2. GitHub shows the App filled in: press 'Create GitHub App'. Keys are saved here automatically.")
    result = setup.serve(timeout)
    say(f"  App created ({result['slug']}). 3. Now install it on {repo}: {setup.install_url()}")
    inst = wait_for_installation(check, result["app_id"], result["key_file"], repo, timeout=timeout)
    return {**result, "installation": inst, "repo": repo}
