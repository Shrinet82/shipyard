"""GitHub App client: JWT, installation token, pull requests, checks, merge. Stdlib + openssl.

The Gatekeeper is the only holder of the App's private key. Every failure raises GitHubError, so
callers fail closed.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

API = "https://api.github.com"
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024


class GitHubError(Exception):
    pass


@dataclass(frozen=True)
class PR:
    number: int
    title: str
    url: str
    author: str
    state: str                  # open | closed | merged
    draft: bool
    head_sha: str
    base: str
    mergeable: bool | None      # None: GitHub has not worked it out yet
    created_at: float
    updated_at: float
    requested_reviewers: tuple[str, ...] = ()
    assignees: tuple[str, ...] = ()
    body: str = ""
    merge_sha: str = ""         # the commit a merged PR left on its base branch (the squash or merge commit)


@dataclass(frozen=True)
class Checks:
    ci: str                     # green | red | pending | none
    failing: tuple[str, ...] = ()


def _epoch(ts: str | None) -> float:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else 0.0


def evaluate_checks(runs: list[dict[str, Any]], required: tuple[str, ...]) -> Checks:
    """CI is green only if every required check (or, with none named, every check) finished successfully."""
    by_name = {r["name"]: r for r in runs}
    names = list(required) if required else sorted(by_name)
    if not names or any(n not in by_name for n in names):
        return Checks("none")
    failing, pending = [], False
    for n in names:
        r = by_name[n]
        if r.get("status") != "completed":
            pending = True
        elif r.get("conclusion") not in ("success", "neutral", "skipped"):
            failing.append(n)
    if failing:
        return Checks("red", tuple(failing))
    return Checks("pending" if pending else "green")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_with_openssl(key_file: str, message: bytes) -> bytes:
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_file], input=message, capture_output=True, timeout=10)
    if p.returncode != 0:
        raise GitHubError("could not sign the GitHub App token (check the private key file)")
    return p.stdout


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):          # we follow redirects ourselves, without our credentials
        return None


def _download_urllib(url: str, headers: dict[str, str], max_bytes: int) -> bytes:
    """GET a file. A redirect (artifacts are served from storage) is followed WITHOUT the Authorization header."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(urllib.request.Request(url, headers=headers), timeout=60)
    except urllib.error.HTTPError as exc:
        if exc.code not in (301, 302, 303, 307, 308):
            raise GitHubError(f"GitHub answered {exc.code} for the download") from exc
        location = exc.headers.get("Location", "")
        if not location.startswith("https://"):
            raise GitHubError("the download redirected somewhere that is not https") from exc
        try:
            resp = urllib.request.urlopen(urllib.request.Request(location), timeout=60)
        except (urllib.error.URLError, OSError) as exc2:
            raise GitHubError(f"could not fetch the artifact: {exc2}") from exc2
    except (urllib.error.URLError, OSError) as exc:
        raise GitHubError(f"GitHub unreachable: {exc}") from exc
    data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise GitHubError("the artifact is larger than the allowed size")
    return data


class GitHubApp:
    def __init__(self, app_id: str, key_file: str, installation_id: str = "", now: Callable[[], float] = time.time,
                 http: Callable[..., tuple[int, Any]] | None = None, sign: Callable[[bytes], bytes] | None = None,
                 download: Callable[[str, dict[str, str], int], bytes] | None = None):
        self.app_id, self.key_file, self.installation_id, self.now = app_id, key_file, installation_id, now
        self._http = http or self._urllib
        self._download = download or _download_urllib
        self._sign = sign or (lambda m: sign_with_openssl(key_file, m))
        self._token: tuple[str, float] | None = None

    # -- transport ------------------------------------------------------------

    @staticmethod
    def _urllib(method: str, url: str, headers: dict[str, str], body: dict | None) -> tuple[int, Any]:
        req = urllib.request.Request(url, method=method, headers=headers, data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None
        except (urllib.error.URLError, OSError) as e:
            raise GitHubError(f"GitHub unreachable: {e}") from e

    def _jwt(self) -> str:
        t = int(self.now())
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = _b64(json.dumps({"iat": t - 30, "exp": t + 540, "iss": str(self.app_id)}).encode())
        return f"{head}.{body}.{_b64(self._sign(f'{head}.{body}'.encode()))}"

    def _call(self, method: str, path: str, body: dict | None = None, *, as_app: bool = False) -> Any:
        token = self._jwt() if as_app else self._installation_token()
        status, data = self._http(method, API + path, {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                                       "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}, body)
        if status >= 400:
            msg = (data or {}).get("message", "") if isinstance(data, dict) else ""
            raise GitHubError(f"GitHub answered {status}: {msg}"[:200])
        return data

    def _installation_token(self) -> str:
        if self._token and self._token[1] - self.now() > 120:
            return self._token[0]
        if not self.installation_id:
            raise GitHubError("no installation id: call installation_for(repo) first")
        data = self._call("POST", f"/app/installations/{self.installation_id}/access_tokens", as_app=True)
        self._token = (data["token"], _epoch(data["expires_at"]))
        return self._token[0]

    def installation_for(self, repo: str) -> str:
        """Find (and remember) the installation of this App on `repo`."""
        data = self._call("GET", f"/repos/{repo}/installation", as_app=True)
        self.installation_id = str(data["id"])
        return self.installation_id

    # -- pull requests --------------------------------------------------------

    @staticmethod
    def _pr(d: dict[str, Any]) -> PR:
        state = "merged" if d.get("merged_at") else d.get("state", "open")
        return PR(number=d["number"], title=d["title"], url=d["html_url"], author=(d.get("user") or {}).get("login", ""),
                  state=state, draft=bool(d.get("draft")), head_sha=d["head"]["sha"], base=d["base"]["ref"],
                  mergeable=d.get("mergeable"), created_at=_epoch(d.get("created_at")), updated_at=_epoch(d.get("updated_at")),
                  requested_reviewers=tuple(u["login"] for u in d.get("requested_reviewers", [])),
                  assignees=tuple(u["login"] for u in d.get("assignees", [])), body=(d.get("body") or "")[:8000],
                  merge_sha=(d.get("merge_commit_sha") or "") if d.get("merged_at") else "")

    def pr(self, repo: str, number: int) -> PR:
        return self._pr(self._call("GET", f"/repos/{repo}/pulls/{number}"))

    def list_open_prs(self, repo: str) -> list[PR]:
        """Open PRs with their conflict state (the list endpoint omits it, so each is fetched)."""
        rows = self._call("GET", f"/repos/{repo}/pulls?state=open&per_page=50")
        return [self.pr(repo, r["number"]) for r in rows]

    def compare(self, repo: str, base: str, head: str) -> str:
        """ahead | behind | identical | diverged: where `head` stands against `base`. `base` is in `head`'s history when this is ahead or identical."""
        for ref in (base, head):
            if not re.fullmatch(r"[0-9a-fA-F]{7,40}", ref or ""):
                raise GitHubError("a commit sha is expected")
        return str(self._call("GET", f"/repos/{repo}/compare/{base}...{head}?per_page=1").get("status", ""))

    def checks(self, repo: str, sha: str, required: tuple[str, ...]) -> Checks:
        data = self._call("GET", f"/repos/{repo}/commits/{sha}/check-runs?per_page=100")
        return evaluate_checks(data.get("check_runs", []), required)

    def assigned_issues(self, repo: str, login: str) -> list[dict[str, Any]]:
        try:
            rows = self._call("GET", f"/repos/{repo}/issues?assignee={login}&state=open&per_page=50")
        except GitHubError as exc:
            if "422" in str(exc) or "404" in str(exc):      # GitHub does not know that login: nobody is assigned
                return []
            raise
        return [r for r in rows if "pull_request" not in r]

    # -- CI artifacts, files, branches, limits -------------------------------------

    def workflow_runs(self, repo: str, sha: str) -> list[dict[str, Any]]:
        data = self._call("GET", f"/repos/{repo}/actions/runs?head_sha={sha}&per_page=20")
        return data.get("workflow_runs", [])

    def run_artifacts(self, repo: str, run_id: int) -> list[dict[str, Any]]:
        return self._call("GET", f"/repos/{repo}/actions/runs/{int(run_id)}/artifacts?per_page=50").get("artifacts", [])

    def download_artifact(self, repo: str, artifact_id: int, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
        headers = {"Authorization": f"Bearer {self._installation_token()}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        return self._download(f"{API}/repos/{repo}/actions/artifacts/{int(artifact_id)}/zip", headers, max_bytes)

    def pr_files(self, repo: str, number: int) -> list[str]:
        names: list[str] = []
        for page in (1, 2, 3):
            rows = self._call("GET", f"/repos/{repo}/pulls/{number}/files?per_page=100&page={page}")
            names += [r["filename"] for r in rows]
            if len(rows) < 100:
                break
        return names

    def branch_head(self, repo: str, branch: str) -> str:
        return self._call("GET", f"/repos/{repo}/branches/{branch}")["commit"]["sha"]

    def pr_head(self, repo: str, number: int) -> dict[str, Any]:
        """The branch a pull request comes from: {ref, repo, sha, state, draft, base}."""
        d = self._call("GET", f"/repos/{repo}/pulls/{number}")
        head = d["head"]
        return {"ref": head["ref"], "repo": (head.get("repo") or {}).get("full_name", ""), "sha": head["sha"], "state": d["state"],
                "draft": bool(d.get("draft")), "base": d["base"]["ref"], "merged": bool(d.get("merged"))}

    def review_comments(self, repo: str, number: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for page in range(1, 6):                                    # at most 500 comments
            rows = self._call("GET", f"/repos/{repo}/pulls/{number}/comments?per_page=100&page={page}")
            out += rows
            if len(rows) < 100:
                break
        return out

    def file_at(self, repo: str, path: str, ref: str) -> dict[str, Any]:
        from urllib.parse import quote
        return self._call("GET", f"/repos/{repo}/contents/{quote(path)}?ref={quote(ref, safe='')}")

    def put_file(self, repo: str, path: str, branch: str, message: str, content: bytes, blob_sha: str) -> str:
        """Commit new content for one file on `branch`. GitHub refuses (409) if the file changed since `blob_sha`. Returns the commit sha."""
        from urllib.parse import quote
        data = self._call("PUT", f"/repos/{repo}/contents/{quote(path)}",
                          {"message": message, "content": base64.b64encode(content).decode(), "sha": blob_sha, "branch": branch})
        return str(data["commit"]["sha"])

    def tag_commit(self, repo: str, tag: str) -> str:
        """The commit a tag points at (annotated tags are followed one step)."""
        obj = self._call("GET", f"/repos/{repo}/git/ref/tags/{tag}")["object"]
        if obj.get("type") == "tag":
            obj = self._call("GET", f"/repos/{repo}/git/tags/{obj['sha']}")["object"]
        return str(obj["sha"])

    def rate_limit(self) -> dict[str, Any]:
        return self._call("GET", "/rate_limit")["resources"]["core"]

    def merge(self, repo: str, number: int, sha: str, method: str = "squash") -> str:
        """Merge only if the head is still `sha`; GitHub refuses (409) if the branch moved."""
        data = self._call("PUT", f"/repos/{repo}/pulls/{number}/merge", {"sha": sha, "merge_method": method})
        return str((data or {}).get("sha", ""))
