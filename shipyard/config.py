"""Load shipyard.yaml. Any malformed entry raises: never guess."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy import Policy, Role, Tier


@dataclass(frozen=True)
class RepoCfg:
    name: str                          # "owner/repo"
    app: str | None = None             # Coolify app (a key of Project.apps) deployed after a merge
    required_checks: tuple[str, ...] = ("test",)
    merge_method: str = "squash"
    branch: str = "main"               # the branch whose head is what "deploy" ships


_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")


@dataclass(frozen=True)
class K8sApp:
    namespace: str
    deployment: str


@dataclass(frozen=True)
class HostCfg:
    ssh: str                           # user@address of the forced-command account
    key_file: str
    port: int = 22


@dataclass(frozen=True)
class KubeCfg:
    kubeconfigs: dict[str, str]        # viewer / deployer / ops -> kubeconfig path
    kubectl: str = "kubectl"
    max_replicas: int = 10
    timeout: float = 30.0


@dataclass(frozen=True)
class SigNozCfg:
    url: str
    api_key_file: str
    service_map: dict[str, str] = field(default_factory=dict)   # SigNoz service name -> Shipyard app
    project: str = ""                                          # which project its alerts belong to (default: the only one)


@dataclass(frozen=True)
class Project:
    name: str
    ops_rooms: frozenset[str]          # alerts and diagnosis
    maintainer_rooms: frozenset[str]   # PR alerts and the digest
    apps: dict[str, str]               # app name -> Coolify application uuid
    repo: RepoCfg | None = None
    github_logins: dict[str, str] = field(default_factory=dict)   # sender id -> GitHub login
    k8s_apps: dict[str, K8sApp] = field(default_factory=dict)     # app name -> Kubernetes deployment
    room_names: dict[str, str] = field(default_factory=dict)      # room id -> label for people, e.g. "#demo-ops"
    incident_rooms: frozenset[str] = frozenset()                  # where alerts and diagnosis go; commands work here too
    exec_host: str | None = None                                  # the host (from `hosts:`) that runs the Coolify containers: `exec <app>` goes there
    ticket_prefix: str = "SY"                                     # Board ticket keys: SY-1, SY-2, ...
    on_call: str | None = None                                    # chat identity that automatic alert tickets are assigned to, if set
    servers: tuple[str, ...] = ()                                 # Coolify server uuids this project owns (for disk alerts); with one project, not needed

    @property
    def rooms(self) -> frozenset[str]:
        return self.ops_rooms | self.maintainer_rooms | self.incident_rooms

    @property
    def alert_rooms(self) -> frozenset[str]:
        """Every room that hears about an alert: the incidents rooms, and the ops rooms too, so the people who watch deploys see it as well."""
        return self.incident_rooms | self.ops_rooms

    @property
    def app_names(self) -> list[str]:
        return sorted([*self.apps, *self.k8s_apps])

    def backend_of(self, name: str) -> str | None:
        return "coolify" if name in self.apps else "k8s" if name in self.k8s_apps else None


@dataclass(frozen=True)
class GithubCfg:
    app_id: str = ""
    installation_id: str = ""
    private_key_file: str = "~/shipyard-github.pem"
    poll_seconds: int = 60
    stale_hours: float = 48.0
    webhook_secret_file: str = "~/shipyard-github-webhook.secret"   # GitHub's webhook secret; with the file present the Gatekeeper accepts GitHub's webhooks


@dataclass(frozen=True)
class SbomCfg:
    workflow: str = ".github/workflows/ci.yml"     # the only workflow whose artifacts we believe
    data_dir: str = "~/shipyard-sbom"
    poll_seconds: int = 90
    enabled: bool = True
    copyleft: tuple[str, ...] = ("AGPL", "GPL", "SSPL", "EUPL", "OSL", "CC-BY-SA")   # licence families to flag (report only, never a block)


@dataclass(frozen=True)
class DashboardCfg:
    bind: str = "127.0.0.1"
    port: int = 8780
    session_hours: float = 8.0
    members_file: str = "~/shipyard-members.json"   # role overlay the dashboard edits
    public_url: str = ""                            # where people open the dashboard (used for links in chat), e.g. http://localhost:8780
    allow_remote: bool = False                      # listen on a non-loopback bind (only `shipyard expose` sets this): plain HTTP, firewall it to yourself


@dataclass(frozen=True)
class AlertCfg:
    secret_file: str = "~/gatekeeper-webhook.secret"
    bind: str = "0.0.0.0"
    port: int = 8766
    evidence_lines: int = 40
    agent: str = "ops-agent"           # who is asked to diagnose
    restart_limit: int = 5             # a Kubernetes pod restarted this many times is an alert
    cluster_poll_seconds: int = 60     # how often the cluster is looked at; 0 turns the Kubernetes alerts off


@dataclass(frozen=True)
class DigestCfg:
    hour: int = 9
    minute: int = 0
    timezone: str = "Asia/Kolkata"


@dataclass(frozen=True)
class Config:
    policy: Policy
    projects: dict[str, Project]
    switch_url: str = "http://localhost:8000"
    agent_credentials_file: str = "~/gatekeeper.json"
    coolify_url: str = ""
    coolify_token_file: str = "~/coolify.env"
    mcp_port: int = 8765
    mcp_token_file: str = "~/gatekeeper-mcp.token"
    db_path: str = "~/shipyard.db"
    known_agents: frozenset[str] = frozenset({"ops-agent", "repo-agent"})
    gateway_env_file: str = "~/switch/.env"        # Switch's admin login, used by the dashboard's agent-access sync
    managed_agents: tuple[str, ...] = ("ops-agent", "repo-agent")
    allow_agents: tuple[str, ...] = ("gatekeeper",)   # agents that may address the managed ones (alerts wake the Ops Agent)
    github: GithubCfg = GithubCfg()
    alerts: AlertCfg = AlertCfg()
    digest: DigestCfg = DigestCfg()
    sbom: SbomCfg = SbomCfg()
    dashboard: DashboardCfg = DashboardCfg()
    standup_at: str = ""                                   # "09:00" (IST): the daily Board standup in the maintainers rooms; empty = off
    hosts: dict[str, HostCfg] = field(default_factory=dict)
    kube: KubeCfg | None = None
    signoz: SigNozCfg | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False)
    desks: dict[str, dict[str, str]] = field(default_factory=dict, compare=False)     # project -> member identity -> personal desk room (filled at start-up)
    desks_file: str = "~/shipyard-desks.json"
    rooms_file: str = "~/shipyard-rooms.json"                 # rooms made by the room sync, remembered here
    discord_bridges: dict[str, str] = field(default_factory=dict, compare=False)     # Switch bridge id -> Discord server id, for apps added with `connect discord`
    discord_token_file: str = ""                              # an env file with DISCORD_BOT_TOKEN: lets the room sync read the server's channel list (read only). Empty = off

    def project_for_room(self, room_id: str) -> Project | None:
        return next((p for p in self.projects.values() if room_id in p.rooms or room_id in self.desks.get(p.name, {}).values()), None)

    def desk_owner(self, room_id: str) -> str | None:
        """The member a personal desk room belongs to, or None when the room is not a desk."""
        return next((i for rooms in self.desks.values() for i, r in rooms.items() if r == room_id), None)

    def project_for_app_uuid(self, uuid: str) -> tuple[Project, str] | None:
        for p in self.projects.values():
            for name, u in p.apps.items():
                if u == uuid:
                    return p, name
        return None


def _role(name: str) -> Role:
    try:
        return Role[str(name).upper()]
    except KeyError:
        raise ValueError(f"unknown role {name!r}") from None


def _policy(raw: dict[str, Any]) -> Policy:
    members = {
        project: {str(identity): _role(role) for identity, role in (spec.get("members") or {}).items()}
        for project, spec in (raw.get("projects") or {}).items()
    }
    actions = {name: Tier(tier) for name, tier in (raw.get("actions") or {}).items()}
    min_role = {name: _role(role) for name, role in (raw.get("min_role") or {}).items()}
    overrides = frozenset(name for name, on in (raw.get("approval_overrides") or {}).items() if on)
    unknown = (set(overrides) | set(min_role)) - set(actions)
    if unknown:
        raise ValueError(f"overrides for undeclared actions: {sorted(unknown)}")
    return Policy(
        members=members,
        actions=actions,
        approval_overrides=overrides,
        min_role=min_role,
        approval_timeout_seconds=int(raw.get("approval_timeout_seconds", 600)),
    )


def load_policy(path: str | Path) -> Policy:
    return _policy(yaml.safe_load(Path(path).read_text()))


def _hhmm(value: Any) -> str:
    text = str(value or "").strip()
    if text and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", text):
        raise ValueError("tickets.standup_at must look like 09:00")
    return text


def _rooms(value: Any) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """`rooms: [a, b]` means ops rooms; `rooms: {ops: [...], maintainers: [...], incidents: [...]}` names them."""
    if isinstance(value, dict):
        return (frozenset(str(r) for r in value.get("ops") or []),
                frozenset(str(r) for r in value.get("maintainers") or []),
                frozenset(str(r) for r in value.get("incidents") or []))
    return frozenset(str(r) for r in value or []), frozenset(), frozenset()


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text())
    projects = {}
    for name, spec in (raw.get("projects") or {}).items():
        apps, k8s_apps = {}, {}
        for app, v in (spec.get("apps") or {}).items():
            app = str(app)
            if isinstance(v, dict) and v.get("backend") == "k8s":
                ns, dep = str(v.get("namespace", "")), str(v.get("deployment", ""))
                if not _K8S_NAME.match(ns) or not _K8S_NAME.match(dep):
                    raise ValueError(f"app {app!r}: namespace and deployment must be valid Kubernetes names")
                k8s_apps[app] = K8sApp(ns, dep)
            elif isinstance(v, dict):
                apps[app] = str(v["uuid"])
            else:
                apps[app] = str(v)
        ops, maint, incidents = _rooms(spec.get("rooms"))
        repo = None
        if spec.get("repo"):
            r = spec["repo"]
            if r.get("app") and r["app"] not in apps:
                raise ValueError(f"repo.app {r['app']!r} is not one of the project's apps")
            repo = RepoCfg(name=str(r["name"]), app=r.get("app"),
                           required_checks=tuple(r.get("required_checks", ["test"])),
                           merge_method=r.get("merge_method", "squash"), branch=str(r.get("branch", "main")))
            if repo.merge_method not in ("merge", "squash", "rebase"):
                raise ValueError("merge_method must be merge, squash or rebase")
        projects[name] = Project(name, ops, maint, apps, repo,
                                 {str(k): str(v) for k, v in (spec.get("github_logins") or {}).items()}, k8s_apps,
                                 {str(k): str(v)[:60] for k, v in (spec.get("room_names") or {}).items()}, incidents,
                                 str(spec["exec_host"]) if spec.get("exec_host") else None,
                                 str(spec.get("ticket_prefix", "SY")), str(spec["on_call"]) if spec.get("on_call") else None,
                                 tuple(str(x) for x in spec.get("servers") or []))
    rooms = [r for p in projects.values() for r in p.rooms]
    if len(rooms) != len(set(rooms)):
        raise ValueError("a room may belong to only one project")
    for p in projects.values():
        if (p.ops_rooms & p.maintainer_rooms) or (p.incident_rooms & (p.ops_rooms | p.maintainer_rooms)):
            raise ValueError("a room cannot have two kinds (ops, maintainers, incidents)")
    hosts = {str(n): HostCfg(str(h["ssh"]), str(h["key_file"]), int(h.get("port", 22))) for n, h in (raw.get("hosts") or {}).items()}
    k = raw.get("kubernetes")
    kube = KubeCfg({str(r): str(f) for r, f in (k.get("kubeconfigs") or {}).items()}, str(k.get("kubectl", "kubectl")),
                   int(k.get("max_replicas", 10)), float(k.get("timeout", 30))) if k else None
    prefixes = [p.ticket_prefix for p in projects.values()]
    if any(not re.fullmatch(r"[A-Z]{2,6}", x) for x in prefixes) or len(prefixes) != len(set(prefixes)):
        raise ValueError("ticket_prefix must be 2 to 6 capital letters, and different for each project")
    for p in projects.values():
        if p.exec_host and p.exec_host not in hosts:
            raise ValueError(f"exec_host {p.exec_host!r} is not one of the `hosts:`")
        if p.k8s_apps and kube is None:
            raise ValueError("Kubernetes apps need a `kubernetes:` block with kubeconfigs")
    switch, coolify, gk = raw.get("switch") or {}, raw.get("coolify") or {}, raw.get("gatekeeper") or {}
    gh, al, dg = raw.get("github") or {}, raw.get("alerts") or {}, raw.get("digest") or {}
    sb, dash = raw.get("sbom") or {}, raw.get("dashboard") or {}
    return Config(
        policy=_policy(raw),
        projects=projects,
        switch_url=switch.get("url", "http://localhost:8000"),
        agent_credentials_file=switch.get("credentials_file", "~/gatekeeper.json"),
        gateway_env_file=switch.get("gateway_env_file", "~/switch/.env"),
        managed_agents=tuple(str(a) for a in switch.get("managed_agents", ["ops-agent", "repo-agent"])),
        allow_agents=tuple(str(a) for a in switch.get("allow_agents", ["gatekeeper"])),
        coolify_url=coolify.get("url", ""),
        coolify_token_file=coolify.get("token_file", "~/coolify.env"),
        mcp_port=int(gk.get("mcp_port", 8765)),
        mcp_token_file=gk.get("mcp_token_file", "~/gatekeeper-mcp.token"),
        db_path=gk.get("db_path", "~/shipyard.db"),
        known_agents=frozenset(gk.get("known_agents", ["ops-agent", "repo-agent"])),
        github=GithubCfg(str(gh.get("app_id", "")), str(gh.get("installation_id", "")),
                         gh.get("private_key_file", "~/shipyard-github.pem"),
                         int(gh.get("poll_seconds", 60)), float(gh.get("stale_hours", 48)),
                        str(gh.get("webhook_secret_file", "~/shipyard-github-webhook.secret"))),
        alerts=AlertCfg(al.get("secret_file", "~/gatekeeper-webhook.secret"), al.get("bind", "0.0.0.0"),
                        int(al.get("port", 8766)), int(al.get("evidence_lines", 40)), al.get("agent", "ops-agent"),
                        int(al.get("restart_limit", 5)), int(al.get("cluster_poll_seconds", 60))),
        digest=DigestCfg(int(dg.get("hour", 9)), int(dg.get("minute", 0)), dg.get("timezone", "Asia/Kolkata")),
        sbom=SbomCfg(str(sb.get("workflow", ".github/workflows/ci.yml")), sb.get("data_dir", "~/shipyard-sbom"),
                     int(sb.get("poll_seconds", 90)), bool(sb.get("enabled", True)),
                     tuple(str(c) for c in sb.get("copyleft", ["AGPL", "GPL", "SSPL", "EUPL", "OSL", "CC-BY-SA"]))),
        dashboard=DashboardCfg(str(dash.get("bind", "127.0.0.1")), int(dash.get("port", 8780)),
                               float(dash.get("session_hours", 8)), dash.get("members_file", "~/shipyard-members.json"),
                               str(dash.get("public_url", "")).rstrip("/"), bool(dash.get("allow_remote", False))),
        standup_at=_hhmm((raw.get("tickets") or {}).get("standup_at", "")),
        hosts=hosts,
        kube=kube,
        signoz=_signoz(raw.get("signoz"), projects),
        raw=raw,
        desks_file=str(raw.get("desks_file", "~/shipyard-desks.json")),
        rooms_file=str(raw.get("rooms_file", "~/shipyard-rooms.json")),
        discord_token_file=str((raw.get("discord") or {}).get("token_file", "")),
        discord_bridges={str(k): str(v) for k, v in ((raw.get("discord") or {}).get("bridges") or {}).items()},
    )


def _signoz(raw: Any, projects: dict[str, Project]) -> SigNozCfg | None:
    if not raw:
        return None
    if not str(raw.get("url", "")).startswith(("http://", "https://")):
        raise ValueError("signoz.url must be an http(s) address")
    project = str(raw.get("project", ""))
    if project and project not in projects:
        raise ValueError(f"signoz.project {project!r} is not a project")
    return SigNozCfg(str(raw["url"]).rstrip("/"), str(raw.get("api_key_file", "~/signoz.env")),
                     {str(k): str(v) for k, v in (raw.get("service_map") or {}).items()}, project)


def expand(path: str) -> str:
    return os.path.expanduser(path)
