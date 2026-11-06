"""`shipyard connect kubernetes`: give Shipyard least-privilege access to a namespace of the cluster your kubectl points at.

You need kubectl working on this machine with enough rights to create service accounts and role bindings (your own admin
access). Shipyard then:
  1. lists the namespaces and deployments and lets you pick;
  2. creates three service accounts in a `shipyard-system` namespace, and in YOUR namespace the bindings that give them rights:
       viewer    reads (the built-in `view` role, which cannot read secrets)
       deployer  restarts, rolls back and scales deployments
       ops       runs allowlisted commands inside pods (pods/exec)
  3. writes one kubeconfig per account (mode 0600) and adds the `kubernetes:` block and the apps to shipyard.yaml.

Your own admin credential is used once, here, and is never stored. Running it again is safe and adds another namespace.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Sequence

import yaml

SA_NAMESPACE = "shipyard-system"
ROLES = ("viewer", "deployer", "ops")
NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", SA_NAMESPACE}

Runner = Callable[[Sequence[str], str | None], "tuple[int, str, str]"]


class ConnectError(Exception):
    pass


def _runner(argv: Sequence[str], stdin: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise ConnectError(f"{argv[0]} is not installed on this machine") from None
    except subprocess.TimeoutExpired:
        raise ConnectError(f"{' '.join(argv[:3])} timed out") from None
    return p.returncode, p.stdout, p.stderr


def rbac_manifest(namespace: str, sa_namespace: str = SA_NAMESPACE) -> str:
    """Everything Shipyard needs in the cluster, as one multi-document YAML."""
    def sa(role: str) -> dict[str, Any]:
        return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": f"shipyard-{role}", "namespace": sa_namespace}}

    def token(role: str) -> dict[str, Any]:
        return {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/service-account-token",
                "metadata": {"name": f"shipyard-{role}-token", "namespace": sa_namespace,
                             "annotations": {"kubernetes.io/service-account.name": f"shipyard-{role}"}}}

    def subject(role: str) -> list[dict[str, str]]:
        return [{"kind": "ServiceAccount", "name": f"shipyard-{role}", "namespace": sa_namespace}]

    docs: list[dict[str, Any]] = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": sa_namespace}}]
    docs += [sa(r) for r in ROLES] + [token(r) for r in ROLES]
    docs += [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "shipyard-viewer", "namespace": namespace},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}, "subjects": subject("viewer")},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "shipyard-deployer-view", "namespace": namespace},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}, "subjects": subject("deployer")},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "shipyard-deployer", "namespace": namespace},
         "rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch", "update"]},
                   {"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get", "patch", "update"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "shipyard-deployer", "namespace": namespace},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "shipyard-deployer"}, "subjects": subject("deployer")},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "shipyard-ops", "namespace": namespace},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                   {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "shipyard-ops", "namespace": namespace},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "shipyard-ops"}, "subjects": subject("ops")},
    ]
    return yaml.safe_dump_all(docs, sort_keys=False)


def kubeconfig_text(role: str, server: str, ca_b64: str, token: str, namespace: str) -> str:
    return yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config", "current-context": role,
        "clusters": [{"name": "shipyard", "cluster": {"server": server, "certificate-authority-data": ca_b64}}],
        "users": [{"name": f"shipyard-{role}", "user": {"token": token}}],
        "contexts": [{"name": role, "context": {"cluster": "shipyard", "user": f"shipyard-{role}", "namespace": namespace}}],
    }, sort_keys=False)


class KubeConnect:
    def __init__(self, kubectl: str = "kubectl", context: str = "", run: Runner | None = None, say: Callable[[str], None] = print,
                 sleep: Callable[[float], None] = time.sleep):
        self.kubectl, self.context, self._run, self.say, self.sleep = kubectl, context, run or _runner, say, sleep

    # -- talking to the cluster as the person running this --------------------------------------

    def _k(self, *args: str, stdin: str | None = None) -> str:
        argv = [self.kubectl, *(["--context", self.context] if self.context else []), *args]
        rc, out, err = self._run(argv, stdin)
        if rc != 0:
            raise ConnectError(f"kubectl {' '.join(args[:3])} failed: {(err or out).strip()[:300]}")
        return out

    def current_context(self) -> str:
        return self.context or self._k("config", "current-context").strip()

    def check_access(self) -> None:
        for verb, what in (("create", "serviceaccounts"), ("create", "rolebindings"), ("create", "secrets")):
            rc, out, _ = self._run([self.kubectl, *(["--context", self.context] if self.context else []), "auth", "can-i", verb, what, "--all-namespaces"], None)
            if rc != 0 or out.strip() != "yes":
                raise ConnectError(f"your kubectl credential cannot {verb} {what}; connect with cluster-admin rights once (Shipyard stores nothing of it)")

    def namespaces(self) -> list[str]:
        data = json.loads(self._k("get", "namespaces", "-o", "json"))
        return sorted(i["metadata"]["name"] for i in data["items"] if i["metadata"]["name"] not in SYSTEM_NAMESPACES)

    def deployments(self, namespace: str) -> list[str]:
        self._check(namespace)
        data = json.loads(self._k("get", "deployments", "-n", namespace, "-o", "json"))
        return sorted(i["metadata"]["name"] for i in data["items"])

    @staticmethod
    def _check(*names: str) -> None:
        for n in names:
            if not NAME.match(n):
                raise ConnectError(f"{n!r} is not a valid Kubernetes name")

    def cluster(self) -> tuple[str, str]:
        """(API server address, CA certificate as base64) of the current context, as the Gatekeeper must reach them."""
        data = json.loads(self._k("config", "view", "--minify", "--raw", "-o", "json"))
        c = data["clusters"][0]["cluster"]
        ca = c.get("certificate-authority-data")
        if not ca and c.get("certificate-authority"):
            ca = base64.b64encode(Path(c["certificate-authority"]).read_bytes()).decode()
        if not ca:
            raise ConnectError("the cluster entry in your kubeconfig has no certificate authority; Shipyard will not talk to an API server it cannot verify")
        return c["server"], ca

    # -- the work ---------------------------------------------------------------------------------

    def apply(self, namespace: str) -> None:
        self._check(namespace)
        self._k("apply", "-f", "-", stdin=rbac_manifest(namespace))

    def tokens(self, wait: float = 30.0) -> dict[str, str]:
        end, got = time.time() + wait, {}
        while True:
            for role in ROLES:
                if role in got:
                    continue
                out = self._k("get", "secret", f"shipyard-{role}-token", "-n", SA_NAMESPACE, "-o", "jsonpath={.data.token}").strip()
                if out:
                    got[role] = base64.b64decode(out).decode()
            if len(got) == len(ROLES):
                return got
            if time.time() > end:
                raise ConnectError("the cluster did not issue the service-account tokens in time; run the command again")
            self.sleep(1)

    def write_kubeconfigs(self, outdir: Path, namespace: str, server: str, ca: str, tokens: dict[str, str]) -> dict[str, str]:
        outdir.mkdir(parents=True, exist_ok=True)
        os.chmod(outdir, 0o700)
        files = {}
        for role in ROLES:
            f = outdir / f"{role}.kubeconfig"
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(kubeconfig_text(role, server, ca, tokens[role], namespace))
            os.chmod(f, 0o600)
            files[role] = str(f)
        return files

    def verify(self, files: dict[str, str], namespace: str) -> None:
        """Prove each credential does what it should and no more, with the credentials themselves."""
        def can(role: str, verb: str, resource: str) -> bool:
            res, _, sub = resource.partition("/")                        # `pods/exec` is resource pods, subresource exec
            argv = [self.kubectl, "--kubeconfig", files[role], "-n", namespace, "auth", "can-i", verb, res, *([f"--subresource={sub}"] if sub else [])]
            rc, out, _ = self._run(argv, None)
            return rc == 0 and out.strip() == "yes"
        checks = [("viewer", ("get", "pods"), True), ("viewer", ("get", "secrets"), False), ("viewer", ("create", "pods/exec"), False),
                  ("deployer", ("patch", "deployments"), True), ("deployer", ("delete", "deployments"), False), ("deployer", ("get", "secrets"), False),
                  ("ops", ("create", "pods/exec"), True), ("ops", ("delete", "pods"), False), ("ops", ("get", "secrets"), False)]
        for role, args, want in checks:
            if can(role, *args) != want:
                raise ConnectError(f"the {role} credential {'cannot' if want else 'can'} {' '.join(args)}; it should {'be able to' if want else 'not be able to'}")

    def connect(self, namespace: str, deployments: list[str], outdir: Path) -> dict[str, Any]:
        self._check(namespace, *deployments)
        server, ca = self.cluster()
        self.apply(namespace)
        files = self.write_kubeconfigs(outdir, namespace, server, ca, self.tokens())
        self.verify(files, namespace)
        return {"server": server, "kubeconfigs": files, "namespace": namespace, "deployments": deployments}


def config_changes(raw: dict[str, Any], project: str | None, result: dict[str, Any], kubectl: str = "kubectl") -> list[str]:
    """Add the kubernetes block and the apps to the loaded config. Returns the names of the apps added."""
    from .confedit import project_of
    _, p = project_of(raw, project)
    block = raw.get("kubernetes") or {}
    raw["kubernetes"] = {**block, "kubectl": block.get("kubectl", kubectl), "max_replicas": block.get("max_replicas", 10), "kubeconfigs": result["kubeconfigs"]}
    apps = p.setdefault("apps", {})
    added = []
    for dep in result["deployments"]:
        name = dep
        existing = apps.get(name)
        if existing is not None and not (isinstance(existing, dict) and existing.get("backend") == "k8s" and existing.get("namespace") == result["namespace"]):
            name = f"{dep}-k8s"
        apps[name] = {"backend": "k8s", "namespace": result["namespace"], "deployment": dep}
        added.append(name)
    return added


def choose(kc: KubeConnect, namespace: str, deployments: str, ask: Callable[[str], str], say: Callable[[str], None] = print) -> tuple[str, list[str]]:
    """Pick the namespace and deployments, by flag or by number from a list."""
    if not namespace:
        names = kc.namespaces()
        if not names:
            raise ConnectError("the cluster has no namespaces besides the system ones")
        for i, n in enumerate(names, 1):
            say(f"  {i}. {n}")
        pick = ask("Which namespace should Shipyard manage? (number or name): ").strip()
        namespace = names[int(pick) - 1] if pick.isdigit() and 0 < int(pick) <= len(names) else pick
    kc._check(namespace)
    available = kc.deployments(namespace)
    if not available:
        raise ConnectError(f"namespace {namespace} has no deployments yet")
    if not deployments:
        for i, d in enumerate(available, 1):
            say(f"  {i}. {d}")
        deployments = ask("Which deployments? (numbers or names separated by commas, or 'all'): ").strip()
    if deployments.lower() == "all":
        return namespace, available
    chosen = []
    for part in [p.strip() for p in deployments.split(",") if p.strip()]:
        name = available[int(part) - 1] if part.isdigit() and 0 < int(part) <= len(available) else part
        if name not in available:
            raise ConnectError(f"{namespace} has no deployment called {name} (it has: {', '.join(available)})")
        chosen.append(name)
    if not chosen:
        raise ConnectError("no deployment chosen")
    return namespace, chosen
