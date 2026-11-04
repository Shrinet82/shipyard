"""Kubernetes adapter: drives kubectl with argument lists, one least-privilege credential per kind of action.

  viewer    reads (status, logs, events)
  deployer  restart, rollback, scale
  ops       exec into a pod

No chat text is ever interpolated into a shell. Names are validated, the namespace comes from config, and
replicas are capped. Every failure raises KubeError so callers fail closed.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Callable, Sequence

from .shellrules import Refused, check_pod

NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")


class KubeError(Exception):
    pass


Runner = Callable[[Sequence[str], float], "tuple[int, str, str]"]


def _subprocess_runner(argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, shell=False,
                           env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent"})
    except subprocess.TimeoutExpired:
        raise KubeError(f"kubectl timed out after {int(timeout)} s") from None
    except OSError as exc:
        raise KubeError(f"could not run kubectl: {exc}") from None
    return p.returncode, p.stdout, p.stderr


class Kube:
    def __init__(self, kubeconfigs: dict[str, str], kubectl: str = "kubectl", max_replicas: int = 10,
                 timeout: float = 30.0, runner: Runner | None = None):
        self.kubeconfigs, self.kubectl, self.max_replicas, self.timeout = kubeconfigs, kubectl, max_replicas, timeout
        self._run = runner or _subprocess_runner

    # -- plumbing -------------------------------------------------------------

    @staticmethod
    def _check(**names: str) -> None:
        for what, value in names.items():
            if not isinstance(value, str) or not NAME.match(value):
                raise KubeError(f"invalid {what} {value!r}")

    def _kubectl(self, role: str, namespace: str, args: Sequence[str], timeout: float | None = None) -> str:
        self._check(namespace=namespace)
        if role not in self.kubeconfigs:
            raise KubeError(f"no {role} credential is configured")
        argv = [self.kubectl, "--kubeconfig", self.kubeconfigs[role], "-n", namespace, *args]
        rc, out, err = self._run(argv, timeout or self.timeout)
        if rc != 0:
            raise KubeError((err.strip().splitlines() or ["kubectl failed"])[-1][:300])
        return out

    def _deployment(self, namespace: str, name: str) -> dict:
        self._check(deployment=name)
        return json.loads(self._kubectl("viewer", namespace, ["get", "deployment", name, "-o", "json"]))

    @staticmethod
    def _selector(dep: dict) -> str:
        labels = (dep.get("spec", {}).get("selector", {}) or {}).get("matchLabels", {})
        if not labels:
            raise KubeError("the deployment has no label selector")
        return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))

    def _pods(self, namespace: str, dep: dict) -> list[dict]:
        out = self._kubectl("viewer", namespace, ["get", "pods", "-l", self._selector(dep), "-o", "json"])
        return json.loads(out).get("items", [])

    # -- reads ----------------------------------------------------------------

    def status(self, namespace: str, name: str) -> str:
        dep = self._deployment(namespace, name)
        st, spec = dep.get("status", {}), dep.get("spec", {})
        want = spec.get("replicas", 0)
        image = spec["template"]["spec"]["containers"][0]["image"]
        rev = dep["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", "?")
        pods = []
        for p in self._pods(namespace, dep):
            cs = (p.get("status", {}).get("containerStatuses") or [{}])[0]
            waiting = (cs.get("state", {}) or {}).get("waiting", {}).get("reason")
            pods.append(f"{p['metadata']['name']} {waiting or p['status'].get('phase', '?')}"
                        + (f" ({cs.get('restartCount', 0)} restarts)" if cs.get("restartCount") else ""))
        return (f"{name}: {st.get('readyReplicas', 0)}/{want} ready (image {image}, revision {rev})"
                + ("; pods: " + ", ".join(pods) if pods else "; no pods"))

    def logs(self, namespace: str, name: str, lines: int = 40) -> list[str]:
        lines = max(1, min(int(lines), 200))
        dep = self._deployment(namespace, name)
        out = self._kubectl("viewer", namespace, ["logs", "-l", self._selector(dep), "--tail", str(lines), "--prefix",
                                                  "--max-log-requests", "5"])
        return out.splitlines()

    def events(self, namespace: str, name: str, limit: int = 15) -> list[str]:
        self._check(deployment=name)
        out = self._kubectl("viewer", namespace, ["get", "events", "--sort-by=.lastTimestamp", "-o", "json"])
        rows = [e for e in json.loads(out).get("items", []) if e.get("involvedObject", {}).get("name", "").startswith(name)]
        return [f"{e.get('type', '')} {e.get('reason', '')} {e['involvedObject']['kind']}/{e['involvedObject']['name']}: "
                f"{e.get('message', '')}" for e in rows[-limit:]]

    # -- changes (deployer) -----------------------------------------------------

    def restart(self, namespace: str, name: str) -> str:
        self._check(deployment=name)
        self._kubectl("deployer", namespace, ["rollout", "restart", f"deployment/{name}"])
        return f"rollout restart of {name} started"

    def revisions(self, namespace: str, name: str) -> list[int]:
        self._check(deployment=name)
        out = self._kubectl("viewer", namespace, ["rollout", "history", f"deployment/{name}"])
        return [int(m.group(1)) for line in out.splitlines() if (m := re.match(r"^\s*(\d+)\s", line))]

    def rollback(self, namespace: str, name: str, revision: str | None = None) -> str:
        self._check(deployment=name)
        revs = self.revisions(namespace, name)
        if len(revs) < 2:
            raise KubeError("there is no earlier revision to roll back to")
        args = ["rollout", "undo", f"deployment/{name}"]
        if revision is not None:
            if not revision.isdigit() or int(revision) not in revs[:-1]:
                raise KubeError(f"{revision!r} is not an earlier revision (have {', '.join(map(str, revs[:-1]))})")
            args.append(f"--to-revision={int(revision)}")
        self._kubectl("deployer", namespace, args)
        return f"rollback of {name} started" + (f" to revision {int(revision)}" if revision else "")

    def scale(self, namespace: str, name: str, replicas: str) -> str:
        self._check(deployment=name)
        if not str(replicas).isdigit() or not 0 <= int(replicas) <= self.max_replicas:
            raise KubeError(f"replicas must be a whole number from 0 to {self.max_replicas}")
        self._kubectl("deployer", namespace, ["scale", f"deployment/{name}", f"--replicas={int(replicas)}"])
        return f"{name} scaled to {int(replicas)}"

    # -- exec (ops) -------------------------------------------------------------

    def exec(self, namespace: str, name: str, argv: Sequence[str]) -> list[str]:
        try:
            argv = check_pod(argv)
        except Refused as exc:
            raise KubeError(str(exc)) from None
        pods = [p["metadata"]["name"] for p in self._pods(namespace, self._deployment(namespace, name))
                if p.get("status", {}).get("phase") == "Running"]
        if not pods:
            raise KubeError("no running pod to exec into")
        self._check(pod=pods[0])
        out = self._kubectl("ops", namespace, ["exec", pods[0], "--", *argv], timeout=20)
        return out.splitlines()
