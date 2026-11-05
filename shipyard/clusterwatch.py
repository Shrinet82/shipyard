"""Alerts from the cluster: Coolify sends webhooks, Kubernetes does not, so the Gatekeeper looks.

Every `alerts.cluster_poll_seconds` it asks Kubernetes (read-only, the viewer credential) which pods of a project's apps crash-loop or have restarted
too often, and which nodes report disk pressure. Each finding goes through the same alert path as Coolify's, at most once an hour per pod or node.
"""
from __future__ import annotations

import logging
from typing import Any

from .evidence import clean_lines
from .kube import KubeError

log = logging.getLogger("shipyard.cluster")


class ClusterWatcher:
    def __init__(self, service: Any, kube: Any):
        self.svc, self.kube = service, kube

    def poll_once(self) -> int:
        raised = 0
        cfg = self.svc.cfg
        hour = int(self.svc.now() // 3600)
        for project in cfg.projects.values():
            for app, k in project.k8s_apps.items():
                try:
                    problems = self.kube.problems(k.namespace, k.deployment, cfg.alerts.restart_limit)
                except KubeError as exc:
                    log.warning("cluster check of %s failed: %s", app, exc)
                    continue
                for pr in problems:
                    if not self.svc.gk.first_time(f"k8s:{pr['kind']}:{project.name}:{pr['pod']}:{hour}"):
                        continue
                    head = f"Pod {pr['pod']}: {pr['restarts']} restarts" + (f", {pr['waiting']}" if pr["waiting"] else "") + f" (limit {cfg.alerts.restart_limit})"
                    try:
                        lines = [head, *clean_lines(self.kube.logs(k.namespace, k.deployment, 30), cfg.alerts.evidence_lines)]
                    except KubeError:
                        lines = [head]
                    self.svc.raise_alert(project, app, pr["kind"], lines, "", audit_action=pr["kind"], pod=pr["pod"])
                    raised += 1
        owner = next(((p, k) for p in cfg.projects.values() for k in p.k8s_apps.values()), None)
        if owner:
            project, k = owner
            for node in self.kube.disk_pressure(k.namespace):
                if self.svc.gk.first_time(f"k8s:disk:{node}:{hour}"):
                    self.svc.raise_alert(project, f"node {node}", "disk_over_threshold", [f"Node {node} reports DiskPressure (the kubelet is short of disk)"], "",
                                         audit_action="disk_over_threshold", node=node)
                    raised += 1
        return raised
