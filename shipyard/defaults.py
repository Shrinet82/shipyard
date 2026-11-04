"""What a new project starts with: the permission tiers. Written into shipyard.yaml by `shipyard init`, where the owner can edit them."""
from __future__ import annotations

ACTIONS = {
    "coolify.status": "read", "coolify.logs": "read", "coolify.history": "read",
    "k8s.status": "read", "k8s.logs": "read", "k8s.events": "read",
    "repo.pr_list": "read", "repo.pr_status": "read", "repo.digest": "read", "audit.read": "read", "sbom.read": "read",
    "coolify.deploy": "change", "coolify.restart": "change", "coolify.rollback": "change",
    "k8s.restart": "change", "k8s.rollback": "change", "k8s.scale": "change",
    "repo.merge": "dangerous", "ops.shell": "dangerous", "ops.exec": "dangerous", "secrets.read": "dangerous",
    "coolify.stop_prod": "dangerous", "coolify.delete": "dangerous", "deploy.override_cve_gate": "dangerous",
    "ops.firewall": "blocked", "repo.force_push_main": "blocked",
}
MIN_ROLE = {"ops.shell": "owner", "ops.exec": "owner"}
APPROVAL_OVERRIDES = {"coolify.rollback": True, "k8s.rollback": True}
