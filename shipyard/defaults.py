"""What a new project starts with: the permission tiers. Written into shipyard.yaml by `shipyard init`, where the owner can edit them."""
from __future__ import annotations

ACTIONS = {
    "coolify.status": "read", "coolify.logs": "read", "coolify.history": "read",
    "k8s.status": "read", "k8s.logs": "read", "k8s.events": "read",
    "repo.pr_list": "read", "repo.pr_status": "read", "repo.ci": "read", "repo.digest": "read", "repo.suggestions": "read", "audit.read": "read", "sbom.read": "read",
    "coolify.deploy": "change", "coolify.restart": "change", "coolify.rollback": "change",
    "coolify.exec": "change", "k8s.exec": "change",         # allowlisted read-only diagnostics inside a container or pod
    "k8s.restart": "change", "k8s.rollback": "change", "k8s.scale": "change",
    "repo.merge": "dangerous", "repo.apply_suggestion": "dangerous", "ticket.delete": "dangerous", "ops.shell": "dangerous", "secrets.read": "dangerous",
    "coolify.stop_prod": "dangerous", "coolify.delete": "dangerous", "deploy.override_cve_gate": "dangerous",
    "ops.firewall": "blocked", "repo.force_push_main": "blocked",
}
MIN_ROLE = {"ops.shell": "owner", "coolify.exec": "maintainer", "k8s.exec": "maintainer", "ticket.delete": "owner"}
APPROVAL_OVERRIDES = {"coolify.rollback": True, "k8s.rollback": True}
