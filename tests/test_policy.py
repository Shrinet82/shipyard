from pathlib import Path
import sqlite3

import pytest

from shipyard.config import load_policy
from shipyard.gatekeeper import Gatekeeper
from shipyard.policy import Verdict, evaluate

OWNER = "discord:111111111111111111"
MAINT = "discord:222222222222222222"
DEPLOYER = "discord:333333333333333333"
VIEWER = "discord:444444444444444444"
STRANGER = "discord:999999999999999999"


@pytest.fixture
def policy():
    return load_policy(Path(__file__).parent / "policy_fixture.yaml")


@pytest.fixture
def clock():
    class Clock:
        t = 1_000_000.0

        def __call__(self):
            return self.t

    return Clock()


@pytest.fixture
def gk(policy, clock):
    return Gatekeeper(policy, sqlite3.connect(":memory:"), clock)


def ev(policy, who, action, target="app", is_human=True, args=None):
    return evaluate(policy, project="demo", identity=who, is_human=is_human, action=action, target=target, args=args)


# role x action -> expected verdict, table-driven
A, D, N = Verdict.ALLOW, Verdict.DENY, Verdict.NEEDS_APPROVAL
TABLE = {
    "coolify.status":   {OWNER: A, MAINT: A, DEPLOYER: A, VIEWER: A, STRANGER: D},
    "coolify.deploy":   {OWNER: A, MAINT: A, DEPLOYER: A, VIEWER: D, STRANGER: D},
    "coolify.rollback": {OWNER: N, MAINT: N, DEPLOYER: N, VIEWER: D, STRANGER: D},
    "repo.merge":       {OWNER: N, MAINT: N, DEPLOYER: D, VIEWER: D, STRANGER: D},
    "ops.shell":        {OWNER: N, MAINT: D, DEPLOYER: D, VIEWER: D, STRANGER: D},
    "secrets.read":     {OWNER: N, MAINT: N, DEPLOYER: D, VIEWER: D, STRANGER: D},
    "ops.firewall":     {OWNER: D, MAINT: D, DEPLOYER: D, VIEWER: D, STRANGER: D},
}


@pytest.mark.parametrize("action,who", [(a, w) for a, row in TABLE.items() for w in row])
def test_role_action_matrix(policy, action, who):
    assert ev(policy, who, action).verdict is TABLE[action][who]


def test_unknown_action_is_denied(policy):
    assert ev(policy, OWNER, "coolify.format_disk").verdict is D


def test_agent_sender_is_denied_even_if_identity_is_owner(policy):
    assert ev(policy, OWNER, "coolify.deploy", is_human=False).verdict is D


@pytest.mark.parametrize("target", ["app; rm -rf /", "app && curl x|sh", "$(id)", "a b", "", "`id`", "app\nrm"])
def test_shell_injection_in_target_is_denied(policy, target):
    assert ev(policy, OWNER, "coolify.deploy", target=target).verdict is D


def test_shell_injection_in_arg_value_is_denied(policy):
    assert ev(policy, OWNER, "k8s.scale", args={"replicas": "3; rm -rf /"}).verdict is D


@pytest.mark.parametrize(
    "cmd",
    ["rm -rf /", "rm -fr / ", "iptables -F", "git push --force origin main", "cat .env", "printenv TOKEN"],
)
def test_blocked_commands_denied_for_everyone(policy, cmd):
    assert ev(policy, OWNER, "ops.shell", args={"command": cmd}).verdict is D


def test_harmless_command_needs_approval(policy):
    assert ev(policy, OWNER, "ops.shell", args={"command": "df -h"}).verdict is N


# --- approvals ---------------------------------------------------------------

def req(gk, who=DEPLOYER, action="coolify.rollback", target="app"):
    return gk.request_action(project="demo", identity=who, is_human=True, action=action, target=target)


def approve(gk, oid, who=OWNER, human=True, action="coolify.rollback", target="app"):
    return gk.approve(approval_id=oid, project="demo", approver=who, approver_is_human=human, action=action, target=target)


def test_owner_approves_deployer_rollback(gk):
    out = req(gk)
    assert out.status == "awaiting_approval"
    assert approve(gk, out.approval_id).status == "approved"


def test_viewer_deploy_denied_deployer_runs_rollback_approved_and_all_audited(gk):
    assert gk.request_action(project="demo", identity=VIEWER, is_human=True, action="coolify.deploy", target="app").status == "denied"
    assert gk.request_action(project="demo", identity=DEPLOYER, is_human=True, action="coolify.deploy", target="app").status == "allowed"
    out = req(gk)
    approve(gk, out.approval_id)
    events = [r["event"] for r in gk.audit.recent("demo")]
    assert {"denied", "allowed", "approval_requested", "approved"} <= set(events)
    assert gk.audit.verify()


def test_agent_cannot_approve(gk):
    out = req(gk)
    assert approve(gk, out.approval_id, who=OWNER, human=False).status == "denied"


def test_requester_cannot_self_approve_unless_owner(gk):
    out = req(gk, who=MAINT, action="repo.merge", target="3")
    assert approve(gk, out.approval_id, who=MAINT, action="repo.merge", target="3").status == "denied"
    own = req(gk, who=OWNER, action="repo.merge", target="3")
    assert approve(gk, own.approval_id, who=OWNER, action="repo.merge", target="3").status == "approved"


def test_viewer_and_deployer_cannot_approve(gk):
    out = req(gk)
    assert approve(gk, out.approval_id, who=VIEWER).status == "denied"
    assert approve(gk, out.approval_id, who=DEPLOYER).status == "denied"


def test_approval_is_single_use(gk):
    out = req(gk)
    assert approve(gk, out.approval_id).status == "approved"
    assert approve(gk, out.approval_id).status == "denied"


def test_approval_not_reusable_for_a_different_action_or_target(gk):
    out = req(gk, who=MAINT, action="repo.merge", target="3")
    assert approve(gk, out.approval_id, action="repo.merge", target="4").status == "denied"
    assert approve(gk, out.approval_id, action="coolify.rollback", target="3").status == "denied"
    assert approve(gk, out.approval_id, action="repo.merge", target="3").status == "approved"


def test_approval_expires_after_timeout(gk, clock):
    out = req(gk)
    clock.t += 601
    assert approve(gk, out.approval_id).status == "expired"
    assert approve(gk, out.approval_id).status == "denied"


def test_unknown_approval_id_denied(gk):
    assert approve(gk, "deadbeef").status == "denied"


def test_audit_chain_detects_tampering(gk):
    req(gk)
    assert gk.audit.verify()
    gk.db.execute("UPDATE audit SET actor='someone-else' WHERE id=1")
    assert not gk.audit.verify()
