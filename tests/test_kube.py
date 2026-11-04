import json

import pytest

from shipyard.kube import Kube, KubeError

DEP = {"metadata": {"name": "demo-k8s", "annotations": {"deployment.kubernetes.io/revision": "3"}},
       "spec": {"replicas": 2, "selector": {"matchLabels": {"app": "demo-k8s"}},
                "template": {"spec": {"containers": [{"image": "nginx:1.27-alpine"}]}}},
       "status": {"readyReplicas": 2}}
PODS = {"items": [
    {"metadata": {"name": "demo-k8s-aaa"}, "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0, "state": {}}]}},
    {"metadata": {"name": "demo-k8s-bbb"}, "status": {"phase": "Running", "containerStatuses": [{"restartCount": 4, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}}]}
EVENTS = {"items": [
    {"type": "Normal", "reason": "Scheduled", "message": "assigned", "involvedObject": {"kind": "Pod", "name": "demo-k8s-aaa"}},
    {"type": "Warning", "reason": "BackOff", "message": "restarting", "involvedObject": {"kind": "Pod", "name": "demo-k8s-bbb"}},
    {"type": "Normal", "reason": "Pulled", "message": "other app", "involvedObject": {"kind": "Pod", "name": "other-xyz"}}]}
HISTORY = "deployment.apps/demo-k8s\nREVISION  CHANGE-CAUSE\n1         <none>\n2         <none>\n3         <none>\n"


class Runner:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        if self.fail:
            return 1, "", self.fail
        a = " ".join(argv)
        if "get deployment" in a:
            return 0, json.dumps(DEP), ""
        if "get pods" in a:
            return 0, json.dumps(PODS), ""
        if "get events" in a:
            return 0, json.dumps(EVENTS), ""
        if "rollout history" in a:
            return 0, HISTORY, ""
        if " logs " in a:
            return 0, "[pod/demo-k8s-aaa/web] GET /\n[pod/demo-k8s-bbb/web] boom\n", ""
        if " exec " in a:
            return 0, "uid=0(root)\n", ""
        return 0, "", ""


def kube(runner=None, **kw):
    r = runner or Runner()
    return Kube({"viewer": "/k/viewer", "deployer": "/k/deployer", "ops": "/k/ops"}, runner=r, **kw), r


def test_status_summarises_the_deployment_and_pods():
    k, _ = kube()
    out = k.status("demo", "demo-k8s")
    assert "2/2 ready" in out and "nginx:1.27-alpine" in out and "revision 3" in out
    assert "demo-k8s-bbb CrashLoopBackOff (4 restarts)" in out


def test_reads_use_the_viewer_credential_and_the_configured_namespace():
    k, r = kube()
    k.status("demo", "demo-k8s"); k.logs("demo", "demo-k8s"); k.events("demo", "demo-k8s")
    assert all(c[:5] == ["kubectl", "--kubeconfig", "/k/viewer", "-n", "demo"] for c in r.calls)


def test_logs_select_pods_by_the_deployments_labels_and_cap_the_lines():
    k, r = kube()
    assert len(k.logs("demo", "demo-k8s", 99999)) == 2
    logs_call = next(c for c in r.calls if "logs" in c)
    assert "app=demo-k8s" in logs_call and logs_call[logs_call.index("--tail") + 1] == "200"


def test_events_are_filtered_to_the_app_and_limited():
    k, _ = kube()
    out = k.events("demo", "demo-k8s", limit=5)
    assert len(out) == 2 and any("BackOff" in e for e in out) and not any("other app" in e for e in out)


def test_restart_uses_the_deployer_credential_and_an_argument_list():
    k, r = kube()
    k.restart("demo", "demo-k8s")
    assert r.calls[-1] == ["kubectl", "--kubeconfig", "/k/deployer", "-n", "demo", "rollout", "restart", "deployment/demo-k8s"]


def test_rollback_needs_history_and_validates_the_revision():
    k, r = kube()
    k.rollback("demo", "demo-k8s")
    assert r.calls[-1][-3:] == ["rollout", "undo", "deployment/demo-k8s"] and "/k/deployer" in r.calls[-1]
    k.rollback("demo", "demo-k8s", "1")
    assert r.calls[-1][-1] == "--to-revision=1"
    for bad in ("3", "9", "x", "1;rm", "-1", ""):
        with pytest.raises(KubeError):
            k.rollback("demo", "demo-k8s", bad)


def test_rollback_with_a_single_revision_is_refused():
    class One(Runner):
        def __call__(self, argv, timeout):
            return (0, "REVISION CHANGE-CAUSE\n1 <none>\n", "") if "rollout history" in " ".join(argv) else super().__call__(argv, timeout)
    k, _ = kube(One())
    with pytest.raises(KubeError, match="no earlier revision"):
        k.rollback("demo", "demo-k8s")


@pytest.mark.parametrize("n", ["11", "9999", "-1", "1;rm -rf /", "abc", "", "1.5", " 3"])
def test_scale_is_capped_and_numeric(n):
    k, r = kube()
    with pytest.raises(KubeError):
        k.scale("demo", "demo-k8s", n)
    assert not any("scale" in c for c in r.calls)


def test_scale_within_the_cap():
    k, r = kube()
    assert "scaled to 3" in k.scale("demo", "demo-k8s", "3")
    assert r.calls[-1][-2:] == ["deployment/demo-k8s", "--replicas=3"] and "/k/deployer" in r.calls[-1]


@pytest.mark.parametrize("name", ["a;b", "x y", "A", "-x", "", "a/b", "$(id)", "a\nb"])
def test_invalid_names_never_reach_kubectl(name):
    k, r = kube()
    with pytest.raises(KubeError):
        k.restart("demo", name)
    with pytest.raises(KubeError):
        k.status(name, "demo-k8s")
    assert not r.calls


def test_exec_uses_the_ops_credential_a_running_pod_and_the_allowlist():
    k, r = kube()
    assert k.exec("demo", "demo-k8s", ["id"]) == ["uid=0(root)"]
    assert r.calls[-1] == ["kubectl", "--kubeconfig", "/k/ops", "-n", "demo", "exec", "demo-k8s-aaa", "--", "id"]
    for cmd in (["env"], ["sh", "-c", "id"], ["cat", "/etc/passwd"], ["printenv", "DEMO_PASSWORD"], []):
        with pytest.raises(KubeError):
            k.exec("demo", "demo-k8s", cmd)


def test_exec_without_a_running_pod():
    class NoPods(Runner):
        def __call__(self, argv, timeout):
            return (0, json.dumps({"items": []}), "") if "get pods" in " ".join(argv) else super().__call__(argv, timeout)
    with pytest.raises(KubeError, match="no running pod"):
        kube(NoPods())[0].exec("demo", "demo-k8s", ["id"])


def test_kubectl_failures_surface_as_errors_and_a_missing_credential_is_refused():
    k, _ = kube(Runner(fail="Error from server (Forbidden): secrets is forbidden\nfinal line"))
    with pytest.raises(KubeError, match="final line"):
        k.status("demo", "demo-k8s")
    with pytest.raises(KubeError, match="no deployer credential"):
        Kube({"viewer": "/k/viewer"}, runner=Runner()).restart("demo", "demo-k8s")


def test_nothing_is_ever_run_through_a_shell():
    k, r = kube()
    k.status("demo", "demo-k8s"); k.restart("demo", "demo-k8s"); k.scale("demo", "demo-k8s", "2"); k.exec("demo", "demo-k8s", ["ls", "/tmp"])
    for call in r.calls:
        assert call[0] == "kubectl" and "sh" not in call[:2] and "-c" not in call
