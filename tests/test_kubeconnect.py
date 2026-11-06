import base64
import json
import os

import pytest
import yaml

from shipyard.config import load_config
from shipyard.confedit import edit_config
from shipyard.kubeconnect import ConnectError, KubeConnect, choose, config_changes, kubeconfig_text, rbac_manifest

CA = base64.b64encode(b"CERT").decode()


class FakeCluster:
    """Answers the kubectl calls KubeConnect makes."""
    def __init__(self, admin=True, can=None, tokens_after=0, namespaces=("shop", "kube-system", "shipyard-system"), deployments=("web", "api")):
        self.calls, self.applied, self.token_polls = [], [], 0
        self.admin, self.tokens_after = admin, tokens_after
        self.namespaces, self.deployments = namespaces, deployments
        # what each credential may do: (role, verb, resource) -> bool
        self.can = can if can is not None else {("viewer", "get", "pods"): True, ("deployer", "patch", "deployments"): True, ("ops", "create", "pods/exec"): True}

    def __call__(self, argv, stdin=None):
        self.calls.append(list(argv))
        a = list(argv)
        if "--kubeconfig" in a:                                     # a Shipyard credential, not the admin
            cfg = a[a.index("--kubeconfig") + 1]
            role = os.path.basename(cfg).split(".")[0]
            i = a.index("can-i")
            verb, res = a[i + 1], a[i + 2]
            sub = [x.split("=", 1)[1] for x in a if x.startswith("--subresource=")]
            if sub:
                res += "/" + sub[0]                                                # as kubectl wants it: `pods` with --subresource=exec
            return 0, ("yes" if self.can.get((role, verb, res), False) else "no"), ""
        if a[1:3] == ["auth", "can-i"]:
            return (0, "yes", "") if self.admin else (1, "no", "")
        if a[1:3] == ["config", "current-context"]:
            return 0, "k3d-shipyard\n", ""
        if a[1:3] == ["get", "namespaces"]:
            return 0, json.dumps({"items": [{"metadata": {"name": n}} for n in self.namespaces]}), ""
        if a[1:3] == ["get", "deployments"]:
            return 0, json.dumps({"items": [{"metadata": {"name": d}} for d in self.deployments]}), ""
        if a[1:3] == ["config", "view"]:
            return 0, json.dumps({"clusters": [{"cluster": {"server": "https://10.0.0.1:6443", "certificate-authority-data": CA}}]}), ""
        if a[1] == "apply":
            self.applied.append(stdin)
            return 0, "applied", ""
        if a[1:3] == ["get", "secret"]:
            self.token_polls += 1
            if self.token_polls <= self.tokens_after * 3:
                return 0, "", ""
            role = a[3].split("-")[1]
            return 0, base64.b64encode(f"token-{role}".encode()).decode(), ""
        return 1, "", "unexpected: " + " ".join(a)


def kc(cluster, **kw):
    return KubeConnect(run=cluster, say=lambda s: None, sleep=lambda n: None, **kw)


def docs(text):
    return list(yaml.safe_load_all(text))


def test_the_manifest_gives_each_account_only_its_own_rights():
    d = docs(rbac_manifest("shop"))
    kinds = [(x["kind"], x["metadata"]["name"]) for x in d]
    assert ("Namespace", "shipyard-system") in kinds and all(("ServiceAccount", f"shipyard-{r}") in kinds for r in ("viewer", "deployer", "ops"))
    roles = {x["metadata"]["name"]: x["rules"] for x in d if x["kind"] == "Role"}
    assert roles["shipyard-deployer"] == [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch", "update"]},
                                          {"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get", "patch", "update"]}]
    assert roles["shipyard-ops"] == [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}, {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]
    flat = json.dumps(roles)
    assert "secrets" not in flat and "delete" not in flat and "*" not in flat
    for x in d:                                            # bindings live in the person's namespace and point at accounts in ours; no cluster-wide grant
        assert x["kind"] != "ClusterRoleBinding"
        if x["kind"] in ("RoleBinding", "Role"):
            assert x["metadata"]["namespace"] == "shop"
        if x["kind"] == "RoleBinding":
            assert x["subjects"][0]["namespace"] == "shipyard-system"
    views = [x for x in d if x["kind"] == "RoleBinding" and x["roleRef"]["name"] == "view"]
    assert {v["subjects"][0]["name"] for v in views} == {"shipyard-viewer", "shipyard-deployer"}


def test_connect_applies_writes_private_kubeconfigs_and_proves_each_credential(tmp_path):
    c = FakeCluster()
    out = kc(c).connect("shop", ["web"], tmp_path / "kube")
    assert out["server"] == "https://10.0.0.1:6443" and len(c.applied) == 1 and "shipyard-system" in c.applied[0]
    for role in ("viewer", "deployer", "ops"):
        f = tmp_path / "kube" / f"{role}.kubeconfig"
        assert oct(f.stat().st_mode & 0o777) == "0o600"
        cfg = yaml.safe_load(f.read_text())
        assert cfg["users"][0]["user"]["token"] == f"token-{role}" and cfg["clusters"][0]["cluster"]["certificate-authority-data"] == CA
        assert cfg["contexts"][0]["context"]["namespace"] == "shop"
    assert oct((tmp_path / "kube").stat().st_mode & 0o777) == "0o700"
    probes = [a for a in c.calls if "can-i" in a and "--kubeconfig" in a]
    assert any("--subresource=exec" in a for a in probes) and not any("pods/exec" in a for a in probes)        # `pods/exec` would be read as a pod NAME


def test_connect_fails_if_a_credential_can_do_too_much_or_too_little(tmp_path):
    greedy = FakeCluster(can={("viewer", "get", "pods"): True, ("viewer", "get", "secrets"): True, ("deployer", "patch", "deployments"): True, ("ops", "create", "pods/exec"): True})
    with pytest.raises(ConnectError, match="viewer credential can get secrets"):
        kc(greedy).connect("shop", ["web"], tmp_path / "k")
    weak = FakeCluster(can={("viewer", "get", "pods"): True})
    with pytest.raises(ConnectError, match="deployer credential cannot patch deployments"):
        kc(weak).connect("shop", ["web"], tmp_path / "k2")


def test_without_admin_rights_it_stops_before_changing_anything():
    c = FakeCluster(admin=False)
    with pytest.raises(ConnectError, match="cannot create serviceaccounts"):
        kc(c).check_access()
    assert not c.applied


def test_it_waits_for_the_cluster_to_issue_tokens_and_gives_up_politely():
    c = FakeCluster(tokens_after=2)
    assert kc(c).tokens(wait=30)["ops"] == "token-ops" and c.token_polls > 3
    stuck = FakeCluster(tokens_after=10 ** 6)
    k = KubeConnect(run=stuck, say=lambda s: None, sleep=lambda n: None)
    import shipyard.kubeconnect as m
    real = m.time.time
    t = iter(range(0, 10 ** 6, 20))
    m.time.time = lambda: next(t)
    try:
        with pytest.raises(ConnectError, match="did not issue"):
            k.tokens(wait=30)
    finally:
        m.time.time = real


def test_names_are_validated_before_they_reach_kubectl(tmp_path):
    for bad in ("Shop", "a b", "x;rm", "--all"):
        with pytest.raises(ConnectError, match="not a valid Kubernetes name"):
            kc(FakeCluster()).connect(bad, ["web"], tmp_path)
    with pytest.raises(ConnectError):
        kc(FakeCluster()).connect("shop", ["../web"], tmp_path)


def test_a_cluster_without_a_ca_is_refused():
    class NoCa(FakeCluster):
        def __call__(self, argv, stdin=None):
            if list(argv)[1:3] == ["config", "view"]:
                return 0, json.dumps({"clusters": [{"cluster": {"server": "https://x"}}]}), ""
            return super().__call__(argv, stdin)
    with pytest.raises(ConnectError, match="certificate authority"):
        kc(NoCa()).cluster()


def replies(*texts):
    it = iter(texts)
    return lambda q: next(it)


def test_choose_by_number_name_flag_and_all():
    c = FakeCluster()
    said = []
    assert choose(kc(c), "", "", replies("1", "2,api"), said.append) == ("shop", ["web", "api"])          # numbers and names mix
    assert "  1. shop" in said and "  2. web" in said and not any("kube-system" in x or "shipyard-system" in x for x in said)
    assert choose(kc(c), "", "", replies("shop", "all"), said.append) == ("shop", ["api", "web"])
    assert choose(kc(c), "shop", "web", lambda q: "", lambda x: None) == ("shop", ["web"])
    with pytest.raises(ConnectError, match="no deployment called nope"):
        choose(kc(c), "shop", "nope", lambda q: "", lambda x: None)
    with pytest.raises(ConnectError, match="no deployments"):
        choose(kc(FakeCluster(deployments=())), "shop", "", lambda q: "", lambda x: None)


BASE = """
projects:
  demo:
    rooms: {ops: [r1], maintainers: [r2]}
    apps: {web: web-uuid}
    members: {}
actions:
  k8s.status: read
"""


def test_config_changes_add_the_block_and_apps_and_never_clobber_an_existing_app(tmp_path):
    conf = tmp_path / "shipyard.yaml"
    conf.write_text(BASE)
    result = {"kubeconfigs": {"viewer": "/v", "deployer": "/d", "ops": "/o"}, "namespace": "shop", "deployments": ["web", "api"]}
    added = []
    edit_config(conf, lambda raw: added.extend(config_changes(raw, None, result)))
    assert added == ["web-k8s", "api"]                         # `web` is already a Coolify app: the new one gets a suffix
    cfg = load_config(conf)
    assert cfg.projects["demo"].apps == {"web": "web-uuid"} and set(cfg.projects["demo"].k8s_apps) == {"web-k8s", "api"}
    assert cfg.kube.kubeconfigs == {"viewer": "/v", "deployer": "/d", "ops": "/o"}
    again = []
    edit_config(conf, lambda raw: again.extend(config_changes(raw, None, result)))        # running it again changes nothing important
    assert again == ["web-k8s", "api"] and set(load_config(conf).projects["demo"].k8s_apps) == {"web-k8s", "api"}


def test_kubeconfig_text_is_a_complete_single_context_file():
    cfg = yaml.safe_load(kubeconfig_text("viewer", "https://s", CA, "tok", "shop"))
    assert cfg["current-context"] == "viewer" and cfg["clusters"][0]["cluster"]["server"] == "https://s"
