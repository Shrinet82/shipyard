#!/usr/bin/env bash
# Optional: a small Kubernetes cluster for the Gatekeeper's Kubernetes backend (status, logs, rollback, scale, exec). Installs kubectl and k3d,
# makes a one-node cluster called `shipyard`, applies deploy/k8s (the workload first, because it creates the `demo` namespace, then the
# RBAC) and writes the three least-privilege kubeconfigs with scripts/k8s_kubeconfigs.sh. Run on the Shipyard machine as a sudo-capable user.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
command -v kubectl >/dev/null || { curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install -m 755 /tmp/kubectl /usr/local/bin/kubectl; }
command -v k3d >/dev/null || curl -fsSL https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | sudo bash >/dev/null 2>&1
sudo k3d cluster list 2>/dev/null | grep -q '^shipyard' || sudo k3d cluster create shipyard --api-port 127.0.0.1:6443 --servers 1 --agents 0 --wait >/dev/null 2>&1
sudo mkdir -p /etc/shipyard
sudo k3d kubeconfig get shipyard | sudo tee /etc/shipyard/admin.kubeconfig >/dev/null && sudo chmod 600 /etc/shipyard/admin.kubeconfig
ADMIN=(sudo kubectl --kubeconfig /etc/shipyard/admin.kubeconfig)
"${ADMIN[@]}" apply -f "$HERE/deploy/k8s/workload.yaml" >/dev/null      # creates the demo namespace
"${ADMIN[@]}" apply -f "$HERE/deploy/k8s/rbac.yaml" >/dev/null
for _ in $(seq 1 30); do "${ADMIN[@]}" -n demo get secret shipyard-viewer-token -o jsonpath='{.data.token}' 2>/dev/null | grep -q . && break; sleep 2; done
"${ADMIN[@]}" -n demo rollout status deployment/demo-k8s --timeout=180s | tail -1
bash "$HERE/scripts/k8s_kubeconfigs.sh"
cat <<MSG

Kubernetes is ready. Add this to ~/shipyard.yaml, then restart the Gatekeeper:
  kubernetes: {kubectl: /usr/local/bin/kubectl, max_replicas: 10, kubeconfigs: {viewer: ~/kube/viewer.kubeconfig, deployer: ~/kube/deployer.kubeconfig, ops: ~/kube/ops.kubeconfig}}
and, under the project's apps:   demo-k8s: {backend: k8s, namespace: demo, deployment: demo-k8s}
MSG
