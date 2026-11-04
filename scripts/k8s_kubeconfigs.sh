#!/usr/bin/env bash
# Build one kubeconfig per ServiceAccount from the cluster. Run on the build VM as the platform user (needs sudo
# for the root-only admin kubeconfig). Writes:
#   ~/kube/{viewer,deployer,ops}.kubeconfig        (0600, the Gatekeeper)
#   /home/agentrun/kube/viewer.kubeconfig          (0600, the agents' read-only MCP server)
set -euo pipefail
ADMIN=(sudo kubectl --kubeconfig /etc/shipyard/admin.kubeconfig)
SERVER=${SERVER:-https://127.0.0.1:6443}
AGENT_USER=${AGENT_USER:-agentrun}
CA=$(mktemp); trap 'rm -f "$CA"' EXIT
"${ADMIN[@]}" config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$CA"
mkdir -p ~/kube && chmod 700 ~/kube
for role in viewer deployer ops; do
  TOKEN=$("${ADMIN[@]}" -n demo get secret "shipyard-$role-token" -o jsonpath='{.data.token}' | base64 -d)
  F=~/kube/$role.kubeconfig; rm -f "$F"
  kubectl config --kubeconfig="$F" set-cluster shipyard --server="$SERVER" --certificate-authority="$CA" --embed-certs=true >/dev/null
  kubectl config --kubeconfig="$F" set-credentials "shipyard-$role" --token="$TOKEN" >/dev/null
  kubectl config --kubeconfig="$F" set-context "$role" --cluster=shipyard --user="shipyard-$role" --namespace=demo >/dev/null
  kubectl config --kubeconfig="$F" use-context "$role" >/dev/null
  chmod 600 "$F"
done
if id "$AGENT_USER" >/dev/null 2>&1; then
  sudo install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 700 "/home/$AGENT_USER/kube"
  sudo install -o "$AGENT_USER" -g "$AGENT_USER" -m 600 ~/kube/viewer.kubeconfig "/home/$AGENT_USER/kube/viewer.kubeconfig"
fi
echo "kubeconfigs written"
