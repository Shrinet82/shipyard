#!/usr/bin/env bash
# A clean place to try Shipyard on: Docker, a k3d Kubernetes cluster running three pods of a small web app (github.com/Shrinet82/namaste-app),
# and SigNoz receiving the pods' logs. It does not install Shipyard: run the guided installer after it.
# Run on a blank Ubuntu 24.04 machine (4 vCPU and 16 GB is comfortable) as a sudo-capable user:  bash scripts/lab-setup.sh
set -euo pipefail
APP_REPO=${APP_REPO:-https://github.com/Shrinet82/namaste-app}
APP_DIR=${APP_DIR:-$HOME/namaste-app}
step() { printf '\n== %s\n' "$*"; }

step "1/5 Docker, kubectl, k3d"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io git curl python3-yaml openssl >/dev/null
sudo systemctl enable --now docker >/dev/null 2>&1
sudo usermod -aG docker "$USER"
command -v kubectl >/dev/null || { curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install -m 755 /tmp/kubectl /usr/local/bin/kubectl; }
command -v k3d >/dev/null || curl -fsSL https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | sudo bash >/dev/null 2>&1

step "2/5 Kubernetes cluster 'lab'"
sudo k3d cluster list 2>/dev/null | grep -q '^lab' || sudo k3d cluster create lab --api-port 127.0.0.1:6443 --servers 1 --agents 0 --wait >/dev/null 2>&1
mkdir -p ~/.kube && chmod 700 ~/.kube
sudo k3d kubeconfig get lab > ~/.kube/config && chmod 600 ~/.kube/config            # your own admin access; Shipyard uses it once and never stores it
kubectl get nodes

step "3/5 The app: three pods of namaste"
if [ -d "$APP_DIR/.git" ]; then git -C "$APP_DIR" pull -q --ff-only; else git clone -q "$APP_REPO" "$APP_DIR"; fi
sudo docker build -q -t namaste:local "$APP_DIR" >/dev/null
sudo k3d image import namaste:local -c lab >/dev/null
kubectl apply -f "$APP_DIR/deploy/k8s.yaml" >/dev/null
kubectl -n namaste rollout status deploy/namaste --timeout=180s
kubectl -n namaste get pods

step "4/5 SigNoz (about 3 GB of memory)"
mkdir -p ~/signoz && cd ~/signoz
export PATH="$HOME/.local/bin:$PATH"
[ -x ~/.local/bin/foundryctl ] || curl -fsSL https://signoz.io/foundry.sh | bash -s -- -d ~/.local/bin >/dev/null
cat > casting.yaml <<'Y'
apiVersion: v1alpha1
kind: Installation
metadata:
  name: signoz
spec:
  deployment:
    flavor: compose
    mode: docker
Y
foundryctl gauge -f casting.yaml >/dev/null 2>&1 || true            # checks the machine; its lock file is what forge builds on
foundryctl forge -f casting.yaml >/dev/null || { echo "foundryctl forge failed; run it by hand in ~/signoz to see why"; exit 1; }
( cd pours/deployment && sudo docker compose up -d >/dev/null 2>&1 )
printf 'waiting for SigNoz'
for _ in $(seq 1 90); do curl -fs http://localhost:8080/api/v2/healthz >/dev/null 2>&1 && break; printf '.'; sleep 5; done; echo
curl -fs http://localhost:8080/api/v2/healthz >/dev/null || { echo "SigNoz did not come up; check: cd ~/signoz/pours/deployment && sudo docker compose ps"; exit 1; }

step "5/5 Some traffic, so there are logs to look at"
bash "$(dirname "${BASH_SOURCE[0]}")/lab-traffic.sh" ok 20 || true

cat <<MSG

Ready.
  Kubernetes   kubectl -n namaste get pods        (3 pods)
  SigNoz       http://localhost:8080 through an SSH tunnel (no account yet: connect it with  python3 -m shipyard connect signoz --bootstrap)
  More logs    bash scripts/lab-traffic.sh ok 30     greetings
               bash scripts/lab-traffic.sh boom 5    errors, so an alert fires
Next: the guided installer  ->  curl -fsSL https://raw.githubusercontent.com/Shrinet82/shipyard/main/scripts/install.sh | bash
MSG
