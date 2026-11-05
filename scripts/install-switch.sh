#!/usr/bin/env bash
# Optional: a local Switch (Docker, pinned 0.31.0 images, bundled Mattermost) for a machine that does not have one yet.
# Verified on a clean Ubuntu 24.04 t3.large. Shipyard's own installer (scripts/install.sh) comes after this.
set -euo pipefail
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 git openssl python3-yaml >/dev/null
sudo usermod -aG docker "$USER"
[ -d ~/switch ] || git clone -q --depth 1 https://github.com/sandbox-quantum/switch.git ~/switch
cd ~/switch
if [ ! -f .env ]; then
  cp .env.example .env
  deploy/local/generate-env-secrets.sh .env shipyard          # fills every password and SECRET_KEYS
  sed -i 's|^SWITCH_VERSION=.*|SWITCH_VERSION=0.31.0|; s|^FEATURE_FLAGS_ENABLED=.*|FEATURE_FLAGS_ENABLED=agent_management|' .env
  # agent_management refuses to start without this signing secret, and .env.example ships it empty
  sed -i "s|^CONTROLLER_TOKEN_SECRET=.*|CONTROLLER_TOKEN_SECRET=$(openssl rand -hex 24)|" .env
fi
# --env-file matters: compose reads .env from the compose file's folder, not from here
sudo docker compose --env-file .env -f deploy/local/standalone-docker-compose.yml --profile collab --profile gateway up -d
# the compose file gives the containers no restart policy, so after a reboot Switch would stay down: start it from systemd
sudo tee /etc/systemd/system/switch-stack.service >/dev/null <<UNIT
[Unit]
Description=Switch and Mattermost (docker compose)
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$HOME/switch
ExecStart=/usr/bin/docker compose --env-file .env -f deploy/local/standalone-docker-compose.yml --profile collab --profile gateway up -d
ExecStop=/usr/bin/docker compose --env-file .env -f deploy/local/standalone-docker-compose.yml --profile collab --profile gateway stop

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable switch-stack.service >/dev/null 2>&1
for _ in $(seq 1 60); do curl -fs http://localhost:8000/health >/dev/null 2>&1 && break; sleep 3; done
curl -s http://localhost:8000/health; echo
echo "Switch is up. Its admin login is in ~/switch/.env. Next: scripts/install.sh"
