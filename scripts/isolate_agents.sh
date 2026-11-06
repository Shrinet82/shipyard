#!/usr/bin/env bash
# Run the Switch agent controller (and so every agent) as a dedicated unprivileged Linux user.
#
# Why: agents run shell tools. As the platform's own user they can read its secrets (the Switch .env,
# Coolify and GitHub keys, the cluster admin kubeconfig) and use Docker. As `agentrun` they cannot:
# no sudo, no docker group, and a systemd unit that hides the platform user's home, /root and /etc/shipyard.
#
# Run on the build VM as the platform user (needs sudo):  bash scripts/isolate_agents.sh
# Idempotent. Steps that need a person (the Codex login) are printed at the end.
set -euo pipefail
AGENT_USER=${AGENT_USER:-agentrun}
PLATFORM_USER=${PLATFORM_USER:-$USER}
PLATFORM_HOME=$(getent passwd "$PLATFORM_USER" | cut -d: -f6)
SWITCH_ENV=${SWITCH_ENV:-$HOME/switch/.env}
BASE=${BASE:-http://localhost:8000}

id "$AGENT_USER" >/dev/null 2>&1 || sudo useradd -m -s /bin/bash "$AGENT_USER"
sudo chmod 750 "/home/$AGENT_USER"
sudo -u "$AGENT_USER" mkdir -p "/home/$AGENT_USER/agents" "/home/$AGENT_USER/.codex"
echo "groups of $AGENT_USER: $(id -nG "$AGENT_USER")"

STATE="/home/$AGENT_USER/.local/state/switch/agent-controller"
if ! sudo test -d "$STATE"; then
  # one-time enrollment code from the Gateway (admin login), never printed
  set -a; . "$SWITCH_ENV"; set +a
  JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
  curl -s -c "$JAR" -o /dev/null -X POST "$BASE/gateway/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$GATEWAY_ADMIN_EMAIL\",\"password\":\"$GATEWAY_ADMIN_PASSWORD\"}"
  CODE=$(curl -s -b "$JAR" -X POST "$BASE/gateway/management/enrollment-codes" -H 'Content-Type: application/json' -d '{}' \
         | python3 -c 'import sys,json; print(json.load(sys.stdin)["code"])')
  sudo -u "$AGENT_USER" -H env HOME="/home/$AGENT_USER" switch-agent-controller enroll --server "$BASE" --code "$CODE" \
    --name shipyard-agents --description "Shipyard agents, isolated user" 2>&1 | grep -v -i "experimental\|trace-warn" | head -3
fi

sudo tee /etc/systemd/system/switch-agents.service >/dev/null <<EOF
[Unit]
Description=Switch agent controller, isolated as $AGENT_USER
After=network-online.target docker.service

[Service]
User=$AGENT_USER
Group=$AGENT_USER
WorkingDirectory=/home/$AGENT_USER
Environment=HOME=/home/$AGENT_USER XDG_STATE_HOME=/home/$AGENT_USER/.local/state
ExecStart=/usr/bin/switch-agent-controller run
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/home/$AGENT_USER
InaccessiblePaths=-$PLATFORM_HOME -/root -/etc/shipyard
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now switch-agents.service
sleep 4
systemctl is-active switch-agents.service
cat <<MSG

Next, as a person (once): sign the agents' provider in as $AGENT_USER, because they no longer share $PLATFORM_USER's login:
  sudo -u $AGENT_USER -H codex login --device-auth
MSG
