#!/usr/bin/env bash
# Optional: run the Ops and Repo agents (Codex) on this machine. Needs Switch running here (scripts/install-switch.sh) with agent_management on.
# Installs Node 22, the Codex CLI and Switch's headless agent controller, then runs scripts/isolate_agents.sh, which enrolls the controller and
# runs it as the unprivileged user `agentrun`. The one step left for a person is printed at the end: the Codex login.
set -euo pipefail
CONTROLLER_VERSION=${CONTROLLER_VERSION:-0.31.0}      # must match the Switch release (install-switch.sh pins 0.31.0)
CODEX_VERSION=${CODEX_VERSION:-0.166.0}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! (command -v node >/dev/null && node -v | grep -q '^v22'); then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - >/dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >/dev/null
fi
sudo npm install -g --silent "@openai/codex@$CODEX_VERSION" \
  "https://github.com/sandbox-quantum/switch/releases/download/switch-agent-controller-v$CONTROLLER_VERSION/switch-agent-controller-$CONTROLLER_VERSION.tgz"
bash "$HERE/isolate_agents.sh"
