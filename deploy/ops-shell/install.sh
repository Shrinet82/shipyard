#!/usr/bin/env bash
# Install the restricted diagnostics account on the production VM. Run there as a sudo-capable user:
#   sudo bash install.sh "<public key line>" <allowed-source-ip>
# Creates `shipyard-ops` (no sudo, no groups, no password), installs the wrapper and the allowlist, and pins
# the account in sshd to the forced command with no tty and no forwarding.
set -euo pipefail
PUBKEY=${1:?public key line}; FROM=${2:?address the Gatekeeper connects from}
HERE=$(cd "$(dirname "$0")" && pwd)
id shipyard-ops >/dev/null 2>&1 || useradd -m -s /bin/bash -c "Shipyard diagnostics (forced command)" shipyard-ops
passwd -l shipyard-ops >/dev/null
install -d -m 755 /usr/local/lib/shipyard-ops
install -m 644 -o root -g root "$HERE/shellrules.py" /usr/local/lib/shipyard-ops/shellrules.py
install -m 755 -o root -g root "$HERE/shipyard-ops-shell" /usr/local/bin/shipyard-ops-shell
install -d -m 700 -o shipyard-ops -g shipyard-ops /home/shipyard-ops/.ssh
printf 'command="/usr/local/bin/shipyard-ops-shell",from="%s",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n' \
  "$FROM" "$PUBKEY" > /home/shipyard-ops/.ssh/authorized_keys
chown shipyard-ops:shipyard-ops /home/shipyard-ops/.ssh/authorized_keys; chmod 600 /home/shipyard-ops/.ssh/authorized_keys
cat > /etc/ssh/sshd_config.d/shipyard-ops.conf <<CONF
Match User shipyard-ops
    ForceCommand /usr/local/bin/shipyard-ops-shell
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PasswordAuthentication no
    PermitUserRC no
CONF
sshd -t                      # refuse to reload on a bad config: never lock out the admin
systemctl reload ssh
echo "installed: shipyard-ops groups = $(id -nG shipyard-ops)"
