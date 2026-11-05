#!/usr/bin/env bash
# Manage the Shipyard dev VMs (AWS profile new-account, Mumbai). SY_ENV=shipyard2 addresses the trial install's VMs instead of the originals.
#   scripts/vm.sh status | start | stop | ssh build|coolify [cmd...] | put <local> <remote-path-on-build> | myip | tunnel [mattermost] [switch]
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-new-account} AWS_REGION=ap-south-1
KEY=$HOME/.ssh/shipyard-dev
ENVNAME=${SY_ENV:-shipyard}            # which set of VMs: the original (shipyard) or a trial install (SY_ENV=shipyard2)
SG_NAME=${ENVNAME}-sg

ids() { aws ec2 describe-instances --filters Name=tag:Project,Values=$ENVNAME Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text; }

status() {
  aws ec2 describe-instances --filters Name=tag:Project,Values=$ENVNAME Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,InstanceType,State.Name,PublicIpAddress,PrivateIpAddress]' --output table
}

ip_of() { aws ec2 describe-instances --filters Name=tag:Name,Values=${ENVNAME}-$1 Name=instance-state-name,Values=running \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text; }

case "${1:-status}" in
  status) status ;;
  start)  aws ec2 start-instances --instance-ids $(ids) >/dev/null; aws ec2 wait instance-running --instance-ids $(ids); status
          echo "Public IPs changed. If your home IP changed too, run: scripts/vm.sh myip" ;;
  stop)   aws ec2 stop-instances --instance-ids $(ids) >/dev/null; echo "stopping; disks still bill (~\$0.36/day)"; status ;;
  ssh)    host=$(ip_of "$2"); shift 2; exec ssh ${SSH_TTY:+-t} -i "$KEY" -o StrictHostKeyChecking=accept-new ubuntu@"$host" "$@" ;;
  put)    host=$(ip_of build); exec scp -i "$KEY" -o StrictHostKeyChecking=accept-new "$2" ubuntu@"$host":"$3" ;;
  tunnel) host=$(ip_of build); fwd=(); shift
          busy() { (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }          # something already listens on that local port (an earlier tunnel)
          want() { local name=$1 port=$2   # forward a port unless an earlier tunnel already holds it
            if busy "$port"; then echo "$name: already forwarded by another tunnel on http://localhost:$port"; else fwd+=(-L "$port:localhost:$port"); echo "$name on http://localhost:$port"; fi; }
          want "Shipyard dashboard" 8780
          for what in "$@"; do case "$what" in
            mattermost) want "Mattermost" 8065 ;;
            switch)     want "Switch Console" 8000 ;;
            *) echo "unknown tunnel target: $what (use mattermost and/or switch)"; exit 2 ;; esac; done
          [ ${#fwd[@]} -gt 0 ] || { echo "nothing new to forward"; exit 0; }
          echo "(Ctrl-C closes the tunnel)"
          exec ssh -N -i "$KEY" -o StrictHostKeyChecking=accept-new -o ExitOnForwardFailure=yes "${fwd[@]}" ubuntu@"$host" ;;
  myip)   sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          me=$(curl -s https://checkip.amazonaws.com)/32
          for port in 22 8000; do
            old=$(aws ec2 describe-security-groups --group-ids "$sg" --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\`].IpRanges[].CidrIp" --output text)
            for c in $old; do aws ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port $port --cidr "$c" >/dev/null; done
            aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port $port --cidr "$me" >/dev/null
          done; echo "ports 22 and 8000 now open to $me only" ;;
  *) echo "usage: $0 status|start|stop|ssh build|coolify [cmd]|put <local> <remote>|myip|tunnel [mattermost] [switch]"; exit 2 ;;
esac
