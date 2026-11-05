#!/usr/bin/env bash
# Manage the Shipyard dev VMs (AWS profile new-account, Mumbai).
#   scripts/vm.sh status | start | stop | ssh build|coolify [cmd...] | put <local> <remote-path-on-build> | myip | tunnel [mattermost]
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-new-account} AWS_REGION=ap-south-1
KEY=$HOME/.ssh/shipyard-dev
SG_NAME=shipyard-sg

ids() { aws ec2 describe-instances --filters Name=tag:Project,Values=shipyard Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text; }

status() {
  aws ec2 describe-instances --filters Name=tag:Project,Values=shipyard Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,InstanceType,State.Name,PublicIpAddress,PrivateIpAddress]' --output table
}

ip_of() { aws ec2 describe-instances --filters Name=tag:Name,Values=shipyard-$1 Name=instance-state-name,Values=running \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text; }

case "${1:-status}" in
  status) status ;;
  start)  aws ec2 start-instances --instance-ids $(ids) >/dev/null; aws ec2 wait instance-running --instance-ids $(ids); status
          echo "Public IPs changed. If your home IP changed too, run: scripts/vm.sh myip" ;;
  stop)   aws ec2 stop-instances --instance-ids $(ids) >/dev/null; echo "stopping; disks still bill (~\$0.36/day)"; status ;;
  ssh)    host=$(ip_of "$2"); shift 2; exec ssh ${SSH_TTY:+-t} -i "$KEY" -o StrictHostKeyChecking=accept-new ubuntu@"$host" "$@" ;;
  put)    host=$(ip_of build); exec scp -i "$KEY" -o StrictHostKeyChecking=accept-new "$2" ubuntu@"$host":"$3" ;;
  tunnel) host=$(ip_of build); fwd=()
          busy() { (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }          # something already listens on that local port (an earlier tunnel)
          if busy 8780; then echo "dashboard: already forwarded by another tunnel on http://localhost:8780"; else fwd+=(-L 8780:localhost:8780); echo "dashboard on http://localhost:8780"; fi
          if [ "${2:-}" = mattermost ]; then
            if busy 8065; then echo "Mattermost: already forwarded on http://localhost:8065"; else fwd+=(-L 8065:localhost:8065); echo "Mattermost on http://localhost:8065"; fi
          fi
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
  *) echo "usage: $0 status|start|stop|ssh build|coolify [cmd]|put <local> <remote>|myip|tunnel [mattermost]"; exit 2 ;;
esac
