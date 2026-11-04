#!/usr/bin/env bash
# Manage the Shipyard dev VMs (AWS profile new-account, Mumbai).
#   scripts/vm.sh status | start | stop | ssh build|coolify [cmd...] | put <local> <remote-path-on-build> | myip
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
  myip)   sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          me=$(curl -s https://checkip.amazonaws.com)/32
          for port in 22 8000; do
            old=$(aws ec2 describe-security-groups --group-ids "$sg" --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\`].IpRanges[].CidrIp" --output text)
            for c in $old; do aws ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port $port --cidr "$c" >/dev/null; done
            aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port $port --cidr "$me" >/dev/null
          done; echo "ports 22 and 8000 now open to $me only" ;;
  *) echo "usage: $0 status|start|stop|ssh build|coolify [cmd]|put <local> <remote>|myip"; exit 2 ;;
esac
