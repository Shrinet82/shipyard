#!/usr/bin/env bash
# The project author's AWS helper for lab machines. It is NOT part of the install. For your own account set AWS_PROFILE, AWS_REGION,
# SY_KEY_NAME (an EC2 key pair) and SY_KEY_FILE (its private key); SY_ENV names the environment (VMs are tagged Project=<name>).
#   scripts/vm.sh status | start | stop | ssh build|coolify [cmd...] | put <local> <remote-path-on-build> | myip | tunnel [mattermost] [switch]
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-new-account} AWS_REGION=${AWS_REGION:-ap-south-1}
KEY=${SY_KEY_FILE:-$HOME/.ssh/shipyard-dev}
KEY_NAME=${SY_KEY_NAME:-shipyard-dev}
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
            signoz)     want "SigNoz" 8080 ;;
            github)     want "GitHub App setup page (open it only while \`shipyard github-app\` runs)" 8767 ;;
            *) echo "unknown tunnel target: $what (use mattermost, switch, signoz and/or github)"; exit 2 ;; esac; done
          [ ${#fwd[@]} -gt 0 ] || { echo "nothing new to forward"; exit 0; }
          echo "(Ctrl-C closes the tunnel)"
          exec ssh -N -i "$KEY" -o StrictHostKeyChecking=accept-new -o ExitOnForwardFailure=yes "${fwd[@]}" ubuntu@"$host" ;;
  create) # ONE blank Ubuntu 24.04 machine (SY_ENV names it, SY_TYPE sets the size). SSH is open to your current address only; nothing else is public.
          ami=$(aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text 2>/dev/null || echo ami-0fc5120b2d80d4749)
          vpc=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
          sg=$(aws ec2 create-security-group --group-name "$SG_NAME" --description "$ENVNAME: SSH from one address" --vpc-id "$vpc" --query GroupId --output text)
          aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 22 --cidr "$(curl -s https://checkip.amazonaws.com)/32" >/dev/null
          id=$(aws ec2 run-instances --image-id "$ami" --instance-type "${SY_TYPE:-t3.xlarge}" --key-name "$KEY_NAME" --security-group-ids "$sg" --associate-public-ip-address \
                 --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=80,VolumeType=gp3,DeleteOnTermination=true}' \
                 --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${ENVNAME}-build},{Key=Project,Value=$ENVNAME}]" "ResourceType=volume,Tags=[{Key=Project,Value=$ENVNAME}]" \
                 --query 'Instances[0].InstanceId' --output text)
          aws ec2 wait instance-running --instance-ids "$id"; status ;;
  destroy) # terminate this environment's machine(s) and delete its security group (the disks go with the machine)
          i=$(ids); [ -z "$i" ] || { aws ec2 terminate-instances --instance-ids $i >/dev/null; aws ec2 wait instance-terminated --instance-ids $i; }
          sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          [ "$sg" = None ] || aws ec2 delete-security-group --group-id "$sg"; echo "$ENVNAME deleted" ;;
  open)   # let YOUR current address (and nobody else) reach these ports of the machine, e.g.  vm.sh open 8080 8065
          [ $# -ge 2 ] || { echo "usage: $0 open <port> [port...]"; exit 2; }; shift
          sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          me=$(curl -s https://checkip.amazonaws.com)/32
          for port in "$@"; do [[ "$port" =~ ^[0-9]{2,5}$ ]] || { echo "bad port $port"; exit 2; }
            aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port "$port" --cidr "$me" >/dev/null 2>&1 || true
            echo "port $port open to $me only"; done ;;
  close)  # take those ports away again
          [ $# -ge 2 ] || { echo "usage: $0 close <port> [port...]"; exit 2; }; shift
          sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          for port in "$@"; do
            for c in $(aws ec2 describe-security-groups --group-ids "$sg" --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\`].IpRanges[].CidrIp" --output text); do
              aws ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port "$port" --cidr "$c" >/dev/null; done
            echo "port $port closed"; done ;;
  myip)   # your address changed: move every port that was open to you (SSH included) to the new one
          sg=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$SG_NAME --query 'SecurityGroups[0].GroupId' --output text)
          me=$(curl -s https://checkip.amazonaws.com)/32
          for port in $(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions[?IpRanges[0].CidrIp!=`null`].FromPort' --output text); do
            for c in $(aws ec2 describe-security-groups --group-ids "$sg" --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\`].IpRanges[].CidrIp" --output text); do
              aws ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port "$port" --cidr "$c" >/dev/null; done
            aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port "$port" --cidr "$me" >/dev/null
            echo "port $port now open to $me only"; done ;;
  *) echo "usage: $0 status|start|stop|ssh build|coolify [cmd]|put <local> <remote>|myip|open <port>...|close <port>...|create|destroy|tunnel [mattermost] [switch] [signoz] [github]"; exit 2 ;;
esac
