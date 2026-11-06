#!/usr/bin/env bash
# Send requests to the namaste pods from inside the cluster.   bash scripts/lab-traffic.sh ok [count]   |   bash scripts/lab-traffic.sh boom [count]
set -euo pipefail
what=${1:-ok}; n=${2:-10}
case "$what" in ok) path='/hello?lang=ta&name=Anya' ;; boom) path='/boom?order=A-17' ;; *) echo "usage: $0 ok|boom [count]"; exit 2 ;; esac
[[ "$n" =~ ^[0-9]{1,4}$ ]] || { echo "count must be a number"; exit 2; }
kubectl -n namaste delete pod traffic --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl -n namaste run traffic --rm -i --restart=Never --image=curlimages/curl:8.10.1 --quiet -- \
  sh -c "i=0; while [ \$i -lt $n ]; do curl -s -o /dev/null -w '%{http_code} ' 'http://namaste$path'; i=\$((i+1)); sleep 0.3; done; echo" 2>/dev/null || true
