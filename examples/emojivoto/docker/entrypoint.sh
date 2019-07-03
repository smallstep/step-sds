#!/bin/sh
set -e
ulimit -n 65536
# Start step-sds
step-sds run /run/step/config/sds.json --provisioner-password-file /run/step/secrets/password &
sleep 5
# Start envoy proxy
/usr/local/bin/envoy -c /run/envoy/server.yaml --service-cluster $SERVICE_CLUSTER --service-node $SERVICE_NODE &
sleep 5
# Start emojivoto service
cd /usr/local/bin
exec "$@"