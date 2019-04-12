#!/bin/sh

set -e

step ca bootstrap -f --ca-url $STEP_CA_URL --fingerprint $STEP_FINGERPRINT
step-sds run /src/sds.json --provisioner-password-file /run/secrets/password &
sleep 5
exec "$@"