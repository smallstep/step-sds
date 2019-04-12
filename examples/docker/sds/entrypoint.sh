#!/bin/sh

set -e

step ca bootstrap -f --ca-url $STEP_CA_URL --fingerprint $STEP_FINGERPRINT

exec "$@"