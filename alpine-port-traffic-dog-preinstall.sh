#!/bin/sh

set -e

apk update
apk add --no-cache bash nftables iproute2 iproute2-ss jq gawk bc unzip dcron ca-certificates

ln -sf /usr/sbin/crond /usr/local/bin/cron

crond -b

echo "Alpine dependencies installed and crond started."
