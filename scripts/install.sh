#!/bin/bash
set -e

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends curl make ca-certificates

export CLAB_VERSION="${CLAB_VERSION:-0.82.0}"
curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"

sudo usermod -aG docker,clab_admins "$USER"

sudo bash "$(dirname "$0")/harden-host.sh" --restart

exec su -l "$USER"
