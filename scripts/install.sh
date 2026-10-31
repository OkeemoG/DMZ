#!/bin/bash
set -e

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends curl make ca-certificates

curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"

sudo usermod -aG docker,clab_admins "$USER"

exec su -l "$USER"
