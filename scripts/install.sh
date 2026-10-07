#!/bin/bash
set -e
curl -sL https://containerlab.dev/setup | sudo -E bash -s "all"
sudo usermod -aG docker,clab_admins "$USER"
