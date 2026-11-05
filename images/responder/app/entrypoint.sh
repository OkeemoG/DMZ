#!/bin/sh
set -e
mkdir -p /home/responder/.ssh /run/responder
cp /etc/responder/keys/responder.key /home/responder/.ssh/id
cp /etc/responder/keys/known_hosts /home/responder/.ssh/known_hosts
chown -R responder:responder /home/responder/.ssh /run/responder
chmod 700 /home/responder/.ssh
chmod 600 /home/responder/.ssh/id
exec su-exec responder python3 /opt/responder/responder.py
