#!/bin/sh
set -e
mkdir -p /etc/ssh/response
chmod 700 /etc/ssh/response
cp /etc/response/keys/fw-edge_host.key /etc/ssh/response/host_key
cp /etc/response/keys/authorized_keys /etc/ssh/response/authorized_keys
chown root:root /etc/ssh/response/host_key /etc/ssh/response/authorized_keys
chmod 600 /etc/ssh/response/host_key /etc/ssh/response/authorized_keys
/usr/sbin/sshd -t -f /etc/response/sshd_config
/usr/sbin/sshd -f /etc/response/sshd_config
