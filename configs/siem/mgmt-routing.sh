#!/bin/sh
set -e
gw=$(ip -4 route show default dev eth0 | awk '{print $3; exit}')
addr=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 >/dev/null
ip route replace default via 10.10.30.1 dev eth1
ip route add default via "$gw" dev eth0 table 100
ip rule add from "$addr" lookup 100
