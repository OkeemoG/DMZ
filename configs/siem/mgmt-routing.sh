#!/bin/sh
set -e
gw=$(ip -4 route show default dev eth0 | awk '{print $3; exit}')
addr=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 >/dev/null
nft -f - <<'RULES'
table inet mgmt {
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "eth0" ct state established,related accept
        iifname "eth0" tcp dport 3000 ct state new accept comment "K-12 Grafana"
        iifname "eth0" counter drop comment "Management-Netz: nur Grafana"
    }

    chain output {
        type filter hook output priority filter; policy accept;
        oifname "eth0" ct state established,related accept
        oifname "eth0" counter drop comment "kein Verbindungsaufbau ins Management-Netz"
    }
}
RULES
ip route replace default via 10.10.30.1 dev eth1
ip route add default via "$gw" dev eth0 table 100
ip rule add from "$addr" lookup 100
