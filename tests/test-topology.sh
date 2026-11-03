#!/usr/bin/env bash

set -uo pipefail

P="clab-dmz"
NODES=(inet attacker ro-client1 ro-client2 fw-edge fw-dmz proxy waf web ids
       router-int client1 fw-backend siem)
fail=0

x() { docker exec "${P}-$1" "${@:2}"; }

result() { # Test-ID, Beschreibung, erwartet, Ergebnis
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

ping_test() { # Test-ID, Knoten, Ziel, erwartet (ok|fail)
  if x "$2" ping -c 1 -W 1 "$3" >/dev/null 2>&1; then r=ok; else r=fail; fi
  result "$1" "$2 -> $3" "$4" "$r"
}

echo "== T-01 Addresses and default routes"
for n in "${NODES[@]}"; do
  echo "-- $n"
  x "$n" ip -br -4 addr show
  def4=$(x "$n" ip -4 route show default)
  def6=$(x "$n" ip -6 route show default)
  echo "   IPv4 default: ${def4:-none}"
  echo "   IPv6 default: ${def6:-none}"
  case "$def4" in
    *"dev eth0"*) r=eth0 ;;
    "")           r=none ;;
    *)            r=data ;;
  esac
  if [ "$n" = "inet" ]; then exp=none; else exp=data; fi
  result T-01 "$n IPv4 default route" "$exp" "$r"
  if [ -n "$def6" ]; then r=present; else r=none; fi
  result T-01 "$n IPv6 default route" none "$r"
  if [ "$n" = "siem" ]; then
    exp=present; d="$n has eth0 for management access only (K-12)"
  else
    exp=missing; d="$n without eth0 (management network)"
  fi
  if x "$n" ip link show eth0 >/dev/null 2>&1; then r=present; else r=missing; fi
  result T-01 "$d" "$exp" "$r"
done
rules=$(x siem ip rule show 2>/dev/null)
result T-01 "siem answers management traffic via table 100 only" yes "$(printf '%s' "$rules" | grep -q 'lookup 100' && echo yes || echo no)"

echo "== T-02 Neighbours"
ping_test T-02 inet       203.0.113.2  ok
ping_test T-02 inet       198.51.100.2 ok
ping_test T-02 inet       192.0.2.10   ok
ping_test T-02 inet       198.51.100.6 ok
ping_test T-02 fw-edge    10.10.0.2    ok
ping_test T-02 fw-edge    10.10.0.6    ok
ping_test T-02 fw-edge    10.10.0.10   ok
ping_test T-02 fw-dmz     10.10.10.2   ok
ping_test T-02 fw-dmz     10.10.10.6   ok
ping_test T-02 fw-dmz     10.10.10.10  ok
ping_test T-02 fw-dmz     10.10.10.14  ok
ping_test T-02 router-int 10.10.20.10  ok
ping_test T-02 fw-backend 10.10.30.10  ok

echo "== T-03 End to end (firewalls active)"
# client1 -> Internet: router-int, fw-edge mit Quellumsetzung, inet (K-05)
ping_test T-03a client1  192.0.2.10  ok
ping_test T-03b attacker 203.0.113.2 ok
# web -> Internet: fw-dmz, fw-edge mit Quellumsetzung, inet (K-06)
ping_test T-03e web      192.0.2.10  ok
# Negativtest: inet kennt keine privaten Netze. Antwortet siem trotzdem,
# laeuft Verkehr am Datenpfad vorbei (z. B. ueber das Management-Netz).
ping_test T-03d inet     10.10.30.10 fail

echo "== R-03 Privileges inside containers"
if x fw-edge sh -c 'nft add table inet r03 && nft delete table inet r03' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "nftables on fw-edge" ok "$r"
if x fw-dmz sh -c 'tc qdisc add dev eth6 clsact && tc qdisc del dev eth6 clsact' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "tc on fw-dmz eth6" ok "$r"
if x fw-edge sh -c 'ip link add wg-r03 type wireguard && ip link del wg-r03' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "WireGuard interface on fw-edge" ok "$r"

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
