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
    echo "FEHLER $1 $2 (erwartet: $3, Ergebnis: $4)"
    fail=1
  fi
}

ping_test() { # Test-ID, Knoten, Ziel, erwartet (ok|fail)
  if x "$2" ping -c 1 -W 1 "$3" >/dev/null 2>&1; then r=ok; else r=fail; fi
  result "$1" "$2 -> $3" "$4" "$r"
}

echo "== T-01 Adressen und Standardrouten"
for n in "${NODES[@]}"; do
  echo "-- $n"
  x "$n" ip -br -4 addr show
  def4=$(x "$n" ip -4 route show default)
  def6=$(x "$n" ip -6 route show default)
  echo "   IPv4 default: ${def4:-keine}"
  echo "   IPv6 default: ${def6:-keine}"
  case "$def4" in
    *"dev eth0"*) r=eth0 ;;
    "")           r=keine ;;
    *)            r=daten ;;
  esac
  if [ "$n" = "inet" ]; then exp=keine; else exp=daten; fi
  result T-01 "$n IPv4-Standardroute" "$exp" "$r"
done

echo "== T-02 Nachbarn"
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

echo "== T-03 Ende zu Ende"
ping_test T-03a client1  10.10.30.10 ok
ping_test T-03b attacker 203.0.113.2 ok
# Negativtest: inet kennt keine privaten Netze. Antwortet siem trotzdem,
# laeuft Verkehr am Datenpfad vorbei (z. B. ueber das Management-Netz).
ping_test T-03d inet     10.10.30.10 fail

echo "== R-03 Rechte im Container"
if x fw-edge sh -c 'nft add table inet r03 && nft delete table inet r03' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "nftables auf fw-edge" ok "$r"
if x fw-dmz sh -c 'tc qdisc add dev eth6 clsact && tc qdisc del dev eth6 clsact' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "tc auf fw-dmz eth6" ok "$r"
if x fw-edge sh -c 'ip link add wg-r03 type wireguard && ip link del wg-r03' >/dev/null 2>&1; then r=ok; else r=fail; fi
result R-03 "WireGuard-Schnittstelle auf fw-edge" ok "$r"

if [ "$fail" -eq 0 ]; then
  echo "ERGEBNIS: bestanden"
else
  echo "ERGEBNIS: nicht bestanden"
  exit 1
fi
