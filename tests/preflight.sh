#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
NODES=(inet attacker ro-client1 ro-client2 fw-edge fw-dmz proxy waf web ids router-int client1 fw-backend siem siem-collector siem-responder siem-loki siem-grafana)
fail=0

x() { docker exec "${P}-$1" "${@:2}"; }

check() {
  if [ "$2" = "$3" ]; then
    printf 'OK    %s\n' "$1"
  else
    printf 'FAIL  %s (expected: %s, got: %s)\n' "$1" "$2" "$3"
    fail=1
  fi
}

has() { if printf '%s' "$1" | grep -qE -- "$2"; then echo yes; else echo no; fi; }

down=""
for n in "${NODES[@]}"; do
  [ "$(docker inspect -f '{{.State.Running}}' "${P}-$n" 2>/dev/null)" = true ] || down="$down $n"
done
check "all ${#NODES[@]} containers running" "" "${down# }"

for fw in fw-edge fw-dmz fw-backend; do
  check "$fw: project rule set loaded" yes "$(has "$(x "$fw" nft list tables 2>/dev/null)" 'table inet filter')"
done
check "fw-edge: reaction table loaded" yes "$(has "$(x fw-edge nft list tables 2>/dev/null)" 'table inet response')"
check "ids: suricata running" yes "$(x ids pgrep -f 'suricata --include' >/dev/null 2>&1 && echo yes || echo no)"
check "client1 -> portal" 200 "$(x client1 curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://10.10.10.2/health 2>/dev/null)"
check "attacker -> portal (not blocked)" 200 "$(x attacker curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://203.0.113.2/health 2>/dev/null)"
check "VPN: 2 tunnels established" 2 "$(x fw-edge swanctl --list-sas 2>/dev/null | grep -c ESTABLISHED)"
check "Loki ready" yes "$(has "$(x siem curl -s -m 2 http://127.0.0.1:3100/ready 2>/dev/null)" '^ready')"
check "Grafana on 127.0.0.1:3000 of the VM" yes "$(has "$(curl -s -m 2 http://127.0.0.1:3000/api/health 2>/dev/null)" '"database": *"ok"')"
st=$(x siem-responder respond status 2>/dev/null)
check "responder: channel K-13 up" yes "$(has "$st" '^channel: +up')"
check "responder: mode enforce" yes "$(has "$st" '^mode: +enforce')"
check "responder: no active blocks left from earlier runs" "" "$(x siem-responder respond list 2>/dev/null | tr '\n' ' ' | sed 's/ $//')"
free=$(df -Pm / 2>/dev/null | awk 'NR == 2 { print $4 }')
check "at least 1 GB free on the VM (${free:-?} MB)" yes "$([ "${free:-0}" -ge 1024 ] && echo yes || echo no)"

echo
if [ "$fail" -eq 0 ]; then
  echo "READY FOR THE DEMO"
else
  echo "NOT READY: fix the lines marked FAIL (blocks: make release IP=..., or docker exec clab-dmz-siem-responder respond flush)"
  exit 1
fi
