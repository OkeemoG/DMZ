#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

PROXY="10.10.10.2"
RUN="a3-$(date +%H%M%S)"

head1 "A-3  Compromised internal host  (client1 10.10.20.10)"
echo "   Scenario: an attacker controls an internal workstation and tries to"
echo "   attack the portal and then pivot to other systems."
wait_waf
if response_prepare enforce; then RESP=yes; else RESP=no; fi

stage "Stage 1  Attack the portal from inside (through proxy and WAF)"
icode() { client curl -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
check "internal SQL injection blocked by WAF" 403 "403" \
  "$(icode --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://${PROXY}/login?${RUN}-sqli")"
check "internal path traversal blocked by WAF" 403 "403" \
  "$(icode -G --data-urlencode "file=../../../../etc/passwd" "https://${PROXY}/download?${RUN}-lfi")"

stage "Stage 2  Try to pivot (forbidden connections)"
blocked() {
  local desc="$1" ip="$2" port="$3"
  if client socat -T1 /dev/null "TCP:${ip}:${port},connect-timeout=2" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  check "${desc}" blocked "blocked" "${r}"
}
blocked "direct to web server, bypassing proxy+waf (V-03)" 10.10.10.10 8080
blocked "direct to the WAF (V-03)"                          10.10.10.6  8080
blocked "direct to the IDS (V-03)"                          10.10.10.14 8080
blocked "into the backend / SIEM network (V-04)"           10.10.30.10 5140

if [ "${RESP}" = yes ]; then
  stage "Stage 3  Automatic reaction (playbook P-4: 3 forbidden internal targets within 60 s)"
  check "client1 isolated at fw-edge" yes "$(wait_listed quarantine 10.10.20.10)"
  respond list 2>/dev/null | grep -E '^quarantine 10\.10\.20\.10' | sed 's/^/   fw-edge: /'
  ms=$(reaction_ms quarantine 10.10.20.10)
  echo "   reaction time from the event in the SIEM to the quarantine on fw-edge: ${ms:-?} ms"
  check "client1 -> portal, normally allowed (K-04)" 000 "000" "$(icode --connect-timeout 1 --max-time 2 "https://${PROXY}/health?${RUN}-q")"
  check "quarantine visible in the SIEM" yes "$(siem_query '{job="dmz", ident="responder"} | json | action="quarantine" | client="10.10.20.10"')"

  stage "Stage 4  Release after cleanup (operator decision, no expiry)"
  echo "   An isolated host stays isolated until someone has checked or rebuilt it."
  echo "   Evidence first: make evidence IP=10.10.20.10, then: make release IP=10.10.20.10"
  respond release 10.10.20.10 >/dev/null 2>&1
  check "after release client1 reaches the portal again" 200 "$(icode --max-time 3 "https://${PROXY}/health?${RUN}-r")"
fi

stage "Outcome: the internal attacker is treated like any other."
echo "   The WAF blocks the web attacks, the firewalls block every pivot."
echo "   Network segmentation holds even from inside the company network."
if [ "${RESP}" = yes ]; then
  echo "   The pivot attempts got the workstation isolated automatically (lateral movement contained)."
fi

stage "In the SIEM, filter this run and the internal source:"
echo "   waf blocks      : {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" |= \"Access denied\""
echo "   blocked pivots  : {job=\"dmz\", ident=\"ulogd\"} | json | client=\"10.10.20.10\""
echo "   reaction        : {job=\"dmz\", ident=\"responder\"} | json | client=\"10.10.20.10\""

finish
