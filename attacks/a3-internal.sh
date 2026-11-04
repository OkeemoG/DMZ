#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

PROXY="10.10.10.2"
RUN="a3-$(date +%H%M%S)"

head1 "A-3  Compromised internal host  (client1 10.10.20.10)"
echo "   Scenario: an attacker controls an internal workstation and tries to"
echo "   attack the portal and then pivot to other systems."

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

stage "Outcome: the internal attacker is treated like any other."
echo "   The WAF blocks the web attacks, the firewalls block every pivot."
echo "   Network segmentation holds even from inside the company network."

stage "In the SIEM, filter this run and the internal source:"
echo "   waf blocks      : {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" |= \"Access denied\""
echo "   blocked pivots  : {job=\"dmz\", ident=\"ulogd\"} | json | client=\"10.10.20.10\""

finish
