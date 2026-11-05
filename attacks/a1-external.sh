#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

TARGET="203.0.113.2"
RUN="a1-$(date +%H%M%S)"

head1 "A-1  External multi-stage attack  (attacker 192.0.2.10 -> ${TARGET})"
wait_waf
if response_prepare enforce; then RESP=yes; else RESP=no; fi

stage "Stage 1  Reconnaissance: TCP port scan"
for p in 21 22 23 25 53 3306 8080 80 443; do
  if inet socat -T1 /dev/null "TCP:${TARGET}:${p},connect-timeout=1" >/dev/null 2>&1; then
    echo "   port ${p}  OPEN"; eval "open_${p}=yes"
  else
    echo "   port ${p}  filtered (no answer, dropped by fw-edge)"; eval "open_${p}=no"
  fi
done
check "scan: service port 443 reachable"      yes "yes" "${open_443}"
check "scan: SSH port 22 filtered"             no  "no"  "${open_22}"
check "scan: database port 3306 filtered"      no  "no"  "${open_3306}"

stage "Stage 2  Fingerprint the only reachable service"
inet curl -skI "https://${TARGET}/?${RUN}-probe" | tr -d '\r' | grep -iE '^(HTTP|server):' | sed 's/^/   /'
inet sh -c "echo | openssl s_client -connect ${TARGET}:443 -brief 2>&1" | grep -iE 'Protocol version|Ciphersuite' | sed 's/^/   /'

stage "Stage 3  Attack the web application"
web() {
  local desc="$1"; shift
  local code r
  code=$(inet curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 3 "$@" 2>/dev/null)
  if [ "${code}" = "403" ]; then
    r="blocked by the WAF (403)"
  elif [ "${code}" = "000" ] && [ "${RESP}" = yes ] && [ "$(listed blocklist 192.0.2.10)" = yes ]; then
    r="dropped at fw-edge, attacker locked out"
  else
    r="reached the application (${code})"
  fi
  if [ "${RESP}" = yes ]; then
    case "${r}" in reached*) check "${desc}" stopped "stopped" "${r}" ;; *) echo "   OK    ${desc} (${r})" ;; esac
  else
    check "${desc}" 403 "403" "${code}"
  fi
}
web "SQL injection login bypass"  --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://${TARGET}/login?${RUN}-sqli"
web "UNION SELECT in search"      -G --data-urlencode "q=' UNION SELECT username,password FROM users-- -" "https://${TARGET}/search?${RUN}-union"
web "reflected XSS in search"     -G --data-urlencode "q=<script>alert(document.cookie)</script>" "https://${TARGET}/search?${RUN}-xss"
web "path traversal in download"  -G --data-urlencode "file=../../../../etc/passwd" "https://${TARGET}/download?${RUN}-lfi"
web "scanner user agent"          -A "Nikto/2.5.0" "https://${TARGET}/?${RUN}-scan"

if [ "${RESP}" = yes ]; then
  stage "Stage 4  Automatic reaction (playbook P-1: 3 WAF blocks within 60 s)"
  check "attacker blocked at fw-edge by the responder" yes "$(wait_listed blocklist 192.0.2.10)"
  respond list 2>/dev/null | grep -E '^blocklist 192\.0\.2\.10 ' | sed 's/^/   fw-edge: /'
  ms=$(reaction_ms block 192.0.2.10)
  echo "   reaction time from the event in the SIEM to the block on fw-edge: ${ms:-?} ms"
  code=$(inet curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 2 "https://${TARGET}/?${RUN}-after" 2>/dev/null)
  check "even a harmless request of the attacker is dropped now" 000 "000" "${code}"
  check "reaction visible in the SIEM" yes "$(siem_query '{job="dmz", ident="responder"} | json | action="block" | client="192.0.2.10"')"
fi

stage "Outcome: the attacker reached no service and extracted no data."
echo "   fw-edge dropped the scan, the WAF answered the web attacks with 403,"
echo "   and the IDS saw the UNION SELECT and the path traversal on the mirror port."
if [ "${RESP}" = yes ]; then
  echo "   After the third blocked attack the responder in the SIEM locked the attacker out at fw-edge."
  echo "   The block lasts 10 min, a repeat offender gets twice as long. Lift it early: make release IP=192.0.2.10"
fi

stage "In the SIEM (Grafana -> Explore), filter this run:"
echo "   all events     : {job=\"dmz\"} |= \"${RUN}\""
echo "   firewall drops : {job=\"dmz\", ident=\"ulogd\"} | json | client=\"192.0.2.10\""
echo "   waf blocks     : {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" |= \"Access denied\""
echo "   ids alerts     : {job=\"dmz\", host=\"ids\"} | json | client=\"192.0.2.10\""
echo "   reaction       : {job=\"dmz\", ident=\"responder\"} | json | client=\"192.0.2.10\""

finish
