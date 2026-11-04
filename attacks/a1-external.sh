#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

TARGET="203.0.113.2"
RUN="a1-$(date +%H%M%S)"

head1 "A-1  External multi-stage attack  (attacker 192.0.2.10 -> ${TARGET})"
wait_waf

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
  local code
  code=$(inet curl -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)
  check "${desc}" 403 "403" "${code}"
}
web "SQL injection login bypass"  --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://${TARGET}/login?${RUN}-sqli"
web "UNION SELECT in search"      -G --data-urlencode "q=' UNION SELECT username,password FROM users-- -" "https://${TARGET}/search?${RUN}-union"
web "reflected XSS in search"     -G --data-urlencode "q=<script>alert(document.cookie)</script>" "https://${TARGET}/search?${RUN}-xss"
web "path traversal in download"  -G --data-urlencode "file=../../../../etc/passwd" "https://${TARGET}/download?${RUN}-lfi"
web "scanner user agent"          -A "Nikto/2.5.0" "https://${TARGET}/?${RUN}-scan"

stage "Outcome: the attacker reached no service and extracted no data."
echo "   fw-edge dropped the scan, the WAF answered every web attack with 403,"
echo "   and the IDS saw the UNION SELECT and the path traversal on the mirror port."

stage "In the SIEM (Grafana -> Explore), filter this run:"
echo "   all events     : {job=\"dmz\"} |= \"${RUN}\""
echo "   firewall drops : {job=\"dmz\", ident=\"ulogd\"} | json | client=\"192.0.2.10\""
echo "   waf blocks     : {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" |= \"Access denied\""
echo "   ids alerts     : {job=\"dmz\", host=\"ids\"} | json | client=\"192.0.2.10\""

finish
