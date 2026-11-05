#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

TARGET="203.0.113.2"
RUN="a2-$(date +%H%M%S)"
blocked=0
passed=()
ALL=()

head1 "A-2  WAF evasion resistance  (attacker 192.0.2.10 -> ${TARGET})"
echo "   The same intent behind many disguises. Each request is sent through"
echo "   proxy and WAF. 403 = the WAF blocked it. Anything else reached the app."
wait_waf
echo "   Part 1 measures the WAF alone, so the automatic response only records what it would do."
if response_prepare monitor; then RESP=yes; else RESP=no; fi

probe() {
  local mark="$1" desc="$2" payload="$3"
  local code
  ALL+=("${payload}")
  code=$(inet curl -sk -o /dev/null -w '%{http_code}' -G --data-urlencode "q=${payload}" "https://${TARGET}/search?${mark}" 2>/dev/null)
  case "${code}" in
    403) echo "   BLOCKED (403)  ${desc}"; blocked=$((blocked + 1)) ;;
    500) echo "   PASSED  (500)  ${desc}   <-- reached the app and broke the query: injection point confirmed"; passed+=("${mark}|${desc}") ;;
    *)   echo "   PASSED  (${code})  ${desc}   <-- reached the app"; passed+=("${mark}|${desc}") ;;
  esac
}

stage "SQL injection, obfuscated"
n=0
sqli() { n=$((n + 1)); probe "${RUN}-s${n}" "$1" "$2"; }
sqli "plain boolean"            "' OR '1'='1"
sqli "mixed case"               "' oR '1'='1"
sqli "inline comments"          "'/**/OR/**/'1'='1"
sqli "comment terminator"       "' OR 1=1-- -"
sqli "hash terminator"          "admin'#"
sqli "dash terminator"          "admin'--"
sqli "block comment"            "admin'/*"
sqli "UNION plain"              "' UNION SELECT username,password FROM users-- -"
sqli "UNION mixed case"         "' UnIoN sElEcT username,password fRoM users-- -"
sqli "UNION with comments"      "'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users-- -"
sqli "whitespace via tab"       "'%09OR%09'1'='1"

stage "Cross-site scripting, obfuscated"
m=0
xss() { m=$((m + 1)); probe "${RUN}-x${m}" "$1" "$2"; }
xss "script tag"                "<script>alert(1)</script>"
xss "mixed case tag"            "<ScRiPt>alert(1)</ScRiPt>"
xss "img onerror"               "<img src=x onerror=alert(1)>"
xss "svg onload"                "<svg/onload=alert(1)>"
xss "body onload"               "<body onload=alert(1)>"

total=$((blocked + ${#passed[@]}))
stage "Coverage: ${blocked} of ${total} evasion attempts blocked by the WAF"

code=$(inet curl -sk -o /dev/null -w '%{http_code}' -G --data-urlencode "q=' OR '1'='1" "https://${TARGET}/search?${RUN}-base" 2>/dev/null)
check "baseline injection is blocked" 403 "403" "${code}"

if [ "${#passed[@]}" -gt 0 ]; then
  stage "Did the SIEM notice the requests that got through?"
  for entry in "${passed[@]}"; do
    echo "   visible in SIEM: $(in_siem "${entry%%|*}")   ${entry#*|}"
  done
  echo
  echo "   A request that slips past the WAF and matches no IDS rule leaves no trace in the SIEM."
  echo "   Remediation:"
  echo "     1. secure application mode (APP_MODE=secure): parameterized queries, the input is never"
  echo "        executed as SQL. This closes the gap regardless of the WAF."
  echo "     2. WAF tuning: test a higher BLOCKING_PARANOIA and weigh it against false positives"
  echo "        (test-waf WA-01 checks that legitimate requests still pass)."
  echo "     3. detection: forward the application's 5xx errors to the SIEM, so a request that"
  echo "        slips past the WAF still leaves a trace."
else
  echo
  echo "   The WAF blocked every evasion attempt: OWASP CRS 4.30 at paranoia level 1"
  echo "   plus the DMZ virtual patch VP-01 (configs/waf/REQUEST-899-DMZ-VIRTUAL-PATCHES.conf)."
fi

if [ "${RESP}" = yes ]; then
  stage "Part 2  The same campaign with the automatic response switched on"
  response_prepare enforce >/dev/null
  sent=0; answered=0; dropped=0; reached=0
  for payload in "${ALL[@]}"; do
    sent=$((sent + 1))
    code=$(inet curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 0.5 --max-time 2 -G --data-urlencode "q=${payload}" "https://${TARGET}/search?${RUN}-e${sent}" 2>/dev/null)
    case "${code}" in
      000) dropped=$((dropped + 1)) ;;
      403) answered=$((answered + 1)) ;;
      *)   answered=$((answered + 1)); reached=$((reached + 1)) ;;
    esac
  done
  echo "   ${sent} attempts: ${answered} answered (${reached} reached the app), ${dropped} dropped at fw-edge"
  check "attacker locked out before the campaign was over" yes "$(listed blocklist 192.0.2.10)"
  check "most variants never reached the proxy" yes "$([ "${dropped}" -ge $((sent / 2)) ] && echo yes || echo no)"
  echo "   Evasion needs many tries. After three blocked attempts (P-1) or one attack the IDS sees"
  echo "   behind the WAF (P-2) the attacker cannot try any further variants for 10 min."
fi

stage "In the SIEM, see which rule caught each blocked variant:"
echo "   {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" | json | line_format \"{{.uri}}  score {{.score}}  {{.rule_msg}}\""

finish
