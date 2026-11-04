#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
. ./lib.sh

TARGET="203.0.113.2"
RUN="a2-$(date +%H%M%S)"
blocked=0
passed=0

head1 "A-2  WAF evasion resistance  (attacker 192.0.2.10 -> ${TARGET})"
echo "   The same intent behind many disguises. Each request is sent through"
echo "   proxy and WAF. 403 = the WAF blocked it. Anything else reached the app."

probe() {
  local desc="$1"; shift
  local code
  code=$(inet curl -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)
  if [ "${code}" = "403" ]; then
    echo "   BLOCKED (403)  ${desc}"; blocked=$((blocked + 1))
  else
    echo "   PASSED  (${code})  ${desc}   <-- reached the application"; passed=$((passed + 1))
  fi
}

stage "SQL injection, obfuscated"
n=0
sqli() { n=$((n + 1)); probe "$1" -G --data-urlencode "q=$2" "https://${TARGET}/search?${RUN}-s${n}"; }
sqli "plain boolean"            "' OR '1'='1"
sqli "mixed case"               "' oR '1'='1"
sqli "inline comments"          "'/**/OR/**/'1'='1"
sqli "comment terminator"       "' OR 1=1-- -"
sqli "hash terminator"          "admin'#"
sqli "UNION plain"              "' UNION SELECT username,password FROM users-- -"
sqli "UNION mixed case"         "' UnIoN sElEcT username,password fRoM users-- -"
sqli "UNION with comments"      "'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users-- -"
sqli "whitespace via tab"       "'%09OR%09'1'='1"

stage "Cross-site scripting, obfuscated"
m=0
xss() { m=$((m + 1)); probe "$1" -G --data-urlencode "q=$2" "https://${TARGET}/search?${RUN}-x${m}"; }
xss "script tag"                "<script>alert(1)</script>"
xss "mixed case tag"            "<ScRiPt>alert(1)</ScRiPt>"
xss "img onerror"               "<img src=x onerror=alert(1)>"
xss "svg onload"                "<svg/onload=alert(1)>"
xss "body onload"               "<body onload=alert(1)>"

total=$((blocked + passed))
stage "Coverage: ${blocked} of ${total} evasion attempts blocked by the WAF"

code=$(inet curl -sk -o /dev/null -w '%{http_code}' -G --data-urlencode "q=' OR '1'='1" "https://${TARGET}/search?${RUN}-base" 2>/dev/null)
check "baseline injection is blocked" 403 "403" "${code}"

if [ "${passed}" -gt 0 ]; then
  echo
  echo "   ${passed} attempt(s) reached the application. In vulnerable mode this is a real bypass."
  echo "   Remediation, in order of depth:"
  echo "     1. raise the WAF sensitivity: BLOCKING_PARANOIA=2 (or lower ANOMALY_INBOUND) in the topology"
  echo "     2. defense in depth: the application in secure mode (APP_MODE=secure) uses"
  echo "        parameterized queries and output escaping, so a bypass of the WAF still fails"
else
  echo
  echo "   CRS 4.30 with libinjection blocked every standard obfuscation at paranoia level 1."
  echo "   The application in secure mode remains the backstop against anything that gets through."
fi

stage "In the SIEM, see which rule caught each variant:"
echo "   {job=\"dmz\", host=\"waf\"} |= \"${RUN}\" | json | line_format \"{{.uri}}  score {{.score}}  {{.rule_msg}}\""

finish
