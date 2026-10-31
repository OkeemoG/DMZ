#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
EXT="https://203.0.113.2"
INT="https://10.10.10.2"
RUN="w$(date +%s)$$"
fail=0

x() { docker exec "${P}-$1" "${@:2}"; }

result() {
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

has() {
  if printf '%s' "$1" | grep -qE -- "$2"; then echo yes; else echo no; fi
}

code() {
  local src="$1"; shift
  x "$src" curl -sk -o /dev/null -w '%{http_code}' "$@" 2>/dev/null
}

weblog() { docker logs "${P}-web" 2>&1 | grep -F -- "$1" | tail -1; }
waflog() { docker logs "${P}-waf" 2>&1 | grep -F -- "$1" | grep -F '"transaction"' | tail -1; }

echo "== W-00 Service and configuration"
if x waf pgrep nginx >/dev/null 2>&1; then r=ok; else r=fail; fi
result W-00 "nginx with ModSecurity running" ok "$r"
eng=$(x waf sh -c 'grep -rhs "^SecRuleEngine" /etc/modsecurity.d /etc/nginx' 2>/dev/null)
result W-00 "rule engine in blocking mode" yes "$(has "$eng" 'SecRuleEngine +On')"
crs=$(x waf sh -c 'ls /opt/owasp-crs/rules 2>/dev/null | grep -c "^REQUEST-9.*\.conf$"' 2>/dev/null)
result W-00 "CRS request rules installed" yes "$([ "${crs:-0}" -gt 10 ] && echo yes || echo no)"
wu=$(x waf sh -c "ps -o user,args | grep 'nginx: worker' | grep -v grep | awk '{print \$1}' | sort -u" 2>/dev/null)
result W-00 "worker processes not running as root" yes "$([ -n "$wu" ] && [ "$wu" != "root" ] && echo yes || echo no)"

echo "== W-01 Legitimate requests pass (false positive check)"
result W-01 "GET / (Internet)" 200 "$(code attacker "$EXT/?id=${RUN}-ok1")"
result W-01 "search (Internet)" 200 "$(code attacker -G --data "id=${RUN}-ok2" --data-urlencode "q=Router" "$EXT/search")"
result W-01 "valid login (Internet)" 200 "$(code attacker --data-urlencode "username=alice" --data-urlencode "password=alice123" "$EXT/login?id=${RUN}-ok3")"
result W-01 "wrong password reaches app, not WAF" 401 "$(code attacker --data-urlencode "username=alice" --data-urlencode "password=wrong" "$EXT/login?id=${RUN}-ok4")"
result W-01 "file download (Internet)" 200 "$(code attacker -G --data "id=${RUN}-ok5" --data-urlencode "file=welcome.txt" "$EXT/download")"
c6=$(code attacker -G --data "id=${RUN}-ok6" --data-urlencode "q=O'Neil router" "$EXT/search")
result W-01 "apostrophe in normal text not blocked by WAF" yes "$([ "$c6" != "403" ] && echo yes || echo no)"
result W-01 "apostrophe request reached web (status $c6)" yes "$([ -n "$(weblog "${RUN}-ok6")" ] && echo yes || echo no)"
result W-01 "search (client network)" 200 "$(code client1 -G --data "id=${RUN}-ok7" --data-urlencode "q=Switch" "$INT/search")"
result W-01 "legitimate requests reached web" yes "$([ -n "$(weblog "${RUN}-ok5")" ] && [ -n "$(weblog "${RUN}-ok7")" ] && echo yes || echo no)"

echo "== W-02 Attacks from the Internet are blocked"
result W-02a "SQL injection login bypass" 403 "$(code attacker --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "$EXT/login?id=${RUN}-atk-a")"
result W-02b "SQL injection UNION SELECT" 403 "$(code attacker -G --data "id=${RUN}-atk-b" --data-urlencode "q=' UNION SELECT username,password FROM users--" "$EXT/search")"
result W-02c "reflected XSS" 403 "$(code attacker -G --data "id=${RUN}-atk-c" --data-urlencode "q=<script>alert(document.cookie)</script>" "$EXT/search")"
result W-02d "path traversal" 403 "$(code attacker -G --data "id=${RUN}-atk-d" --data-urlencode "file=../../../../etc/passwd" "$EXT/download")"
result W-02e "OS command injection" 403 "$(code attacker -G --data "id=${RUN}-atk-e" --data-urlencode "q=;cat /etc/passwd" "$EXT/search")"
result W-02f "scanner user agent" 403 "$(code attacker -A "Nikto/2.5.0" "$EXT/?id=${RUN}-atk-f")"

echo "== W-03 Attacks from the client network are blocked"
result W-03 "SQL injection login bypass (client1)" 403 "$(code client1 --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "$INT/login?id=${RUN}-atk-g")"

echo "== W-04 Blocked requests never reach the web server"
leaked=$(docker logs "${P}-web" 2>&1 | grep -cF -- "${RUN}-atk")
result W-04 "no blocked request in web log" 0 "$leaked"

echo "== W-05 Audit log for detection and SIEM"
la=$(waflog "${RUN}-atk-a")
result W-05 "audit entry for blocked attack" yes "$([ -n "$la" ] && echo yes || echo no)"
result W-05 "audit entry names SQLi rule (942xxx)" yes "$(has "$la" '"ruleId": ?"942[0-9]{3}"')"
result W-05 "audit entry has real attacker address" yes "$(has "$la" '"client_ip": ?"192\.0\.2\.10"')"
lg=$(waflog "${RUN}-atk-g")
result W-05 "audit entry has real internal address" yes "$(has "$lg" '"client_ip": ?"10\.10\.20\.10"')"
lok=$(waflog "${RUN}-ok3")
result W-05 "no audit entry for legitimate login" no "$([ -n "$lok" ] && echo yes || echo no)"
x attacker curl -sk -o /dev/null -H "Host: 198.18.0.1" "$EXT/?id=${RUN}-host" >/dev/null 2>&1
lh=$(waflog "${RUN}-host")
result W-05 "foreign numeric Host header still detected (920350)" yes "$(has "$lh" '"ruleId": ?"920350"')"

echo "== W-06 Block page does not reveal details"
resp=$(x attacker curl -sk -i -G --data "id=${RUN}-atk-h" --data-urlencode "q=<script>alert(1)</script>" "$EXT/search" 2>/dev/null | tr -d '\r')
result W-06 "no WAF product or version in response" no "$(has "$resp" '[Mm]od[Ss]ecurity|OWASP|nginx/[0-9]')"

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
