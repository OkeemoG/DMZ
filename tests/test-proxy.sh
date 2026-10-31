#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
RUN="p$(date +%s)$$"
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

tls() {
  x attacker sh -c "openssl s_client -connect 203.0.113.2:443 -brief $* </dev/null 2>&1"
}

weblog() {
  docker logs "${P}-web" 2>&1 | grep -F -- "$1" | tail -1
}

srcip() {
  printf '%s' "$1" | sed -n 's/.*"src_ip": *"\([^"]*\)".*/\1/p'
}

echo "== P-00 Service and certificate"
if x proxy pgrep nginx >/dev/null 2>&1; then r=ok; else r=fail; fi
result P-00 "nginx running" ok "$r"
if x proxy test -f /etc/nginx/tls/proxy.key; then r=ok; else r=fail; fi
result P-00 "private key present in image" ok "$r"
result P-00 "private key readable by root only" 600 "$(x proxy stat -c '%a' /etc/nginx/tls/proxy.key 2>/dev/null)"

echo "== P-01 Redirect"
out=$(x attacker curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://203.0.113.2/test 2>/dev/null)
result P-01 "HTTP 80 redirects to HTTPS" "301 https://203.0.113.2/test" "$out"

echo "== P-02 End to end: Internet -> proxy -> waf -> web (K-01, K-02, K-03)"
body=$(x attacker curl -sk "https://203.0.113.2/health?id=${RUN}-02" 2>/dev/null)
result P-02 "health endpoint answers through the chain" yes "$(has "$body" '"status": ?"ok"')"
log=$(weblog "${RUN}-02")
result P-02 "request logged by web" yes "$([ -n "$log" ] && echo yes || echo no)"

echo "== P-03 Client address is passed on"
result P-03 "web sees attacker address via waf" 192.0.2.10 "$(srcip "$log")"

echo "== P-04 Spoofed forwarding headers are replaced"
x attacker curl -sk -o /dev/null -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 1.2.3.4' "https://203.0.113.2/health?id=${RUN}-04" >/dev/null 2>&1
result P-04 "spoofed X-Forwarded-For / X-Real-IP ignored" 192.0.2.10 "$(srcip "$(weblog "${RUN}-04")")"

echo "== P-05 Client network -> proxy -> waf -> web (K-04)"
code=$(x client1 curl -sk -o /dev/null -w '%{http_code}' "https://10.10.10.2/health?id=${RUN}-05" 2>/dev/null)
result P-05 "internal client reaches web application" 200 "$code"
result P-05 "web sees internal client address" 10.10.20.10 "$(srcip "$(weblog "${RUN}-05")")"

echo "== P-06 Header hardening"
hdr=$(x attacker curl -skI https://203.0.113.2/health 2>/dev/null | tr -d '\r')
result P-06 "Server header without version" yes "$(has "$hdr" '^[Ss]erver: nginx$')"
result P-06 "no upstream Server header leaked" no "$(has "$hdr" '^[Ss]erver: web')"

echo "== P-07 TLS according to BSI TR-02102-2"
out=$(tls)
result P-07a "default client negotiates TLS 1.3" yes "$(has "$out" '^Protocol version: TLSv1\.3$')"
result P-07a "cipher suite from table 13" yes "$(has "$out" '^Ciphersuite: TLS_AES_(256_GCM_SHA384|128_GCM_SHA256)$')"
result P-07a "signature ECDSA with SHA-512" yes "$(has "$out" '^Hash used: SHA512$')"
result P-07a "group from table 10" yes "$(has "$out" '(Temp Key: ECDH, |group: )(secp(256|384|521)r1|prime256v1|brainpoolP(256|384|512)r1)')"

cert=$(x attacker sh -c "openssl s_client -connect 203.0.113.2:443 </dev/null 2>/dev/null | openssl x509 -noout -text" 2>/dev/null)
result P-07c "certificate curve brainpoolP512r1" yes "$(has "$cert" 'ASN1 OID: brainpoolP512r1')"
result P-07c "certificate signature ecdsa-with-SHA512" yes "$(has "$cert" 'Signature Algorithm: ecdsa-with-SHA512')"
result P-07c "certificate SAN 203.0.113.2 and 10.10.10.2" yes "$(has "$cert" 'IP Address:203\.0\.113\.2, IP Address:10\.10\.10\.2')"

out=$(tls -tls1_3 -groups X25519)
result P-07d "X25519 rejected" no "$(has "$out" '^Protocol version')"
out=$(tls -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256)
result P-07d "ChaCha20 rejected" no "$(has "$out" '^Protocol version')"
out=$(tls -tls1_2 -groups brainpoolP512r1:secp384r1)
result P-07d "TLS 1.2 rejected" no "$(has "$out" '^Protocol version')"
out=$(tls -tls1_1 -cipher DEFAULT@SECLEVEL=0)
result P-07d "TLS 1.1 rejected" no "$(has "$out" '^Protocol version')"

echo "== P-08 Rate limiting (20 r/s, burst 40)"
codes=$(x attacker sh -c 'curl -sk -Z --parallel-max 50 -o "/tmp/r#1" -w "%{http_code}\n" "https://203.0.113.2/health?r=[1-100]"; rm -f /tmp/r*' 2>/dev/null)
n200=$(printf '%s\n' "$codes" | grep -c '^200$')
n429=$(printf '%s\n' "$codes" | grep -c '^429$')
echo "   100 parallel requests: ${n200}x 200, ${n429}x 429"
result P-08 "excess requests rejected with 429" yes "$([ "$n429" -gt 0 ] && echo yes || echo no)"
result P-08 "requests within limit answered" yes "$([ "$n200" -gt 0 ] && echo yes || echo no)"
sleep 3

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
