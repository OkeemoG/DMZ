#!/usr/bin/env bash
set -uo pipefail

IMG="web:0.1"
CLIENT="client:0.1"
fail=0

result() {
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

start() {
  docker run -d --rm --name "$1" -e "APP_MODE=$2" "$IMG" >/dev/null
  for _ in $(seq 1 20); do
    docker exec "$1" python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

req()      { docker run --rm --network "container:$1" "$CLIENT" curl -s -o /dev/null -w '%{http_code}' "$2" 2>/dev/null; }
body()     { docker run --rm --network "container:$1" "$CLIENT" curl -s "$2" 2>/dev/null; }
head_()    { docker run --rm --network "container:$1" "$CLIENT" curl -sI "$2" 2>/dev/null; }
post()     { docker run --rm --network "container:$1" "$CLIENT" curl -s --data "$3" "$2" 2>/dev/null; }
postcode() { docker run --rm --network "container:$1" "$CLIENT" curl -s -o /dev/null -w '%{http_code}' --data "$3" "$2" 2>/dev/null; }

docker rm -f web-vuln web-secure >/dev/null 2>&1

echo "== W-00 Container and user"
start web-vuln vulnerable || { echo "FAIL   W-00 vulnerable container did not become ready"; exit 1; }
u=$(docker exec web-vuln sh -c "ps -o user,comm | grep gunicorn | grep -v root | head -1 | awk '{print \$1}'")
result W-00 "worker runs as app" app "$u"
result W-00 "health endpoint" 200 "$(req web-vuln http://127.0.0.1:8080/health)"

echo "== W-01 Function (vulnerable mode)"
result W-01 "index page" 200 "$(req web-vuln http://127.0.0.1:8080/)"
ok=$(post web-vuln http://127.0.0.1:8080/login "username=alice&password=alice123" | grep -c "Logged in as alice")
result W-01 "valid login" 1 "$ok"
result W-01 "wrong password rejected" 401 "$(postcode web-vuln http://127.0.0.1:8080/login 'username=alice&password=wrong')"
result W-01 "search works" 200 "$(req web-vuln 'http://127.0.0.1:8080/search?q=Router')"

echo "== W-02 Vulnerabilities present (vulnerable mode)"
inj=$(post web-vuln http://127.0.0.1:8080/login "username=admin' OR '1'='1&password=x" | grep -c "Logged in as admin")
result W-02 "SQL injection login bypass" 1 "$inj"
xss=$(body web-vuln 'http://127.0.0.1:8080/search?q=<script>alert(1)</script>' | grep -c "<script>alert(1)</script>")
result W-02 "reflected XSS" 1 "$xss"
trav=$(body web-vuln 'http://127.0.0.1:8080/download?file=../../../../etc/passwd' | grep -c "root:")
result W-02 "path traversal" 1 "$trav"
docker rm -f web-vuln >/dev/null 2>&1

echo "== W-03 Secure mode closes the holes"
start web-secure secure || { echo "FAIL   W-03 secure container did not become ready"; exit 1; }
inj=$(post web-secure http://127.0.0.1:8080/login "username=admin' OR '1'='1&password=x" | grep -c "Logged in as admin")
result W-03 "SQL injection blocked" 0 "$inj"
xss=$(body web-secure 'http://127.0.0.1:8080/search?q=<script>alert(1)</script>' | grep -c "<script>alert(1)</script>")
result W-03 "XSS escaped" 0 "$xss"
trav=$(body web-secure 'http://127.0.0.1:8080/download?file=../../../../etc/passwd' | grep -c "root:")
result W-03 "path traversal blocked" 0 "$trav"
ok=$(post web-secure http://127.0.0.1:8080/login "username=alice&password=alice123" | grep -c "Logged in as alice")
result W-03 "valid login still works" 1 "$ok"

echo "== W-04 Hardening"
srv=$(head_ web-secure http://127.0.0.1:8080/health | tr -d '\r' | grep -ic '^server: web$')
result W-04 "Server header without version" 1 "$srv"
err=$(body web-secure 'http://127.0.0.1:8080/download?file=nope.txt' | grep -ic traceback)
result W-04 "no stack trace on error" 0 "$err"
docker rm -f web-secure >/dev/null 2>&1

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
