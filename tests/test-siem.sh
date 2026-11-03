#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
SAMPLES="${SAMPLES:-10}"
LIMIT_MS="${LIMIT_MS:-1000}"
PASS="${GRAFANA_PASSWORD:-dmz-soc}"
RUN="s$(date +%s)$$"
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

wait_for() {
  local tries="$1" pattern="$2" out=""
  shift 2
  for _ in $(seq "$tries"); do
    out=$("$@" 2>/dev/null)
    if printf '%s' "$out" | grep -qE -- "$pattern"; then echo yes; return; fi
    sleep 1
  done
  echo no
}

poll() {
  docker exec -i "${P}-siem" sh -s "$1" <<'POLL'
i=0
while [ "$i" -lt 150 ]; do
  if curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query=$1" --data-urlencode limit=1 | grep -q '"result":\[{'; then
    cut -d' ' -f1 /proc/uptime
    exit 0
  fi
  i=$((i + 1))
  usleep 10000
done
echo timeout
POLL
}

lines() {
  x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query=$1" --data-urlencode limit=50 2>/dev/null
}

elapsed() {
  if [ "$2" = "timeout" ] || [ -z "$2" ] || [ -z "$1" ]; then echo 99999; else echo $(( (${2/./} - ${1/./}) * 10 )); fi
}

attack() {
  docker exec -i "${P}-attacker" sh -s "$1" <<'ATTACK'
t=$(cut -d' ' -f1 /proc/uptime)
curl -sk -o /dev/null --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://203.0.113.2/login?id=$1"
echo "$t"
ATTACK
}

send() {
  docker run --rm -i --network "container:${P}-waf" client:0.1 sh -s "$1" <<'SEND'
t=$(cut -d' ' -f1 /proc/uptime)
echo "<134>$(date '+%b %e %H:%M:%S') waf dmztest: latency $1" | socat -u - UDP-SENDTO:10.10.30.10:5140
echo "$t"
SEND
}

echo "== S-00 Services"
for n in siem siem-collector siem-loki siem-grafana; do
  result S-00 "$n running" true "$(docker inspect -f '{{.State.Running}}' "${P}-$n" 2>/dev/null)"
done
result S-00 "Loki ready (waits up to 60 s after start)" yes "$(wait_for 60 '^ready' x siem curl -s http://127.0.0.1:3100/ready)"
result S-00 "Grafana healthy (waits up to 120 s after start)" yes "$(wait_for 120 '"database": *"ok"' x siem curl -s http://127.0.0.1:3000/api/health)"
result S-00 "Loki data source provisioned in Grafana" yes "$(has "$(x siem curl -s -u "admin:${PASS}" http://127.0.0.1:3000/api/datasources/uid/loki 2>/dev/null)" '"type": *"loki"')"

for n in siem-collector siem-loki siem-grafana; do
  result S-00 "$n not killed for lack of memory, no restarts" "false 0" "$(docker inspect -f '{{.State.OOMKilled}} {{.RestartCount}}' "${P}-$n" 2>/dev/null)"
done

echo "== S-01 Management access (K-12)"
result S-01 "Grafana reachable from the VM on port 3000" yes "$(has "$(curl -s -m 3 http://127.0.0.1:3000/api/health 2>/dev/null)" '"database": *"ok"')"
mgmt=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${P}-siem" 2>/dev/null)
if curl -s -m 2 "http://${mgmt}:3100/ready" >/dev/null 2>&1; then r=reachable; else r=blocked; fi
result S-01 "Loki not reachable from outside siem (${mgmt:-?}:3100)" blocked "$r"
r6=$(x siem ip -6 route show default 2>/dev/null)
result S-01 "siem has no IPv6 default route" "" "$r6"

echo "== S-02 Latency DMZ -> SIEM (waf -> fw-dmz -> fw-edge -> fw-backend -> Fluent Bit -> Loki)"
tmp=$(mktemp)
lat=()
for i in $(seq "$SAMPLES"); do
  tok="${RUN}-${i}"
  poll "{job=\"dmz\", host=\"waf\", ident=\"dmztest\"} |= \"$tok\"" > "$tmp" &
  pid=$!
  sleep 0.3
  sent=$(send "$tok" | tail -1)
  wait "$pid"
  ms=$(elapsed "$sent" "$(tr -d '\r\n' < "$tmp")")
  if [ "$ms" = "99999" ]; then echo "   sample $i: not found"; else echo "   sample $i: ${ms} ms"; fi
  lat+=("$ms")
done
rm -f "$tmp"
min=${lat[0]}; max=${lat[0]}; sum=0
for v in "${lat[@]}"; do
  [ "$v" -lt "$min" ] && min=$v
  [ "$v" -gt "$max" ] && max=$v
  sum=$((sum + v))
done
echo "   min ${min} ms, avg $((sum / ${#lat[@]})) ms, max ${max} ms (resolution about 20 ms)"
result S-02 "every message searchable in Loki within ${LIMIT_MS} ms" yes "$([ "$max" -lt "$LIMIT_MS" ] && echo yes || echo no)"

echo "== S-03 WAF reports attacks to the SIEM (K-09)"
tok="${RUN}-waf"
tmp=$(mktemp)
poll "{job=\"dmz\", host=\"waf\", ident=\"modsecurity\"} |= \"$tok\" |= \"Access denied\"" > "$tmp" &
pid=$!
sleep 0.3
sent=$(attack "$tok" | tail -1)
wait "$pid"
ms=$(elapsed "$sent" "$(tr -d '\r\n' < "$tmp")")
rm -f "$tmp"
waf=$(lines "{job=\"dmz\", host=\"waf\", ident=\"modsecurity\"} |= \"$tok\"")
result S-03 "blocked SQL injection reported by waf" yes "$([ "$ms" != "99999" ] && echo yes || echo no)"
result S-03 "report names the attack rule (942xxx, SQL injection)" yes "$(has "$waf" '942[0-9]{3}')"
result S-03 "report names the real attacker 192.0.2.10" yes "$(has "$waf" 'client: 192\.0\.2\.10')"
result S-03 "attack visible in SIEM within ${LIMIT_MS} ms (${ms} ms)" yes "$([ "$ms" -lt "$LIMIT_MS" ] && echo yes || echo no)"
noise=$(lines '{job="dmz", host="waf", ident="modsecurity"} != "ModSecurity: "')
result S-03 "nginx messages without ModSecurity are filtered out" no "$(has "$noise" '"result":\[\{')"

echo "== Resources"
docker stats --no-stream --format '   {{.Name}}: {{.MemUsage}}' "${P}-siem-collector" "${P}-siem-loki" "${P}-siem-grafana" 2>/dev/null

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
