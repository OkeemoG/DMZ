#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
PASS="${GRAFANA_PASSWORD:-$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' "$(dirname "$0")/../configs/siem/secrets/grafana.env" 2>/dev/null)}"
LIMIT_MS="${LIMIT_MS:-1000}"
RUN="r$(date +%s)$$"
fail=0

x()       { docker exec "${P}-$1" "${@:2}"; }
side()    { docker run --rm --network "container:${P}-$1" client:0.1 "${@:2}"; }
respond() { x siem-responder respond "$@"; }

result() {
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

has() { if printf '%s' "$1" | grep -qE -- "$2"; then echo yes; else echo no; fi; }

entry() { respond list 2>/dev/null | grep -E "^$1 $2( |$)"; }

active() { if [ -n "$(entry "$1" "$2")" ]; then echo yes; else echo no; fi; }

wait_active() {
  for _ in $(seq "${3:-40}"); do
    if [ "$(active "$1" "$2")" = yes ]; then echo yes; return; fi
    sleep 0.25
  done
  echo no
}

reach() {
  local b=""
  [ -n "${4:-}" ] && b=",bind=$4"
  if x "$1" socat -T1 /dev/null "TCP:$2:$3,connect-timeout=1${b}" >/dev/null 2>&1; then echo reachable; else echo blocked; fi
}

web_reach() {
  if side web socat -T1 /dev/null "TCP:$1:$2,connect-timeout=1" >/dev/null 2>&1; then echo reachable; else echo blocked; fi
}

portal() { x "$1" curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "https://$2/health?m=${RUN}" 2>/dev/null; }

sqli() {
  x attacker curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
    --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" \
    "https://203.0.113.2/login?m=${RUN}-$1" 2>/dev/null
}

history_has() {
  if respond history 300 2>/dev/null | grep -F "\"action\":\"$1\"" | grep -F "\"client\":\"$2\"" | grep -qF -- "$3"; then echo yes; else echo no; fi
}

loki_has() {
  for _ in $(seq "${3:-10}"); do
    if x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query=$1" \
         --data-urlencode "start=$2" --data-urlencode limit=1 2>/dev/null | grep -q '"result":\[{'; then
      echo yes; return
    fi
    sleep 0.3
  done
  echo no
}

stat_of() { respond stats 2>/dev/null | sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }

ssh_fw() {
  docker exec -u responder "${P}-siem-responder" ssh -T -F /dev/null -i /home/responder/.ssh/id \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=3 \
    -o UserKnownHostsFile=/home/responder/.ssh/known_hosts -o StrictHostKeyChecking=yes "$@" 2>&1
}

clean() {
  respond flush >/dev/null 2>&1
  respond reset >/dev/null 2>&1
  respond mode enforce >/dev/null 2>&1
}

cleanup() {
  clean
  x attacker sh -c 'pkill -f "openssl s_client" ; pkill socat' >/dev/null 2>&1
  for a in 192.0.2.66/24 192.0.2.99/24 10.10.20.10/32; do x attacker ip addr del "$a" dev eth1 >/dev/null 2>&1; done
}
trap cleanup EXIT

echo "== RE-00 Services"
result RE-00 "siem-responder running" true "$(docker inspect -f '{{.State.Running}}' "${P}-siem-responder" 2>/dev/null)"
result RE-00 "siem-responder not killed for lack of memory, no restarts" "false 0" "$(docker inspect -f '{{.State.OOMKilled}} {{.RestartCount}}' "${P}-siem-responder" 2>/dev/null)"
result RE-00 "fw-edge: sshd for K-13 running" yes "$(x fw-edge pgrep -f /etc/response/sshd_config >/dev/null && echo yes || echo no)"
listen=$(x fw-edge ss -Htln 2>/dev/null)
result RE-00 "fw-edge: sshd listens on 10.10.0.9:22 only (backend side)" "yes no" "$(has "$listen" '10\.10\.0\.9:22 ') $(has "$listen" '(0\.0\.0\.0|\*|203\.0\.113\.2|10\.10\.0\.1|10\.10\.0\.5):22 ')"
up=no
for _ in $(seq 60); do
  if respond status 2>/dev/null | grep -q '^channel:  up'; then up=yes; break; fi
  sleep 1
done
result RE-00 "responder connected to fw-edge (waits up to 60 s)" yes "$up"
clean
result RE-00 "mode enforce" enforce "$(respond mode 2>/dev/null)"
before=$(respond status 2>/dev/null | sed -n 's/^events: *\([0-9]*\).*/\1/p')
x siem sh -c "echo '<134>$(date '+%b %e %H:%M:%S') waf dmztest: ${RUN}' | socat -u - UDP-SENDTO:127.0.0.1:5140" >/dev/null 2>&1
after="${before:-0}"
for _ in $(seq 20); do
  after=$(respond status 2>/dev/null | sed -n 's/^events: *\([0-9]*\).*/\1/p')
  [ "${after:-0}" -gt "${before:-0}" ] && break
  sleep 0.1
done
result RE-00 "Fluent Bit forwards every event to the responder" yes "$([ "${after:-0}" -gt "${before:-0}" ] && echo yes || echo no)"

echo "== RE-01 Channel K-13: SSH with forced command, BSI TR-02102-4"
result RE-01 "client1 -> fw-edge 10.10.0.9 TCP 22" blocked "$(reach client1 10.10.0.9 22)"
result RE-01 "attacker -> fw-edge 203.0.113.2 TCP 22" blocked "$(reach attacker 203.0.113.2 22)"
out=$(ssh_fw root@10.10.0.9 id)
result RE-01 "shell command replaced by fw-response (no shell)" "yes no" "$(has "$out" 'ERR unknown command') $(has "$out" 'uid=')"
result RE-01 "ping over the channel" yes "$(has "$(ssh_fw root@10.10.0.9 ping)" '^OK pong')"
out=$(ssh_fw -o KexAlgorithms=diffie-hellman-group14-sha256 root@10.10.0.9 ping)
result RE-01 "key exchange outside TR-02102-4 rejected" yes "$(has "$out" 'no matching key exchange')"
out=$(ssh_fw -o Ciphers=aes128-ctr root@10.10.0.9 ping)
result RE-01 "cipher other than AES-256-GCM rejected" yes "$(has "$out" 'no matching cipher')"
out=$(ssh_fw -o PreferredAuthentications=password -o PubkeyAuthentication=no root@10.10.0.9 ping)
result RE-01 "password login impossible" yes "$(has "$out" 'Permission denied \(publickey\)')"
x siem-responder sh -c 'rm -f /tmp/k /tmp/k.pub; ssh-keygen -q -t ecdsa -b 384 -N "" -f /tmp/k' >/dev/null 2>&1
out=$(docker exec "${P}-siem-responder" ssh -T -F /dev/null -i /tmp/k -o IdentitiesOnly=yes -o BatchMode=yes \
  -o UserKnownHostsFile=/home/responder/.ssh/known_hosts root@10.10.0.9 ping 2>&1)
result RE-01 "unknown key rejected" yes "$(has "$out" 'Permission denied')"

echo "== RE-02 Protected addresses are never blocked"
respond block 10.10.10.10 60 RE-02 >/dev/null 2>&1; rc=$?
result RE-02 "responder refuses to block web 10.10.10.10" 1 "$rc"
result RE-02 "fw-edge refuses to block siem 10.10.30.10 even if asked directly" yes "$(has "$(ssh_fw root@10.10.0.9 block 10.10.30.10 60 RE-02)" '^ERR protected')"
result RE-02 "fw-edge refuses VPN peer 198.51.100.2 (spoofing would cut the tunnel)" yes "$(has "$(ssh_fw root@10.10.0.9 block 198.51.100.2 60 RE-02)" '^ERR protected')"
result RE-02 "fw-edge refuses to quarantine the client gateway 10.10.20.1 (router-int)" yes "$(has "$(ssh_fw root@10.10.0.9 quarantine 10.10.20.1 0 RE-02)" '^ERR protected')"
result RE-02 "fw-edge refuses to quarantine an external address" yes "$(has "$(ssh_fw root@10.10.0.9 quarantine 192.0.2.10 0 RE-02)" '^ERR not internal')"
x fw-edge nft add element inet response blocklist '{ 10.10.10.2 timeout 30s }' >/dev/null 2>&1
result RE-02 "second safeguard: proxy listed by hand in the ruleset, client1 still reaches it" 200 "$(portal client1 10.10.10.2)"
clean

echo "== RE-03 P-1 repeated web attacks: attacker locked out at fw-edge"
since=$(date +%s%N)
d0=$(stat_of blocked)
timing=$(docker exec -i "${P}-attacker" sh -s "${RUN}" <<'MEASURE'
for i in 1 2 3; do
  curl -sk -o /dev/null --max-time 3 --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://203.0.113.2/login?m=$1-l$i"
done
t0=$(cut -d' ' -f1 /proc/uptime)
i=0
while [ "$i" -lt 60 ]; do
  t1=$(cut -d' ' -f1 /proc/uptime)
  if ! socat -T1 /dev/null TCP:203.0.113.2:443,connect-timeout=0.15 >/dev/null 2>&1; then
    echo "$t0 $t1"; exit 0
  fi
  i=$((i + 1))
  usleep 50000
done
echo "$t0 timeout"
MEASURE
)
read -r t0 t1 <<< "$timing"
if [ "${t1:-timeout}" = "timeout" ]; then ms=99999; else ms=$(( (${t1/./} - ${t0/./}) * 10 )); fi
result RE-03 "block in place within ${LIMIT_MS} ms after the third blocked attack (${ms} ms)" yes "$([ "$ms" -lt "$LIMIT_MS" ] && echo yes || echo no)"
result RE-03 "fw-edge lists 192.0.2.10 with reason P-1" yes "$(has "$(entry blocklist 192.0.2.10)" 'timeout 10m .*comment "P-1"')"
result RE-03 "attacker -> portal TCP 443 (now also legitimate requests)" blocked "$(reach attacker 203.0.113.2 443)"
result RE-03 "attacker -> portal TCP 80" blocked "$(reach attacker 203.0.113.2 80)"
result RE-03 "no collateral damage: client1 still reaches the portal" 200 "$(portal client1 10.10.10.2)"
result RE-03 "responder history: block with reaction time" yes "$(history_has block 192.0.2.10 '"latency_ms":')"
result RE-03 "reaction visible in the SIEM" yes "$(loki_has '{job="dmz", ident="responder"} | json | action="block" | client="192.0.2.10" | playbook="P-1"' "$since")"
result RE-03 "blocked packets reported by fw-edge" yes "$(loki_has '{job="dmz", host="fw-edge", ident="ulogd"} | json | fw_rule="fw-edge block drop" | client="192.0.2.10"' "$since")"
d1=$(stat_of blocked)
result RE-03 "block counter on fw-edge rises (${d0:-?} -> ${d1:-?} packets)" yes "$([ "${d1:-0}" -gt "${d0:-0}" ] && echo yes || echo no)"
respond release 192.0.2.10 >/dev/null 2>&1
result RE-03 "after release the attacker reaches the portal again" reachable "$(reach attacker 203.0.113.2 443)"
clean

echo "== RE-04 Existing connections are ended"
docker exec -d "${P}-attacker" sh -c 'sleep 30 | openssl s_client -quiet -connect 203.0.113.2:443 >/dev/null 2>&1'
sleep 1.5
c0=$(x fw-edge sh -c 'conntrack -L -s 192.0.2.10 2>/dev/null | grep -c ESTABLISHED')
result RE-04 "open TLS session of the attacker in conntrack" yes "$([ "${c0:-0}" -ge 1 ] && echo yes || echo no)"
out=$(respond block 192.0.2.10 60 RE-04 2>&1)
result RE-04 "block deletes the attacker's connection state" yes "$(has "$out" 'flows=[1-9]')"
c1=$(x fw-edge sh -c 'conntrack -L -s 192.0.2.10 2>/dev/null | grep -c ESTABLISHED')
result RE-04 "no established connection of 192.0.2.10 left" 0 "${c1:-0}"
x attacker pkill -f "openssl s_client" >/dev/null 2>&1
clean

echo "== RE-05 P-3 port scan"
x attacker ip addr add 192.0.2.66/24 dev eth1 >/dev/null 2>&1
result RE-05 "control: 192.0.2.66 reaches the portal" reachable "$(reach attacker 203.0.113.2 443 192.0.2.66)"
x attacker sh -c 'for p in 21 22 23 25 53 110 135 139 445 1433 3306 3389; do socat -T1 /dev/null TCP:203.0.113.2:$p,connect-timeout=1,bind=192.0.2.66 >/dev/null 2>&1 & done; wait'
result RE-05 "scan of 12 ports blocked (threshold 10 ports in 20 s)" yes "$(wait_active blocklist 192.0.2.66)"
result RE-05 "reason P-3" yes "$(has "$(entry blocklist 192.0.2.66)" 'comment "P-3"')"
result RE-05 "192.0.2.66 -> portal" blocked "$(reach attacker 203.0.113.2 443 192.0.2.66)"
result RE-05 "only the scanner is blocked, not 192.0.2.10 in the same network" no "$(active blocklist 192.0.2.10)"
x attacker ip addr del 192.0.2.66/24 dev eth1 >/dev/null 2>&1
clean

echo "== RE-06 P-4 lateral movement: internal host quarantined"
result RE-06 "control: client1 reaches the portal" 200 "$(portal client1 10.10.10.2)"
for p in 8080 22 80; do reach client1 10.10.10.10 "$p" >/dev/null; done
sleep 1
result RE-06 "3 forbidden ports on one host: no quarantine (P-4 counts hosts)" no "$(active quarantine 10.10.20.10)"
for t in 10.10.10.10:8080 10.10.10.6:8080 10.10.10.14:8080; do reach client1 "${t%:*}" "${t#*:}" >/dev/null; done
result RE-06 "client1 quarantined after 3 forbidden internal targets" yes "$(wait_active quarantine 10.10.20.10)"
result RE-06 "quarantine has no expiry (until an operator releases it)" no "$(has "$(entry quarantine 10.10.20.10)" 'timeout')"
result RE-06 "client1 -> portal" 000 "$(portal client1 10.10.10.2)"
result RE-06 "responder history: quarantine P-4" yes "$(history_has quarantine 10.10.20.10 '"playbook":"P-4"')"
respond release 10.10.20.10 >/dev/null 2>&1
result RE-06 "after release client1 reaches the portal again" 200 "$(portal client1 10.10.10.2)"
clean

echo "== RE-07 P-5 connection to command and control: connections from inside to the destination blocked"
x attacker ip addr add 192.0.2.99/24 dev eth1 >/dev/null 2>&1
docker exec -d "${P}-attacker" socat TCP-LISTEN:443,bind=192.0.2.99,fork,reuseaddr "SYSTEM:echo ok"
sleep 0.5
result RE-07 "control: web -> 192.0.2.99 TCP 443 (K-06)" reachable "$(web_reach 192.0.2.99 443)"
web_reach 192.0.2.99 4444 >/dev/null
result RE-07 "web -> 192.0.2.99 TCP 4444 (V-12) blocks connections to 192.0.2.99" yes "$(wait_active egress 192.0.2.99)"
result RE-07 "reason P-5" yes "$(has "$(entry egress 192.0.2.99)" 'comment "P-5"')"
result RE-07 "web -> 192.0.2.99 TCP 443 now dropped as well" blocked "$(web_reach 192.0.2.99 443)"
result RE-07 "client1 -> 192.0.2.99 TCP 443 dropped too (whole company)" blocked "$(reach client1 192.0.2.99 443)"
result RE-07 "192.0.2.99 itself still reaches the portal (no denial of service by a compromised server)" reachable "$(reach attacker 203.0.113.2 443 192.0.2.99)"
result RE-07 "192.0.2.10 not affected" no "$(active blocklist 192.0.2.10)"
x attacker pkill -f "bind=192.0.2.99" >/dev/null 2>&1
x attacker ip addr del 192.0.2.99/24 dev eth1 >/dev/null 2>&1
clean

echo "== RE-08 P-2 attack seen behind the WAF (simulated WAF bypass)"
side waf curl -s -o /dev/null --max-time 3 -H "X-Forwarded-For: 192.0.2.77" \
  "http://10.10.10.10:8080/search?q=1%20UNION%20SELECT%20name%20FROM%20users--&m=${RUN}-p2" >/dev/null 2>&1
result RE-08 "IDS alert waf -> web blocks the original client 192.0.2.77 at once" yes "$(wait_active blocklist 192.0.2.77)"
result RE-08 "reason P-2" yes "$(has "$(entry blocklist 192.0.2.77)" 'comment "P-2"')"
clean

echo "== RE-09 Attribution: forged X-Forwarded-For in front of the proxy is ignored"
since=$(date +%s%N)
x attacker curl -s -o /dev/null --max-time 3 -H "X-Forwarded-For: 10.10.20.10" \
  "http://203.0.113.2/search?q=1%20UNION%20SELECT%20name%20FROM%20users--&m=${RUN}-xff" >/dev/null 2>&1
result RE-09 "IDS alert carries the forged header" yes "$(loki_has '{job="dmz", host="ids"} | json | alert_xff="10.10.20.10"' "$since")"
result RE-09 "collector names the real sender 192.0.2.10" yes "$(loki_has '{job="dmz", host="ids"} | json | alert_xff="10.10.20.10" | client="192.0.2.10"' "$since" 3)"
result RE-09 "collector does not name the forged 10.10.20.10" no "$(loki_has '{job="dmz", host="ids"} | json | alert_xff="10.10.20.10" | client="10.10.20.10"' "$since" 3)"
clean

echo "== RE-10 Anti-spoofing on fw-edge"
since=$(date +%s%N)
s0=$(stat_of spoofed)
x attacker ip addr add 10.10.20.10/32 dev eth1 >/dev/null 2>&1
x attacker sh -c 'for p in 22 23 25 443; do socat -T1 /dev/null TCP:203.0.113.2:$p,connect-timeout=1,bind=10.10.20.10 >/dev/null 2>&1 & done; wait'
x attacker ip addr del 10.10.20.10/32 dev eth1 >/dev/null 2>&1
s1=$(stat_of spoofed)
result RE-10 "packets from the Internet with sender 10.10.20.10 dropped (${s0:-?} -> ${s1:-?})" yes "$([ "${s1:-0}" -gt "${s0:-0}" ] && echo yes || echo no)"
result RE-10 "reported to the SIEM as spoof drop" yes "$(loki_has '{job="dmz", host="fw-edge", ident="ulogd"} | json | fw_rule="fw-edge spoof drop" | client="10.10.20.10"' "$since")"
sleep 1
result RE-10 "forged sender does not get client1 quarantined" no "$(active quarantine 10.10.20.10)"
clean

echo "== RE-11 Monitor mode: detect and report only"
respond mode monitor >/dev/null
for i in 1 2 3; do sqli "m$i" >/dev/null; done
sleep 1
result RE-11 "attacker not blocked in monitor mode" reachable "$(reach attacker 203.0.113.2 443)"
result RE-11 "decision reported as would_block" yes "$(history_has would_block 192.0.2.10 '"playbook":"P-1"')"
clean

echo "== RE-12 Expiry and repeat offenders"
respond block 192.0.2.88 2 RE-12 >/dev/null
result RE-12 "manual block with 2 s" yes "$(active blocklist 192.0.2.88)"
sleep 3.5
result RE-12 "block expired on fw-edge" no "$(active blocklist 192.0.2.88)"
result RE-12 "expiry reported" yes "$(history_has expire 192.0.2.88 RE-12)"
for i in 1 2 3; do sqli "e$i" >/dev/null 2>&1; done
result RE-12 "first offence: 10 min" yes "$(wait_active blocklist 192.0.2.10 >/dev/null; has "$(entry blocklist 192.0.2.10)" 'timeout 10m ')"
respond release 192.0.2.10 >/dev/null
for i in 1 2 3; do sqli "f$i" >/dev/null 2>&1; done
result RE-12 "second offence: 20 min" yes "$(wait_active blocklist 192.0.2.10 >/dev/null; has "$(entry blocklist 192.0.2.10)" 'timeout 20m ')"
clean

echo "== RE-13 Blocks survive a restart of the responder"
respond block 192.0.2.89 300 RE-13 >/dev/null
docker restart "${P}-siem-responder" >/dev/null
result RE-13 "block stays on fw-edge while the responder is down" yes "$(x fw-edge nft list set inet response blocklist 2>/dev/null | grep -q '192\.0\.2\.89' && echo yes || echo no)"
up=no
for _ in $(seq 30); do
  if respond status 2>/dev/null | grep -q '^channel:  up'; then up=yes; break; fi
  sleep 1
done
result RE-13 "responder reconnects" yes "$up"
result RE-13 "responder takes over the state from fw-edge" yes "$(has "$(respond status 2>/dev/null)" 'blocklist +192\.0\.2\.89 ')"
clean

echo "== RE-14 SOC dashboard shows the reaction"
dash=$(x siem curl -s -u "admin:${PASS}" http://127.0.0.1:3000/api/dashboards/uid/dmz-soc 2>/dev/null)
result RE-14 "panels mode, blocks, quarantine, channel, reaction time, reaction log" "6" "$(printf '%s' "$dash" | grep -oE '"title": *"(Reaktion: Modus|Gesperrte Adressen \(fw-edge\)|Isolierte interne Hosts|Kanal zu fw-edge|Letzte Reaktionszeit|Reaktionen \(neueste oben\))"' | sort -u | wc -l | tr -d ' ')"
result RE-14 "heartbeat of the responder in Loki" yes "$(loki_has '{job="dmz", ident="responder"} | json | action="state"' "$(( ($(date +%s) - 30) * 1000000000 ))")"

echo "== RE-15 Sensor binding: a compromised waf cannot pose as a firewall"
since=$(date +%s%N)
r0=$(respond status 2>/dev/null | sed -n 's/.*rejected: *\([0-9]*\).*/\1/p')
for d in 10.10.10.10 10.10.10.6 10.10.10.14; do
  printf '<134>%s fw-edge ulogd: fw-edge forward drop:  IN=eth3 OUT=eth2 MAC= SRC=10.10.20.10 DST=%s LEN=60 TOS=00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 %s\n' "$(date '+%b %e %H:%M:%S')" "$d" "${RUN}-spoof" \
    | docker run --rm -i --network "container:${P}-waf" client:0.1 socat -u - UDP-SENDTO:10.10.30.10:5140 >/dev/null 2>&1
done
sleep 1.5
r1=$(respond status 2>/dev/null | sed -n 's/.*rejected: *\([0-9]*\).*/\1/p')
result RE-15 "3 forged firewall drops from waf: client1 not quarantined" no "$(active quarantine 10.10.20.10)"
result RE-15 "responder rejects them (${r0:-?} -> ${r1:-?})" yes "$([ "${r1:-0}" -ge $(( ${r0:-0} + 3 )) ] && echo yes || echo no)"
result RE-15 "SIEM labels them with the real sender waf" yes "$(loki_has "{job=\"dmz\", host=\"waf\", ident=\"ulogd\"} |= \"${RUN}-spoof\"" "$since")"
result RE-15 "rejection reported in the SIEM" yes "$(loki_has '{job="dmz", ident="responder"} | json | action="rejected"' "$since")"
clean

echo "== RE-16 P-5 reacts only to its signatures (1000003, 1000007)"
alert() { x ids logger -t suricata "{\"event_type\":\"alert\",\"src_ip\":\"10.10.10.10\",\"dest_ip\":\"$1\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{\"signature_id\":$2,\"signature\":\"${RUN} test\"}}"; }
alert 192.0.2.55 1000001
sleep 1.5
result RE-16 "IDS alert DMZ -> 192.0.2.55 with another signature (1000001): no block" no "$(active egress 192.0.2.55)"
alert 192.0.2.56 1000007
result RE-16 "IDS alert DMZ -> 192.0.2.56 with SID 1000007 (command output): blocked" yes "$(wait_active egress 192.0.2.56)"
clean

echo "== Resources"
docker stats --no-stream --format '   {{.Name}}: {{.MemUsage}}' "${P}-siem-responder" 2>/dev/null

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
