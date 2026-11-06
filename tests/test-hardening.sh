#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
. "$(dirname "$0")/lib-response.sh"
response_suspend
SECRETS="$(dirname "$0")/../configs/siem/secrets/grafana.env"
PASS="${GRAFANA_PASSWORD:-$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' "$SECRETS" 2>/dev/null)}"
RUN="h$(date +%s)$$"
fail=0

ROUTER=(fw-edge fw-dmz fw-backend router-int)
DMZ=(proxy waf web ids)
SIEM=(siem-collector siem-loki siem-grafana siem-responder)

x() { docker exec "${P}-$1" "${@:2}"; }

result() {
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

has() { if printf '%s' "$1" | grep -qE -- "$2"; then echo yes; else echo no; fi; }

hasi() { if printf '%s' "$1" | grep -qiE -- "$2"; then echo yes; else echo no; fi; }

status_of() { awk -v k="$2:" '$1 == k { print $2; exit }' "/proc/$(docker inspect -f '{{.State.Pid}}' "${P}-$1" 2>/dev/null)/status" 2>/dev/null; }

cap() {
  local hex v
  hex=$(status_of "$1" CapBnd)
  [ -n "$hex" ] || { echo "?"; return; }
  v=$((16#$hex))
  if [ $(( (v >> $2) & 1 )) -eq 1 ]; then echo yes; else echo no; fi
}

loki_has() {
  for _ in $(seq "${3:-10}"); do
    if x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query=$1" \
         --data-urlencode "start=$2" --data-urlencode limit=1 2>/dev/null | grep -q '"result":\[{'; then
      echo yes; return
    fi
    sleep 1
  done
  echo no
}

uptime_cs() { cut -d' ' -f1 /proc/uptime | tr -d .; }

side() { docker run --rm -i --network "container:${P}-$1" client:0.1 "${@:2}"; }

counter_of() { x "$1" nft list chain inet filter "$2" 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\) .*/\1/p' | tail -1; }

suricata_pid() { x ids pgrep -f 'suricata --include' 2>/dev/null | head -1; }

echo "== H-01 Containers without privileged mode, minimal capabilities"
for n in "${ROUTER[@]}" "${DMZ[@]}" "${SIEM[@]}"; do
  result H-01 "$n not privileged" false "$(docker inspect -f '{{.HostConfig.Privileged}}' "${P}-$n" 2>/dev/null)"
  result H-01 "$n no-new-privileges" 1 "$(status_of "$n" NoNewPrivs)"
  result H-01 "$n without SYS_ADMIN, SYS_MODULE, SYS_RAWIO, SYS_PTRACE, DAC_READ_SEARCH" "no no no no no" "$(cap "$n" 21) $(cap "$n" 16) $(cap "$n" 17) $(cap "$n" 19) $(cap "$n" 2)"
done
for n in "${ROUTER[@]}" "${DMZ[@]}"; do
  result H-01 "$n keeps NET_ADMIN for its interfaces" yes "$(cap "$n" 12)"
done
for n in "${SIEM[@]}"; do
  result H-01 "$n without NET_ADMIN" no "$(cap "$n" 12)"
done
echo "   NET_RAW is a Docker default and stays in every container (containerlab offers no cap-drop)."
echo "   It only matters for root inside a container; the services run without root (H-02)."
echo "   still privileged on purpose: $(for n in inet attacker client1 ro-client1 ro-client2 siem; do [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "${P}-$n" 2>/dev/null)" = true ] && printf '%s ' "$n"; done)"

echo "== H-02 Services without root"
for n in waf siem-collector siem-loki siem-grafana siem-responder; do
  uid=$(status_of "$n" Uid)
  result H-02 "$n main process not root (uid ${uid:-?})" yes "$([ -n "$uid" ] && [ "$uid" != 0 ] && echo yes || echo no)"
done
sp=$(suricata_pid)
su=$(x ids ps -o pid,user 2>/dev/null | awk -v p="${sp:-x}" '$1 == p { print $2 }')
result H-02 "ids: suricata runs as user suricata" suricata "$su"
if [ "$su" != suricata ]; then
  echo "   last start errors (watchdog):"
  x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode 'query={job="dmz", ident="ids-watchdog"}' --data-urlencode limit=8 2>/dev/null \
    | grep -oE 'suricata (exited|does not)[^"]*' | head -8 | sed 's/^/     /'
fi
result H-02 "ids: suricata holds only NET_ADMIN and NET_RAW" 0000000000003000 "$(x ids sh -c "awk '/^CapEff:/ { print \$2 }' /proc/${sp:-0}/status" 2>/dev/null)"
w=$(x web ps -o user,args 2>/dev/null | grep -c '^app .*gunicorn')
result H-02 "web: gunicorn workers as app" yes "$([ "${w:-0}" -ge 1 ] && echo yes || echo no)"
w=$(x proxy ps -o user,args 2>/dev/null | grep -c '^nginx .*worker process')
result H-02 "proxy: nginx workers as nginx" yes "$([ "${w:-0}" -ge 1 ] && echo yes || echo no)"

echo "== H-03 Break-out attempts from a compromised web server fail (root shell inside web)"
if x web mount -t tmpfs none /mnt >/dev/null 2>&1; then r=allowed; x web umount /mnt >/dev/null 2>&1; else r=denied; fi
result H-03 "mount a file system" denied "$r"
result H-03 "host block devices visible" no "$(has "$(x web ls /dev 2>/dev/null)" '^(sd[a-z]|vd[a-z]|nvme|xvd)')"
if x web sh -c 'echo 1 > /proc/sys/kernel/sysrq' >/dev/null 2>&1; then r=allowed; else r=denied; fi
result H-03 "write kernel parameters" denied "$r"
if x web sh -c 'echo 1 > /proc/sysrq-trigger' >/dev/null 2>&1; then r=allowed; else r=denied; fi
result H-03 "trigger kernel functions (sysrq)" denied "$r"
if x inet sh -c 'mount -t tmpfs none /mnt && umount /mnt' >/dev/null 2>&1; then r=allowed; else r=denied; fi
echo "   for comparison, privileged inet: mount ${r}"

echo "== H-04 Kernel parameters (routers and DMZ servers)"
sys() { x "$1" cat "/proc/sys/$2" 2>/dev/null; }
for n in "${ROUTER[@]}" "${DMZ[@]}"; do
  got="$(sys "$n" net/ipv4/conf/all/accept_redirects)$(sys "$n" net/ipv4/conf/eth1/accept_redirects)$(sys "$n" net/ipv4/conf/all/send_redirects)$(sys "$n" net/ipv4/conf/eth1/send_redirects)$(sys "$n" net/ipv4/conf/eth1/accept_source_route)$(sys "$n" net/ipv4/tcp_syncookies)"
  result H-04 "$n no redirects in or out, no source routing, SYN cookies (all and eth1)" 000001 "$got"
done
for n in "${ROUTER[@]}"; do
  result H-04 "$n forwards packets" 1 "$(sys "$n" net/ipv4/ip_forward)"
done
for n in "${DMZ[@]}"; do
  result H-04 "$n does not forward packets on eth1" 0 "$(sys "$n" net/ipv4/conf/eth1/forwarding)"
done
result H-04 "siem does not forward packets (management network stays a dead end)" 0 "$(sys siem net/ipv4/ip_forward)"
result H-04 "ids mirror port eth2 without any address" "" "$(x ids ip -o addr show dev eth2 2>/dev/null)"
result H-04 "fw-dmz mirror port eth6 without any address" "" "$(x fw-dmz ip -o addr show dev eth6 2>/dev/null)"
for fw in fw-edge fw-dmz fw-backend; do
  result H-04 "$fw filters IPv6 as well (inet tables, policy drop)" "yes yes" "$(has "$(x "$fw" nft list chain inet filter input 2>/dev/null)" 'policy drop') $(has "$(x "$fw" nft list chain inet filter forward 2>/dev/null)" 'policy drop')"
done

echo "== H-05 Firewalls only send what they must (output chain)"
for fw in fw-edge fw-dmz fw-backend; do
  result H-05 "$fw output policy drop" yes "$(has "$(x "$fw" nft list chain inet filter output 2>/dev/null)" 'policy drop')"
done
x attacker pkill -f 'TCP-LISTEN:80,' >/dev/null 2>&1
docker exec -d "${P}-attacker" socat TCP-LISTEN:80,fork,reuseaddr "SYSTEM:echo ok"
sleep 0.5
result H-05 "control: client1 -> 192.0.2.10 TCP 80 (K-05)" ok "$(x client1 socat -T2 - TCP:192.0.2.10:80,connect-timeout=2 </dev/null 2>/dev/null | tr -d '\r\n')"
since=$(date +%s%N)
for fw in fw-edge fw-dmz; do
  c0=$(x "$fw" nft list chain inet filter output 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\) .*verworfen.*/\1/p')
  if x "$fw" sh -c 'echo x | nc -w 2 192.0.2.10 80' >/dev/null 2>&1; then r=reachable; else r=blocked; fi
  c1=$(x "$fw" nft list chain inet filter output 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\) .*verworfen.*/\1/p')
  result H-05 "$fw itself -> 192.0.2.10 TCP 80" blocked "$r"
  result H-05 "$fw output drop counted (${c0:-?} -> ${c1:-?})" yes "$([ "${c1:-0}" -gt "${c0:-0}" ] && echo yes || echo no)"
done
x attacker pkill -f 'TCP-LISTEN:80,' >/dev/null 2>&1
result H-05 "fw-edge reports its own blocked connection to the SIEM" yes "$(loki_has '{job="dmz", host="fw-edge", ident="ulogd"} | json | fw_rule="fw-edge output drop"' "$since")"
result H-05 "fw-dmz reports its own blocked connection to the SIEM" yes "$(loki_has '{job="dmz", host="fw-dmz", ident="ulogd"} | json | fw_rule="fw-dmz output drop"' "$since")"
sas=$(x fw-edge swanctl --list-sas 2>/dev/null)
result H-05 "VPN still works: 2 IKE SAs established" 2 "$(printf '%s\n' "$sas" | grep -c 'ESTABLISHED')"
result H-05 "SIEM channel K-13 still works" yes "$(has "$(x siem-responder respond status 2>/dev/null)" '^channel: +up')"

echo "== H-06 IDS restarts itself and keeps its logs small"
result H-06 "watchdog running" yes "$(x ids pgrep -f ids-watchdog.sh >/dev/null 2>&1 && echo yes || echo no)"
result H-06 "log guard running" yes "$(x ids pgrep -f ids-logguard.sh >/dev/null 2>&1 && echo yes || echo no)"
since=$(date +%s%N)
old=$(x ids pgrep -f 'suricata --include' 2>/dev/null | head -1)
x ids pkill -9 -f 'suricata --include' >/dev/null 2>&1
new=""
for _ in $(seq 30); do
  new=$(x ids pgrep -f 'suricata --include' 2>/dev/null | head -1)
  [ -n "$new" ] && [ "$new" != "$old" ] && break
  sleep 1
done
result H-06 "suricata killed (pid ${old:-?}) and restarted (pid ${new:-?})" yes "$([ -n "$new" ] && [ "$new" != "$old" ] && echo yes || echo no)"
result H-06 "restart reported to the SIEM" yes "$(loki_has '{job="dmz", ident="ids-watchdog"} |= "suricata exited"' "$since")"
det=no
for i in $(seq 15); do
  x attacker curl -sk -o /dev/null --max-time 3 "https://203.0.113.2/search?q=1%20UNION%20SELECT%20name%20FROM%20users--&m=${RUN}-$i" >/dev/null 2>&1
  if [ "$(loki_has '{job="dmz", host="ids", ident="suricata"} | json | alert_signature_id="1000001"' "$since" 2)" = yes ]; then det=yes; break; fi
done
result H-06 "detection works again after the restart" yes "$det"
size_before=$(x ids sh -c 'dd if=/dev/zero bs=1M count=51 2>/dev/null >> /var/log/suricata/stats.log; wc -c < /var/log/suricata/stats.log' 2>/dev/null)
shrunk=no
for _ in $(seq 40); do
  s=$(x ids sh -c 'wc -c < /var/log/suricata/stats.log' 2>/dev/null)
  if [ -n "$s" ] && [ "$s" -lt 52428800 ]; then shrunk=yes; break; fi
  sleep 1
done
result H-06 "stats.log above 50 MB (${size_before:-?} bytes) is truncated" yes "$shrunk"
result H-06 "truncation reported to the SIEM" yes "$(loki_has '{job="dmz", ident="ids-logguard"} |= "truncated"' "$since")"

echo "== H-07 Container logs limited in size"
for n in proxy waf web ids; do
  lc=$(docker inspect -f '{{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config "max-size"}} {{index .HostConfig.LogConfig.Config "max-file"}}' "${P}-$n" 2>/dev/null)
  result H-07 "$n log driver with size limit ($lc), set up by make host-hardening" yes "$(has "$lc" '^json-file [0-9]+[kmg] [0-9]+$')"
done

echo "== H-08 Proxy closes slow requests (Slowloris)"
timing=$(docker exec -i "${P}-attacker" sh <<'SLOW'
rm -f /tmp/slow.t1
t0=$(cut -d' ' -f1 /proc/uptime)
(printf 'GET / HTTP/1.1\r\nHost: 203.0.113.2\r\n'; sleep 12) | (timeout 15 openssl s_client -quiet -connect 203.0.113.2:443 >/dev/null 2>&1; cut -d' ' -f1 /proc/uptime > /tmp/slow.t1)
echo "$t0 $(cat /tmp/slow.t1)"
SLOW
)
read -r t0 t1 <<< "$timing"
ms=$(( (${t1/./} - ${t0/./}) * 10 ))
result H-08 "incomplete request header closed after the 5 s timeout (${ms} ms)" yes "$([ "$ms" -ge 4000 ] && [ "$ms" -lt 9000 ] && echo yes || echo no)"
cfg=$(x proxy nginx -T 2>/dev/null)
result H-08 "header and body timeouts, connection limit per address" "yes yes yes" "$(has "$cfg" 'client_header_timeout 5s') $(has "$cfg" 'client_body_timeout 5s') $(has "$cfg" 'limit_conn conn_limit')"

echo "== H-09 SIEM access"
code() { x siem curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
result H-09 "former default password dmz-soc rejected" 401 "$(code -u admin:dmz-soc http://127.0.0.1:3000/api/user)"
result H-09 "generated password accepted" 200 "$(code -u "admin:${PASS}" http://127.0.0.1:3000/api/user)"
result H-09 "dashboard not readable without login" 401 "$(code http://127.0.0.1:3000/api/dashboards/uid/dmz-soc)"
result H-09 "password file only readable by its owner" 600 "$(stat -c '%a' "$SECRETS" 2>/dev/null)"
result H-09 "password file excluded from git" yes "$(git -C "$(dirname "$0")/.." check-ignore -q configs/siem/secrets/grafana.env && echo yes || echo no)"
hdr=$(x siem curl -sI http://127.0.0.1:3000/login 2>/dev/null)
result H-09 "Grafana sends nosniff, frame and content security headers" "yes yes yes" "$(hasi "$hdr" '^x-content-type-options: nosniff') $(hasi "$hdr" '^x-frame-options: deny') $(hasi "$hdr" '^content-security-policy:')"

echo "== H-10 Firewalls fail closed"
for fw in fw-edge fw-dmz fw-backend; do
  result H-10 "$fw: project rule set active, not the failsafe" "yes no" "$(has "$(x "$fw" nft list tables 2>/dev/null)" 'table inet filter') $(has "$(x "$fw" nft list tables 2>/dev/null)" 'table inet failsafe')"
done
fs=$(docker run --rm --network none --cap-add NET_ADMIN -v "$(cd "$(dirname "$0")/.." && pwd)/configs/fw/fw-start.sh:/fw-start.sh:ro" fw:0.1 \
  sh -c 'echo "table inet filter { broken" > /tmp/bad.nft; sh /fw-start.sh /tmp/bad.nft >/dev/null 2>&1; echo "rc=$?"; nft list ruleset' 2>/dev/null)
result H-10 "broken rule set: start script reports the error" yes "$(has "$fs" '^rc=1')"
result H-10 "broken rule set: failsafe drops input, forward and output" 3 "$(printf '%s\n' "$fs" | grep -c 'policy drop;')"

echo "== H-11 fw-dmz binds every DMZ address to its port (anti-spoofing)"
x attacker pkill -f 'TCP-LISTEN:80,' >/dev/null 2>&1
docker exec -d "${P}-attacker" socat TCP-LISTEN:80,fork,reuseaddr "SYSTEM:echo ok"
sleep 0.5
result H-11 "control: web -> 192.0.2.10 TCP 80 with its own address (K-06)" ok "$(side web socat -T2 - TCP:192.0.2.10:80,connect-timeout=2 </dev/null 2>/dev/null | tr -d '\r\n')"
s0=$(counter_of fw-dmz spoofed)
x web ip addr add 10.10.10.2/32 dev eth1 >/dev/null 2>&1
r=$(side web socat -T2 - TCP:192.0.2.10:80,connect-timeout=2,bind=10.10.10.2 </dev/null 2>/dev/null | tr -d '\r\n')
x web ip addr del 10.10.10.2/32 dev eth1 >/dev/null 2>&1
s1=$(counter_of fw-dmz spoofed)
result H-11 "web posing as proxy 10.10.10.2 -> 192.0.2.10 TCP 80" blocked "$([ "$r" = ok ] && echo reachable || echo blocked)"
result H-11 "fw-dmz drops the forged sender (${s0:-?} -> ${s1:-?} packets)" yes "$([ "${s1:-0}" -gt "${s0:-0}" ] && echo yes || echo no)"
x attacker pkill -f 'TCP-LISTEN:80,' >/dev/null 2>&1
since=$(date +%s%N)
msg="<134>$(date '+%b %e %H:%M:%S') ids suricata: {\"event_type\":\"alert\",\"src_ip\":\"10.10.10.10\",\"dest_ip\":\"192.0.2.55\",\"dest_port\":4444,\"alert\":{\"signature_id\":1000003,\"signature\":\"${RUN}\"}}"
docker exec -u 0 "${P}-waf" ip addr add 10.10.10.14/32 dev eth1 >/dev/null 2>&1
side waf socat -u - UDP-SENDTO:10.10.30.10:5140,bind=10.10.10.14 <<< "$msg" >/dev/null 2>&1
docker exec -u 0 "${P}-waf" ip addr del 10.10.10.14/32 dev eth1 >/dev/null 2>&1
result H-11 "waf posing as ids 10.10.10.14 does not reach the SIEM" no "$(loki_has "{job=\"dmz\"} |= \"${RUN}\"" "$since" 3)"
result H-11 "forged sender reported by fw-dmz" yes "$(loki_has '{job="dmz", host="fw-dmz", ident="ulogd"} | json | fw_rule="fw-dmz spoof drop"' "$since")"

echo "== Resources"
docker stats --no-stream --format '   {{.Name}}: {{.MemUsage}}' "${P}-ids" "${P}-fw-edge" "${P}-proxy" 2>/dev/null

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
