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
    echo "FEHLER $1 $2 (erwartet: $3, Ergebnis: $4)"
    fail=1
  fi
}

has() { # Text, Muster (erweiterter regulaerer Ausdruck) -> ja|nein
  if printf '%s' "$1" | grep -qE -- "$2"; then echo ja; else echo nein; fi
}

events() { # event_type, Muster ... -> Anzahl passender Eintraege in eve.json
  local out
  out=$(x ids cat "$EVE" 2>/dev/null | grep -F "\"event_type\":\"$1\"")
  shift
  for m in "$@"; do out=$(printf '%s\n' "$out" | grep -F -- "$m"); done
  printf '%s\n' "$out" | grep -c .
}

waitfor() { # Mindestanzahl, event_type, Muster ... -> ja|nein, wartet bis 5 s
  local n="$1"; shift
  for _ in $(seq 10); do
    [ "$(events "$@")" -ge "$n" ] && { echo ja; return; }
    sleep 0.5
  done
  echo nein
}

rx() { x ids sh -c "sed -n 's/^ *eth2: *//p' /proc/net/dev | awk '{print \$2}'" 2>/dev/null; } # empfangene Pakete auf eth2

echo "== Platzhalter fuer die WAF (nur solange waf noch das Image client:0.1 hat)"
ph=0
if x waf sh -c 'command -v socat' >/dev/null 2>&1; then
  docker exec -i "${P}-waf" sh -c 'cat > /tmp/echo-http.sh' <<'EOF'
#!/bin/sh
cr=$(printf '\r')
while IFS= read -r line; do
  line=${line%"$cr"}
  [ -z "$line" ] && break
done
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nok\n'
EOF
  x waf pkill socat >/dev/null 2>&1
  docker exec -d "${P}-waf" socat TCP-LISTEN:8080,fork,reuseaddr "SYSTEM:sh /tmp/echo-http.sh"
  ph=1
  echo "   Platzhalter gestartet"
else
  echo "   waf ist kein Platzhalter mehr, Anfragen laufen durch die echte WAF"
fi
x attacker pkill socat >/dev/null 2>&1
docker exec -d "${P}-attacker" socat TCP-LISTEN:4444,fork,reuseaddr "SYSTEM:echo ok"
sleep 1

echo "== Dienst"
# suricata -D kehrt vor dem Laden der Regeln zurueck: bis 30 s auf den Start warten
for _ in $(seq 30); do
  x ids grep -q 'Engine started' /var/log/suricata/suricata.log 2>/dev/null && break
  sleep 1
done
if x ids pgrep -f 'suricata --include' >/dev/null 2>&1; then r=ok; else r=fail; fi
result I-00 "Suricata laeuft" ok "$r"
result I-00 "Version 8.0" ja "$(has "$(x ids suricata -V 2>&1)" 'version 8\.0\.')"
log=$(x ids cat /var/log/suricata/suricata.log 2>/dev/null)
result I-00 "3 eigene Regeln geladen, keine fehlerhaft" ja "$(has "$log" ' 3 rules successfully loaded, 0 rules failed')"
result I-00 "Engine gestartet" ja "$(has "$log" 'Engine started')"
if x ids test -e /var/lib/suricata/rules/suricata.rules; then r=ja; else r=nein; fi
result I-00 "kein fremder Regelsatz im Image (E-08)" nein "$r"

echo "== Spiegelport"
result I-01 "ids eth2 ohne Adresse (V-11)" "" "$(x ids ip -o addr show dev eth2 2>/dev/null)"
result I-01 "fw-dmz eth6 ohne Adresse (V-11)" "" "$(x fw-dmz ip -o addr show dev eth6 2>/dev/null)"
for i in eth1 eth2 eth3 eth4; do
  result I-02 "fw-dmz $i: Kopie nach eth6" ja "$(has "$(x fw-dmz tc filter show dev "$i" ingress 2>/dev/null)" 'Egress Mirror to device eth6')"
done
result I-02 "fw-dmz eth5 (ids selbst) nicht gespiegelt" nein "$(has "$(x fw-dmz tc filter show dev eth5 ingress 2>/dev/null)" 'mirred')"
rx0=$(rx)

echo "== Erkennung"
x attacker curl -sk -o /dev/null "https://203.0.113.2/suche?q=1%27%20UNION%20SELECT%20name%20FROM%20users--&m=$M-3"
result I-03 "Internet: SQL-Injection erkannt (SID 1000001)" ja "$(waitfor 1 alert '"signature_id":1000001,' "m=$M-3")"
result I-03 "Alarm nennt den Angreifer 192.0.2.10 (xff)" ja "$(waitfor 1 alert '"signature_id":1000001,' "m=$M-3" '"xff":"192.0.2.10"')"

x client1 curl -sk -o /dev/null "https://10.10.10.2/datei?name=../../etc/passwd&m=$M-4"
result I-04 "Client-Netz: Pfad-Traversal erkannt (SID 1000002)" ja "$(waitfor 1 alert '"signature_id":1000002,' "m=$M-4")"
result I-04 "Alarm nennt den Client 10.10.20.10 (xff)" ja "$(waitfor 1 alert '"signature_id":1000002,' "m=$M-4" '"xff":"10.10.20.10"')"

n0=$(events alert '"signature_id":1000003,' '"src_ip":"10.10.10.10"' '"dest_port":4444')
if side web socat -T1 /dev/null TCP:192.0.2.10:4444,connect-timeout=2 >/dev/null 2>&1; then r=ok; else r=fail; fi
result I-05 "web -> 192.0.2.10 TCP 4444 von fw-dmz gesperrt (V-12)" fail "$r"
result I-05 "gesperrter Versuch trotzdem erkannt (SID 1000003)" ja "$(waitfor $((n0 + 1)) alert '"signature_id":1000003,' '"src_ip":"10.10.10.10"' '"dest_port":4444')"

x attacker curl -sk -o /dev/null "https://203.0.113.2/suche?q=hallo&m=$M-6"
result I-06 "normale Anfrage wird gesehen (HTTP-Eintrag)" ja "$(waitfor 1 http "m=$M-6")"
result I-06 "normale Anfrage loest keinen Alarm aus" 0 "$(events alert "m=$M-6")"

rx1=$(rx)
[ "${rx1:-0}" -gt "${rx0:-0}" ] && r=ja || r=nein
result I-02 "ids eth2 empfaengt Kopien (${rx0:-?} -> ${rx1:-?} Pakete)" ja "$r"

echo "== Ressourcen"
echo "   ids: $(docker stats --no-stream --format '{{.MemUsage}}' "${P}-ids")"

x attacker pkill socat >/dev/null 2>&1
[ "$ph" -eq 1 ] && x waf pkill socat >/dev/null 2>&1

if [ "$fail" -eq 0 ]; then
  echo "ERGEBNIS: bestanden"
else
  echo "ERGEBNIS: nicht bestanden"
  exit 1
fi
