#!/usr/bin/env bash
# Test der Kommunikationsmatrix (Phase 3, Schritt 3.2): erlaubte (K-xx) und
# verbotene (V-xx) Verbindungen durch fw-edge, fw-dmz und fw-backend.
# Anforderungen: SYS-01, SYS-06, NET-03, NET-06, SEC-02, TST-01, TST-02
# Aufruf: bash tests/test-matrix.sh   (im Repo-Verzeichnis DMZ, nach make deploy)
#
# Methode: Auf den Zielen laufen socat-Dienste, die "ok" antworten. Jeder
# Negativtest hat also einen echten Dienst am Ziel. Scheitert die Verbindung,
# liegt das an Firewall, Routing oder Adressumsetzung, nicht an einem fehlenden Dienst.
# Noch nicht enthalten: K-07, K-08, V-10 (VPN, 3.7), V-11 (Spiegelport, 3.6),
# K-10, K-11 (Meldungen der Firewalls selbst, Phase 4).
set -uo pipefail

P="clab-dmz"
fail=0

x() { docker exec "${P}-$1" "${@:2}"; }

result() { # Test-ID, Beschreibung, erwartet, Ergebnis
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FEHLER $1 $2 (erwartet: $3, Ergebnis: $4)"
    fail=1
  fi
}

listen() { # Knoten, tcp|udp, Port
  case "$2" in
    tcp) docker exec -d "${P}-$1" socat "TCP-LISTEN:$3,fork,reuseaddr" "SYSTEM:echo ok" ;;
    udp) docker exec -d "${P}-$1" socat "UDP-RECVFROM:$3,fork" "SYSTEM:echo ok" ;;
  esac
}

probe() { # Test-ID, Quelle, tcp|udp|icmp, Ziel, Port, erwartet (ok|fail)
  local out=""
  case "$3" in
    tcp)  out=$(x "$2" socat -T2 - "TCP:$4:$5,connect-timeout=2" </dev/null 2>/dev/null) ;;
    udp)  out=$(x "$2" sh -c "echo ping | socat -t2 -T2 - UDP:$4:$5" 2>/dev/null) ;;
    icmp) x "$2" ping -c 1 -W 1 "$4" >/dev/null 2>&1 && out=ok ;;
  esac
  [ "$out" = "ok" ] && r=ok || r=fail
  local d="$2 -> $4"
  [ "$3" = "icmp" ] && d="$d ICMP" || d="$d ${3^^} $5"
  result "$1" "$d" "$6" "$r"
}

echo "== F-00 Regelwerke geladen"
for fw in fw-edge fw-dmz fw-backend; do
  if x "$fw" nft list table inet filter >/dev/null 2>&1; then r=ok; else r=fail; fi
  result F-00 "$fw inet filter" ok "$r"
done
if x fw-edge nft list table ip nat >/dev/null 2>&1; then r=ok; else r=fail; fi
result F-00 "fw-edge ip nat" ok "$r"

echo "== Testdienste starten"
for n in proxy waf web ids siem client1 attacker; do x "$n" pkill socat >/dev/null 2>&1; done
listen proxy    tcp 80
listen proxy    tcp 443
listen waf      tcp 8080
listen web      tcp 8080
listen ids      tcp 8080
listen siem     udp 5140
listen client1  tcp 8080
listen attacker tcp 80
listen attacker tcp 443
listen attacker tcp 22
sleep 1

echo "== Erlaubte Verbindungen"
probe K-01 attacker tcp  203.0.113.2 443  ok
probe K-01 attacker tcp  203.0.113.2 80   ok
probe K-02 proxy    tcp  10.10.10.6  8080 ok
probe K-03 waf      tcp  10.10.10.10 8080 ok
probe K-04 client1  tcp  10.10.10.2  443  ok
probe K-05 client1  tcp  192.0.2.10  443  ok
probe K-05 client1  tcp  192.0.2.10  80   ok
probe K-05 client1  icmp 192.0.2.10  -    ok
probe K-06 web      tcp  192.0.2.10  443  ok
probe K-06 proxy    tcp  192.0.2.10  80   ok
probe K-06 ids      icmp 192.0.2.10  -    ok
probe K-09 waf      udp  10.10.30.10 5140 ok
probe K-09 ids      udp  10.10.30.10 5140 ok

echo "== Verbotene Verbindungen"
# V-01, V-02: zusaetzlich durch Routing gesperrt (inet kennt keine privaten Netze)
probe V-01 attacker tcp  10.10.20.10 8080 fail
probe V-02 attacker tcp  10.10.10.10 8080 fail
probe V-03 client1  tcp  10.10.10.10 8080 fail
probe V-03 client1  tcp  10.10.10.6  8080 fail
probe V-03 client1  tcp  10.10.10.14 8080 fail
probe V-03 client1  tcp  10.10.10.2  80   fail
probe V-04 client1  udp  10.10.30.10 5140 fail
probe V-04 client1  icmp 10.10.30.10 -    fail
probe V-05 web      tcp  10.10.10.2  443  fail
probe V-05 web      tcp  10.10.10.6  8080 fail
probe V-06 web      tcp  10.10.20.10 8080 fail
probe V-07 web      udp  10.10.30.10 5140 fail
# V-08: zusaetzlich ohne Adressumsetzung fuer das Backend
probe V-08 siem     tcp  192.0.2.10  443  fail
probe V-12 web      tcp  192.0.2.10  22   fail

echo "== Testdienste beenden"
for n in proxy waf web ids siem client1 attacker; do x "$n" pkill socat >/dev/null 2>&1; done

echo "== Zaehler verworfener Pakete (Nachweis)"
for fw in fw-edge fw-dmz fw-backend; do
  for chain in input forward; do
    c=$(x "$fw" nft list chain inet filter "$chain" 2>/dev/null | grep 'comment "verworfen"' | sed 's/^[[:space:]]*//')
    echo "   $fw $chain: ${c:-nicht gefunden}"
  done
done

if [ "$fail" -eq 0 ]; then
  echo "ERGEBNIS: bestanden"
else
  echo "ERGEBNIS: nicht bestanden"
  exit 1
fi
