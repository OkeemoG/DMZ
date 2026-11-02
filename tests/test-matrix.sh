#!/usr/bin/env bash
# Test der Kommunikationsmatrix (Phase 3, Schritt 3.2): erlaubte (K-xx) und
# verbotene (V-xx) Verbindungen durch fw-edge, fw-dmz und fw-backend.
# Anforderungen: SYS-01, SYS-06, NET-03, NET-06, SEC-02, TST-01, TST-02
# Aufruf: bash tests/test-matrix.sh   (im Repo-Verzeichnis DMZ, nach make deploy)
#
# Methode: Auf den Zielen laufen socat-Dienste. TCP-Dienste antworten "ok", UDP-Dienste
# schreiben Empfangenes in eine Datei, wie ein Syslog-Empfaenger ohne Antwort. Jeder
# Negativtest hat also einen echten Dienst am Ziel. Scheitert die Verbindung,
# liegt das an Firewall, Routing oder Adressumsetzung, nicht an einem fehlenden Dienst.
# Noch nicht enthalten: K-07, K-08, V-10 (VPN, 3.7), V-11 (Spiegelport, 3.6),
# K-10, K-11 (Meldungen der Firewalls selbst, Phase 4).
set -uo pipefail

P="clab-dmz"
fail=0

x() {
  case "$1" in
    web|waf|proxy|ids) docker run --rm --network "container:${P}-$1" client:0.1 "${@:2}" ;;
    *)       docker exec "${P}-$1" "${@:2}" ;;
  esac
}

result() {
  if [ "$3" = "$4" ]; then
    echo "OK     $1 $2"
  else
    echo "FAIL   $1 $2 (expected: $3, got: $4)"
    fail=1
  fi
}

listen() {
  local a
  if [ "$2" = "udp" ]; then
    docker exec "${P}-$1" rm -f "/tmp/udp-$3.log"
    docker exec -d "${P}-$1" socat -u "UDP-RECV:$3" "OPEN:/tmp/udp-$3.log,creat,append"
    return
  fi
  a="TCP-LISTEN:$3,fork,reuseaddr"
  if [ "$1" = "ids" ]; then
    # ids hat kein socat: Dienst in einem Hilfscontainer im Netz von ids
    docker run -d --rm --name "${P}-ids-socat" --network "container:${P}-ids" client:0.1 socat "$a" "SYSTEM:echo ok" >/dev/null
  else
    docker exec -d "${P}-$1" socat "$a" "SYSTEM:echo ok"
  fi
}

node_by_ip() {
  case "$1" in
    10.10.30.10) echo siem ;;
  esac
}

probe() {
  local out="" tok node
  case "$3" in
    tcp)  out=$(x "$2" socat -T2 - "TCP:$4:$5,connect-timeout=2" </dev/null 2>/dev/null) ;;
    conn) x "$2" socat -T1 /dev/null "TCP:$4:$5,connect-timeout=2" >/dev/null 2>&1 && out=ok ;;
    udp)  tok="$1-$2-$$-$RANDOM"
          node=$(node_by_ip "$4")
          x "$2" sh -c "echo $tok | socat -u - UDP-SENDTO:$4:$5" >/dev/null 2>&1
          for _ in 1 2 3 4; do
            if [ -n "$node" ] && docker exec "${P}-$node" grep -qF "$tok" "/tmp/udp-$5.log" 2>/dev/null; then out=ok; break; fi
            sleep 0.5
          done ;;
    icmp) x "$2" ping -c 1 -W 1 "$4" >/dev/null 2>&1 && out=ok ;;
  esac
  [ "$out" = "ok" ] && r=ok || r=fail
  local d="$2 -> $4"
  [ "$3" = "icmp" ] && d="$d ICMP" || d="$d ${3^^} $5"
  result "$1" "$d" "$6" "$r"
}

echo "== F-00 Rule sets loaded"
for fw in fw-edge fw-dmz fw-backend; do
  if x "$fw" nft list table inet filter >/dev/null 2>&1; then r=ok; else r=fail; fi
  result F-00 "$fw inet filter" ok "$r"
done
if x fw-edge nft list table ip nat >/dev/null 2>&1; then r=ok; else r=fail; fi
result F-00 "fw-edge ip nat" ok "$r"

echo "== Start test services"
for n in ids siem client1 attacker; do x "$n" pkill socat >/dev/null 2>&1; done
docker rm -f "${P}-ids-socat" >/dev/null 2>&1

listen ids      tcp 8080
listen siem     udp 5140
listen client1  tcp 8080
listen attacker tcp 80
listen attacker tcp 443
listen attacker tcp 22
sleep 1

echo "== Allowed connections"
probe K-01 attacker conn 203.0.113.2 443  ok
probe K-01 attacker conn 203.0.113.2 80   ok
probe K-02 proxy    conn 10.10.10.6  8080 ok
probe K-03 waf      conn 10.10.10.10 8080 ok
probe K-04 client1  conn 10.10.10.2  443  ok
probe K-05 client1  tcp  192.0.2.10  443  ok
probe K-05 client1  tcp  192.0.2.10  80   ok
probe K-05 client1  icmp 192.0.2.10  -    ok
probe K-06 web      tcp  192.0.2.10  443  ok
probe K-06 waf      tcp  192.0.2.10  80   ok
probe K-06 ids      icmp 192.0.2.10  -    ok
probe K-09 waf      udp  10.10.30.10 5140 ok
probe K-09 ids      udp  10.10.30.10 5140 ok

echo "== Forbidden connections"
probe V-01 attacker tcp  10.10.20.10 8080 fail
probe V-02 attacker conn 10.10.10.10 8080 fail
probe V-03 client1  conn 10.10.10.10 8080 fail
probe V-03 client1  conn 10.10.10.6  8080 fail
probe V-03 client1  tcp  10.10.10.14 8080 fail
probe V-03 client1  conn 10.10.10.2  80   fail
probe V-04 client1  udp  10.10.30.10 5140 fail
probe V-04 client1  icmp 10.10.30.10 -    fail
probe V-05 web      conn 10.10.10.2  443  fail
probe V-05 web      conn 10.10.10.6  8080 fail
probe V-06 web      tcp  10.10.20.10 8080 fail
probe V-07 web      udp  10.10.30.10 5140 fail
probe V-08 siem     tcp  192.0.2.10  443  fail
probe V-12 web      tcp  192.0.2.10  22   fail

echo "== Stop test services"
for n in ids siem client1 attacker; do x "$n" pkill socat >/dev/null 2>&1; done
docker rm -f "${P}-ids-socat" >/dev/null 2>&1

echo "== Dropped packet counters (evidence)"
for fw in fw-edge fw-dmz fw-backend; do
  for chain in input forward; do
    c=$(x "$fw" nft list chain inet filter "$chain" 2>/dev/null | grep 'comment "verworfen"' | sed 's/^[[:space:]]*//')
    echo "   $fw $chain: ${c:-not found}"
  done
done

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
