#!/usr/bin/env bash
# Test des VPN (Phase 3, Schritt 3.7): IKEv2 und IPsec mit strongSwan nach BSI TR-02102-3 (2026-01).
# Anforderungen: NET-04, NET-05, SEC-01, SEC-02, TST-01, TST-02; Matrix: K-07, K-08, V-10, V-13
# Aufruf: bash tests/test-vpn.sh   (im Repo-Verzeichnis DMZ, nach make deploy)
#
# Methode: Zustand der Tunnel aus swanctl auf beiden Seiten, Verkehr durch den Tunnel mit
# Markierung im Log von web, Mitschnitt auf dem Uebertragungsweg bei inet, Gegenproben mit
# Testdiensten am Ziel, abgewiesene Verbindungsversuche mit unzulaessigen Verfahren.
set -uo pipefail

P="clab-dmz"
RUN="v$(date +%s)$$"
PKI="$(cd "$(dirname "$0")/.." && pwd)/configs/vpn/pki"
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

ike() { # Knoten, Name der Verbindung -> Abschnitt dieser IKE-SA aus swanctl --list-sas
  x "$1" swanctl --list-sas 2>/dev/null | awk -v n="$2:" '/^[^ ]/ { on = ($1 == n) } on'
}

up() { # Knoten, Name der Verbindung -> yes|no: IKE-SA aufgebaut und CHILD_SA installiert
  local s
  s=$(ike "$1" "$2")
  if [ "$(has "$s" ', ESTABLISHED, IKEv2')" = yes ] && [ "$(has "$s" '^  firmennetz: #[0-9]+, reqid [0-9]+, INSTALLED, TUNNEL')" = yes ]; then
    echo yes
  else
    echo no
  fi
}

waitup() { # Sekunden, Knoten:Verbindung ... -> yes|no
  local t="$1" all nc
  shift
  for _ in $(seq "$t"); do
    all=yes
    for nc in "$@"; do
      [ "$(up "${nc%%:*}" "${nc#*:}")" = yes ] || { all=no; break; }
    done
    [ "$all" = yes ] && { echo yes; return; }
    sleep 1
  done
  echo no
}

secs() { # Text, Zeilenanfang, Bezeichnung -> groesster Wert hinter der Bezeichnung in Sekunden
  printf '%s\n' "$1" | sed -n "s/^$2.*$3 \([0-9]*\)s.*/\1/p" | sort -n | tail -1
}

detail() { # Ergebnis, Ausgabe -> letzte Zeilen der Ausgabe eingerueckt anzeigen, wenn das Ergebnis nicht yes ist
  [ "$1" = yes ] || printf '%s\n' "$2" | tail -10 | sed 's/^/         | /'
}

conn() { # Knoten, Ziel, Port -> ok|fail (TCP-Verbindungsaufbau)
  local run=x
  case "$1" in inet|proxy|waf|web) run=side ;; esac
  if $run "$1" socat -T1 /dev/null "TCP:$2:$3,connect-timeout=2" >/dev/null 2>&1; then echo ok; else echo fail; fi
}

udp() { # Knoten, Token -> yes|no: Syslog-Meldung mit Token kommt im SIEM (Loki) an, wie in test-matrix.sh
  local run=x
  case "$1" in waf) run=side ;; esac
  $run "$1" sh -c "echo \"<134>\$(date '+%b %e %H:%M:%S') $1 dmztest: $2\" | socat -u - UDP-SENDTO:10.10.30.10:5140" >/dev/null 2>&1
  for _ in 1 2 3 4 5 6; do
    x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query={job=\"dmz\"} |= \"$2\"" --data-urlencode "limit=1" 2>/dev/null | grep -q '"result":\[{' && { echo yes; return; }
    sleep 0.5
  done
  echo no
}

code() { # Knoten, URL -> HTTP-Status
  x "$1" curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$2" 2>/dev/null
}

weblog() { # Markierung -> src_ip aus dem Log von web
  local l
  for _ in 1 2 3 4 5 6; do
    l=$(docker logs "${P}-web" 2>&1 | grep -F -- "$1" | tail -1)
    [ -n "$l" ] && break
    sleep 0.5
  done
  printf '%s' "$l" | sed -n 's/.*"src_ip": *"\([^"]*\)".*/\1/p'
}

dropped() { # Paketzaehler "verworfen" im input von fw-edge
  x fw-edge nft list chain inet filter input 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\) bytes .*verworfen.*/\1/p'
}

echo "== Service"
# pidof statt pgrep -x: BusyBox-pgrep -x vergleicht mit argv[0], also mit dem vollen Pfad /usr/lib/strongswan/charon
for n in fw-edge ro-client1 ro-client2; do
  if x "$n" pidof charon >/dev/null 2>&1; then r=ok; else r=fail; fi
  result N-00 "$n: charon running" ok "$r"
done
result N-00 "fw-edge: strongSwan 6.0 answers on vici" yes "$(has "$(x fw-edge swanctl --version --daemon 2>&1)" '^strongSwan 6\.0\.[0-9]+ charon')"
n=$(x fw-edge grep -c 'Starting IKE charon daemon' /var/log/charon.log 2>/dev/null)
[ "${n:-0}" -ge 1 ] && r=yes || r=no
result N-00 "fw-edge: charon writes /var/log/charon.log" yes "$r"

conns=$(x fw-edge swanctl --list-conns 2>/dev/null)
result N-00 "fw-edge: 2 connections, IKE rekeying every 4 h" 2 "$(printf '%s\n' "$conns" | grep -cE '^ro-client[12]: IKEv2, no reauthentication, rekeying every 14400s')"
result N-00 "fw-edge: 2 children, IPsec rekeying every 1 h" 2 "$(printf '%s\n' "$conns" | grep -cE '^  firmennetz: TUNNEL, rekeying every 3600s')"
result N-00 "fw-edge: clients authenticate with certificates" 2 "$(printf '%s\n' "$conns" | grep -c '^  remote public key authentication:')"
result N-00 "fw-edge: no pre-shared key configured (TR-02102-3 Tab. 7)" no "$(has "$conns" 'pre-shared key')"

echo "== Tunnels"
result N-01 "both tunnels up (waits up to 60 s)" yes "$(waitup 60 fw-edge:ro-client1 fw-edge:ro-client2 ro-client1:firmennetz ro-client2:firmennetz)"
for i in 1 2; do
  vip="10.99.0.$((i + 1))"
  pub="198.51.100.$((i * 4 - 2))"
  s=$(ike fw-edge "ro-client$i")
  result N-01 "fw-edge: ro-client$i identified by certificate, address $vip, no NAT-T" yes "$(has "$s" "^  remote 'CN=ro-client$i' @ ${pub//./\\.}\[500\] \[${vip//./\\.}\]")"
  result N-01 "fw-edge: ro-client$i IKE AES-GCM-256, HMAC-SHA2-512, brainpoolP512r1 (Tab. 3, 4, 6)" yes "$(has "$s" '^  AES_GCM_16-256/PRF_HMAC_SHA2_512/ECP_512_BP$')"
  result N-01 "fw-edge: ro-client$i ESP AES-GCM-256 in tunnel mode (Tab. 8, 2.2.2)" yes "$(has "$s" 'INSTALLED, TUNNEL, ESP:AES_GCM_16-256')"
  m=$(secs "$s" '  established' 'rekeying in')
  [ -n "$m" ] && [ "$m" -le 14400 ] && r=yes || r=no
  result N-01 "fw-edge: ro-client$i IKE SA rekeyed within 4 h (${m:-?} s)" yes "$r"
  m=$(secs "$s" '    installed' 'expires in')
  [ -n "$m" ] && [ "$m" -le 14400 ] && r=yes || r=no
  result N-01 "fw-edge: ro-client$i IPsec SA lifetime at most 4 h (3.4, ${m:-?} s)" yes "$r"
  c=$(ike "ro-client$i" firmennetz)
  result N-01 "ro-client$i: fw-edge identified by certificate" yes "$(has "$c" "^  remote 'CN=fw-edge' @ 203\.0\.113\.2\[500\]")"
done
# Die Ablaufzeit einer IKE-SA meldet vici nicht (vici_query.c), charon schreibt sie beim Aufbau ins Log (ike_sa.c)
m=$(x fw-edge sed -n 's/.*maximum IKE_SA lifetime \([0-9]*\)s.*/\1/p' /var/log/charon.log 2>/dev/null | sort -n | tail -1)
[ -n "$m" ] && [ "$m" -le 86400 ] && r=yes || r=no
result N-01 "fw-edge: IKE SA lifetime at most 24 h (3.4, ${m:-?} s)" yes "$r"

echo "== Virtual address"
for i in 1 2; do
  vip="10.99.0.$((i + 1))"
  result N-02 "ro-client$i: virtual address $vip/32" yes "$(has "$(x "ro-client$i" ip -o -4 addr show 2>/dev/null)" "inet ${vip//./\\.}/32 ")"
  result N-02 "ro-client$i: only 10.10.0.0/16 through the tunnel (table 220)" yes "$(has "$(x "ro-client$i" ip route show table 220 2>/dev/null)" "^10\.10\.0\.0/16 .*src ${vip//./\\.}")"
  result N-02 "ro-client$i: default route stays on the local internet access" yes "$(has "$(x "ro-client$i" ip -4 route show default 2>/dev/null)" 'via 198\.51\.100\.')"
done

echo "== Access through the tunnel (K-08)"
for i in 1 2; do
  vip="10.99.0.$((i + 1))"
  result N-03 "ro-client$i -> proxy 10.10.10.2 TCP 443" 200 "$(code "ro-client$i" "https://10.10.10.2/health?m=$RUN-3$i")"
  result N-03 "web sees the virtual address $vip (no NAT on the tunnel)" "$vip" "$(weblog "m=$RUN-3$i")"
done

echo "== Encryption on the path"
cap=$(mktemp)
x inet timeout 8 tcpdump -lnni eth2 host 198.51.100.2 >"$cap" 2>/dev/null &
cpid=$!
sleep 2
x ro-client1 curl -sk -o /dev/null --max-time 5 "https://10.10.10.2/health?m=$RUN-4"
wait "$cpid"
out=$(cat "$cap")
rm -f "$cap"
result N-04 "inet eth2: traffic of ro-client1 as ESP" yes "$(has "$out" '198\.51\.100\.2 > 203\.0\.113\.2: ESP\(spi=0x[0-9a-f]+,seq=0x[0-9a-f]+\)')"
result N-04 "inet eth2: inner addresses not visible" no "$(has "$out" '10\.10\.10\.2|10\.99\.0\.2')"
result N-04 "inet eth2: no UDP encapsulation (port 4500)" no "$(has "$out" '\.4500[ :]')"

echo "== Perfect forward secrecy"
x ro-client1 swanctl --rekey --child firmennetz >/dev/null 2>&1
r=no
for _ in $(seq 10); do
  r=$(has "$(ike ro-client1 firmennetz)" 'INSTALLED, TUNNEL, ESP:AES_GCM_16-256/ECP_512_BP')
  [ "$r" = yes ] && break
  sleep 1
done
result N-05 "ro-client1: rekeyed CHILD_SA uses a new key exchange ECP_512_BP (2.1.4)" yes "$r"
result N-05 "ro-client1 -> proxy after rekeying" 200 "$(code ro-client1 "https://10.10.10.2/health?m=$RUN-5")"

echo "== Start test services"
for n in client1 ro-client1; do x "$n" pkill socat >/dev/null 2>&1; done
docker exec -d "${P}-client1" socat TCP-LISTEN:8080,fork,reuseaddr "SYSTEM:echo ok"
docker exec -d "${P}-ro-client1" socat TCP-LISTEN:443,fork,reuseaddr "SYSTEM:echo ok"
sleep 1
result N-06 "control: test service client1 TCP 8080 listening" ok "$(conn client1 127.0.0.1 8080)"
result N-06 "control: waf -> siem UDP 5140 arrives (K-09)" yes "$(udp waf "$RUN-c")"
result N-07 "control: inet -> ro-client1 198.51.100.2 TCP 443 (public address)" ok "$(conn inet 198.51.100.2 443)"

echo "== Tunnel limited to the web application (V-10)"
result N-06 "ro-client1 -> client1 10.10.20.10 TCP 8080" fail "$(conn ro-client1 10.10.20.10 8080)"
if x ro-client1 ping -c 1 -W 1 10.10.20.10 >/dev/null 2>&1; then r=ok; else r=fail; fi
result N-06 "ro-client1 -> client1 10.10.20.10 ICMP" fail "$r"
result N-06 "ro-client1 -> siem 10.10.30.10 UDP 5140" no "$(udp ro-client1 "$RUN-6")"
if x ro-client1 ping -c 1 -W 1 10.10.30.10 >/dev/null 2>&1; then r=ok; else r=fail; fi
result N-06 "ro-client1 -> siem 10.10.30.10 ICMP" fail "$r"
result N-06 "ro-client1 -> web 10.10.10.10 TCP 8080" fail "$(conn ro-client1 10.10.10.10 8080)"
result N-06 "ro-client1 -> waf 10.10.10.6 TCP 8080" fail "$(conn ro-client1 10.10.10.6 8080)"
result N-06 "ro-client1 -> proxy 10.10.10.2 TCP 80" fail "$(conn ro-client1 10.10.10.2 80)"

echo "== No access to the VPN clients (V-13)"
result N-07 "client1 -> ro-client1 10.99.0.2 TCP 443" fail "$(conn client1 10.99.0.2 443)"
result N-07 "web -> ro-client1 10.99.0.2 TCP 443" fail "$(conn web 10.99.0.2 443)"

echo "== Stop test services"
for n in client1 ro-client1; do x "$n" pkill socat >/dev/null 2>&1; done

echo "== VPN endpoint only for the remote office (K-07)"
d0=$(dropped)
x attacker sh -c 'echo probe | socat -u - UDP-SENDTO:203.0.113.2:500' >/dev/null 2>&1
x attacker sh -c 'echo probe | socat -u - IP4-SENDTO:203.0.113.2:50' >/dev/null 2>&1
sleep 1
d1=$(dropped)
[ $(( ${d1:-0} - ${d0:-0} )) -ge 2 ] && r=yes || r=no
result N-08 "attacker -> fw-edge UDP 500 and ESP dropped (${d0:-?} -> ${d1:-?} packets)" yes "$r"
result N-08 "charon on fw-edge never saw 192.0.2.10" 0 "$(x fw-edge grep -c '192\.0\.2\.10' /var/log/charon.log 2>/dev/null)"

echo "== Rejected methods (TR-02102-3)"
# Probeverbindungen auf ro-client2 zusaetzlich zur bestehenden Verbindung firmennetz.
# Die Datei liegt in /etc/swanctl: swanctl --file setzt das Basisverzeichnis fuer relative
# Pfade (certs = client.crt, private/) auf das Verzeichnis der Datei (swanctl.c).
# mobike = no wie in ro-client.conf: sonst wechselt IKE_AUTH auf UDP 4500, das fw-edge verwirft.
docker exec -i "${P}-ro-client2" sh -c 'cat > /etc/swanctl/probe.conf' <<'EOF'
include /etc/swanctl/swanctl.conf

connections {
    probe-legacy {
        version = 2
        remote_addrs = 203.0.113.2
        mobike = no
        proposals = aes128-sha1-modp1024
        local {
            auth = pubkey
            certs = client.crt
        }
        remote {
            auth = pubkey
            id = "CN=fw-edge"
        }
        children {
            p {
                esp_proposals = aes256gcm16
            }
        }
    }
    probe-modp2048 {
        version = 2
        remote_addrs = 203.0.113.2
        mobike = no
        proposals = aes256gcm16-prfsha512-modp2048
        local {
            auth = pubkey
            certs = client.crt
        }
        remote {
            auth = pubkey
            id = "CN=fw-edge"
        }
        children {
            p {
                esp_proposals = aes256gcm16
            }
        }
    }
    probe-chacha {
        version = 2
        remote_addrs = 203.0.113.2
        mobike = no
        proposals = chacha20poly1305-prfsha256-curve25519
        local {
            auth = pubkey
            certs = client.crt
        }
        remote {
            auth = pubkey
            id = "CN=fw-edge"
        }
        children {
            p {
                esp_proposals = aes256gcm16
            }
        }
    }
    probe-psk {
        version = 2
        remote_addrs = 203.0.113.2
        mobike = no
        proposals = aes256gcm16-prfsha512-ecp512bp
        local {
            auth = psk
            id = "CN=ro-client2"
        }
        remote {
            auth = pubkey
            id = "CN=fw-edge"
        }
        children {
            p {
                esp_proposals = aes256gcm16
            }
        }
    }
}

secrets {
    ike-probe {
        secret = "labor-probe"
    }
}
EOF
out=$(x ro-client2 swanctl --load-conns --file /etc/swanctl/probe.conf 2>&1)
r=$(has "$out" 'successfully loaded 5 connections')
result N-09 "probe connections loaded (firmennetz and 4 probes)" yes "$r"
detail "$r" "$out"
x ro-client2 swanctl --load-creds --file /etc/swanctl/probe.conf >/dev/null 2>&1
n0=$(x fw-edge grep -c 'received proposals unacceptable' /var/log/charon.log 2>/dev/null)
for c in "probe-legacy:AES-CBC-128, SHA-1, MODP-1024" "probe-modp2048:MODP-2048 (not in Tab. 6)" "probe-chacha:ChaCha20-Poly1305, Curve25519"; do
  out=$(x ro-client2 swanctl --initiate --ike "${c%%:*}" --child p --timeout 15 2>&1)
  r=$(has "$out" 'received NO_PROPOSAL_CHOSEN notify error')
  result N-09 "IKE proposal ${c#*:} rejected" yes "$r"
  detail "$r" "$out"
done
n1=$(x fw-edge grep -c 'received proposals unacceptable' /var/log/charon.log 2>/dev/null)
result N-09 "fw-edge logs the 3 rejected proposals" 3 "$(( ${n1:-0} - ${n0:-0} ))"
out=$(x ro-client2 swanctl --initiate --ike probe-psk --child p --timeout 15 2>&1)
r=$(has "$out" 'received AUTHENTICATION_FAILED notify error')
result N-09 "pre-shared key rejected with valid proposal (Tab. 7)" yes "$r"
detail "$r" "$out"
x ro-client2 rm -f /etc/swanctl/probe.conf
x ro-client2 swanctl --load-all >/dev/null 2>&1
result N-09 "probe connections removed again" no "$(has "$(x ro-client2 swanctl --list-conns 2>/dev/null)" '^probe-')"
result N-09 "ro-client2 tunnel unaffected" yes "$(waitup 30 ro-client2:firmennetz)"

echo "== PKI"
for f in ca fw-edge ro-client1 ro-client2; do
  t=$(docker run --rm -v "$PKI:/pki:ro" client:0.1 openssl x509 -in "/pki/$f.crt" -noout -text 2>/dev/null)
  result N-10 "$f.crt: ECDSA key on brainpoolP512r1" yes "$(has "$t" 'ASN1 OID: brainpoolP512r1')"
  result N-10 "$f.crt: signed with ecdsa-with-SHA512" yes "$(has "$t" 'Signature Algorithm: ecdsa-with-SHA512')"
done
v=$(docker run --rm -v "$PKI:/pki:ro" client:0.1 openssl verify -CAfile /pki/ca.crt /pki/fw-edge.crt /pki/ro-client1.crt /pki/ro-client2.crt 2>&1)
result N-10 "fw-edge, ro-client1, ro-client2 issued by the lab CA" 3 "$(printf '%s\n' "$v" | grep -c ': OK$')"
for k in "$PKI"/*.key; do
  result N-10 "$(basename "$k"): mode 600" 600 "$(stat -c %a "$k" 2>/dev/null)"
done
if git -C "$PKI/.." check-ignore -q "$PKI/ca.key" 2>/dev/null; then r=yes; else r=no; fi
result N-10 "private keys excluded from git (.gitignore)" yes "$r"

echo "== Resources"
for n in fw-edge ro-client1 ro-client2; do
  echo "   $n: $(docker stats --no-stream --format '{{.MemUsage}}' "${P}-$n")"
done

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
