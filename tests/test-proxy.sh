#!/usr/bin/env bash
# Test des Reverse-Proxys (Phase 3, Schritt 3.3).
# Anforderungen: SYS-02, SEC-01, SEC-02, K-01, K-02, K-04
# TLS-Pruefungen (P-07) nach BSI TR-02102-2, Version 2026-01
# Aufruf: bash tests/test-proxy.sh   (im Repo-Verzeichnis DMZ, nach make deploy)
#
# Methode: Solange die WAF fehlt, antwortet auf waf:8080 ein socat-Dienst mit
# HTTP 200 und gibt die empfangenen Kopfzeilen als Inhalt zurueck. So zeigt die
# Antwort, was der proxy tatsaechlich weitergibt.
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

has() { # Text, Muster (erweiterter regulaerer Ausdruck) -> ja|nein
  if printf '%s' "$1" | grep -qE -- "$2"; then echo ja; else echo nein; fi
}

tls() { # Optionen fuer openssl s_client -> Kurzausgabe des Handshakes (Quelle: attacker)
  x attacker sh -c "openssl s_client -connect 203.0.113.2:443 -brief $* </dev/null 2>&1"
}

echo "== Platzhalter fuer die WAF starten (waf:8080)"
docker exec -i "${P}-waf" sh -c 'cat > /tmp/echo-http.sh' <<'EOF'
#!/bin/sh
# Antwortet mit HTTP 200 und gibt die empfangenen Kopfzeilen zurueck
cr=$(printf '\r')
req=""
while IFS= read -r line; do
  line=${line%"$cr"}
  [ -z "$line" ] && break
  req="$req$line
"
done
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n'
printf '%s' "$req"
EOF
x waf pkill socat >/dev/null 2>&1
docker exec -d "${P}-waf" socat TCP-LISTEN:8080,fork,reuseaddr "SYSTEM:sh /tmp/echo-http.sh"
sleep 1

echo "== Dienst und Zertifikat"
if x proxy pgrep nginx >/dev/null 2>&1; then r=ok; else r=fail; fi
result P-00 "nginx laeuft" ok "$r"
if x proxy test -f /etc/nginx/tls/proxy.key; then r=ok; else r=fail; fi
result P-00 "Schluessel im Image vorhanden" ok "$r"
r=$(x proxy stat -c '%a' /etc/nginx/tls/proxy.key 2>/dev/null)
result P-00 "Schluessel nur fuer root lesbar" 600 "$r"

echo "== Umleitung und TLS"
out=$(x attacker curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://203.0.113.2/test 2>/dev/null)
result P-01 "HTTP 80 leitet auf HTTPS um" "301 https://203.0.113.2/test" "$out"

body=$(x attacker curl -sk https://203.0.113.2/pfad 2>/dev/null)
result P-02 "Internet -> proxy -> waf (K-01, K-02)" ja "$(has "$body" '^GET /pfad ')"
result P-03 "X-Forwarded-For ist die Adresse des Angreifers" ja "$(has "$body" '^X-Forwarded-For: 192.0.2.10$')"
result P-03 "X-Forwarded-Proto ist https" ja "$(has "$body" '^X-Forwarded-Proto: https$')"

body=$(x attacker curl -sk -H 'X-Forwarded-For: 1.2.3.4' https://203.0.113.2/ 2>/dev/null)
result P-04 "gefaelschtes X-Forwarded-For wird ersetzt" nein "$(has "$body" '1\.2\.3\.4')"

body=$(x client1 curl -sk https://10.10.10.2/intern 2>/dev/null)
result P-05 "Client-Netz -> proxy -> waf (K-04)" ja "$(has "$body" '^X-Forwarded-For: 10.10.20.10$')"

hdr=$(x attacker curl -skI https://203.0.113.2/ 2>/dev/null | tr -d '\r')
result P-06 "Server-Kopfzeile ohne Version" ja "$(has "$hdr" '^[Ss]erver: nginx$')"

echo "== TLS nach BSI TR-02102-2"
out=$(tls)
result P-07a "Standard-Client: TLS 1.3 (Tabelle 2)" ja "$(has "$out" '^Protocol version: TLSv1\.3$')"
result P-07a "Cipher-Suite nach Tabelle 13" ja "$(has "$out" '^Ciphersuite: TLS_AES_(256_GCM_SHA384|128_GCM_SHA256)$')"
result P-07a "Signatur ECDSA mit SHA-512 (Tabelle 11)" ja "$(has "$out" '^Hash used: SHA512$')"
result P-07a "Gruppe nach Tabelle 10" ja "$(has "$out" '(Temp Key: ECDH, |group: )(secp(256|384|521)r1|prime256v1|brainpoolP(256|384|512)r1)')"

out=$(tls -tls1_2 -groups brainpoolP512r1:secp384r1)
result P-07b "TLS 1.2 mit Brainpool-Gruppe (Tabellen 2, 6)" ja "$(has "$out" '^Protocol version: TLSv1\.2$')"
result P-07b "TLS 1.2 Cipher-Suite nach Tabelle 3 (GCM)" ja "$(has "$out" '^Ciphersuite: ECDHE-ECDSA-AES(256-GCM-SHA384|128-GCM-SHA256)$')"

cert=$(x attacker sh -c "openssl s_client -connect 203.0.113.2:443 </dev/null 2>/dev/null | openssl x509 -noout -text" 2>/dev/null)
result P-07c "Zertifikat: Kurve brainpoolP512r1 (Abschnitt 3.6.2)" ja "$(has "$cert" 'ASN1 OID: brainpoolP512r1')"
result P-07c "Zertifikat: Signatur ecdsa-with-SHA512" ja "$(has "$cert" 'Signature Algorithm: ecdsa-with-SHA512')"
result P-07c "Zertifikat: SAN 203.0.113.2 und 10.10.10.2" ja "$(has "$cert" 'IP Address:203\.0\.113\.2, IP Address:10\.10\.10\.2')"

# Negativtests: der Server muss ablehnen, der Client bietet das Verfahren ausdruecklich an
out=$(tls -tls1_3 -groups X25519)
result P-07d "X25519 abgelehnt (nicht in Tabelle 10)" nein "$(has "$out" '^Protocol version')"
out=$(tls -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256)
result P-07d "ChaCha20 abgelehnt (nicht in Tabelle 13)" nein "$(has "$out" '^Protocol version')"
out=$(tls -tls1_2 -groups brainpoolP512r1:secp384r1 -cipher ECDHE-ECDSA-AES256-SHA384)
result P-07d "TLS 1.2 mit CBC abgelehnt" nein "$(has "$out" '^Protocol version')"
out=$(tls -tls1_1 -cipher DEFAULT@SECLEVEL=0)
result P-07d "TLS 1.1 abgelehnt (Tabelle 2)" nein "$(has "$out" '^Protocol version')"

# Information: TLS 1.2 ohne angebotene Brainpool-Gruppe (Standard-Client)
out=$(tls -tls1_2)
if [ "$(has "$out" '^Protocol version')" = ja ]; then i="moeglich"; else i="nicht moeglich"; fi
echo "INFO   P-07e TLS 1.2 mit Standard-Gruppen des Clients: $i"

echo "== Ratenbegrenzung (20/s, Puffer 40)"
codes=$(x attacker sh -c 'curl -sk -Z --parallel-max 50 -o "/tmp/r#1" -w "%{http_code}\n" "https://203.0.113.2/r[1-100]"; rm -f /tmp/r*' 2>/dev/null)
n200=$(printf '%s\n' "$codes" | grep -c '^200$')
n429=$(printf '%s\n' "$codes" | grep -c '^429$')
echo "   100 parallele Anfragen: ${n200}x 200, ${n429}x 429"
[ "$n429" -gt 0 ] && r=ja || r=nein
result P-08 "Ueberschuss wird mit 429 abgewiesen" ja "$r"
[ "$n200" -gt 0 ] && r=ja || r=nein
result P-08 "Anfragen im Rahmen werden beantwortet" ja "$r"

x waf pkill socat >/dev/null 2>&1

if [ "$fail" -eq 0 ]; then
  echo "ERGEBNIS: bestanden"
else
  echo "ERGEBNIS: nicht bestanden"
  exit 1
fi
