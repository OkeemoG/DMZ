#!/usr/bin/env bash
# Erzeugt die Labor-PKI fuer das VPN: eine CA und Zertifikate fuer fw-edge, ro-client1, ro-client2.
# Schluessel ECDSA mit brainpoolP512r1, Signatur SHA-512 (BSI TR-02102-3, Tabelle 7, Nr. 6).
# Ablage in configs/vpn/pki/ (nicht im Repo). Eine vorhandene PKI bleibt unveraendert.
# Benoetigt das Image client:0.1 (openssl), also vorher make images.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/configs/vpn/pki"

if [ -f "$DIR/ca.crt" ]; then
  echo "== PKI vorhanden: $DIR"
  exit 0
fi

mkdir -p "$DIR"
echo "== Erzeuge PKI in $DIR"

docker run --rm --user "$(id -u):$(id -g)" -v "$DIR:/pki" -w /pki client:0.1 sh -eu -c '
  key="-newkey ec -pkeyopt ec_paramgen_curve:brainpoolP512r1 -nodes"

  openssl req -x509 $key -sha512 -days 365 -subj "/CN=DMZ-Labor VPN-CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout ca.key -out ca.crt

  printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" > ee.ext
  for n in fw-edge ro-client1 ro-client2; do
    openssl req -new $key -subj "/CN=$n" -keyout "$n.key" -out "$n.csr"
    openssl x509 -req -in "$n.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -sha512 -days 365 -extfile ee.ext -out "$n.crt"
  done

  rm -f ./*.csr ee.ext ca.srl
  chmod 600 ./*.key
'

ls -l "$DIR"
