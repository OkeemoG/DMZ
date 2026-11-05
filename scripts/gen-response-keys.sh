#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/configs/response/keys"

if [ -f "$DIR/responder.key" ] && [ -f "$DIR/fw-edge_host.key" ]; then
  echo "== Response keys present: $DIR"
  exit 0
fi

mkdir -p "$DIR"
echo "== Generating response keys in $DIR"

docker run --rm -e OWNER="$(id -u):$(id -g)" -v "$DIR:/keys" -w /keys --entrypoint sh responder:0.1 -eu -c '
  rm -f responder.key responder.key.pub fw-edge_host.key fw-edge_host.key.pub authorized_keys known_hosts
  ssh-keygen -q -t ecdsa -b 384 -N "" -C "responder@siem" -f responder.key
  ssh-keygen -q -t ecdsa -b 384 -N "" -C "fw-edge" -f fw-edge_host.key
  printf "restrict,from=\"10.10.30.10\",command=\"/bin/sh /etc/response/fw-response\" %s\n" "$(cut -d" " -f1,2 responder.key.pub)" > authorized_keys
  printf "10.10.0.9 %s\n" "$(cut -d" " -f1,2 fw-edge_host.key.pub)" > known_hosts
  chmod 600 responder.key fw-edge_host.key
  chmod 644 responder.key.pub fw-edge_host.key.pub authorized_keys known_hosts
  chown "$OWNER" ./*
'

ls -l "$DIR"
