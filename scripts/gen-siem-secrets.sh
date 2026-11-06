#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/configs/siem/secrets"
FILE="$DIR/grafana.env"

if [ -f "$FILE" ]; then
  echo "== SIEM secrets present: $FILE"
  exit 0
fi

mkdir -p "$DIR"
chmod 700 "$DIR"
umask 077
pw=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$pw" > "$FILE"
chmod 600 "$FILE"
echo "== Generated Grafana admin password in $FILE (show it with: make grafana-password)"
