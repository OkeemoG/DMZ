#!/usr/bin/env bash
set -uo pipefail

TAG="0.1"
fail=0

check() {
  local img="$1"; shift
  for tool in "$@"; do
    if docker run --rm "${img}:${TAG}" sh -c "command -v ${tool}" >/dev/null 2>&1; then
      echo "OK    ${img}: ${tool}"
    else
      echo "FEHLT ${img}: ${tool}"
      fail=1
    fi
  done
}

check fw      ip nft ulogd tcpdump wg
check router  ip tcpdump
check client  ip curl tcpdump wg

if [ "$fail" -eq 0 ]; then
  echo "ERGEBNIS: bestanden"
else
  echo "ERGEBNIS: nicht bestanden"
  exit 1
fi
