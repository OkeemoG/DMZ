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
      echo "MISSING ${img}: ${tool}"
      fail=1
    fi
  done
}

check fw      ip nft ulogd tcpdump swanctl sshd conntrack ss logger
check router  ip tcpdump
check client  ip curl tcpdump swanctl socat openssl
check proxy   ip nginx
check web     ip python3 gunicorn
check waf     ip nginx
check ids     ip suricata
check responder python3 ssh ssh-keygen su-exec respond

if [ "$fail" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
