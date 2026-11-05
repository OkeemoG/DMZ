#!/bin/sh

PROTECTED="10.10.0.0/24 10.10.10.0/24 10.10.30.0/24 127.0.0.0/8 198.51.100.2/32 198.51.100.6/32 203.0.113.0/30"
INTERNAL="10.10.20.0/24 10.99.0.0/24"
MAX_SECONDS=86400
TABLE="inet response"

set -f

say() { printf '%s\n' "$*"; }

audit() { logger -t fw-response -p auth.notice -- "$*" 2>/dev/null; }

is_ipv4() {
  printf '%s' "$1" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}

is_seconds() {
  case "$1" in
    0) return 0 ;;
    ''|0*|*[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 6 ] && [ "$1" -le "$MAX_SECONDS" ]
}

is_reason() {
  case "$1" in
    ''|*[!A-Za-z0-9_.:-]*) return 1 ;;
  esac
  [ "${#1}" -le 48 ]
}

ip2int() {
  local IFS=.
  set -- $1
  echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
}

in_nets() {
  local ip n net bits mask
  ip=$(ip2int "$1")
  shift
  for n in "$@"; do
    net=$(ip2int "${n%/*}")
    bits=${n#*/}
    mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    [ $(( ip & mask )) -eq $(( net & mask )) ] && return 0
  done
  return 1
}

kill_flows() {
  local n=0 out
  for dir in -s -d; do
    out=$(conntrack -D "$dir" "$1" 2>&1 >/dev/null)
    out=$(printf '%s' "$out" | sed -n 's/.* \([0-9][0-9]*\) flow entries have been deleted.*/\1/p')
    n=$(( n + ${out:-0} ))
  done
  echo "$n"
}

add_to() {
  local set="$1" ip="$2" sec="$3" reason="$4" timeout="" flows
  if ! is_ipv4 "$ip"; then say "ERR invalid address"; return; fi
  if ! is_seconds "$sec"; then say "ERR invalid seconds (0..${MAX_SECONDS})"; return; fi
  if ! is_reason "$reason"; then say "ERR invalid reason"; return; fi
  if in_nets "$ip" $PROTECTED; then
    audit "refused ${set} ${ip} protected reason=${reason}"
    say "ERR protected ${ip}"
    return
  fi
  if [ "$set" = "quarantine" ] && ! in_nets "$ip" $INTERNAL; then
    say "ERR not internal ${ip}"
    return
  fi
  if [ "$set" = "blocklist" ] && [ "$sec" -eq 0 ]; then
    say "ERR block needs seconds > 0"
    return
  fi
  [ "$sec" -gt 0 ] && timeout=" timeout ${sec}s"
  if ! nft -f - <<NFT
add element ${TABLE} ${set} { ${ip} }
delete element ${TABLE} ${set} { ${ip} }
add element ${TABLE} ${set} { ${ip}${timeout} comment "${reason}" }
NFT
  then
    say "ERR nft failed"
    return
  fi
  flows=$(kill_flows "$ip")
  audit "${set} ${ip} seconds=${sec} reason=${reason} flows=${flows}"
  say "OK ${set} ${ip} ${sec} flows=${flows}"
}

release() {
  if ! is_ipv4 "$1"; then say "ERR invalid address"; return; fi
  if ! nft -f - <<NFT
add element ${TABLE} blocklist { $1 }
delete element ${TABLE} blocklist { $1 }
add element ${TABLE} quarantine { $1 }
delete element ${TABLE} quarantine { $1 }
NFT
  then
    say "ERR nft failed"
    return
  fi
  audit "release $1"
  say "OK release $1"
}

list() {
  local set
  for set in blocklist quarantine; do
    nft list set ${TABLE} "$set" 2>/dev/null \
      | tr -d '\n\t' \
      | sed -n 's/.*elements = { \(.*\) }.*/\1/p' \
      | tr ',' '\n' \
      | sed 's/^ *//; s/ *$//' \
      | while IFS= read -r e || [ -n "$e" ]; do [ -n "$e" ] && say "${set} ${e}"; done
  done
  say "OK list"
}

flush() {
  nft flush set ${TABLE} blocklist && nft flush set ${TABLE} quarantine || { say "ERR nft failed"; return; }
  audit "flush"
  say "OK flush"
}

packets() {
  nft list chain $1 "$2" 2>/dev/null | sed -n 's/.*counter packets \([0-9][0-9]*\) .*/\1/p' | head -1
}

stats() {
  say "OK stats blocked=$(packets "${TABLE}" blocked) quarantined=$(packets "${TABLE}" quarantined) spoofed=$(packets "inet filter" spoofed)"
}

dispatch() {
  case "${1:-}" in
    ping)       say "OK pong" ;;
    block)      if [ $# -eq 4 ]; then add_to blocklist "$2" "$3" "$4"; else say "ERR usage: block IP SECONDS REASON"; fi ;;
    quarantine) if [ $# -eq 4 ]; then add_to quarantine "$2" "$3" "$4"; else say "ERR usage: quarantine IP SECONDS REASON"; fi ;;
    release)    if [ $# -eq 2 ]; then release "$2"; else say "ERR usage: release IP"; fi ;;
    list)       list ;;
    flush)      flush ;;
    stats)      stats ;;
    *)          audit "refused unknown command (${#1} chars)"; say "ERR unknown command" ;;
  esac
}

if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  set -- $SSH_ORIGINAL_COMMAND
fi

if [ "${1:-}" = "session" ]; then
  say "OK session"
  while IFS= read -r line; do
    set -- $line
    [ $# -eq 0 ] && continue
    dispatch "$@"
  done
  exit 0
fi

dispatch "$@"
