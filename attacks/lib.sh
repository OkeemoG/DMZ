P="clab-dmz"
fail=0

inet()   { docker exec "${P}-attacker" "$@"; }
client() { docker exec "${P}-client1" "$@"; }

head1() { echo; echo "#### $1"; }

wait_waf() {
  local s=""
  for _ in $(seq 60); do
    s=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${P}-waf" 2>/dev/null)
    if [ "${s}" = "healthy" ] || [ "${s}" = "none" ]; then return 0; fi
    sleep 1
  done
  echo "   WARN  waf not healthy after 60 s (${s:-unknown})"
  return 1
}

in_siem() {
  sleep 1
  if docker exec "${P}-siem" curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range --data-urlencode "query={job=\"dmz\"} |= \"$1\"" --data-urlencode limit=1 2>/dev/null | grep -q '"result":\[{'; then
    echo yes
  else
    echo no
  fi
}
stage() { echo; echo "== $1"; }

check() {
  if [ "$3" = "$4" ]; then
    echo "   OK    $1 ($4)"
  else
    echo "   FAIL  $1 (expected: $3, got: $4)"
    fail=1
  fi
}

finish() {
  echo
  if [ "$fail" -eq 0 ]; then
    echo "RESULT: all defenses held"
  else
    echo "RESULT: a defense did not hold"
    exit 1
  fi
}
