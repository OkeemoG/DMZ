P="clab-dmz"
fail=0

inet()   { docker exec "${P}-attacker" "$@"; }
client() { docker exec "${P}-client1" "$@"; }

head1() { echo; echo "#### $1"; }
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
