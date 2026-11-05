#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
cd "$(dirname "$0")/.."
export APP_MODE="${APP_MODE:-secure}"
STATE=$(mktemp)
trap 'rm -f "$STATE"' EXIT

respond() { docker exec "${P}-siem-responder" respond "$@"; }

echo "== 1 Preserve evidence before rebuilding"
if [ "${SKIP_EVIDENCE:-0}" = "1" ]; then
  echo "   skipped (SKIP_EVIDENCE=1)"
else
  bash scripts/collect-evidence.sh "${IP:-}" "${MINUTES:-60}" | tail -3
fi

echo "== 2 Remember active blocks and quarantines"
respond export > "$STATE" 2>/dev/null || true
echo "   $(wc -l < "$STATE") entries"
sed 's/^/   /' "$STATE"

echo "== 3 Rebuild all systems from the images (APP_MODE=${APP_MODE})"
containerlab deploy -t topology/dmz.clab.yml --reconfigure >/dev/null || { echo "RESULT: deploy failed"; exit 1; }

echo "== 4 Wait for the responder and the channel to fw-edge"
up=no
for _ in $(seq 90); do
  if respond status 2>/dev/null | grep -q '^channel:  up'; then up=yes; break; fi
  sleep 1
done
echo "   channel up: ${up}"
[ "$up" = yes ] || { echo "RESULT: responder not ready, blocks not restored"; exit 1; }

echo "== 5 Restore blocks and quarantines"
fail=0
while read -r kind ip seconds reason; do
  [ -n "${kind:-}" ] || continue
  if respond "$kind" "$ip" "$seconds" "$reason" >/dev/null; then
    echo "   restored ${kind} ${ip} ${seconds} s ${reason}"
  else
    echo "   FAILED   ${kind} ${ip}"; fail=1
  fi
done < "$STATE"

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: systems rebuilt from images, application mode ${APP_MODE}, containment kept"
  echo "   next: make test-all"
else
  echo "RESULT: rebuilt, but not every block could be restored"
  exit 1
fi
