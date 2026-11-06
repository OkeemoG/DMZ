#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
for a in attacks/a1-external.sh attacks/a2-waf-evasion.sh attacks/a3-internal.sh attacks/a4-compromised-web.sh; do
  echo "######## ${a}"
  bash "${a}" || fail=1
done
echo
if [ "${fail}" -eq 0 ]; then
  echo "RESULT: passed"
else
  echo "RESULT: failed"
  exit 1
fi
