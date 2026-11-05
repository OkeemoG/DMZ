#!/usr/bin/env bash
set -euo pipefail

CONF=/etc/docker/daemon.json
MAX_SIZE="${LOG_MAX_SIZE:-10m}"
MAX_FILE="${LOG_MAX_FILE:-3}"
RESTART=no
[ "${1:-}" = "--restart" ] && RESTART=yes

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E bash "$0" "$@"
fi

echo "== Docker log limits: json-file, max-size ${MAX_SIZE}, max-file ${MAX_FILE}"
mkdir -p /etc/docker
changed=no
if [ ! -s "$CONF" ]; then
  printf '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "%s", "max-file": "%s" }\n}\n' "$MAX_SIZE" "$MAX_FILE" > "$CONF"
  changed=yes
elif grep -q '"max-size"' "$CONF"; then
  echo "   $CONF already limits log size, unchanged"
elif command -v python3 >/dev/null 2>&1; then
  cp "$CONF" "$CONF.bak"
  python3 - "$CONF" "$MAX_SIZE" "$MAX_FILE" <<'PY'
import json, sys
path, size, files = sys.argv[1:4]
with open(path) as fh:
    conf = json.load(fh)
conf.setdefault("log-driver", "json-file")
opts = conf.setdefault("log-opts", {})
opts["max-size"] = size
opts["max-file"] = files
with open(path, "w") as fh:
    json.dump(conf, fh, indent=2)
    fh.write("\n")
PY
  changed=yes
  echo "   merged into $CONF, backup in $CONF.bak"
else
  echo "   $CONF exists and python3 is missing. Add by hand:"
  echo "   \"log-driver\": \"json-file\", \"log-opts\": { \"max-size\": \"${MAX_SIZE}\", \"max-file\": \"${MAX_FILE}\" }"
  exit 1
fi

if [ "$changed" = yes ]; then
  if [ "$RESTART" = yes ]; then
    systemctl restart docker
    echo "   docker restarted"
  else
    echo "   takes effect after: sudo systemctl restart docker && make deploy (stops running containers)"
  fi
fi
