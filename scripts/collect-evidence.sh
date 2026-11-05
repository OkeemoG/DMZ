#!/usr/bin/env bash
set -uo pipefail

P="clab-dmz"
IP="${1:-}"
MINUTES="${2:-30}"
cd "$(dirname "$0")/.."

if [ -n "$IP" ] && ! printf '%s' "$IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "usage: $0 [IP] [MINUTES]" >&2
  exit 2
fi
case "$MINUTES" in ''|*[!0-9]*) echo "usage: $0 [IP] [MINUTES]" >&2; exit 2 ;; esac

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DIR="evidence/${STAMP}${IP:+-${IP}}"
mkdir -p "$DIR"
START_NS=$(( ($(date +%s) - MINUTES * 60) * 1000000000 ))

x() { docker exec "${P}-$1" "${@:2}"; }

save() {
  local name="$1"; shift
  if "$@" > "${DIR}/${name}" 2>&1; then
    echo "   saved   ${name} ($(wc -l < "${DIR}/${name}") lines)"
  else
    echo "   partial ${name} (command failed, output kept)"
  fi
}

loki() {
  x siem curl -s -G http://127.0.0.1:3100/loki/api/v1/query_range \
    --data-urlencode "query=$1" --data-urlencode "start=${START_NS}" \
    --data-urlencode "limit=5000" --data-urlencode "direction=forward"
}

echo "== Evidence for ${IP:-all sources}, last ${MINUTES} min -> ${DIR}"

{
  echo "collected_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "collected_by:  ${USER:-unknown}@$(hostname)"
  echo "subject:       ${IP:-all}"
  echo "window_min:    ${MINUTES}"
  echo "git_commit:    $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "app_mode:      $(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${P}-web" 2>/dev/null | sed -n 's/^APP_MODE=//p')"
} > "${DIR}/meta.txt"
echo "   saved   meta.txt"

if [ -n "$IP" ]; then
  save siem-events.json         loki "{job=\"dmz\"} |= \"${IP}\""
else
  save siem-events.json         loki '{job="dmz", ident=~"modsecurity|suricata|ulogd|responder|fw-response"}'
fi
save responder-status.txt       x siem-responder respond status
save responder-history.jsonl    x siem-responder respond history 500
save responder-active.txt       x siem-responder respond list

for fw in fw-edge fw-dmz fw-backend; do
  save "${fw}-ruleset.txt"      x "$fw" nft list ruleset
done
if [ -n "$IP" ]; then
  save fw-edge-conntrack.txt    sh -c "docker exec ${P}-fw-edge conntrack -L 2>/dev/null | grep -F '=${IP} ' || true"
else
  save fw-edge-conntrack.txt    x fw-edge conntrack -L
fi

for n in proxy waf web; do
  save "${n}-container.log"     docker logs --timestamps --since "${MINUTES}m" "${P}-${n}"
done
if [ -n "$IP" ]; then
  save ids-eve.json             x ids grep -F "\"${IP}\"" /var/log/suricata/eve.json
else
  save ids-eve.json             x ids tail -n 5000 /var/log/suricata/eve.json
fi

{
  for n in fw-edge fw-dmz proxy waf web ids fw-backend; do
    echo "## ${n}"
    docker diff "${P}-${n}" 2>&1
  done
} > "${DIR}/integrity-docker-diff.txt"
echo "   saved   integrity-docker-diff.txt (changes against the image: A added, C changed, D deleted)"

docker ps --filter "name=${P}-" --format '{{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}' > "${DIR}/containers.txt"
for n in $(cut -f1 "${DIR}/containers.txt"); do
  printf '%s\t%s\n' "$n" "$(docker inspect -f '{{.Image}}' "$n")"
done > "${DIR}/image-digests.txt"
echo "   saved   containers.txt, image-digests.txt"

( cd "$DIR" && sha256sum -- * > SHA256SUMS )
chmod a-w "$DIR"/*
tar -czf "${DIR}.tar.gz" -C evidence "$(basename "$DIR")"
sha256sum "${DIR}.tar.gz" > "${DIR}.tar.gz.sha256"

echo
echo "RESULT: evidence stored in ${DIR}"
echo "   archive: ${DIR}.tar.gz"
echo "   sha256:  $(cut -d' ' -f1 "${DIR}.tar.gz.sha256")"
