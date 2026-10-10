#!/usr/bin/env bash
set -euo pipefail

TAG="0.1"
IMAGES=(fw router client)

cd "$(dirname "$0")"

for img in "${IMAGES[@]}"; do
  echo "== Baue ${img}:${TAG}"
  docker build -t "${img}:${TAG}" "${img}"
done

echo "== Groessen"
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' \
  | grep -E "^($(IFS='|'; echo "${IMAGES[*]}")):${TAG}"
