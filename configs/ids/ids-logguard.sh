#!/bin/sh
limit=$(( ${IDS_LOG_MAX_MB:-50} * 1024 * 1024 ))
while true; do
  for f in /var/log/suricata/eve.json /var/log/suricata/fast.log /var/log/suricata/stats.log /var/log/suricata/suricata.log; do
    [ -f "$f" ] || continue
    size=$(wc -c < "$f")
    if [ "$size" -gt "$limit" ]; then
      : > "$f"
      pkill -HUP -f 'suricata --include'
      logger -t ids-logguard -p daemon.warning "truncated ${f} at ${size} bytes (limit ${limit})"
    fi
  done
  sleep "${IDS_LOG_CHECK_S:-30}"
done
