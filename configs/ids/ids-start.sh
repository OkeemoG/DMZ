#!/bin/sh
setsid sh /etc/suricata/ids-watchdog.sh </dev/null >/dev/null 2>&1 &
setsid sh /etc/suricata/ids-logguard.sh </dev/null >/dev/null 2>&1 &
n=0
until pgrep -f 'suricata --include' >/dev/null 2>&1; do
  n=$((n + 1))
  [ "$n" -ge 50 ] && { echo "ids-start: suricata did not start" >&2; exit 1; }
  sleep 0.2
done
echo "ids-start: suricata running under watchdog, log guard at ${IDS_LOG_MAX_MB:-50} MB"
