#!/bin/sh
while true; do
  suricata --include /etc/suricata/lab.yaml --af-packet
  rc=$?
  logger -t ids-watchdog -p daemon.err "suricata exited with code ${rc}, restarting in 2 s"
  sleep 2
done
