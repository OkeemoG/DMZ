#!/bin/sh
fast=0
while true; do
  t0=$(cut -d. -f1 /proc/uptime)
  if [ "$fast" -lt 3 ]; then
    setpriv --reuid=suricata --regid=suricata --init-groups \
      --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
      suricata --include /etc/suricata/lab.yaml --af-packet
  else
    logger -t ids-watchdog -p daemon.crit "suricata failed 3 times as user suricata, running it as root"
    suricata --include /etc/suricata/lab.yaml --af-packet
  fi
  rc=$?
  t1=$(cut -d. -f1 /proc/uptime)
  if [ $((t1 - t0)) -lt 10 ]; then fast=$((fast + 1)); else fast=0; fi
  logger -t ids-watchdog -p daemon.err "suricata exited with code ${rc}, restarting in 2 s"
  sleep 2
done
