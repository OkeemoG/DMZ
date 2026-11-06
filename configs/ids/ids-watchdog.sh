#!/bin/sh
args="--include /etc/suricata/lab.yaml --af-packet"
err=/var/log/suricata/watchdog.err
mode=0
fails=0
while true; do
  chown -R suricata:suricata /var/log/suricata 2>/dev/null
  t0=$(cut -d. -f1 /proc/uptime)
  case "$mode" in
    0) how="user suricata via --user"
       suricata --user suricata --group suricata $args >"$err" 2>&1 ;;
    1) how="user suricata via setpriv"
       setpriv --reuid=suricata --regid=suricata --init-groups \
         --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
         suricata $args >"$err" 2>&1 ;;
    *) how="root"
       suricata $args >"$err" 2>&1 ;;
  esac
  rc=$?
  t1=$(cut -d. -f1 /proc/uptime)
  why=$(grep -iE 'error|fail|denied|not permitted|unable' "$err" 2>/dev/null | tail -1 | cut -c1-300)
  [ -n "$why" ] || why=$(tail -1 "$err" 2>/dev/null | cut -c1-300)
  logger -t ids-watchdog -p daemon.err "suricata exited with code ${rc} (ran as ${how}), restarting in 2 s: ${why:-no output}"
  if [ $((t1 - t0)) -lt 10 ]; then fails=$((fails + 1)); else fails=0; fi
  if [ "$fails" -ge 2 ] && [ "$mode" -lt 2 ]; then
    mode=$((mode + 1))
    fails=0
    [ "$mode" -eq 2 ] && logger -t ids-watchdog -p daemon.crit "suricata does not start without root, running it as root"
  fi
  sleep 2
done
