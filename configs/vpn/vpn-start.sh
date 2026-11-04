#!/bin/sh
# Startet charon (strongSwan) im Hintergrund und laedt Verbindungen, Zertifikate und Schluessel.
# Aufruf aus der Topologie (exec) auf fw-edge, ro-client1 und ro-client2.

/usr/lib/strongswan/charon >/dev/null 2>&1 &

n=0
until swanctl --stats >/dev/null 2>&1; do
  n=$((n + 1))
  if [ "$n" -ge 50 ]; then
    echo "vpn-start: charon nicht erreichbar" >&2
    exit 1
  fi
  sleep 0.2
done

swanctl --load-all
