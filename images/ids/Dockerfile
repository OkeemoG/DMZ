# Image ids: IDS (Suricata 8) am Spiegelport von fw-dmz
# Alpine 3.24, da Alpine 3.20 seit 2026-04-01 ohne Unterstuetzung ist und nur Suricata 7.0.7 enthaelt.
FROM alpine:3.24

RUN apk add --no-cache --no-scripts iproute2 suricata setpriv \
 && addgroup -S suricata \
 && adduser -S -G suricata -H -h /var/lib/suricata -s /sbin/nologin suricata \
 && mkdir -p /var/log/suricata /var/lib/suricata /run/suricata \
 && chown -R suricata:suricata /var/log/suricata /var/lib/suricata /run/suricata \
 && chgrp -R suricata /etc/suricata \
 && chmod -R g+rX /etc/suricata

CMD ["sleep", "infinity"]
