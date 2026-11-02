# Image ids: IDS (Suricata 8) am Spiegelport von fw-dmz
# Alpine 3.24, da Alpine 3.20 seit 2026-04-01 ohne Unterstuetzung ist und nur Suricata 7.0.7 enthaelt.
FROM alpine:3.24

RUN apk add --no-cache --no-scripts iproute2 suricata \
 && mkdir -p /var/log/suricata

CMD ["sleep", "infinity"]
