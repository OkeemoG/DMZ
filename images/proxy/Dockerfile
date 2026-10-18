# Image proxy: Reverse-Proxy (Nginx) mit selbst signiertem Zertifikat
# Zertifikat nach BSI TR-02102-2 (2026-01), Abschnitt 3.6.2 Tabelle 14:
# ECDSA mit brainpoolP512r1, Signatur mit SHA-512
FROM nginx:1.28-alpine

RUN apk add --no-cache iproute2 openssl \
 && mkdir -p /etc/nginx/tls \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:brainpoolP512r1 -sha512 -nodes -days 365 \
      -subj "/CN=203.0.113.2" \
      -addext "subjectAltName=IP:203.0.113.2,IP:10.10.10.2" \
      -keyout /etc/nginx/tls/proxy.key -out /etc/nginx/tls/proxy.crt \
 && chmod 600 /etc/nginx/tls/proxy.key \
 && apk del openssl
