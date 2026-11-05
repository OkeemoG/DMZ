# Image fw: Firewall-Knoten (fw-edge, fw-dmz, fw-backend)
FROM alpine:3.24

RUN apk add --no-cache \
      iproute2 \
      nftables \
      ulogd \
      tcpdump \
      strongswan \
      openssh-server \
      conntrack-tools

CMD ["sleep", "infinity"]
