# Image web application firewall
FROM owasp/modsecurity-crs:4.30.0-nginx-alpine-202610180210

USER root

RUN apk add --no-cache iproute2 su-exec

ENTRYPOINT ["su-exec", "nginx", "/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
