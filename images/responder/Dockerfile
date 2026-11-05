FROM python:3.12-alpine3.24

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apk add --no-cache openssh-client-default su-exec \
 && addgroup -S responder \
 && adduser -S -G responder -h /home/responder -s /sbin/nologin responder

COPY app/ /opt/responder/

RUN chmod 755 /opt/responder/entrypoint.sh /opt/responder/respond /opt/responder/responder.py \
 && ln -s /opt/responder/respond /usr/local/bin/respond

CMD ["/opt/responder/entrypoint.sh"]
