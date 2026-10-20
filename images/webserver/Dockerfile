# Image webserver:
FROM python:3.12-alpine3.20

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_MODE=vulnerable

RUN apk add --no-cache iproute2 \
 && pip install --no-cache-dir flask==3.1.0 gunicorn==23.0.0 \
 && addgroup -S app \
 && adduser -S -G app -H -s /sbin/nologin app

WORKDIR /app
COPY app/ /app/

EXPOSE 8080

CMD ["gunicorn", "--user", "app", "--group", "app", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "10", "app:app"]
