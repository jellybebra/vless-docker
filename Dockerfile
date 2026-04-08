FROM ghcr.io/mhsanaei/3x-ui:latest

USER root

RUN apk add --no-cache \
    bash \
    jq \
    procps

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 443 8080

ENTRYPOINT ["/entrypoint.sh"]
