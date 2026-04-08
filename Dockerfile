FROM ghcr.io/mhsanaei/3x-ui:latest

RUN apk add --no-cache curl jq openssl procps

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
