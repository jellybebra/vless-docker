FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        certbot \
        curl \
        git \
        jq \
        nginx \
        openssl \
        procps \
        tar \
        tzdata \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local

# Keep the same 3x-ui release used by 3xinstall.sh in this repository.
RUN wget -q -O x-ui-linux-amd64.tar.gz \
      https://github.com/MHSanaei/3x-ui/releases/download/v2.6.7/x-ui-linux-amd64.tar.gz \
    && tar -xzf x-ui-linux-amd64.tar.gz \
    && rm -f x-ui-linux-amd64.tar.gz \
    && chmod +x /usr/local/x-ui/x-ui \
    && chmod +x /usr/local/x-ui/bin/xray-linux-amd64

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443 8080

ENTRYPOINT ["/entrypoint.sh"]
