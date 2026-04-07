FROM ghcr.io/mhsanaei/3x-ui:v2.6.7

# Устанавливаем утилиты, необходимые для работы твоего entrypoint.sh
# и создаем символическую ссылку, чтобы скрипт работал без изменений
RUN apk add --no-cache bash jq curl procps openssl \
    && ln -s /app /usr/local/x-ui

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]