# vless-docker

`3x-ui` + `self-sni` через `docker compose`

## Требования

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования


## Как пользоваться

1. Создайте файл `docker-compose.yml` и вставьте, заменив значения:

    ```yaml
    services:
      vless:
        image: ghcr.io/jellybebra/vless-docker:latest
        restart: unless-stopped

        environment:
          XUI_USERNAME: "admin" # логин в панель 3x-ui
          XUI_PASSWORD: "change_me" # пароль в панель 3x-ui
          XUI_WEBPATH: "panelpath" # путь панели в URL
          SELF_SNI_DOMAIN: "example.com" # ваш домен для self-sni

        ports:
          - "80:80" # HTTP (редирект на HTTPS)
          - "443:443" # VLESS Reality
          # - "8080:8080" # опционально: локальный HTTP-доступ к панели (без TLS)

        volumes:
          - ./data/xui:/etc/x-ui
          - ./data/letsencrypt:/etc/letsencrypt
          - ./data/www:/var/www/html
          - ./data/cert:/root/cert
    ```

2. Запустите:

    ```bash
    docker compose up -d
    ```

3. Откройте панель:

    ```text
    https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
    ```
