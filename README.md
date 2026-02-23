# vless-docker

`3x-ui` + `self-sni` через `docker compose`

## Требования

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования


## Быстрый старт

1. Создайте файл `docker-compose.yml` и вставьте:

    ```yaml
    services:
      vless:
        image: ghcr.io/jellybebra/vless-docker:latest
        container_name: vless-selfsni
        restart: unless-stopped
        environment:
          XUI_USERNAME: "admin"
          XUI_PASSWORD: "change_me"
          XUI_WEBPATH: "panelpath"
          SELF_SNI_DOMAIN: "example.com"
          SELF_SNI_PORT: "9000"
        ports:
          - "80:80"
          - "443:443"
          - "8080:8080"
        volumes:
          - ./data/xui:/etc/x-ui
          - ./data/letsencrypt:/etc/letsencrypt
          - ./data/www:/var/www/html
          - ./data/cert:/root/cert
    ```

2. Замените значения:

   - `XUI_USERNAME` — логин в панель.
   - `XUI_PASSWORD` — пароль в панель.
   - `XUI_WEBPATH` — путь панели (например `panelpath`).
   - `SELF_SNI_DOMAIN` — ваш домен с корректной A-записью на сервер.


3. Запустите:

    ```bash
    docker compose up -d
    ```

4. Откройте панель:

    ```text
    http://<IP_сервера>:8080/<XUI_WEBPATH>
    ```

