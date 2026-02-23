# vless-docker

`3x-ui` + `self-sni` через `docker compose`

## Требования

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования


## Быстрый старт

1. Создайте файл `docker-compose.yml` и вставьте, заменив значения:

    ```yaml
    services:
      vless:
        image: ghcr.io/jellybebra/vless-docker:latest # образ контейнера
        container_name: vless-selfsni # имя контейнера
        restart: unless-stopped # автозапуск после перезагрузки/падения

        environment:
          XUI_USERNAME: "admin" # логин в панель 3x-ui
          XUI_PASSWORD: "change_me" # пароль в панель 3x-ui
          XUI_WEBPATH: "panelpath" # путь панели в URL
          XUI_PORT: "8080" # порт панели 3x-ui
          SELF_SNI_DOMAIN: "example.com" # ваш домен для self-sni с корректной A-записью на сервер
          SELF_SNI_PORT: "9000" # локальный nginx-таргет для reality dest

        ports:
          - "80:80" # HTTP (редирект на HTTPS)
          - "443:443" # VLESS Reality
          - "8080:8080" # панель 3x-ui

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
    http://<IP_сервера>:<XUI_PORT>/<XUI_WEBPATH>
    ```
