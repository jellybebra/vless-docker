# vless-docker

`3x-ui` + `self-sni` через `docker compose`

## Требования

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования


## Как пользоваться

1. Создайте файл [docker-compose.yml](docker-compose.yml), заменив значения

2. Запустите:

    ```bash
    docker compose up -d
    ```

3. Откройте панель:

    ```text
    https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
    ```
