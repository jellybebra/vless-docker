# vless-docker

`3x-ui` + `traefik` через `docker compose`

## Требования

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования

## Как пользоваться

1. Создайте файл [docker-compose.yml](docker-compose.yml), заменив значения

2. Создайте .env файл по примеру [.env.example](.env.example)

3. Запустите:

    ```bash
    docker compose up -d
    ```

4. Откройте панель:

    ```text
    https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
    ```

При первом старте контейнер `vless` сам:

- применит логин, пароль и `web path` для `3x-ui`
- создаст или обновит inbound на `443`
- выставит `dest` в `traefik:8443` и `serverNames` в `SELF_SNI_DOMAIN`
- поставит `xver=1`
- очистит `flow` у существующих клиентов

## Бэкап
```bash
cp -a docker-compose.yml docker-compose.backupN.yml
cp -a data/xui data/xui_backupN
```
## Тест
```bash
nano docker-compose.yml
docker compose pull
docker compose up -d
```
## Откат
```bash
cd /opt/vpn
docker compose down
cp -a docker-compose.backupN.yml docker-compose.yml
rm -rf data/xui
cp -a data/xui_backupN data/xui
docker compose up -d
```

