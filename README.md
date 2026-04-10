# vless-docker

`3x-ui` + `traefik` через `docker compose`

## Как пользоваться

### 0. Купить и настроить домен

- У домена в `SELF_SNI_DOMAIN` должна быть A-запись на IP сервера без проксирования


### 1. Получение CF_DNS_API_TOKEN

1. https://dash.cloudflare.com/profile/api-tokens
2. Create token
3. Custom token
4. Name

   let's encrypt

5. Permissions
   - `Zone / Zone / Read`
   - `Zone / DNS / Edit`
6. `Zone Resources`:
   - `Include` → `Specific zone` → `example.com`
7. Continue

### 2. Traefik

1. Создайте файл [traefik.yml](traefik.yml) в папке `/opt/traefik`

2. Создайте .env файл по примеру [.env.example](.env.example)

3. Запустите:

    ```bash
    docker network create traefik-public
    docker compose -f traefik.yml pull
    docker compose up -d
    ```

### 3. Vless

1. Создайте файл [docker-compose.yml](docker-compose.yml) в папке `/opt/vless`

2. Создайте .env файл по примеру [.env.example](.env.example)

3. Запустите:

    ```bash
    docker compose pull
    docker compose up -d
    ```

4. Откройте панель:

    ```text
    https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
    ```

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

## WARP

1. Откройте **3x-ui** → **Xray Settings** → **Outbounds**.
   Нажмите **WARP** → **Create**.
   Если панель не добавила outbound автоматически, добавьте outbound вручную с тегом `warp`.
   
   Заодно надо заменить `engage.cloudflareclient.com:2408` на `162.159.192.1:2408`

2. Откройте **Xray Settings** → **Routing Rules** и добавьте правило для всего трафика:

   ```
   Network      = tcp,udp
   Outbound Tag = warp
   ```

3. Сделай порядок правил таким:
   
   ```
   1. api -> api
   2. geoip:ru -> blocked
   3. geoip:private -> blocked
   4. bittorrent -> blocked
   5. TCP,UDP -> warp
   ```

4. Сохрани и перезагрузи
