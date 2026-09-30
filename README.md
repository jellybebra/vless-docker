# VLESS + Traefik Docker Stack

Связка `3x-ui` (VLESS TCP REALITY), `warp` и `traefik` через `docker compose`. 

**Особенности сборки:**
* Автоматическая выписка и обновление SSL-сертификатов (Let's Encrypt).
* Автоматически скачивает фейковый сайт. 
* Автоматически настраивает Cloudflare WARP и маршрутизацию против раскрытия реального IP-адреса сервера.

---

## 🛠 Подготовка

### 1. Настройка домена
У вашего домена (`SELF_SNI_DOMAIN`) должна быть создана **A-запись** на IP-адрес вашего сервера. 
> **Важно:** Проксирование Cloudflare должно быть **выключено** (DNS Only).

### 2. Получение токена Cloudflare (CF_DNS_API_TOKEN)
Для работы Traefik с вашим доменом нужен токен:
1. Перейдите в [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens).
2. Нажмите **Create token** → **Custom token** → **Get started**.
3. Задайте имя (например, `Traefik Let's Encrypt`).
4. В блоке **Permissions** добавьте:
   * `Zone` / `Zone` / `Read`
   * `Zone` / `DNS` / `Edit`
5. В блоке **Zone Resources** выберите:
   * `Include` → `Specific zone` → `ваш-домен.com`
6. Нажмите **Continue to summary** и скопируйте полученный токен.

---

## 🚀 Установка

### Шаг 1. Развертывание Traefik

1. Создайте директорию и перейдите в неё:
   ```bash
   mkdir -p /opt/traefik && cd /opt/traefik
   ```
2. Создайте файл `docker-compose.yml` ([traefik.yml](traefik.yml)) и [.env](.env.example), заполнив данные.
3. Запустите сеть и контейнер:
   ```bash
   docker network create traefik-public
   docker compose up -d --pull always
   ```

### Только Traefik для веб-приложений

Для сервера без VLESS используйте [traefik.web.yml](traefik.web.yml).
В `.env` достаточно `EMAIL` и `CF_DNS_API_TOKEN`. Создайте сеть, если её ещё нет:

```bash
docker network create traefik-public
docker compose -f traefik.web.yml up -d
```

Подключите веб-приложение к `traefik-public` и задайте ему Docker labels:
`traefik.enable=true`, правило `Host(...)`, точку входа `websecure`, резолвер
`letsencrypt` и внутренний порт сервиса. HTTP автоматически перенаправляется на HTTPS.
Сертификаты хранятся в постоянном томе `traefik_letsencrypt`.
Для последующих команд Compose также указывайте `-f traefik.web.yml`.

### Шаг 2. Развертывание и настройка 3x-ui (VLESS)
1. Создайте директорию и перейдите в неё:
   ```bash
   mkdir -p /opt/vless && cd /opt/vless
   ```
2. Создайте файл [docker-compose.yml](docker-compose.yml), [entrypoint.sh](entrypoint.sh) и [.env](.env.example), заполнив данные от панели и домена.
3. Запустите скрипт автоматической настройки на хосте:
   ```bash
   bash entrypoint.sh
   ```
4. Панель будет доступна по адресу:
   ```text
   https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
   ```

### Cloudflare Tunnel

Один раз добавьте исключения сниффинга, чтобы `cloudflared` работал через VLESS с HTTP/2.

1. Откройте панель **3x-ui → Inbounds / Входящие подключения**.
2. У VLESS TCP REALITY-входа на порту **443** выберите **Edit / Изменить → Sniffing / Сниффинг**.
3. Включите сниффинг, отметьте **HTTP** и **TLS**. Оставьте **Route only / Только маршрутизация** выключенным.
4. В **Domains excluded / Исключённые домены** добавьте три отдельных значения, подтверждая каждое клавишей Enter:

   ```text
   h2.cftunnel.com
   probe.cftunnel.com
   quic.cftunnel.com
   ```

5. Сохраните входящее подключение и нажмите **Перезапуск Xray** в панели.
6. На компьютере настройте такие же исключения по [инструкции для v2rayN](https://github.com/jellybebra/device-setup/blob/main/docs/v2rayn-routing.md).
