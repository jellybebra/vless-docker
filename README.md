# VLESS + Traefik Docker Stack

Связка `3x-ui` (VLESS/Xray) и `traefik` через `docker compose`. 

**Особенности сборки:**
* Автоматическая выписка и обновление SSL-сертификатов (Let's Encrypt).
* Автоматически скачивает фейковый сайт.

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
2. Создайте файл `docker-compose.yml` (содержимое взять из [traefik.yml](traefik.yml)) и `.env` (по примеру `.env.example`), впишите туда `CF_DNS_API_TOKEN` и ваш `EMAIL`.
3. Запустите сеть и контейнер:
   ```bash
   docker network create traefik-public
   docker compose up -d --pull always
   ```

### Шаг 2. Развертывание 3x-ui (VLESS)
1. Создайте директорию и перейдите в неё:
   ```bash
   mkdir -p /opt/vless && cd /opt/vless
   ```
2. Создайте файл `docker-compose.yml` и `.env` (по примеру `.env.example`), заполнив данные от панели и домена.
3. Запустите контейнер:
   ```bash
   docker compose up -d --pull always
   ```
4. Панель будет доступна по адресу:
   ```text
   https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
   ```

---

## ⚙️ Настройка WARP

Это необходимо, чтобы не палить IP прокси-сервера.

1. **Создание исходящего соединения (Outbound):**
   * Откройте панель **3x-ui** → **Xray Settings** → **Outbounds**.
   * Нажмите **WARP** → **Create**.
   * Проверьте, что добавлен outbound с тегом `warp`.
   * В настройках этого outbound замените `engage.cloudflareclient.com:2408` на `162.159.192.1:2408`, а также выставьте `Domain Strategy` - `ForceIPv4`

2. **Настройка правил маршрутизации (Routing Rules):**
   * Перейдите в **Xray Settings** → **Routing Rules**.
   * Добавьте новое правило для перенаправления всего трафика в WARP:
     ```text
     Network      = tcp,udp
     Outbound Tag = warp
     ```

3. **Сортировка правил:**
   Убедитесь, что правила маршрутизации расположены **строго в следующем порядке**, иначе VPN перестанет работать:
   ```text
   1. api -> api
   2. geoip:ru -> blocked
   3. geoip:private -> blocked
   4. bittorrent -> blocked
   5. TCP,UDP -> warp
   ```
4. Нажмите **Save** и перезагрузите Xray (Restart Xray).

> Еще в outbounds, в WARP, надо настроить .

---

## 🛡 Тестирование

### Бэкап панели и базы данных
Создает резервную копию конфигурации Docker и базы данных `3x-ui`:
```bash
cp -a docker-compose.yml docker-compose.backup.yml
cp -a data/xui data/xui_backup
```

### Обновление / Применение изменений
Если вы отредактировали `docker-compose.yml` или `.env`, примените их командами:
```bash
docker compose pull
docker compose up -d
```

### Откат к бэкапу
Если что-то пошло не так, восстановите рабочую версию из бэкапа:
```bash
docker compose down
cp -a docker-compose.backup.yml docker-compose.yml
rm -rf data/xui
cp -a data/xui_backup data/xui
docker compose up -d
```
