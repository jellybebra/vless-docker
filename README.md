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

---

## 🛡 Тестирование

### Бэкап панели и базы данных
Создает резервную копию конфигурации Docker и базы данных `3x-ui`:
```bash
cp -a docker-compose.yml docker-compose.backup.yml
docker run --rm -v xui_data:/volume -v $(pwd):/backup alpine tar czf /backup/xui_backup.tar.gz -C /volume .
```

### Откат к бэкапу
Если что-то пошло не так, восстановите рабочую версию из бэкапа:
```bash
docker compose down
cp -a docker-compose.backup.yml docker-compose.yml
docker run --rm -v xui_data:/volume -v $(pwd):/backup alpine sh -c "rm -rf /volume/* && tar xzf /backup/xui_backup.tar.gz -C /volume"
docker compose up -d
```
