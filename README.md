# VLESS + Traefik Docker Stack

Связка `3x-ui` (VLESS TCP REALITY) и `traefik` через `docker compose`, с опциональными Proton VPN и WARP.

**Особенности сборки:**
* Автоматическая выписка и обновление SSL-сертификатов (Let's Encrypt).
* Автоматически скачивает фейковый сайт. 
* Направляет трафик напрямую по умолчанию. Cloudflare WARP включается только через `WARP_ENABLED=true`.

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
2. Скопируйте [docker-compose.yml](docker-compose.yml), [entrypoint.sh](entrypoint.sh), [proton-routing.sh](proton-routing.sh), папку [happ](happ) и [.env](.env.example), заполнив данные от панели и домена.
3. Запустите скрипт автоматической настройки на хосте:
   ```bash
   bash entrypoint.sh
   ```
4. Панель будет доступна по адресу:
   ```text
   https://<SELF_SNI_DOMAIN>/<XUI_WEBPATH>
   ```

### Подписка Happ

1. Для существующего развёртывания скопируйте обновлённый `docker-compose.yml` и папку `happ` в `/opt/vless`.
2. Из этой папки запустите сервис:

   ```bash
   docker compose up -d --build --no-deps happ
   ```

3. Если 3x-ui использует другой путь или порт подписок, задайте `HAPP_SUB_BASE_URL` в `.env` и повторите запуск.
4. Используйте подписку с серверами VLESS TCP REALITY.
5. В ссылке пользователя замените `/sub/` на `/happ/`: `https://example.com/sub/TOKEN` → `https://example.com/happ/TOKEN`.
6. Добавьте полученную ссылку в Happ и подключитесь к одному из серверов **iPhone - YouTube DPI**.

Маршрутизация включает `geosite:supercell`, чтобы домены Brawl Stars и Supercell ID
шли через VPN. JSON-профиль также направляет TCP/UDP на порт назначения `9339`
через VPN: игровой протокол может обращаться к IP без домена, и одного GeoSite
для этого недостаточно. Исключения для локальной сети сохраняют приоритет;
соединения других приложений к внешним адресам на порту `9339` тоже идут через VPN.
После обновления сервиса обновите подписку и GeoSite в Happ,
переподключитесь и перезапустите игру. На Android игра также должна быть включена
в VPN, если используется выбор приложений. Если проблема сохраняется, нужны
логи Happ: правило `9339` не гарантирует охват игровых соединений на других портах.

Проверка маршрутизации настоящим Xray без внешних соединений (выходы заменены
локальными заглушками; Geo-файлы должны включать категории из профиля):

```bash
XRAY_BIN=/path/to/xray XRAY_LOCATION_ASSET=/path/to/geo-files \
  python3 -m unittest discover -s tests -p 'test_happ*.py'
```

### ChatGPT через Proton VPN

Опциональный выход `proton-openai` направляет домены `chatgpt.com`, `openai.com`,
`oaistatic.com`, `oaiusercontent.com` и `chat.com` (включая поддомены) через Proton.
Остальной трафик идёт напрямую. WARP выключен по умолчанию и используется для
остального трафика только при `WARP_ENABLED=true`. Существующие правила блокировки
сохраняют приоритет, пользовательские правила сохраняются перед общим выходом.
Если Proton недоступен, совпавший трафик не переключается на другой выход автоматически.
Для разрешения этих доменов добавляется DNS из `.conf` с отдельным правилом
через Proton; остальные настройки DNS сохраняются.

1. Создайте бесплатный аккаунт [Proton VPN](https://protonvpn.com/free-vpn).
   В **Downloads → WireGuard configuration** скачайте конфигурацию бесплатного
   сервера в США. Если такого сервера нет в генераторе, проверьте Канаду, Японию,
   Сингапур или Мексику. Страну проверяйте в кабинете, она не определяется по имени файла.
2. На сервере положите файл рядом со скриптом в `secrets/proton-us.conf`:

   ```bash
   mkdir -p secrets
   chmod 700 secrets
   # Скопируйте скачанный .conf в secrets/proton-us.conf
   chmod 600 secrets/proton-us.conf
   ```

   Файл содержит приватный ключ: не публикуйте его. `secrets/` и `*.conf`
   исключены из Git. Файл читается на хосте, дополнительный контейнер не требуется.
   Proton на вашем компьютере запускать не нужно: соединение устанавливает
   VLESS-сервер. Если кабинет Proton недоступен напрямую, попробуйте открыть
   его через существующий VLESS/WARP.
3. В `.env` задайте путь (относительно текущей папки или абсолютный):

   ```dotenv
   PROTON_WG_CONFIG=secrets/proton-us.conf
   WARP_ENABLED=false
   ```

4. Для **существующего** развёртывания выполните из папки с Compose и `.env`:

   ```bash
   bash entrypoint.sh --routing-only
   ```

   Нужны `bash`, `jq`, `openssl` и Docker Compose. Данные входа и путь панели в
   `.env` должны соответствовать работающей панели. Команда обновляет маршрутизацию
   и перезапускает VLESS, кратковременно прерывая подключения. Она не создаёт
   новых клиентов и не меняет пароли, URL подписок или входящие подключения.
   Для новой установки используйте обычный `bash entrypoint.sh`.

5. Проверьте **на клиенте через VLESS** открытие ChatGPT, вход, загрузку файлов
   и голос, если используете его. В 3x-ui проверьте наличие выхода `proton-openai`
   и правила OpenAI перед общим правилом `direct`. Обычная проверка IP на стороннем
   сайте покажет IP VLESS-сервера — это ожидаемо при маршрутизации только доменов
   OpenAI (или IP WARP, если вы явно включили WARP).

Маршрутизация по доменам требует, чтобы клиент передавал имя назначения либо
сниффинг Xray определял его. Для QUIC нужен сниффинг `quic` на существующем входе.
Голос/WebRTC и запросы к IP без имени могут не попасть под доменное правило;
это нужно проверить на реальном клиенте, список доменов не гарантирует охват
всех будущих соединений Dots. Настройки существующих входов команда не меняет.

В `.conf` поддерживается один peer, IPv4 default route `0.0.0.0/0`, DNS-серверы
в виде IP, MTU 1280–1420 и стандартные ключи WireGuard. Shell hooks из `.conf`
не выполняются. Пустой `PROTON_WG_CONFIG` с повторным `--routing-only` удаляет
управляемый выход Proton и возвращает этот трафик на обычный выход.

VPN меняет сетевой выход, но не тариф или право аккаунта на Dots.
[Доступность Dots](https://learn.chatgpt.com/docs/dots#access) зависит также от
возраста, региона и постепенного включения функции. Для личного Pro сейчас
исключены ЕЭЗ, Великобритания и Швейцария.

Проверка без настоящего аккаунта Proton (искусственные ключи, без VPN-соединения):

```bash
docker run --rm --mount "type=bind,source=$(pwd),target=/work,readonly" \
  --workdir /work --entrypoint sh ghcr.io/mhsanaei/3x-ui:3.2.5 \
  -c 'apk add --no-cache jq >/dev/null && bash tests/proton-routing.sh'
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
