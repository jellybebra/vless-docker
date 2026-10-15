# WireGuard / wg-easy

Отдельный Compose-проект на **wg-easy 15.4.0**, образ закреплён по digest.
Он не зависит от контейнеров VLESS и не перезапускает их.
WARP работает на клиенте; сервер принимает обычный WireGuard.

Панель доступна на loopback хоста, WireGuard — на заданном UDP-порту.
Отдельная bridge-сеть изолирует сервис от `traefik-public`.
Нужен Linux/Docker с поддержкой WireGuard в ядре и `NET_ADMIN` контейнера;
`privileged`, `SYS_MODULE`, Docker socket и host networking не используются.
На хосте при необходимости заранее выполнить `modprobe wireguard`.

## Что сохраняет импорт

- Приватный/публичный ключ сервера и все ключи клиентов, включая PSK при наличии.
- Адреса четырёх существующих клиентов и подсеть `10.203.13.0/29`.
- UDP-порт `51871` и MTU `1200` (явные параметры позволяют тестировать на другом порту).
- Клиентские Endpoint из исходного конфига. Для локальной копии использовать
  `--forget-endpoints`: адреса клиентов будут изучены только при их подключении.
- Выходной IP `138.124.114.237` задаётся Docker-сети через `wireguard.server.yml`.

Имена клиентов берутся из имён файлов `.key`. Приватные ключи сверяются с публичными
ключами peers. Они нужны для корректного скачивания клиентских конфигов и QR-кодов
в панели. Секреты не попадают в Git или вывод импортёра.
Отсутствующий PSK кодируется нулевым ключом WireGuard (это означает «без PSK»).

Импорт поддерживает исходный формат `wg showconf`: один Interface с PrivateKey и
ListenPort; у каждого Peer — PublicKey, один IPv4 /32 AllowedIPs, необязательные
PresharedKey и Endpoint. Неизвестные поля, hooks, дубликаты и адреса вне подсети
отклоняются. Это намеренно узкий импортёр текущей установки, не универсальный
конвертер произвольных VPN-конфигураций.

Вместо старых host firewall hooks устанавливается `firewall.sh` внутри контейнера:
запрет частных/служебных назначений и доступа VPN-клиентов к самому контейнеру,
доступ в интернет и возвратный established-трафик. IPv6 отключён. Текущие
параметры DNS клиентов — `1.1.1.1,1.0.0.1`, AllowedIPs — `0.0.0.0/0`, keepalive — 25.
Это значения для выдаваемых панелью конфигов; существующие клиенты не изменяются.
Скачанный обычный WG-конфиг сам по себе не настраивает клиентскую цепочку WARP.

## Подготовка и репетиция

Команды выполнять из корня этого репозитория. Не использовать основной
`docker-compose.yml`: у WireGuard отдельный проект и named volume.

1. Скопировать `wireguard/.env.example` в `wireguard/.env`. Задать длинный случайный
   пароль администратора. Файл `.env` исключён из Git. Для локальной репетиции
   использовать свободные порты, например `WG_PORT=51881`, `WG_UI_PORT=51831`,
   `WG_BIND_IP=127.0.0.1`, `WG_ENDPOINT=127.0.0.1`.
2. Скопировать исходные файлы в `.private/wireguard-import/`:
   `server.conf` из `/etc/device-setup/warp-wireguard/server.conf`, а в `keys/` —
   `warp.key`, `direct.key`, `native-win.key`, `native-mac.key` из
   `/opt/warp-wireguard-test/`. На Linux каталог должен иметь права 700, файлы 600;
   на Windows ограничить ACL текущим пользователем, администраторами и SYSTEM.
3. Инициализировать базу с `WG_INIT_ENABLED=true`, `WG_INIT_USERNAME`,
   `WG_INIT_PASSWORD` и `WG_ENDPOINT`, затем остановить **только новый** контейнер:

```sh
docker compose --env-file wireguard/.env -p wireguard -f wireguard.compose.yml up -d wg-easy
docker compose --env-file wireguard/.env -p wireguard -f wireguard.compose.yml stop wg-easy
```

До импорта и проверки пароль должен быть установлен, а панель — доступна только
локально. Пустой пароль не завершит автоматическую настройку.

4. Сначала dry run, затем импорт в остановленную базу. Для репетиции:

```sh
docker compose --env-file wireguard/.env -p wireguard -f wireguard.compose.yml run --rm import \
  --address 10.203.13.1/29 --endpoint 127.0.0.1 --port 51881 --forget-endpoints
docker compose --env-file wireguard/.env -p wireguard -f wireguard.compose.yml run --rm import \
  --address 10.203.13.1/29 --endpoint 127.0.0.1 --port 51881 --forget-endpoints --apply --stopped
```

Для конечной серверной базы заменить endpoint на `92.246.139.113`, порт — на `51871`.
Импорт создаёт согласованную SQLite-копию `wg-easy.db.before-import-<timestamp>`
в том же volume, затем выполняет изменения одной транзакцией. База с уже
существующими клиентами не перезаписывается. `--stopped` — подтверждение оператора,
что контейнер остановлен; сам импортёр не имеет доступа к Docker socket.

5. Удалить `WG_INIT_USERNAME` и `WG_INIT_PASSWORD` из `.env`, установить
   `WG_INIT_ENABLED=false`, запустить новый контейнер.
6. Проверить вход, четыре peer, скачивание конфига, handshake, TCP/UDP и блокировки.
   `healthy` проверяет интерфейс и HTTP API, но не доказывает доступность интернета.

Для локального HTTP допускается `WG_INSECURE=true` **только с loopback-привязкой
панели**. В production использовать HTTPS и `WG_INSECURE=false`. Внешний HTTPS-прокси
должен передавать Host и X-Forwarded-Proto. Нельзя публиковать незавершённый setup.
При Cloudflare Tunnel данные и сессии остаются в локальном volume; наружу идёт
только панель по HTTPS. Обычный HTTP Tunnel не переносит публичный WireGuard UDP.

## Переключение существующего сервера

Выполнять при публикации, после репетиции и проверки актуального снимка.
Подготовку на сервере проводить на временном свободном UDP-порту/loopback, чтобы
не конфликтовать с работающим `wg-codex`. Перед финальным импортом остановить
новый контейнер. В `.env` установить конечные endpoint, порт и выходной IP.

Включение `wireguard.server.yml` создаёт сеть с выбранным SNAT. Для перехода от
тестовой сети без этой настройки сначала выполнить `docker compose ... down`
**без `-v`**, сохранив базу, и затем создать сеть с обоими Compose-файлами.

Сохранить копии старого конфига, unit и правил firewall вне Git. Старый unit
при остановке не удаляет интерфейс, поэтому для освобождения UDP-порта нужно
отдельно удалить **только** `wg-codex`:

```sh
systemctl disable --now device-setup-wireguard.service
ip link delete wg-codex
docker compose --env-file wireguard/.env -p wireguard \
  -f wireguard.compose.yml -f wireguard.server.yml up -d wg-easy
```

На ПК проверить текущий SOCKS `127.0.0.1:19506`, выход `138.124.114.237`, HTTPS,
UDP и отсутствие доступа к частным сетям. На сервере проверить handshakes и
сохранность VLESS. Docker обновляет SNAT только для отдельной сети wg-easy.
Фактический выходной IP обязательно проверяется после переключения.

При неуспехе остановить новый сервис и вернуть старый:

```sh
docker compose --env-file wireguard/.env -p wireguard \
  -f wireguard.compose.yml -f wireguard.server.yml stop wg-easy
systemctl enable --now device-setup-wireguard.service
```

Старый unit восстановит интерфейс из неизменённого `/etc/device-setup/warp-wireguard/server.conf`.
После подтверждённой миграции можно убрать старые правила с меткой `codex-warp-wg`
и цепь `CWARPWG`, предварительно проверив ссылки на них. Не очищать целиком
FORWARD/POSTROUTING и не перезапускать основной VLESS Compose.

## HTTPS-панель через Cloudflare Tunnel

Production размещён в `/opt/wireguard`, панель — `https://wg.vzl0m.com`.
Туннель запускается отдельным сервисом через `wireguard.tunnel.yml`:

```sh
docker compose --env-file wireguard/.env -p wireguard \
  -f wireguard.compose.yml -f wireguard.server.yml -f wireguard.tunnel.yml up -d
```

Создать named tunnel и DNS-запись средствами `cloudflared`. Его credentials JSON
сохранить в `.private/panel-tunnel.json`, а `wireguard/tunnel.yml.example`
скопировать в `.private/panel-tunnel.yml` и вписать UUID. Каталог `.private` имеет
права 700; JSON — 600 и владельца `65532:65532` для чтения непривилегированным
контейнером, конфигурация — 644. Секреты и база в Git не хранятся.

В production `WG_INSECURE=false`; вход — штатный логин/пароль wg-easy,
с возможностью включить 2FA в панели. После первой настройки убрать INIT-пароль
из `.env` и пересоздать контейнер. TCP-порт панели слушает только loopback хоста.
Tunnel передаёт только веб-панель; WireGuard UDP идёт напрямую на сервер.

## Обновления, резервные копии и проверки

База — источник конфигурации; редактирование генерируемого `wg0.conf` не сохраняется.
Не менять IPv4-подсеть или `eth0` через панель без пересмотра firewall hooks.
Для резервной копии остановить контейнер и сохранить весь volume `wg_data`.
Не использовать `down -v` для действующей установки.

Перед обновлением версии повторить импортные и сетевые проверки на копии базы.
Количество миграций SQLite и состав полей импортёра привязаны к 15.4.0.
Запуск тестов с копией инициализированной пустой базы (не с рабочей базой peers):

```sh
docker run --rm --network none \
  --mount "type=bind,source=$(pwd)/wireguard,target=/tests,readonly" \
  --mount "type=bind,source=$(pwd)/.private/baseline.db,target=/baseline.db,readonly" \
  -e WG_TEST_DB=/baseline.db --entrypoint node \
  ghcr.io/wg-easy/wg-easy:15.4.0@sha256:0e7bc9d34e86ddcaa92bc700d4d7dc9b33291dbc07ac8d13382f7c2095f949ec \
  --test /tests/import.test.mjs
```

Источники: [wg-easy](https://wg-easy.github.io/wg-easy/latest/),
[настройка Docker SNAT](https://docs.docker.com/engine/network/port-publishing/).

## Проверено 15 октября 2026

На отдельном Docker Desktop экземпляре с копией исходного серверного конфига
и четырёх клиентских ключей проверены импорт, вход локально и через HTTPS Tunnel,
список peers, соответствие приватных ключей в скачиваемых конфигах, MTU и выдача QR.
Шесть тестов проверяют ключи, ограничения импорта, dry run, backup, отказ повторного
импорта и транзакционный откат при ошибке SQLite.
Отдельный клиентский контейнер установил WireGuard-соединение и получил HTTPS 200
и ответ UDP DNS. Запреты частных назначений и доступа к панели через WG проверены
также по счётчикам DROP. Повторный запуск firewall не меняет набор правил.

Production переключён на Compose-проект `wireguard` в `/opt/wireguard`.
Старый `device-setup-wireguard.service` отключён; его конфигурация и скрипт отката
сохранены в `/opt/codex-backups/wireguard-20261015/`. Не запускать старый unit или
старый установщик одновременно с wg-easy: они используют один UDP-порт.

Текущий Windows WARP → WireGuard клиент переподключился без изменения ключей.
Проверены HTTPS с выходом `138.124.114.237`, UDP DNS (5/5 до и после перезапуска
контейнера), обновление handshake и healthy-состояние supervisor.
Через v2rayN `10808` Google вернул 204, OpenAI API — ожидаемый 401 без API-ключа;
учтены существующие правила direct для отдельных сайтов.
Вход через `https://wg.vzl0m.com` и список четырёх клиентов работают;
неавторизованный запрос к API клиентов возвращает 401.
Контейнер VLESS не перезапускался.
