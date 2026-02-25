#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

require_env() {
  local key="$1"
  if [[ -z "${!key:-}" ]]; then
    log "ERROR: env var $key is required"
    exit 1
  fi
}

require_env XUI_USERNAME
require_env XUI_PASSWORD
require_env XUI_WEBPATH
require_env SELF_SNI_DOMAIN

XUI_WEBPATH="${XUI_WEBPATH#/}"
XUI_WEBPATH="${XUI_WEBPATH%/}"
XUI_PORT="${XUI_PORT:-8080}"
SELF_SNI_PORT="${SELF_SNI_PORT:-9000}"

if ! [[ "${XUI_PORT}" =~ ^[0-9]+$ ]] || ((XUI_PORT < 1 || XUI_PORT > 65535)); then
  log "ERROR: XUI_PORT must be an integer in range 1..65535"
  exit 1
fi

BASE_URL="http://127.0.0.1:${XUI_PORT}/${XUI_WEBPATH}"
COOKIE_JAR="/tmp/xui_cookie.jar"
PANEL_INFO_FILE="/etc/x-ui/3x-ui.txt"

readonly CURL_CONNECT_TIMEOUT=3
readonly CURL_MAX_TIME=15

PANEL_ORIGINS=(
  "http://127.0.0.1:${XUI_PORT}"
  "http://localhost:${XUI_PORT}"
  "http://[::1]:${XUI_PORT}"
)

build_login_urls_for_origin() {
  local origin="$1"
  cat <<EOF
${origin}/${XUI_WEBPATH}/login
${origin}/${XUI_WEBPATH}/login/
${origin}/${XUI_WEBPATH}/panel/login
${origin}/${XUI_WEBPATH}/panel/login/
${origin}/login
${origin}/login/
EOF
}

cleanup() {
  set +e
  pkill -f "/usr/local/x-ui/x-ui" >/dev/null 2>&1 || true
  nginx -s quit >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_for_panel() {
  log "Waiting for x-ui panel on 127.0.0.1:${XUI_PORT} ..."
  for _ in $(seq 1 180); do
    for origin in "${PANEL_ORIGINS[@]}"; do
      if curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time 5 -sS -o /dev/null "${origin}/"; then
        return 0
      fi
    done
    sleep 1
  done
  log "ERROR: x-ui panel did not become ready"
  return 1
}

login_panel() {
  local payload resp origin url
  log "Trying panel login ..."
  payload="$(jq -cn --arg u "${XUI_USERNAME}" --arg p "${XUI_PASSWORD}" '{username:$u,password:$p}')"

  for origin in "${PANEL_ORIGINS[@]}"; do
    while IFS= read -r url; do
      resp="$(
        curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" \
          -sS -c "${COOKIE_JAR}" -X POST "${url}" \
          -H "Content-Type: application/json" -d "${payload}" || true
      )"

      if jq -e '.success == true' >/dev/null 2>&1 <<<"${resp}"; then
        if [[ "${url}" == "${origin}/login"* ]]; then
          BASE_URL="${origin}"
        else
          BASE_URL="${origin}/${XUI_WEBPATH}"
        fi
        log "Panel login successful via ${url}"
        return 0
      fi
    done < <(build_login_urls_for_origin "${origin}")
  done

  log "ERROR: panel login failed on all known URLs"
  return 1
}

api_post() {
  local endpoint="$1"
  shift || true
  log "API POST ${endpoint}" >&2
  curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" -sS -b "${COOKIE_JAR}" -X POST "${BASE_URL}${endpoint}" "$@"
}

panel_list_inbounds() {
  api_post "/panel/inbound/list"
}

panel_get_new_x25519() {
  api_post "/server/getNewX25519Cert" \
    -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
    -H "X-Requested-With: XMLHttpRequest"
}

ensure_success() {
  local resp="$1"
  local action="$2"
  if ! jq -e '.success == true' >/dev/null 2>&1 <<<"${resp}"; then
    log "ERROR: ${action} failed: ${resp}"
    return 1
  fi
}

build_default_client_settings() {
  local client_id="$1"
  local email="$2"
  local sub_id="$3"
  jq -cn \
    --arg client_id "${client_id}" \
    --arg email "${email}" \
    --arg sub_id "${sub_id}" \
    '{
      clients: [
        {
          id: $client_id,
          flow: "xtls-rprx-vision",
          email: $email,
          limitIp: 0,
          totalGB: 0,
          expiryTime: 0,
          enable: true,
          tgId: "",
          subId: $sub_id,
          comment: "",
          reset: 0
        }
      ],
      decryption: "none",
      fallbacks: []
    }'
}

build_default_sniffing() {
  jq -cn '{enabled:true,destOverride:["http","tls"],metadataOnly:false,routeOnly:false}'
}

build_stream_settings() {
  local dest="$1"
  local sni="$2"
  local xver="$3"
  local private_key="$4"
  local public_key="$5"
  local short_id="$6"
  jq -cn \
    --arg dest "${dest}" \
    --arg sni "${sni}" \
    --arg private_key "${private_key}" \
    --arg public_key "${public_key}" \
    --arg short_id "${short_id}" \
    --argjson xver "${xver}" \
    '{
      network: "tcp",
      security: "reality",
      externalProxy: [],
      realitySettings: {
        show: false,
        xver: $xver,
        dest: $dest,
        serverNames: [$sni],
        privateKey: $private_key,
        minClientVer: "",
        maxClientVer: "",
        maxTimediff: 0,
        shortIds: [$short_id],
        mldsa65Seed: "",
        settings: {
          publicKey: $public_key,
          fingerprint: "chrome",
          serverName: "",
          spiderX: "/",
          mldsa65Verify: ""
        }
      },
      tcpSettings: {
        acceptProxyProtocol: false,
        header: {type: "none"}
      }
    }'
}

panel_add_inbound() {
  local enable="$1"
  local settings="$2"
  local stream_settings="$3"
  local sniffing="$4"

  api_post "/panel/inbound/add" \
    --data-urlencode "up=0" \
    --data-urlencode "down=0" \
    --data-urlencode "total=0" \
    --data-urlencode "remark=reality443-auto" \
    --data-urlencode "enable=${enable}" \
    --data-urlencode "expiryTime=0" \
    --data-urlencode "listen=" \
    --data-urlencode "port=443" \
    --data-urlencode "protocol=vless" \
    --data-urlencode "settings=${settings}" \
    --data-urlencode "streamSettings=${stream_settings}" \
    --data-urlencode "sniffing=${sniffing}"
}

panel_update_inbound() {
  local inbound_id="$1"
  local enable="$2"
  local settings="$3"
  local stream_settings="$4"
  local sniffing="$5"

  api_post "/panel/inbound/update/${inbound_id}" \
    --data-urlencode "up=0" \
    --data-urlencode "down=0" \
    --data-urlencode "total=0" \
    --data-urlencode "remark=reality443-auto" \
    --data-urlencode "enable=${enable}" \
    --data-urlencode "expiryTime=0" \
    --data-urlencode "listen=" \
    --data-urlencode "port=443" \
    --data-urlencode "protocol=vless" \
    --data-urlencode "settings=${settings}" \
    --data-urlencode "streamSettings=${stream_settings}" \
    --data-urlencode "sniffing=${sniffing}"
}

install_fake_site() {
  local temp_dir selected
  temp_dir="$(mktemp -d)"
  log "Downloading fake website templates ..."
  git clone --depth=1 https://github.com/learning-zone/website-templates.git "${temp_dir}" >/dev/null 2>&1
  selected="$(find "${temp_dir}" -mindepth 1 -maxdepth 1 -type d | shuf -n 1)"
  rm -rf /var/www/html/*
  cp -a "${selected}/." /var/www/html/
  rm -rf "${temp_dir}"
}

write_nginx_challenge_config() {
  cat >/etc/nginx/sites-available/sni.conf <<EOF
server {
    listen 80;
    server_name ${SELF_SNI_DOMAIN};

    root /var/www/html;
    index index.html;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/sni.conf /etc/nginx/sites-enabled/sni.conf
  rm -f /etc/nginx/sites-enabled/default
}

write_nginx_final_config() {
  cat >/etc/nginx/sites-available/sni.conf <<EOF
server {
    listen 80;
    server_name ${SELF_SNI_DOMAIN};

    if (\$host = ${SELF_SNI_DOMAIN}) {
        return 301 https://\$host\$request_uri;
    }

    return 404;
}

server {
    listen 127.0.0.1:${SELF_SNI_PORT} ssl http2 proxy_protocol;
    server_name ${SELF_SNI_DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${SELF_SNI_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${SELF_SNI_DOMAIN}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";

    ssl_stapling on;
    ssl_stapling_verify on;

    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    real_ip_header proxy_protocol;
    set_real_ip_from 127.0.0.1;

    location / {
        root /var/www/html;
        index index.html;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/sni.conf /etc/nginx/sites-enabled/sni.conf
  rm -f /etc/nginx/sites-enabled/default
}

start_or_reload_nginx() {
  nginx -t
  # Prefer reload; if nginx is not started yet, fallback to start.
  if ! nginx -s reload >/dev/null 2>&1; then
    nginx
  fi
}

issue_certificate() {
  log "Requesting certificate for ${SELF_SNI_DOMAIN} ..."
  certbot certonly \
    --non-interactive \
    --agree-tos \
    --register-unsafely-without-email \
    --keep-until-expiring \
    --webroot \
    -w /var/www/html \
    -d "${SELF_SNI_DOMAIN}"
}

persist_panel_info() {
  mkdir -p "$(dirname "${PANEL_INFO_FILE}")"
  cat >"${PANEL_INFO_FILE}" <<EOF
3x-ui panel:
URL: http://127.0.0.1:${XUI_PORT}/${XUI_WEBPATH}
Username: ${XUI_USERNAME}
Password: ${XUI_PASSWORD}

Self-SNI:
Domain: ${SELF_SNI_DOMAIN}
Dest (Target): 127.0.0.1:${SELF_SNI_PORT}
EOF
}

main() {
  cd /usr/local/x-ui

  if [[ ! -x "./x-ui" || ! -x "./bin/xray-linux-amd64" ]]; then
    log "ERROR: x-ui binaries are missing or not executable in /usr/local/x-ui"
    exit 1
  fi

  log "Applying x-ui settings (port ${XUI_PORT}, HTTP, custom credentials/path) ..."
  ./x-ui setting \
    -username "${XUI_USERNAME}" \
    -password "${XUI_PASSWORD}" \
    -port "${XUI_PORT}" \
    -webBasePath "${XUI_WEBPATH}" >/dev/null 2>&1 || true
  ./x-ui migrate >/dev/null 2>&1 || true

  log "Starting x-ui ..."
  ./x-ui &

  wait_for_panel
  log "Panel is reachable."
  login_panel

  local list_resp inbound inbound_id settings stream sniffing
  local keys_resp priv_key pub_key short_id client_id email sub_id

  list_resp="$(panel_list_inbounds)"
  ensure_success "${list_resp}" "inbound list"

  inbound="$(jq -c '.obj[]? | select(.port == 443)' <<<"${list_resp}" | head -n 1 || true)"
  sniffing="$(build_default_sniffing)"

  if [[ -z "${inbound}" ]]; then
    log "Inbound on port 443 not found, creating one (wizard style) ..."
    keys_resp="$(panel_get_new_x25519)"
    ensure_success "${keys_resp}" "getNewX25519Cert"
    priv_key="$(jq -r '.obj.privateKey' <<<"${keys_resp}")"
    pub_key="$(jq -r '.obj.publicKey' <<<"${keys_resp}")"
    short_id="$(openssl rand -hex 8)"
    client_id="$(cat /proc/sys/kernel/random/uuid)"
    email="client-$(openssl rand -hex 4)"
    sub_id="$(openssl rand -hex 16)"
    settings="$(build_default_client_settings "${client_id}" "${email}" "${sub_id}")"
    stream="$(build_stream_settings "${SELF_SNI_DOMAIN}:443" "${SELF_SNI_DOMAIN}" 0 "${priv_key}" "${pub_key}" "${short_id}")"
    ensure_success "$(panel_add_inbound true "${settings}" "${stream}" "${sniffing}")" "create inbound 443"
    list_resp="$(panel_list_inbounds)"
    ensure_success "${list_resp}" "inbound list after create"
    inbound="$(jq -c '.obj[]? | select(.port == 443)' <<<"${list_resp}" | head -n 1 || true)"
  fi

  if [[ -z "${inbound}" ]]; then
    log "ERROR: could not obtain inbound on port 443"
    exit 1
  fi

  inbound_id="$(jq -r '.id' <<<"${inbound}")"
  settings="$(jq -c '
    (
      .settings
      | if type == "string" then (try fromjson catch {}) else . end
      | .clients = ((.clients // []) | map(.flow = "xtls-rprx-vision"))
      | .decryption = "none"
      | .fallbacks = []
    )' <<<"${inbound}")"

  # Ensure at least one client exists.
  if [[ "$(jq '.clients | length' <<<"${settings}")" -eq 0 ]]; then
    client_id="$(cat /proc/sys/kernel/random/uuid)"
    email="client-$(openssl rand -hex 4)"
    sub_id="$(openssl rand -hex 16)"
    settings="$(build_default_client_settings "${client_id}" "${email}" "${sub_id}")"
  fi

  stream="$(jq -c '
    (
      .streamSettings
      | if type == "string" then (try fromjson catch {}) else . end
    )' <<<"${inbound}")"
  if [[ "${stream}" == "null" || -z "${stream}" ]]; then
    keys_resp="$(panel_get_new_x25519)"
    ensure_success "${keys_resp}" "getNewX25519Cert"
    priv_key="$(jq -r '.obj.privateKey' <<<"${keys_resp}")"
    pub_key="$(jq -r '.obj.publicKey' <<<"${keys_resp}")"
    short_id="$(openssl rand -hex 8)"
    stream="$(build_stream_settings "${SELF_SNI_DOMAIN}:443" "${SELF_SNI_DOMAIN}" 0 "${priv_key}" "${pub_key}" "${short_id}")"
  fi

  log "Disabling inbound ${inbound_id} ..."
  ensure_success "$(panel_update_inbound "${inbound_id}" false "${settings}" "${stream}" "${sniffing}")" "disable inbound"

  write_nginx_challenge_config
  start_or_reload_nginx
  issue_certificate
  install_fake_site
  write_nginx_final_config
  start_or_reload_nginx

  log "Applying self-sni fields (dest, sni, xver) to inbound ${inbound_id} ..."
  short_id="$(openssl rand -hex 8)"
  stream="$(jq -c \
    --arg dest "127.0.0.1:${SELF_SNI_PORT}" \
    --arg sni "${SELF_SNI_DOMAIN}" \
    --arg sid "${short_id}" \
    '
    .network = (.network // "tcp") |
    .security = (.security // "reality") |
    .externalProxy = (.externalProxy // []) |
    .realitySettings = (.realitySettings // {}) |
    .realitySettings.dest = $dest |
    .realitySettings.serverNames = [$sni] |
    .realitySettings.xver = 1 |
    .realitySettings.shortIds =
      (
        if ((.realitySettings.shortIds // []) | type) == "array" and ((.realitySettings.shortIds // []) | length) > 0
        then (.realitySettings.shortIds // [])
        else [$sid]
        end
      ) |
    .realitySettings.settings = (.realitySettings.settings // {}) |
    .realitySettings.settings.fingerprint = (.realitySettings.settings.fingerprint // "chrome") |
    .realitySettings.settings.serverName = (.realitySettings.settings.serverName // "") |
    .realitySettings.settings.spiderX = (.realitySettings.settings.spiderX // "/") |
    .tcpSettings = (.tcpSettings // {"acceptProxyProtocol": false, "header": {"type": "none"}})
    ' <<<"${stream}")"
  ensure_success "$(panel_update_inbound "${inbound_id}" false "${settings}" "${stream}" "${sniffing}")" "apply dest/sni/xver"

  priv_key="$(jq -r '.realitySettings.privateKey // empty' <<<"${stream}")"
  pub_key="$(jq -r '.realitySettings.settings.publicKey // empty' <<<"${stream}")"

  if [[ -z "${priv_key}" || -z "${pub_key}" ]]; then
    log "Reality cert/key pair is missing, requesting a new pair (Get New Cert) ..."
    keys_resp="$(panel_get_new_x25519)"
    ensure_success "${keys_resp}" "getNewX25519Cert for final update"
    priv_key="$(jq -r '.obj.privateKey' <<<"${keys_resp}")"
    pub_key="$(jq -r '.obj.publicKey' <<<"${keys_resp}")"

    stream="$(jq -c \
      --arg priv "${priv_key}" \
      --arg pub "${pub_key}" \
      '
      .realitySettings = (.realitySettings // {}) |
      .realitySettings.privateKey = $priv |
      .realitySettings.settings = (.realitySettings.settings // {}) |
      .realitySettings.settings.publicKey = $pub
      ' <<<"${stream}")"
  else
    log "Keeping existing Reality cert/key pair to preserve client compatibility after restart."
  fi

  log "Saving inbound update and enabling inbound back ..."
  ensure_success "$(panel_update_inbound "${inbound_id}" true "${settings}" "${stream}" "${sniffing}")" "enable inbound with self-sni settings"

  persist_panel_info
  log "Provisioning completed."
  log "Panel: http://<server-ip>:${XUI_PORT}/${XUI_WEBPATH}"
  log "Dest: 127.0.0.1:${SELF_SNI_PORT}; SNI: ${SELF_SNI_DOMAIN}; Xver: 1"

  # Keep container alive and fail fast if one of core processes dies.
  while true; do
    if ! curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time 5 -sS -o /dev/null "${BASE_URL}/"; then
      log "ERROR: x-ui panel is not reachable"
      exit 1
    fi
    if ! pgrep nginx >/dev/null 2>&1; then
      log "ERROR: nginx process stopped"
      exit 1
    fi
    sleep 5
  done
}

main "$@"
