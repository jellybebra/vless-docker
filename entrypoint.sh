#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

# Load environment variables from .env on the host
if [[ -f .env ]]; then
  log "Loading environment variables from .env ..."
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ ! "$line" =~ ^# ]] && [[ "$line" =~ = ]]; then
      key="${line%%=*}"
      value="${line#*=}"
      value="${value#[\"\']}"
      value="${value%[\"\']}"
      export "$key=$value"
    fi
  done < .env
fi

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
REALITY_DEST="${REALITY_DEST:-traefik:8443}"
REALITY_XVER="${REALITY_XVER:-1}"

if ! [[ "${XUI_PORT}" =~ ^[0-9]+$ ]] || ((XUI_PORT < 1 || XUI_PORT > 65535)); then
  log "ERROR: XUI_PORT must be an integer in range 1..65535"
  exit 1
fi

if ! [[ "${REALITY_XVER}" =~ ^[0-9]+$ ]]; then
  log "ERROR: REALITY_XVER must be a non-negative integer"
  exit 1
fi

# Helper to run curl inside the Docker container
container_curl() {
  docker compose exec -T vless curl "$@"
}

# Helper to generate a UUID in a cross-platform way
generate_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import uuid; print(str(uuid.uuid4()))'
  else
    od -x -N 16 /dev/urandom | head -n 1 | awk '{print $2$3"-"$4"-"$5"-"$6"-"$7$8$9}'
  fi
}

BASE_URL="http://127.0.0.1:${XUI_PORT}/${XUI_WEBPATH}"
COOKIE_JAR="/tmp/xui_cookie.jar"
CSRF_TOKEN=""

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

wait_for_panel() {
  log "Waiting for x-ui panel on 127.0.0.1:${XUI_PORT} ..."
  for _ in $(seq 1 180); do
    for origin in "${PANEL_ORIGINS[@]}"; do
      if container_curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time 5 -sS -o /dev/null "${origin}/"; then
        return 0
      fi
    done
    sleep 1
  done
  log "ERROR: x-ui panel did not become ready"
  return 1
}

login_panel() {
  local payload resp origin url html token
  log "Trying panel login ..."
  payload="$(jq -cn --arg u "${XUI_USERNAME}" --arg p "${XUI_PASSWORD}" '{username:$u,password:$p}')"

  for origin in "${PANEL_ORIGINS[@]}"; do
    # Fetch login page first to get initial cookie and CSRF token if present
    html="$(container_curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" -s -c "${COOKIE_JAR}" "${origin}/${XUI_WEBPATH}/" || true)"
    token="$(echo "${html}" | sed -n 's/.*meta name="csrf-token" content="\([^"]*\)".*/\1/p' | tr -d ' \t\r\n')"
    
    if [[ -n "${token}" ]]; then
      log "CSRF Token detected: ${token}"
      CSRF_TOKEN="${token}"
    else
      log "No CSRF Token detected (possibly 2.x panel)."
      CSRF_TOKEN=""
    fi

    while IFS= read -r url; do
      local headers=(
        -H "Content-Type: application/json"
      )
      if [[ -n "${CSRF_TOKEN}" ]]; then
        headers+=( -H "X-CSRF-Token: ${CSRF_TOKEN}" )
      fi

      resp="$(
        container_curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" \
          -sS -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" -X POST "${url}" \
          "${headers[@]}" -d "${payload}" || true
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
  local headers=()
  if [[ -n "${CSRF_TOKEN:-}" ]]; then
    headers+=( -H "X-CSRF-Token: ${CSRF_TOKEN}" )
  fi
  container_curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" -sS -b "${COOKIE_JAR}" "${headers[@]}" -X POST "${BASE_URL}${endpoint}" "$@"
}

api_get() {
  local endpoint="$1"
  shift || true
  log "API GET ${endpoint}" >&2
  local headers=()
  if [[ -n "${CSRF_TOKEN:-}" ]]; then
    headers+=( -H "X-CSRF-Token: ${CSRF_TOKEN}" )
  fi
  container_curl --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" -sS -b "${COOKIE_JAR}" "${headers[@]}" "${BASE_URL}${endpoint}" "$@"
}

response_is_success() {
  local resp="${1:-}"
  [[ -n "${resp}" ]] && jq -e '.success == true' >/dev/null 2>&1 <<<"${resp}"
}



panel_get_new_x25519() {
  local resp
  resp="$(api_get "/panel/api/server/getNewX25519Cert" || true)"
  if response_is_success "${resp}"; then
    printf '%s\n' "${resp}"
    return 0
  fi
  printf '%s\n' "${resp}"
  return 1
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
          fingerprint: "firefox",
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
  local payload=(
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
    --data-urlencode "sniffing=${sniffing}" \
    --data-urlencode "nodeId=0"
  )
  local resp

  resp="$(api_post "/panel/api/inbounds/add" "${payload[@]}" || true)"
  if response_is_success "${resp}"; then
    printf '%s\n' "${resp}"
    return 0
  fi

  api_post "/panel/inbound/add" "${payload[@]}"
}


normalize_path_with_slashes() {
  local p="${1:-}"
  [[ -n "${p}" ]] || p="/"
  [[ "${p}" == /* ]] || p="/${p}"
  [[ "${p}" == */ ]] || p="${p}/"
  printf '%s\n' "${p}"
}

panel_get_settings() {
  api_post "/panel/setting/all"
}

panel_update_settings() {
  local settings_json="$1"
  api_post "/panel/setting/update" \
    -H "Content-Type: application/json" \
    -d "${settings_json}"
}

panel_get_xray_setting() {
  api_post "/panel/xray/"
}

panel_update_xray_setting() {
  local xray_setting_json="$1"
  local outbound_test_url="$2"
  api_post "/panel/xray/update" \
    --data-urlencode "xraySetting=${xray_setting_json}" \
    --data-urlencode "outboundTestUrl=${outbound_test_url}"
}

ensure_warp_configuration() {
  local xray_resp xray_payload xray_setting outbound_test_url
  local warp_exists updated_xray_setting update_resp

  log "Loading current Xray template settings ..."
  xray_resp="$(panel_get_xray_setting || true)"
  ensure_success "${xray_resp}" "get Xray settings"

  xray_payload="$(jq -c '.obj | fromjson' <<<"${xray_resp}")"
  xray_setting="$(jq -c '.xraySetting' <<<"${xray_payload}")"
  outbound_test_url="$(jq -r '.outboundTestUrl // "https://www.google.com/generate_204"' <<<"${xray_payload}")"

  # 1. Check if WARP outbound already exists
  warp_exists="$(jq -r '.outbounds[]? | select(.tag == "warp" and .protocol == "wireguard") | .tag' <<<"${xray_setting}")"

  if [[ -z "${warp_exists}" ]]; then
    log "WARP outbound not found. Registering a new free Cloudflare WARP account ..."
    
    # Generate X25519 keypair inside the container
    local tmp_pem="/tmp/warp_priv.pem"
    local priv_key pub_key
    docker compose exec -T vless sh -c "openssl genpkey -algorithm X25519 -out ${tmp_pem}"
    priv_key="$(docker compose exec -T vless sh -c "openssl pkey -in ${tmp_pem} -outform DER | tail -c 32 | base64" | tr -d ' \t\r\n')"
    pub_key="$(docker compose exec -T vless sh -c "openssl pkey -in ${tmp_pem} -pubout -outform DER | tail -c 32 | base64" | tr -d ' \t\r\n')"
    docker compose exec -T vless sh -c "rm -f ${tmp_pem}"

    if [[ -z "${priv_key}" ]] || [[ -z "${pub_key}" ]]; then
      log "ERROR: Failed to generate X25519 keypair inside the container"
      return 1
    fi

    # Register on Cloudflare API
    local warp_resp v4_addr v6_addr peer_pub_key
    warp_resp="$(
      docker compose exec -T vless curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"install_id\":\"\",\"key\":\"${pub_key}\",\"fcm_token\":\"\",\"tos\":\"2020-04-02T00:00:00.000+02:00\",\"model\":\"\",\"brand\":\"\",\"locale\":\"en_US\"}" \
        https://api.cloudflareclient.com/v0a2408/reg || true
    )"

    if ! jq -e '.config.peers[0].public_key' >/dev/null 2>&1 <<<"${warp_resp}"; then
      log "ERROR: Cloudflare WARP registration failed: ${warp_resp}"
      return 1
    fi

    v4_addr="$(jq -r '.config.interface.addresses.v4' <<<"${warp_resp}")"
    v6_addr="$(jq -r '.config.interface.addresses.v6' <<<"${warp_resp}")"
    peer_pub_key="$(jq -r '.config.peers[0].public_key' <<<"${warp_resp}")"

    log "Successfully registered WARP: v4=${v4_addr}, v6=${v6_addr}"

    # Inject the WARP outbound using JQ
    xray_setting="$(
      jq -c \
        --arg priv_key "${priv_key}" \
        --arg pub_key "${peer_pub_key}" \
        --arg v4 "${v4_addr}/32" \
        --arg v6 "${v6_addr}/128" \
        '
        .outbounds |= (. // []) |
        .outbounds += [{
          tag: "warp",
          protocol: "wireguard",
          settings: {
            secretKey: $priv_key,
            address: [$v4, $v6],
            peers: [{
              publicKey: $pub_key,
              endpoint: "162.159.192.1:2408"
            }],
            domainStrategy: "ForceIPv4"
          }
        }]
        ' <<<"${xray_setting}"
    )"
  else
    log "WARP outbound already configured."
  fi

  # 2. Re-arrange and enforce routing rules order strictly as per README:
  # 1. api -> api
  # 2. geoip:ru -> blocked
  # 3. geoip:private -> blocked
  # 4. bittorrent -> blocked
  # 5. TCP,UDP -> warp
  log "Enforcing Xray routing rules order strictly ..."
  updated_xray_setting="$(
    jq -c '
      .routing = (.routing // {}) |
      .routing.rules = [
        {
          type: "field",
          inboundTag: ["api"],
          outboundTag: "api"
        },
        {
          type: "field",
          ip: ["geoip:ru"],
          outboundTag: "blocked"
        },
        {
          type: "field",
          ip: ["geoip:private"],
          outboundTag: "blocked"
        },
        {
          type: "field",
          protocol: ["bittorrent"],
          outboundTag: "blocked"
        },
        {
          type: "field",
          network: "tcp,udp",
          outboundTag: "warp"
        }
      ]
    ' <<<"${xray_setting}"
  )"

  if [[ "$(jq -cS '.' <<<"${xray_setting}")" == "$(jq -cS '.' <<<"${updated_xray_setting}")" ]]; then
    log "Xray settings and routing rules are already in the correct state."
    return 0
  fi

  log "Applying updated Xray template settings (WARP outbound and routing rules) ..."
  update_resp="$(panel_update_xray_setting "${updated_xray_setting}" "${outbound_test_url}" || true)"
  ensure_success "${update_resp}" "update Xray settings"
}

ensure_subscription_urls() {
  local settings_resp settings_obj update_resp
  local desired_sub_path desired_sub_uri desired_subjson_path desired_subjson_uri

  desired_sub_path="$(normalize_path_with_slashes "${SUB_PATH:-/sub/}")"
  desired_sub_uri="${SUB_REVERSE_PROXY_URI:-https://${SELF_SNI_DOMAIN}${desired_sub_path}}"
  [[ "${desired_sub_uri}" == */ ]] || desired_sub_uri="${desired_sub_uri}/"

  desired_subjson_path="$(normalize_path_with_slashes "${SUB_JSON_PATH:-/json/}")"
  desired_subjson_uri="${SUB_JSON_REVERSE_PROXY_URI:-https://${SELF_SNI_DOMAIN}${desired_subjson_path}}"
  [[ "${desired_subjson_uri}" == */ ]] || desired_subjson_uri="${desired_subjson_uri}/"

  log "Loading current panel settings ..."
  settings_resp="$(panel_get_settings || true)"
  ensure_success "${settings_resp}" "get panel settings"

  settings_obj="$(jq -c '.obj' <<<"${settings_resp}")"

  log "Applying subscription URLs ..."
  settings_obj="$(
    jq -c \
      --arg sub_domain "${SELF_SNI_DOMAIN}" \
      --arg sub_path "${desired_sub_path}" \
      --arg sub_uri "${desired_sub_uri}" \
      --arg subjson_path "${desired_subjson_path}" \
      --arg subjson_uri "${desired_subjson_uri}" \
      '
      .subDomain   = $sub_domain   |
      .subPath     = $sub_path     |
      .subURI      = $sub_uri      |
      .subJsonPath = $subjson_path |
      .subJsonURI  = $subjson_uri
      ' <<<"${settings_obj}"
  )"

  update_resp="$(panel_update_settings "${settings_obj}" || true)"
  ensure_success "${update_resp}" "update subscription URLs"

  log "Subscription Reverse Proxy URI: ${desired_sub_uri}"
  log "Subscription JSON Reverse Proxy URI: ${desired_subjson_uri}"
}

main() {
  log "Ensuring vless container is running ..."
  docker compose up -d vless

  log "Ensuring curl, jq, and openssl are installed inside the container ..."
  docker compose exec -T vless apk add --no-cache curl jq openssl bash >/dev/null 2>&1 || true

  # Set up the base URL for curl commands inside the container
  BASE_URL="http://127.0.0.1:${XUI_PORT}/${XUI_WEBPATH}"

  log "Initializing settings inside the container..."
  
  # Run the x-ui setting command inside the container to configure port, credentials, and web path.
  docker compose exec -T vless /app/x-ui setting \
    -username "${XUI_USERNAME}" \
    -password "${XUI_PASSWORD}" \
    -port "${XUI_PORT}" \
    -webBasePath "${XUI_WEBPATH}" >/dev/null 2>&1 || true
  
  log "Restarting container to apply settings..."
  docker compose restart vless
  
  log "Waiting for panel to start up..."
  wait_for_panel
  
  log "Logging in..."
  login_panel

  ensure_subscription_urls
  ensure_warp_configuration

  log "Creating Reality inbound on port 443..."
  local keys_resp priv_key pub_key short_id client_id email sub_id settings stream sniffing

  keys_resp="$(panel_get_new_x25519)"
  ensure_success "${keys_resp}" "getNewX25519Cert"
  priv_key="$(jq -r '.obj.privateKey' <<<"${keys_resp}")"
  pub_key="$(jq -r '.obj.publicKey' <<<"${keys_resp}")"
  
  short_id="$(openssl rand -hex 8)"
  client_id="$(generate_uuid)"
  email="client-$(openssl rand -hex 4)"
  sub_id="$(openssl rand -hex 16)"
  
  settings="$(build_default_client_settings "${client_id}" "${email}" "${sub_id}")"
  stream="$(build_stream_settings "${REALITY_DEST}" "${SELF_SNI_DOMAIN}" "${REALITY_XVER}" "${priv_key}" "${pub_key}" "${short_id}")"
  sniffing="$(build_default_sniffing)"
  
  local add_inbound_resp
  add_inbound_resp="$(panel_add_inbound true "${settings}" "${stream}" "${sniffing}" || true)"
  if response_is_success "${add_inbound_resp}"; then
    log "Reality inbound on port 443 created successfully."
  else
    log "Reality inbound on port 443 creation skipped or failed (it might already exist)."
  fi

  log "Restarting container to apply all settings..."
  docker compose restart vless

  log "Provisioning completed."
  log "Panel (HTTPS): https://${SELF_SNI_DOMAIN}/${XUI_WEBPATH}"
}

main "$@"
