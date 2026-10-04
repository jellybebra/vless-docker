#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
repo_path="$PWD"
# shellcheck source=proton-routing.sh
source ./proton-routing.sh
task_tmp="$(mktemp -d)"
trap 'rm -rf -- "$task_tmp"' EXIT
test_key="$(openssl rand -base64 32)"
cat > "$task_tmp/proton.conf" <<EOF
# Synthetic credentials, never connects to a real VPN.
[Interface]
PrivateKey = $test_key
Address = 10.2.0.2/32, fd00::2/128
DNS = 10.2.0.1
MTU = 1280
PostUp = touch $task_tmp/hook-executed
[Peer]
PublicKey = $test_key
PresharedKey = $test_key
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
# Real downloads often use Windows line endings and no final newline.
sed 's/$/\r/' "$task_tmp/proton.conf" > "$task_tmp/crlf.conf"
proton="$(build_proton_outbound "$task_tmp/proton.conf")"
[[ "$proton" == "$(build_proton_outbound "$task_tmp/crlf.conf")" ]]
printf '%s' "$(cat "$task_tmp/proton.conf")" > "$task_tmp/no-newline.conf"
[[ "$proton" == "$(build_proton_outbound "$task_tmp/no-newline.conf")" ]]
sed -e '/^MTU =/d' -e '/^PersistentKeepalive =/d' -e '/^PresharedKey =/d' \
  -e 's/, fd00::2\/128//' -e 's/, ::\/0//' "$task_tmp/proton.conf" > "$task_tmp/ipv4.conf"
jq -e '.settings.mtu == 1280 and .settings.address == ["10.2.0.2/32"] and
  .settings.peers[0].keepAlive == 0 and (.settings.peers[0] | has("preSharedKey") | not)' \
  <<< "$(build_proton_outbound "$task_tmp/ipv4.conf")" >/dev/null
[[ ! -e "$task_tmp/hook-executed" ]]
jq -e '.protonDNS == ["10.2.0.1"] and .settings.noKernelTun and
  .settings.peers[0].keepAlive == 25 and .settings.peers[0].preSharedKey != null' <<< "$proton" >/dev/null

reject_config() {
  if build_proton_outbound "$1" > "$task_tmp/rejected.json" 2> "$task_tmp/error"; then
    printf 'FAIL: accepted invalid config\n' >&2
    exit 1
  fi
  [[ ! -s "$task_tmp/rejected.json" ]]
  if grep -Fq "$test_key" "$task_tmp/error"; then
    printf 'FAIL: error disclosed credentials\n' >&2
    exit 1
  fi
}
reject_config "$task_tmp/missing.conf"
for replacement in 'PrivateKey = broken' 'Address = 999.2.0.2/32' \
  'DNS = dns.example.com' 'DNS = fd00::1' 'AllowedIPs = 10.0.0.0/8' \
  'Endpoint = 192.0.2.1:70000' 'MTU = 1500' 'PersistentKeepalive = nope'; do
  directive="${replacement%% =*}"
  sed "s|^$directive =.*|$replacement|" "$task_tmp/proton.conf" > "$task_tmp/invalid.conf"
  reject_config "$task_tmp/invalid.conf"
done
cat "$task_tmp/proton.conf" > "$task_tmp/two-peers.conf"
printf '\n[Peer]\n' >> "$task_tmp/two-peers.conf"
reject_config "$task_tmp/two-peers.conf"

base='{"outbounds":[{"tag":"warp","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],"dns":{"tag":"existing-dns","hosts":{"example.org":"192.0.2.2"},"servers":["1.1.1.1"]},"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["domain:example.org"],"outboundTag":"warp"},{"type":"field","network":"tcp,udp","outboundTag":"warp"}]}}'
updated="$(build_task_routing "$base" "$proton")"
[[ "$updated" == "$(build_task_routing "$updated" "$proton")" ]]
jq -e '
  ([.outbounds[] | select(.tag == "proton-openai")] | length) == 1 and
  (.outbounds[] | select(.tag == "proton-openai") | has("protonDNS") | not) and
  .routing.rules[0].outboundTag == "api" and
  .routing.rules[1].inboundTag == ["proton-openai-dns"] and
  .routing.rules[2].ip == ["geoip:ru"] and
  .routing.rules[5].outboundTag == "proton-openai" and
  .routing.rules[6].domain == ["domain:example.org"] and
  .routing.rules[-1].outboundTag == "direct" and
  .dns.servers[0].address == "10.2.0.1" and .dns.servers[0].finalQuery and
  .dns.servers[-1] == "1.1.1.1" and .dns.tag == "existing-dns" and
  .dns.hosts["example.org"] == "192.0.2.2"
' <<< "$updated" >/dev/null
disabled="$(build_task_routing "$updated" null)"
[[ "$disabled" == "$(build_task_routing "$disabled" null)" ]]
jq -e '[.outbounds[].tag] | index("proton-openai") | not' <<< "$disabled" >/dev/null
jq -e '.dns.servers == ["1.1.1.1"] and .routing.rules[-2].domain == ["domain:example.org"]' <<< "$disabled" >/dev/null
warp_enabled="$(build_task_routing "$updated" "$proton" warp)"
jq -e '.routing.rules[-1].outboundTag == "warp"' <<< "$warp_enabled" >/dev/null
[[ "$updated" == "$(build_task_routing "$warp_enabled" "$proton")" ]]
no_dns="$(build_task_routing '{"outbounds":[],"routing":{}}' "$proton")"
jq -e '.dns.servers[-1] == "localhost"' <<< "$no_dns" >/dev/null

# Check the actual version of Xray bundled with the project's pinned image.
if [[ -x /app/bin/xray-linux-amd64 ]]; then
  jq '.api = {tag:"api", services:["HandlerService"]} |
      .inbounds = [{tag:"api", listen:"127.0.0.1", port:18081,
                    protocol:"dokodemo-door", settings:{address:"127.0.0.1"}}]' \
    <<< "$updated" > "$task_tmp/xray.json"
  /app/bin/xray-linux-amd64 run -test -config "$task_tmp/xray.json"
fi

# Existing-deployment command must never reset credentials or add clients.
export XUI_USERNAME=test XUI_PASSWORD=test XUI_WEBPATH=test SELF_SNI_DOMAIN=example.org
unset PROTON_WG_CONFIG
cd "$task_tmp"
# shellcheck source=entrypoint.sh
source "$repo_path/entrypoint.sh"
if PROTON_WG_CONFIG="$task_tmp/missing.conf" bash "$repo_path/entrypoint.sh" --routing-only \
    > "$task_tmp/preflight.log" 2>&1; then
  printf 'FAIL: missing config did not stop provisioning\n' >&2
  exit 1
fi
grep -q 'PROTON_WG_CONFIG must be a readable' "$task_tmp/preflight.log"
# Default provisioning must not attempt WARP registration, even if no WARP exists.
printf '%s\n' '{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"blocked","protocol":"blackhole"}],"routing":{"rules":[]}}' > "$task_tmp/panel-template.json"
panel_get_xray_setting() {
  jq -cn --argjson template "$(cat "$task_tmp/panel-template.json")" \
    '{success:true,obj:({xraySetting:$template,outboundTestUrl:"https://example.org"}|tojson)}'
}
panel_update_xray_setting() {
  printf '%s\n' "$1" > "$task_tmp/panel-template.json"
  printf '%s\n' '{"success":true}'
}
docker() { printf 'FAIL: disabled WARP called Docker\n' >&2; return 1; }
WARP_ENABLED=false
PROTON_OUTBOUND_JSON="$proton"
PROTON_WG_CONFIG="$task_tmp/proton.conf"
ensure_outbound_configuration
jq -e '.routing.rules[-1].outboundTag == "direct" and
  ([.outbounds[].tag] | index("warp") | not)' "$task_tmp/panel-template.json" >/dev/null
ensure_outbound_configuration
wait_for_panel() { :; }
login_panel() { :; }
docker() { [[ "$*" == 'compose restart vless' ]]; }
ensure_subscription_urls() { printf 'FAIL: subscriptions changed\n' >&2; return 1; }
panel_add_inbound() { printf 'FAIL: new inbound created\n' >&2; return 1; }
main --routing-only
printf 'PASS: parsing, invalid inputs, routing/DNS, preservation, enable/disable and routing-only\n'
