#!/usr/bin/env bash
# Sourced by entrypoint.sh; never execute directives from a WireGuard file.

trim_wg_value() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

build_proton_outbound() {
  local config="$1" line section="" key value peer_count=0
  local private_key="" address="" dns="" mtu=1280
  local public_key="" endpoint="" allowed_ips="" preshared_key="" keepalive=0
  if [[ ! -r "$config" || ! -f "$config" ]]; then
    printf 'ERROR: PROTON_WG_CONFIG must be a readable WireGuard .conf file.\n' >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line%%#*}"
    line="${line%%;*}"
    line="$(trim_wg_value "$line")"
    [[ -n "$line" ]] || continue
    if [[ "$line" == '[Interface]' ]]; then
      section=interface
      continue
    elif [[ "$line" == '[Peer]' ]]; then
      section=peer
      peer_count=$((peer_count + 1))
      continue
    elif [[ "$line" == '['* ]]; then
      printf 'ERROR: Unsupported WireGuard section.\n' >&2
      return 1
    fi
    [[ "$line" == *=* ]] || { printf 'ERROR: Invalid WireGuard directive.\n' >&2; return 1; }
    key="$(trim_wg_value "${line%%=*}")"
    value="$(trim_wg_value "${line#*=}")"
    case "$section:$key" in
      interface:PrivateKey) private_key="$value" ;;
      interface:Address) address="${address:+$address,}$value" ;;
      interface:DNS) dns="${dns:+$dns,}$value" ;;
      interface:MTU) mtu="$value" ;;
      peer:PublicKey) public_key="$value" ;;
      peer:Endpoint) endpoint="$value" ;;
      peer:AllowedIPs) allowed_ips="${allowed_ips:+$allowed_ips,}$value" ;;
      peer:PresharedKey) preshared_key="$value" ;;
      peer:PersistentKeepalive) keepalive="$value" ;;
      # wg-quick options (including shell hooks) are intentionally not executed.
    esac
  done < "$config"
  if ((peer_count != 1)) || [[ -z "$address" || -z "$dns" || -z "$allowed_ips" || -z "$endpoint" ]]; then
    printf 'ERROR: Expected one WireGuard peer, Address, DNS, AllowedIPs and Endpoint.\n' >&2
    return 1
  fi
  if ! [[ "$private_key" =~ ^[A-Za-z0-9+/]{43}=$ && "$public_key" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
     { [[ -n "$preshared_key" ]] && ! [[ "$preshared_key" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }; then
    printf 'ERROR: Invalid WireGuard key (expected a base64-encoded 32-byte key).\n' >&2
    return 1
  fi
  if ! [[ "$mtu" =~ ^[0-9]+$ && "$keepalive" =~ ^[0-9]+$ ]]; then
    printf 'ERROR: WireGuard MTU and PersistentKeepalive must be integers.\n' >&2
    return 1
  fi
  jq -cen --arg secret "$private_key" --arg address "$address" --arg dns "$dns" \
    --arg public "$public_key" --arg endpoint "$endpoint" --arg allowed "$allowed_ips" \
    --arg psk "$preshared_key" --arg mtu "$mtu" --arg keepalive "$keepalive" '
    def items: split(",") | map(gsub("^\\s+|\\s+$"; "")) | unique;
    def ipv4: split(".") | length == 4 and all(.[]; test("^[0-9]{1,3}$") and (tonumber <= 255));
    def ip: if contains(":") then test("^[0-9a-fA-F:]+$") else ipv4 end;
    def cidr: split("/") | length == 2 and (.[0] | ip) and
      (.[1] | test("^[0-9]+$")) and (.[1] | tonumber) <= (if .[0] | contains(":") then 128 else 32 end);
    ($address | items) as $addresses | ($dns | items) as $dns_ips |
    ($allowed | items) as $allowed_ips |
    if ($mtu | tonumber) < 1280 or ($mtu | tonumber) > 1420 or
       ($keepalive | tonumber) > 65535 or
       ($addresses | all(.[]; cidr) | not) or ($dns_ips | all(.[]; ip) | not) or
       ($addresses | any(.[]; contains(":") | not) | not) or
       ($dns_ips | any(.[]; contains(":") | not) | not) or
       ($allowed_ips | all(.[]; cidr) | not) or
       ($allowed_ips | index("0.0.0.0/0") | not) or
       ($endpoint | test("^(\\[[0-9a-fA-F:]+\\]|[A-Za-z0-9_.-]+):[0-9]+$") | not) or
       ($endpoint | split(":") | last | tonumber) < 1 or
       ($endpoint | split(":") | last | tonumber) > 65535
    then error("Invalid WireGuard addresses, DNS, endpoint, MTU, keepalive or IPv4 default route")
    else {
      tag: "proton-openai", protocol: "wireguard",
      settings: {
        secretKey: $secret, address: $addresses, mtu: ($mtu | tonumber),
        noKernelTun: true, domainStrategy: "ForceIPv4",
        peers: [{publicKey: $public, endpoint: $endpoint, allowedIPs: $allowed_ips,
          keepAlive: ($keepalive | tonumber)} +
          (if $psk != "" then {preSharedKey: $psk} else {} end)]
      }
    } + {protonDNS: $dns_ips} end'
}

build_task_routing() {
  local xray_setting="$1" proton_outbound="$2" fallback_tag="${3:-direct}"
  jq -ce --argjson proton "$proton_outbound" --arg fallback_tag "$fallback_tag" '
    [
      {type:"field", inboundTag:["api"], outboundTag:"api"},
      {type:"field", ip:["geoip:ru"], outboundTag:"blocked"},
      {type:"field", ip:["geoip:private"], outboundTag:"blocked"},
      {type:"field", protocol:["bittorrent"], outboundTag:"blocked"}
    ] as $base |
    {type:"field", network:"tcp,udp", outboundTag:$fallback_tag} as $fallback |
    [{type:"field", network:"tcp,udp", outboundTag:"warp"},
     {type:"field", network:"tcp,udp", outboundTag:"direct"}] as $old_fallbacks |
    ["domain:chatgpt.com", "domain:openai.com", "domain:oaistatic.com",
     "domain:oaiusercontent.com", "domain:chat.com"] as $openai_domains |
    # Preserve custom rules; replace only the rules managed by this provisioner.
    [.routing.rules[]? | select(. as $rule |
      ($base | index($rule)) == null and ($old_fallbacks | index($rule)) == null and
      .outboundTag != "proton-openai")
    ] as $custom |
    .outbounds = ([.outbounds[]? | select(.tag != "proton-openai")] +
      (if $proton == null then [] else [$proton | del(.protonDNS)] end)) |
    if $fallback_tag == "direct" and ([.outbounds[].tag] | index("direct")) == null then
      .outbounds = [{tag:"direct", protocol:"freedom"}] + .outbounds
    else . end |
    # Xray 26.6.1 (bundled with 3x-ui 3.2.5) resolves WireGuard targets
    # through built-in DNS; it does not support the newer remoteDNS option.
    if .dns != null or $proton != null then
      .dns = (.dns // {}) |
      .dns.servers = ([.dns.servers[]? | select(
        if type == "object" then .tag != "proton-openai-dns" else true end)]) |
      if $proton != null then
        .dns.servers = ([$proton.protonDNS[] | select(contains(":") | not) |
          {address:., domains:$openai_domains, skipFallback:true, finalQuery:true,
           queryStrategy:"UseIPv4", tag:"proton-openai-dns"}] +
          (if (.dns.servers | length) == 0 then ["localhost"] else .dns.servers end))
      else . end
    else . end |
    .routing = (.routing // {}) |
    .routing.rules = ([$base[0]] + (if $proton == null then [] else
      [{type:"field", inboundTag:["proton-openai-dns"], network:"tcp,udp",
        outboundTag:"proton-openai"}]
    end) + $base[1:] + (if $proton == null then [] else
      [{type:"field", domain:$openai_domains, network:"tcp,udp", outboundTag:"proton-openai"}]
    end) + $custom + [$fallback])
  ' <<< "$xray_setting"
}
