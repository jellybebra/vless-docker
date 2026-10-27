"""The Happ routing profile validated on iPhone; credentials come from 3x-ui."""

import base64
import json
from pathlib import Path
import socket
import urllib.parse
import uuid

PROFILE_NAMES = {
    "selective": "Заблокированное + YouTube без рекламы",
    "all-except-ru": "Всё, кроме РФ",
    "all": "Всё",
    "all-except-ru-youtube": "Всё, кроме РФ + YouTube без рекламы",
}
RU_DIRECT_SITES = [
    "geosite:category-ru", "geosite:tld-ru", "geosite:ru-available-only-inside",
]
RU_DIRECT_IP = ["geoip:ru"]

YOUTUBE = [
    "regexp:(^|\\.)youtube\\.[a-z.]+$",
    *["domain:" + d for d in (
        "googlevideo.com", "youtu.be", "yt.be", "ytimg.com", "ggpht.com",
        "youtube-nocookie.com", "youtubekids.com", "youtube.googleapis.com",
        "youtubei.googleapis.com", "youtubeembeddedplayer.googleapis.com",
        "wide-youtube.l.google.com", "youtube-ui.l.google.com",
    )],
    "full:yt3.googleusercontent.com",
]
DISCORD = ["domain:" + d for d in (
    "discord.com", "discord.gg", "discord.media", "discordapp.com",
    "discordapp.net", "discordcdn.com", "discord.co", "dis.gd",
    "discord.gift", "discord.gifts", "discordstatus.com", "discord.dev",
    "discord-activities.com", "discordactivities.com", "discordsays.com",
)] + ["full:discord-attachments-uploads-prd.storage.googleapis.com"]


def vless_outbound(subscription):
    text = subscription.strip()
    if not text.startswith("vless://"):
        text = base64.b64decode(text + "=" * (-len(text) % 4)).decode()
    links = [line.strip() for line in text.splitlines() if line.startswith("vless://")]
    if len(links) != 1:
        raise ValueError("Expected exactly one VLESS server; choose one URI explicitly.")
    uri = urllib.parse.urlsplit(links[0])
    params = urllib.parse.parse_qs(uri.query)
    value = lambda key, default="": params.get(key, [default])[0]
    if value("type", "tcp") != "tcp" or value("security") != "reality":
        raise ValueError("This builder supports VLESS TCP REALITY only.")
    user_id = str(uuid.UUID(uri.username or ""))
    if not uri.hostname or not uri.port or not value("pbk") or not value("sni"):
        raise ValueError("Missing server, port, REALITY public key or SNI.")
    # A static bootstrap prevents the VLESS endpoint needing its own tunneled DNS.
    addresses = socket.getaddrinfo(uri.hostname, uri.port, socket.AF_INET, socket.SOCK_STREAM)
    host_ip = addresses[0][4][0]
    outbound = {
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": uri.hostname, "port": uri.port,
            "users": [{"id": user_id, "encryption": "none", "flow": value("flow")}]}]},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "serverName": value("sni"), "fingerprint": value("fp", "chrome"),
                "publicKey": value("pbk"), "shortId": value("sid"),
                "spiderX": value("spx", "/"),
            },
        },
    }
    return outbound, {uri.hostname: host_ip}


def build(subscription, port=10808, *, mode="selective"):
    name = PROFILE_NAMES[mode]
    base = json.loads(Path(__file__).with_name("routing.json").read_text())
    proxy, hosts = vless_outbound(subscription)
    rule = lambda tag, **fields: {"type": "field", **fields, "outboundTag": tag}
    config = {
        "remarks": name,
        "log": {"loglevel": "warning"},
        "dns": {"hosts": hosts, "servers": ["https://1.1.1.1/dns-query"],
                "queryStrategy": "UseIPv4"},
        "inbounds": [{
            "tag": "socks", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                         "routeOnly": True},
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {},
             "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}},
            proxy,
            {"tag": "youtube-dpi", "protocol": "freedom",
             "settings": {"domainStrategy": "UseIPv4", "fragment": {
                 "packets": "tlshello", "length": "1-3", "interval": "1-2"}},
             "streamSettings": {"sockopt": {"tcpNoDelay": True}}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
            {"tag": "dns-out", "protocol": "dns", "settings": {}},
        ],
        "routing": {"domainStrategy": base["DomainStrategy"], "rules": [
            rule("dns-out", port="53", network="tcp,udp"),
            rule("direct", ip=base["DirectIp"]),
            rule("direct", domain=base["DirectSites"]),
            # Supercell's game protocol has no HTTP/TLS domain for sniffing.
            # Cover IP-only login/game traffic; private destinations stay direct.
            # Other apps connecting to this destination port also use the proxy.
            rule("proxy", network="tcp,udp", port="9339"),
            # TLS fragmentation cannot handle QUIC; sniffing may miss its domain.
            # Block UDP/443 even for IP-only traffic, after the direct exceptions.
            rule("block", network="udp", port="443"),
            rule("youtube-dpi", domain=YOUTUBE, network="tcp"),
            rule("proxy", domain=DISCORD),
            # IP-only Discord voice traffic cannot be matched by domain.
            # These ranges also affect other apps using the same UDP ports.
            rule("proxy", network="udp", port="19294-19344,50000-65535"),
            rule("proxy", ip=["1.1.1.1"] + base["ProxyIp"]),
            rule("proxy", domain=base["ProxySites"]),
            rule("direct", network="tcp,udp"),
        ]},
    }
    if mode != "selective":
        # Keep each JSON configuration self-contained. Happ's routing header
        # only supplies shared geo assets; it does not override these rules.
        youtube_direct = mode == "all-except-ru-youtube"
        outbound_tags = {"proxy", "direct", "dns-out"}
        if youtube_direct:
            outbound_tags.update(("youtube-dpi", "block"))
        config["outbounds"] = [
            out for out in config["outbounds"]
            if out["tag"] in outbound_tags
        ]
        direct_sites = ["geosite:private"]
        direct_ips = ["geoip:private"]
        if mode == "all-except-ru":
            direct_sites += RU_DIRECT_SITES
            direct_ips += RU_DIRECT_IP
        rules = [
            rule("dns-out", port="53", network="tcp,udp"),
            rule("direct", domain=direct_sites),
            rule("direct", ip=direct_ips),
        ]
        if youtube_direct:
            rules += [
                # Apply YouTube handling before Russia's IP exceptions: Google
                # video caches may be located in Russia. Private IPs stay direct.
                rule("block", domain=YOUTUBE, network="udp", port="443"),
                rule("youtube-dpi", domain=YOUTUBE, network="tcp"),
                rule("direct", domain=RU_DIRECT_SITES),
                # IP-only QUIC to Russian Google caches must not escape through
                # geoip:ru when sniffing misses the hostname. Keep private
                # destinations and recognized Russian domains above this rule.
                rule("block", network="udp", port="443"),
                rule("direct", ip=RU_DIRECT_IP),
            ]
        rules.append(rule("proxy", network="tcp,udp"))
        config["routing"] = {"domainStrategy": "IPOnDemand", "rules": rules}
    return config

