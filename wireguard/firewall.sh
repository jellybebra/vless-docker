#!/bin/sh
# Runs in the wg-easy network namespace, never on the Docker host.
set -eu
action=${1:?up or down}
iface=${2:-wg0}
subnet=${3:?IPv4 subnet}
wan=${4:-eth0}
case "$iface:$wan" in wg0:eth0) ;; *) echo 'Unexpected interfaces' >&2; exit 1 ;; esac
case "$subnet" in *[!0-9./]*|'') echo 'Invalid subnet' >&2; exit 1 ;; esac
chain=WG_EASY_EGRESS

if [ "$action" = up ]; then
  iptables -w -N "$chain" 2>/dev/null || iptables -w -S "$chain" >/dev/null
  iptables -w -C "$chain" -j DROP 2>/dev/null || iptables -w -A "$chain" -j DROP
  # Keep blocking attached before changing rules; a failure must not open egress.
  iptables -w -C FORWARD -i "$iface" -j "$chain" 2>/dev/null || iptables -w -I FORWARD 1 -i "$iface" -j "$chain"
  iptables -w -C INPUT -i "$iface" -j DROP 2>/dev/null || iptables -w -I INPUT 1 -i "$iface" -j DROP
  # Insert accept before the final drop, then insert destination denies ahead of it.
  iptables -w -C "$chain" -s "$subnet" -o "$wan" -j ACCEPT 2>/dev/null || iptables -w -I "$chain" 1 -s "$subnet" -o "$wan" -j ACCEPT
  for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3; do
    iptables -w -C "$chain" -d "$net" -j DROP 2>/dev/null || iptables -w -I "$chain" 1 -d "$net" -j DROP
  done
  iptables -w -C FORWARD -i "$wan" -o "$iface" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -w -I FORWARD 1 -i "$wan" -o "$iface" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -w -t nat -C POSTROUTING -s "$subnet" -o "$wan" -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -s "$subnet" -o "$wan" -j MASQUERADE
elif [ "$action" = down ]; then
  iptables -w -D FORWARD -i "$iface" -j "$chain" 2>/dev/null || true
  iptables -w -D INPUT -i "$iface" -j DROP 2>/dev/null || true
  iptables -w -D FORWARD -i "$wan" -o "$iface" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -w -t nat -D POSTROUTING -s "$subnet" -o "$wan" -j MASQUERADE 2>/dev/null || true
  iptables -w -F "$chain" 2>/dev/null || true
  iptables -w -X "$chain" 2>/dev/null || true
else
  echo 'Expected up or down' >&2
  exit 1
fi
