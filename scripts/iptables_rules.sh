#!/bin/sh

IFACE="${1:-wlan0}"

sysctl -w net.ipv4.ip_forward=1
iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
iptables -t nat -I POSTROUTING --out-interface "$IFACE" -j MASQUERADE
iptables -I FORWARD --in-interface "$IFACE" --out-interface tun0 -j ACCEPT
iptables -I FORWARD --in-interface tun0 --out-interface "$IFACE" -j ACCEPT
