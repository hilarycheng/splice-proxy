#!/bin/sh
# 啟動 WireGuard
wg-quick up wg0

rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf

# 啟動你寫嘅 Proxy (用 exec 確保佢成為主進程)
exec /bin/sh -c 'cd /usr/local/bin && ./proxy-worker'
