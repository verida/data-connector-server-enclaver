#!/bin/sh

# Set up networking
ulimit -n 65536

# Setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

update-alternatives --set iptables /usr/sbin/iptables-legacy

# adding a default route
ip route add default via 127.0.0.1 dev lo
route -n

# iptables rules to route traffic to transparent proxy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:1200
iptables -t nat -A POSTROUTING -o lo -s 0.0.0.0 -j SNAT --to-source 127.0.0.1
iptables -L -t nat

# Generate identity key
/app/keygen --secret /app/id.sec --public /app/id.pub

sleep 3 && apt-get update && apt-get install -y git &
sleep 5 && cd /app/data-connector-server && yarn &

# opening port 1700
# /app/vsock-to-ip --vsock-addr 88:1700 --ip-addr 127.0.0.1:1700 &
# /app/secret_manager --ip-addr 127.0.0.1:1700 --private-key /app/id.sec --loader /app/keystore/key.pub --output /app/data-connector-server/src/serverconfig.local.json

# Start supervisord
cat /etc/supervisord.conf
/app/supervisord