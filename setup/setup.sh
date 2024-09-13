#!/bin/sh

# Set up networking
ulimit -n 65536

# Setting an address for loopback
ifconfig lo 127.0.0.1
ifconfig

# Adding a default route
ip route add default via 127.0.0.1 dev lo
route -n

# iptables rules to route traffic to transparent proxy
iptables -A OUTPUT -t nat -p tcp --dport 1:65535 ! -d 127.0.0.1  -j DNAT --to-destination 127.0.0.1:1200
iptables -t nat -A POSTROUTING -o lo -s 0.0.0.0 -j SNAT --to-source 127.0.0.1
iptables -L -t nat

# Generate identity key
/app/keygen --secret /app/id.sec --public /app/id.pub

# Set up Django environment
export DJANGO_SETTINGS_MODULE=api.settings

# Navigate to the Django project directory
cd /app/server

# Apply database migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Start supervisord
cat /etc/supervisord.conf
/app/supervisord