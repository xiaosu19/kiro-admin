#!/usr/bin/env bash
# DNS must already point to this server. Reuses the installed renewal timer.
set -euo pipefail
test "$EUID" -eq 0 || { echo 'Run as root'; exit 1; }
domain="${1:?Domain required}"
public_ip="${2:?Static IPv4 required}"
[[ "$domain" =~ ^[a-z0-9][a-z0-9.-]+\.[a-z]+$ ]] || exit 1
[[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
config=/etc/nginx/sites-available/kiro-console
test -f "$config"
test -x /opt/kiro-console/certbot/bin/certbot
/opt/kiro-console/certbot/bin/certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --webroot --webroot-path /var/www/acme --domain "$domain" --cert-name kiro-console-domain --deploy-hook '/usr/bin/systemctl reload nginx'
cp -p "$config" "$config.before-domain"
sed -e "s/__DOMAIN__/$domain/g" -e "s/__PUBLIC_IP__/$public_ip/g" /opt/kiro-console/current/deploy/nginx-domain.conf.template > "$config"
if ! nginx -t; then
    cp -p "$config.before-domain" "$config"
    exit 1
fi
systemctl reload nginx
systemctl enable --now kiro-cert-renew.timer
systemctl is-active nginx kiro-console kiro-worker kiro-cert-renew.timer
