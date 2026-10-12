#!/usr/bin/env bash
# Run on a NEW dedicated Ubuntu 24.04 server after uploading the release and env.
set -euo pipefail
test "$EUID" -eq 0 || { echo 'Run as root'; exit 1; }
release_dir="${1:?Absolute release directory required}"
public_ip="${2:?Static public IPv4 required}"
[[ "$release_dir" == /opt/kiro-console/releases/* ]] || exit 1
[[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
test -f /etc/kiro-console/app.env
test -f /etc/kiro-console/backup.env
test -f "$release_dir/frontend/dist/index.html"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv nginx ca-certificates
if ! id kiro-console >/dev/null 2>&1; then
    useradd --system --home /var/lib/kiro-console --shell /usr/sbin/nologin kiro-console
fi
install -d -m 700 -o kiro-console -g kiro-console /var/lib/kiro-console
install -d -m 700 -o root -g root /var/lib/kiro-console/backup-work
chmod 600 /etc/kiro-console/*.env
python3 -m venv /opt/kiro-console/venv
/opt/kiro-console/venv/bin/pip install --disable-pip-version-check -q -r "$release_dir/backend/requirements.lock"
install -d -m 755 /opt/kiro-console/browsers
PLAYWRIGHT_BROWSERS_PATH=/opt/kiro-console/browsers /opt/kiro-console/venv/bin/python -m playwright install --with-deps chromium
ln -sfn "$release_dir" /opt/kiro-console/current
# Environment files are generated with shell-safe base64 / alphanumeric values.
set -a
source /etc/kiro-console/app.env
if test -f /etc/kiro-console/bootstrap.env; then source /etc/kiro-console/bootstrap.env; fi
set +a
cd "$release_dir/backend"
/opt/kiro-console/venv/bin/python -m app.init_db
chown kiro-console:kiro-console /var/lib/kiro-console/console.db*
rm -f /etc/kiro-console/bootstrap.env
install -m 644 "$release_dir"/deploy/kiro-*.service /etc/systemd/system/
install -m 644 "$release_dir"/deploy/kiro-*.timer /etc/systemd/system/
install -d -m 755 /var/www/acme
cat > /etc/nginx/sites-available/kiro-console <<'NGINX'
server {
    listen 80 default_server;
    server_name _;
    location ^~ /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 503; }
}
NGINX
rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/kiro-console /etc/nginx/sites-enabled/kiro-console
nginx -t
systemctl enable --now nginx
systemctl reload nginx
python3 -m venv /opt/kiro-console/certbot
/opt/kiro-console/certbot/bin/pip install --disable-pip-version-check -q 'certbot>=5.4,<6'
/opt/kiro-console/certbot/bin/certbot certonly --non-interactive --agree-tos --register-unsafely-without-email --preferred-profile shortlived --webroot --webroot-path /var/www/acme --ip-address "$public_ip" --cert-name kiro-console --deploy-hook '/usr/bin/systemctl reload nginx'
sed "s/__PUBLIC_IP__/$public_ip/g" "$release_dir/deploy/nginx.conf.template" > /etc/nginx/sites-available/kiro-console
nginx -t
systemctl reload nginx
systemctl daemon-reload
systemctl enable --now kiro-console kiro-worker kiro-auth-worker kiro-backup.timer kiro-cert-renew.timer
systemctl start kiro-backup.service
systemctl --no-pager --full status kiro-console kiro-worker kiro-auth-worker kiro-backup.timer kiro-cert-renew.timer
