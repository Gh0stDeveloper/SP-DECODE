#!/usr/bin/env bash
# Ubuntu/Debian SP-DECODE Cloud first deployment: root, domain required.
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
fail(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo "[spdecode installer] $*"; }
[[ $(id -u) -eq 0 ]] || fail "sudo/root required"
# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || fail "Ubuntu/Debian only"
DOMAIN="" EMAIL="" REF="feat/cloud-c8-vps-installer-updater" ADMIN_CIDR=""
REPO_URL="https://github.com/Gh0stDeveloper/SP-DECODE.git"
while (($#)); do
  case "$1" in
    --domain) DOMAIN="$2";shift 2;;
    --email) EMAIL="$2";shift 2;;
    --ref) REF="$2";shift 2;;
    --admin-cidr) ADMIN_CIDR="$2";shift 2;;
    --repo-ssh) REPO_URL="git@github.com:Gh0stDeveloper/SP-DECODE.git";shift;;
    *) fail "Unknown option: $1";;
  esac
done
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{1,250})[A-Za-z0-9]$ &&
  "$DOMAIN" == *.* && "$DOMAIN" != *..* ]] || fail "--domain is required and must resolve to this VPS"
[[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || fail "--email required"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ && "$REF" != -* && "$REF" != *..* ]] || fail "Invalid --ref"
[[ ! -e /etc/spdecode/install.conf ]] || fail "Already installed; use spdecode update"
log "Checking DNS"
[[ -n $(getent ahostsv4 "$DOMAIN" || true) ]] || fail "Domain has no A DNS record"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg git python3 jq unzip nginx certbot openssl
if ! docker compose version >/dev/null 2>&1; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod 0644 /etc/apt/keyrings/docker.gpg
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker nginx
install -d -m 0700 /etc/spdecode /opt/spdecode /opt/spdecode/backups /opt/spdecode/builds
[[ ! -e /opt/spdecode/repo ]] || fail "Checkout already exists; won't overwrite"
git clone --depth 1 --branch "$REF" -- "$REPO_URL" /opt/spdecode/repo
test -f /opt/spdecode/repo/cloud/compose.yaml || fail "Missing Cloud compose"
printf 'SPDECODE_REF=%q\nSPDECODE_REPO_URL=%q\n' "$REF" "$REPO_URL" > /etc/spdecode/install.conf
cat > /etc/spdecode/cloud.env <<EOC
CLOUD_API_ENABLED=false
CLOUD_ADMIN_ENABLED=false
CLOUD_TRUST_PROXY=true
CLOUD_FORCE_MAINTENANCE=true
CLOUD_PUBLIC_SITE_INDEX=false
CLOUD_SITE_PUBLIC_ORIGIN=https://$DOMAIN
CLOUD_ADMIN_PUBLIC_ORIGIN=https://$DOMAIN
CLOUD_GOOGLE_PLAY_PACKAGE=com.ghostdeveloper.spdecode
CLOUD_WORKER_TOKEN=$(openssl rand -hex 32)
CLOUD_SESSION_SIGNING_KEY=$(openssl rand -hex 32)
CLOUD_ADMIN_SESSION_KEY=$(openssl rand -hex 32)
CLOUD_EHI_IMPORT_ENABLED=false
CLOUD_NUR_FETCH_ENABLED=false
EOC
chmod 600 /etc/spdecode/install.conf /etc/spdecode/cloud.env
printf '%s\n' "$DOMAIN" > /etc/spdecode/domain
chmod 600 /etc/spdecode/domain
install -m 0755 /opt/spdecode/repo/cloud/infra/vps/spdecodectl /usr/local/bin/spdecode
install -d -m 0755 /var/www/spdecode-acme/.well-known/acme-challenge
cat >/etc/nginx/sites-available/spdecode.conf <<EOC
server {
  listen 80;
  server_name $DOMAIN;
  root /var/www/spdecode-acme;
  location ^~ /.well-known/acme-challenge/ { try_files \$uri =404; }
  location / { return 404; }
}
EOC
ln -sf /etc/nginx/sites-available/spdecode.conf /etc/nginx/sites-enabled/spdecode.conf
nginx -t && systemctl reload nginx
log "Requesting HTTPS certificate for $DOMAIN; open inbound TCP 80/443"
certbot certonly --webroot --non-interactive --agree-tos --email "$EMAIL" \
   -w /var/www/spdecode-acme -d "$DOMAIN" ||
   fail "Let's Encrypt failed; check DNS, 80/443 and cloud firewall / NSG"
if [[ -n "$ADMIN_CIDR" ]]; then
  python3 /opt/spdecode/repo/cloud/infra/vps/nginx-config.py "$DOMAIN" "$ADMIN_CIDR" \
   > /etc/nginx/sites-available/spdecode.conf
else
  python3 /opt/spdecode/repo/cloud/infra/vps/nginx-config.py "$DOMAIN" \
   > /etc/nginx/sites-available/spdecode.conf
fi
nginx -t && systemctl reload nginx
systemctl enable --now certbot.timer 2>/dev/null || true
# Keep session and admin disabled; enabling requires actual Play configuration.
cd /opt/spdecode/repo
docker compose --project-name spdecode --env-file /etc/spdecode/cloud.env \
 -f cloud/compose.yaml config --quiet
docker compose --project-name spdecode --env-file /etc/spdecode/cloud.env \
 -f cloud/compose.yaml up -d --build
log "Installed. API and admin disabled, maintenance enabled. Do not publish until C7/C8 approval."
spdecode status
