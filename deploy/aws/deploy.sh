#!/bin/bash
# Build and (re)start Agent Guard Web on the instance. Run as root after bootstrap.sh:
#   sudo bash /opt/agentguard/deploy/aws/deploy.sh [domain]
# Without a domain it uses <public-ip-with-dashes>.sslip.io, which resolves to the
# instance's Elastic IP and gets a Let's Encrypt certificate like any other name.
# Safe to re-run: pulls the latest commit, rebuilds, keeps .env and the database.
set -euo pipefail

APP_DIR="/opt/agentguard"
HERE="$APP_DIR/deploy/aws"
ENV_FILE="$HERE/.env"
COMPOSE=(docker compose -f "$HERE/compose.prod.yaml")

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -f /var/lib/agentguard-bootstrap.done ] || { echo "bootstrap.sh has not finished; see /var/log/agentguard-bootstrap.log" >&2; exit 1; }

git -C "$APP_DIR" pull --ff-only

public_ip() {
  local token
  token="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
  curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/public-ipv4
}

if [ ! -f "$ENV_FILE" ]; then
  domain="${1:-}"
  if [ -z "$domain" ]; then
    ip="$(public_ip)"
    domain="${ip//./-}.sslip.io"
  fi
  umask 077
  cat > "$ENV_FILE" <<EOF
# Generated on the instance by deploy.sh. Never commit or copy this file.
DOMAIN=$domain
AGW_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
DOCKER_GID=$(getent group docker | cut -d: -f3)
AGW_DOCKER_RUNTIME=runsc
# Optional: a fine-grained GitHub token with no permissions raises the API rate limit.
AGW_GITHUB_TOKEN=
EOF
  echo "wrote $ENV_FILE for $domain"
elif [ -n "${1:-}" ]; then
  sed -i "s|^DOMAIN=.*|DOMAIN=$1|" "$ENV_FILE"
fi
domain="$(grep '^DOMAIN=' "$ENV_FILE" | cut -d= -f2)"

echo "== building images (a few minutes on a t4g.small)"
docker build -f "$APP_DIR/web/docker/scanner.Dockerfile" -t agentguard-scanner:local "$APP_DIR"
docker build -f "$APP_DIR/web/docker/server.Dockerfile" -t agentguard-web:local "$APP_DIR"

echo "== checking the scanner sandbox (gVisor, no network)"
docker info --format '{{json .Runtimes}}' | grep -q runsc || { echo "gVisor (runsc) is not registered with Docker" >&2; exit 1; }
"${COMPOSE[@]}" --env-file "$ENV_FILE" run --rm -T --no-deps dispatcher check-sandbox | tee /dev/stderr | grep -qx NO-EGRESS \
  || { echo "check-sandbox did not print NO-EGRESS; not starting" >&2; exit 1; }

echo "== starting services"
"${COMPOSE[@]}" --env-file "$ENV_FILE" up -d --remove-orphans
docker image prune -f >/dev/null

# Daily report pruning (AGW_RETENTION_DAYS, default 90).
cat > /etc/systemd/system/agentguard-prune.service <<EOF
[Unit]
Description=Agent Guard Web: delete old reports
[Service]
Type=oneshot
ExecStart=/usr/bin/docker compose -f $HERE/compose.prod.yaml --env-file $ENV_FILE run --rm -T dispatcher prune
EOF
cat > /etc/systemd/system/agentguard-prune.timer <<'EOF'
[Unit]
Description=Agent Guard Web: daily report pruning
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now agentguard-prune.timer

echo "== waiting for https://$domain/api/health (first start fetches a certificate)"
for _ in $(seq 1 30); do
  if curl -fsS "https://$domain/api/health" >/dev/null 2>&1; then
    echo "up: https://$domain/api/health"
    echo "Vercel rewrite destination: https://$domain/api/:path*"
    exit 0
  fi
  sleep 5
done
echo "not reachable over HTTPS yet; check: ${COMPOSE[*]} logs caddy api" >&2
exit 1
