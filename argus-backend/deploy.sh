#!/usr/bin/env bash
# Deploy Argus memory backend to VPS (run from repo root or argus-backend/)
set -euo pipefail

REMOTE="${ARGUS_DEPLOY_HOST:-root@2.26.249.201}"
REMOTE_DIR="${ARGUS_DEPLOY_DIR:-/opt/argus-backend}"
DOMAIN="${ARGUS_MEMORY_DOMAIN:-argus.cloud.badkiko.ru}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> packaging argus-backend"
tar czf /tmp/argus-backend.tgz \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='.pytest_cache' \
  Dockerfile docker-compose.yml requirements.txt .env.example README.md app tests deploy.sh Caddyfile

echo "==> upload to $REMOTE:$REMOTE_DIR"
ssh "$REMOTE" "mkdir -p $REMOTE_DIR"
scp /tmp/argus-backend.tgz "$REMOTE:$REMOTE_DIR/"

echo "==> remote setup"
ssh "$REMOTE" bash -s <<REMOTE_EOF
set -euo pipefail
cd $REMOTE_DIR
tar xzf argus-backend.tgz
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "WARNING: edit $REMOTE_DIR/.env and set GEMINI_API_KEY"
fi
docker compose up -d --build
docker compose ps
curl -sf http://127.0.0.1:8787/v1/health || echo "health check pending"
REMOTE_EOF

echo "==> TLS: ensure Caddy/nginx proxies $DOMAIN -> 127.0.0.1:8787"
echo "    See Caddyfile in $REMOTE_DIR"
echo "Done. Set client: export ARGUS_MEMORY_URL=https://$DOMAIN"
