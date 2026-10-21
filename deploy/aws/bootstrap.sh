#!/bin/bash
# First-boot setup for the Agent Guard Web instance (Amazon Linux 2023, arm64).
# Passed as EC2 user data; runs once as root. Holds no secrets: deploy.sh
# generates them on the instance later. Progress: /var/log/agentguard-bootstrap.log
set -euo pipefail
exec > >(tee -a /var/log/agentguard-bootstrap.log) 2>&1

REPO_URL="https://github.com/ak2dev/agentguard-v1.git"
REPO_REF="main"
APP_DIR="/opt/agentguard"
COMPOSE_VERSION="v5.6.0"
SWAP_SIZE="2G"

echo "== $(date -Is) bootstrap start"

dnf -y update
dnf -y install docker git tar zstd
systemctl enable --now docker

# Docker Compose v2 plugin (not packaged for AL2023), checksum-verified.
arch="$(uname -m)"   # aarch64 on Graviton
tmp="$(mktemp -d)"
(
  cd "$tmp"
  base="https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}"
  curl -fsSLO "${base}/docker-compose-linux-${arch}"
  curl -fsSLO "${base}/docker-compose-linux-${arch}.sha256"
  sha256sum -c "docker-compose-linux-${arch}.sha256"
  install -D -m 0755 "docker-compose-linux-${arch}" /usr/local/lib/docker/cli-plugins/docker-compose
)

# gVisor (runsc) for the scanner containers, checksum-verified, registered with Docker.
# Releases since 2026-07 are one tarball; runsc runs sidecars from gvisor-bin/ next to it.
(
  cd "$tmp"
  base="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
  curl -fsSLO "${base}/gvisor.tar.zstd"
  curl -fsSLO "${base}/gvisor.tar.zstd.sha512"
  sha512sum -c gvisor.tar.zstd.sha512
  tar --zstd --no-same-owner -xf gvisor.tar.zstd -C /usr/local/bin runsc gvisor-bin
)
rm -rf "$tmp"
/usr/local/bin/runsc install
systemctl restart docker

# Swap: headroom for a 768 MB scan next to Postgres, Redis, the API and the dispatcher on 2 GB RAM.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l "$SWAP_SIZE" /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap defaults 0 0" >> /etc/fstab
fi
sysctl -w vm.swappiness=10
echo "vm.swappiness=10" > /etc/sysctl.d/90-agentguard.conf

if [ ! -d "$APP_DIR/.git" ]; then
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$APP_DIR"
fi

docker --version
docker compose version
docker info --format '{{json .Runtimes}}' | grep -q runsc && echo "gVisor runtime registered"
echo "== $(date -Is) bootstrap done. Next: sudo bash $APP_DIR/deploy/aws/deploy.sh"
touch /var/lib/agentguard-bootstrap.done
