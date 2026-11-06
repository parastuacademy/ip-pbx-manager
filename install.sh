#!/usr/bin/env bash
# ip-pbx-manager — one-command installer for a clean Ubuntu/Debian server.
# Usage:  curl -fsSL https://raw.githubusercontent.com/parastuacademy/ip-pbx-manager/main/install.sh | sudo bash
# Or:     REPO_URL=https://github.com/parastuacademy/ip-pbx-manager.git sudo bash install.sh
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/parastuacademy/ip-pbx-manager.git}"
INSTALL_DIR="/opt/ip-pbx-manager"

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ این اسکریپت باید با دسترسی root اجرا شود (sudo bash install.sh)" >&2
  exit 1
fi

echo "==> ۱/۴ بررسی داکر"
if ! command -v docker >/dev/null 2>&1; then
  echo "    نصب داکر از مخازن سیستم..."
  apt-get update -y
  apt-get install -y --no-install-recommends docker.io ca-certificates
  systemctl enable --now docker
else
  echo "    داکر موجود است ✔"
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "    نصب افزونه compose..."
  apt-get install -y --no-install-recommends docker-compose
  COMPOSE="docker-compose"
fi

echo "==> ۲/۴ دانلود پروژه از گیت‌هاب"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull --ff-only || true
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

echo "==> ۳/۴ ساخت و اجرای کانتینرها"
cd "$INSTALL_DIR"
if [ ! -f .env ]; then
  cp .env.example .env
  # Generate a random AMI password if none was provided
  RAND_PW="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 20)"
  sed -i "s|ipbx-ami-change-me|${RAND_PW}|" .env
fi
$COMPOSE up -d --build

echo "==> ۴/۴ پایان"
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "✅ نصب کامل شد!"
echo "   پنل مدیریت:   http://${SERVER_IP:-SERVER-IP}:8080"
echo "   پورت‌های تلفنی: UDP 5060 و UDP 10000-10100 (باید در فایروال باز باشند)"
echo "   محل داده‌ها:   ${INSTALL_DIR} (ولوم داکری ipbx-data)"
echo ""
echo "⚠️  امنیت: پورت 8080 را در فایروال فقط برای IPهای مورد اعتماد باز بگذارید."
