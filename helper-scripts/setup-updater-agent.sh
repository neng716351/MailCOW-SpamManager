#!/usr/bin/env bash
# One-time setup for the web update button.
#
# Installs a systemd path unit that watches for an update request written by the mailcow
# web UI, and a service that verifies the update passphrase and runs the update as root.
# Run once:  sudo ./helper-scripts/setup-updater-agent.sh
set -euo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-updater-agent.sh"
SECRET_DIR="/etc/mailcow-updater"
SECRET_FILE="${SECRET_DIR}/passphrase.hash"
PHP_UID=82   # www-data inside the php-fpm container

if [[ $EUID -ne 0 ]]; then
  echo "請以 root 執行：sudo $0" >&2
  exit 1
fi
[[ -x "$AGENT" ]] || { echo "找不到或無法執行 ${AGENT}" >&2; exit 1; }

echo "==> 設定更新密碼"
echo "    這組密碼之後要在網頁按「更新」時輸入。與 mailcow 管理員密碼不同，請另外設一組。"
read -rsp "    請輸入更新密碼： " PASS1; echo
read -rsp "    請再輸入一次：   " PASS2; echo
[[ "$PASS1" == "$PASS2" ]] || { echo "兩次輸入不一致。" >&2; exit 1; }
[[ ${#PASS1} -ge 8 ]] || { echo "密碼至少 8 個字元。" >&2; exit 1; }

install -d -m 0700 "$SECRET_DIR"
SALT="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HASH="$(printf '%s%s' "$SALT" "$PASS1" | sha256sum | cut -d' ' -f1)"
printf '%s:%s\n' "$SALT" "$HASH" > "$SECRET_FILE"
chmod 0600 "$SECRET_FILE"
unset PASS1 PASS2
echo "    已儲存（只存雜湊，不存明碼）：${SECRET_FILE}"

echo "==> 設定共用目錄權限"
install -d -m 0750 "$UPDATER_DIR"
chown "${PHP_UID}:${PHP_UID}" "$UPDATER_DIR"
echo "    ${UPDATER_DIR} → uid ${PHP_UID}, 0750"

echo "==> 安裝 systemd 單元"
cat > /etc/systemd/system/mailcow-updater.service <<EOF
[Unit]
Description=Mailcow update agent (verifies passphrase, runs the one-click update)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${AGENT}
TimeoutStartSec=3600
EOF

cat > /etc/systemd/system/mailcow-updater.path <<EOF
[Unit]
Description=Watch for a mailcow update request from the web UI

[Path]
PathExists=${UPDATER_DIR}/request.json
Unit=mailcow-updater.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mailcow-updater.path
echo "    已啟用 mailcow-updater.path"

echo
echo "完成。現在可以在 Spam Manager 的「總覽」分頁使用「更新 Mailcow」按鈕。"
echo "狀態檢查： systemctl status mailcow-updater.path --no-pager"
echo "更新紀錄： journalctl -t mailcow-updater --no-pager -n 50"
echo
echo "要更換更新密碼：重新執行本腳本即可。"
echo "要停用網頁更新：sudo systemctl disable --now mailcow-updater.path"
