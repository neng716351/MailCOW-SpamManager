#!/usr/bin/env bash
# One-time host step so the NAS connection can be configured from the Spam Manager page.
#
# This installs no secrets and asks nothing. It only puts the packages and the agent in
# place; the actual NAS connection is then entered on the page. Everything else about the
# NAS (credentials, encryption key, systemd units for backup/restore) is created by the
# agent on the first successful configuration.
#
# Run once:  sudo ./helper-scripts/setup-nas-webconfig.sh
set -euo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-nassetup-agent.sh"
PHP_UID=82

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
[[ -x "$AGENT" ]] || { echo "找不到或無法執行 ${AGENT}" >&2; exit 1; }

if [[ ! -f /etc/mailcow-updater/passphrase.hash ]]; then
  echo "尚未設定更新密碼，網頁設定 NAS 需要它做二次驗證。" >&2
  echo "請先執行： sudo ./helper-scripts/setup-updater-agent.sh" >&2
  exit 1
fi

echo "==> 安裝必要套件"
MISSING=()
command -v mount.cifs >/dev/null 2>&1 || MISSING+=(cifs-utils)
command -v gpg        >/dev/null 2>&1 || MISSING+=(gnupg)
if [[ ${#MISSING[@]} -gt 0 ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}"
  echo "    已安裝：${MISSING[*]}"
else
  echo "    cifs-utils 與 gnupg 都已存在"
fi

echo "==> 設定共用目錄"
install -d -m 0750 "$UPDATER_DIR"
chown "${PHP_UID}:${PHP_UID}" "$UPDATER_DIR"

echo "==> 安裝 systemd 單元"
cat > /etc/systemd/system/mailcow-nassetup-agent.service <<UNIT
[Unit]
Description=Mailcow NAS configuration agent (verifies the passphrase, applies and tests)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${AGENT}
TimeoutStartSec=600
UNIT

cat > /etc/systemd/system/mailcow-nassetup-agent.path <<UNIT
[Unit]
Description=Watch for a NAS configuration request from the mailcow web UI

[Path]
PathExists=${UPDATER_DIR}/nas-setup-request.json
Unit=mailcow-nassetup-agent.service

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now mailcow-nassetup-agent.path
echo "    已啟用 mailcow-nassetup-agent.path"

# Tells the page the web configuration path is available (no secrets in here).
cat > "${UPDATER_DIR}/nas-webconfig.json" <<JSON
{"available":true,"installed":$(date +%s)}
JSON
chmod 0644 "${UPDATER_DIR}/nas-webconfig.json"

echo
echo "完成。現在到 Spam Manager 的「總覽」分頁，在「NAS 連線設定」區塊填入 NAS 資訊即可。"
echo
echo "注意：備份加密金鑰會在第一次成功設定時自動產生，但不會顯示在網頁上。"
echo "      設定完成後請在主機執行： sudo cat /etc/mailcow-nas/backup.key"
echo "      並將它離線保管 — 金鑰遺失將無法還原任何備份。"
echo
echo "紀錄： journalctl -t mailcow-nassetup -n 30"
echo "停用： sudo systemctl disable --now mailcow-nassetup-agent.path"
