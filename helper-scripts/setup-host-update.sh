#!/usr/bin/env bash
# One-time setup for host OS maintenance from the Spam Manager page.
#
# What this configures, and why it is split this way:
#   * unattended-upgrades applies security AND regular updates automatically, because
#     mailcow runs entirely in containers — host libraries cannot interrupt mail.
#     A new kernel installs safely too: installing one does not activate it.
#   * docker.io / containerd / runc are blacklisted from that automatic path, because
#     their install immediately restarts the container runtime, which DOES interrupt mail.
#     They are applied only when an admin triggers it.
#   * Automatic reboot stays off. Rebooting is always an explicit, separate action.
#
# Run once:  sudo ./helper-scripts/setup-host-update.sh
set -euo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
JOB="${MAILCOW_DIR}/helper-scripts/mailcow-host-update.sh"
AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-hostupdate-agent.sh"
APT_CONF="/etc/apt/apt.conf.d/52mailcow-host-autoupgrade"
PHP_UID=82

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
[[ -x "$JOB"   ]] || { echo "找不到或無法執行 ${JOB}" >&2; exit 1; }
[[ -x "$AGENT" ]] || { echo "找不到或無法執行 ${AGENT}" >&2; exit 1; }

if [[ ! -f /etc/mailcow-updater/passphrase.hash ]]; then
  echo "尚未設定更新密碼，網頁的主機更新按鈕會共用它做二次驗證。" >&2
  echo "請先執行： sudo ./helper-scripts/setup-updater-agent.sh" >&2
  exit 1
fi

if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
  echo "==> 安裝 unattended-upgrades"
  DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
fi

echo "==> 設定自動更新策略"
cat > "$APT_CONF" <<'CONF'
// Managed by mailcow helper-scripts/setup-host-update.sh — edits here may be overwritten.
//
// mailcow runs entirely in containers, so host package updates cannot interrupt mail,
// with one exception: the container runtime. Those packages are blacklisted below and
// applied only when an admin triggers the maintenance action, so the interruption
// happens at a time somebody chose.
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}:${distro_codename}-updates";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
};

// Upgrading these restarts dockerd/containerd, which restarts every mailcow container.
Unattended-Upgrade::Package-Blacklist {
        "docker.io";
        "docker-ce";
        "docker-ce-cli";
        "containerd";
        "containerd.io";
        "runc";
};

// A kernel may install automatically (that is harmless), but we never reboot on our own.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
CONF
chmod 0644 "$APT_CONF"
echo "    已寫入 ${APT_CONF}"
apt-config dump 2>/dev/null | grep -q 'Unattended-Upgrade::Package-Blacklist' \
  && echo "    設定語法檢查通過" || { echo "    設定語法有問題，請檢查 ${APT_CONF}" >&2; exit 1; }

echo "==> 確認自動更新排程已啟用"
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades >/dev/null 2>&1 || true
systemctl is-enabled unattended-upgrades >/dev/null 2>&1 \
  && echo "    unattended-upgrades 已啟用" || echo "    警告：unattended-upgrades 未啟用"

echo "==> 設定共用目錄"
install -d -m 0750 "$UPDATER_DIR"
chown "${PHP_UID}:${PHP_UID}" "$UPDATER_DIR"

echo "==> 安裝 systemd 單元"
cat > /etc/systemd/system/mailcow-hostupdate-agent.service <<UNIT
[Unit]
Description=Mailcow host maintenance agent (verifies the passphrase, then applies or reboots)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${AGENT}
TimeoutStartSec=7200
UNIT

cat > /etc/systemd/system/mailcow-hostupdate-agent.path <<UNIT
[Unit]
Description=Watch for a host maintenance request from the mailcow web UI

[Path]
PathExists=${UPDATER_DIR}/host-request.json
Unit=mailcow-hostupdate-agent.service

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/mailcow-host-check.service <<UNIT
[Unit]
Description=Refresh the host update status shown on the Spam Manager page
After=network-online.target

[Service]
Type=oneshot
ExecStart=${JOB} --check
TimeoutStartSec=1800
UNIT

cat > /etc/systemd/system/mailcow-host-check.timer <<UNIT
[Unit]
Description=Daily host update check for the mailcow page

[Timer]
OnCalendar=*-*-* 05:30
Persistent=true
RandomizedDelaySec=20m

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now mailcow-hostupdate-agent.path
systemctl enable --now mailcow-host-check.timer
echo "    已啟用 mailcow-hostupdate-agent.path 與 mailcow-host-check.timer（每日 05:30 檢查）"

echo "==> 執行第一次檢查，讓頁面立刻有資料"
"$JOB" --check || echo "    檢查有錯誤，請看 ${UPDATER_DIR}/host-update.log"

echo
echo "完成。Spam Manager 的「總覽」分頁會出現「主機系統更新」區塊。"
echo
echo "自動：安全性與一般更新每日自動安裝（含新核心，但不會自動重開機）。"
echo "手動：docker.io／containerd／runc 與重開機保留給你按。"
echo
echo "狀態：   systemctl list-timers mailcow-host-check.timer"
echo "紀錄：   journalctl -t mailcow-host-update -n 50"
echo "自動更新紀錄： /var/log/unattended-upgrades/"
echo "不經網頁操作： sudo ${JOB} --check | --apply | --reboot"
echo "停用：   sudo systemctl disable --now mailcow-hostupdate-agent.path mailcow-host-check.timer"
