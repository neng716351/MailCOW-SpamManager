#!/usr/bin/env bash
# One-time setup for the login-region allowlist (Spam Manager > 登入地區).
#
# Restricts the ports that accept a password (POP3/IMAP/SMTP submission/Sieve/HTTPS) to
# source countries chosen on the page. Port 25 (vendors sending us mail) and port 80
# (https redirect, Let's Encrypt) stay open to the world.
#
# Run once:  sudo ./helper-scripts/setup-geo-allowlist.sh
#   Initial countries (first install only; change later on the page):
#     sudo GEO_COUNTRIES="TW JP" ./helper-scripts/setup-geo-allowlist.sh   (default: TW)
#   Install without enforcing yet:
#     sudo GEO_ENABLE=0 ./helper-scripts/setup-geo-allowlist.sh
# Emergency: sudo ./helper-scripts/mailcow-geo-agent.py --disable
set -euo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-geo-agent.py"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
[[ -x "$AGENT" ]] || chmod 0755 "$AGENT"
command -v nft >/dev/null || { echo "找不到 nft（nftables）" >&2; exit 1; }
[[ -f /etc/mailcow-updater/passphrase.hash ]] || {
  echo "尚未設定更新密碼；變更登入地區需要它做二次驗證。" >&2
  echo "請先執行： sudo ./helper-scripts/setup-updater-agent.sh" >&2; exit 1; }
[[ -d "$UPDATER_DIR" ]] || { echo "找不到 ${UPDATER_DIR}，請先完成網頁更新功能的設定" >&2; exit 1; }

# The agent runs as root from this path, so it must not be writable by anyone else.
chown root:root "$AGENT"; chmod 0755 "$AGENT"

echo "==> 安裝 systemd 單元"
cat > /etc/systemd/system/mailcow-geo-request.service <<UNIT
[Unit]
Description=Mailcow login-region allowlist: apply a change requested from the web UI
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${AGENT} --request
UNIT

cat > /etc/systemd/system/mailcow-geo-request.path <<UNIT
[Unit]
Description=Watch for a login-region change requested from the mailcow web UI

[Path]
PathExists=${UPDATER_DIR}/geo-request.json
Unit=mailcow-geo-request.service

[Install]
WantedBy=multi-user.target
UNIT

# Boot + every 10 minutes: restores the table after a reboot, drops expired temporary
# openings, refreshes the counters shown on the page.
cat > /etc/systemd/system/mailcow-geo-apply.service <<UNIT
[Unit]
Description=Mailcow login-region allowlist: (re)apply the stored policy
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${AGENT} --apply
UNIT

cat > /etc/systemd/system/mailcow-geo-apply.timer <<UNIT
[Unit]
Description=Re-apply the mailcow login-region allowlist (expiry, counters, boot)

[Timer]
OnBootSec=30s
OnUnitActiveSec=10min
AccuracySec=30s

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/mailcow-geo-refresh.service <<UNIT
[Unit]
Description=Mailcow login-region allowlist: refresh country IP data from the five RIRs
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I ${AGENT} --refresh-data
TimeoutStartSec=900
UNIT

cat > /etc/systemd/system/mailcow-geo-refresh.timer <<UNIT
[Unit]
Description=Daily refresh of country IP data for the login-region allowlist

[Timer]
OnCalendar=*-*-* 04:20:00
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload

echo "==> 下載國家 IP 資料（五個區域網際網路註冊管理機構，約 1 分鐘）"
POLICY=/etc/mailcow-geo/policy.json
if [[ ! -f "$POLICY" ]]; then
  install -d -m 0700 /etc/mailcow-geo
  python3 -I - "$POLICY" "${GEO_COUNTRIES:-TW}" "${GEO_ENABLE:-1}" <<'PY'
import json, re, sys, time
ccs = [c.upper() for c in sys.argv[2].split()]
bad = [c for c in ccs if not re.fullmatch(r"[A-Z]{2}", c)]
if not ccs or bad:
    sys.exit(f"GEO_COUNTRIES 格式不正確：{bad or '（空白）'}，請用兩碼國家代碼，例如 TW JP")
json.dump({"enabled": sys.argv[3] != "0", "countries": ccs, "temporary": [],
           "changed": int(time.time()), "by": "setup-geo-allowlist.sh"},
          open(sys.argv[1], "w"), ensure_ascii=False)
print("    初始設定：" + ("啟用" if sys.argv[3] != "0" else "先不啟用") + "，開放 " + " ".join(ccs))
PY
  chmod 0600 "$POLICY"
fi
python3 -I "$AGENT" --refresh-data

systemctl enable --now mailcow-geo-request.path mailcow-geo-apply.timer mailcow-geo-refresh.timer >/dev/null
echo "==> 目前狀態"
nft list table inet mailcow_geo 2>/dev/null | grep -E 'hook|jump' | sed 's/^\s*/    /' || echo "    （未啟用）"
python3 -I - "${UPDATER_DIR}/geo-status.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("    " + d.get("message", ""))
print("    台灣 IPv4 範圍：", d.get("set_v4"), "筆（已合併）")
PY
echo
echo "完成。之後請在 Spam Manager「登入地區」頁面調整。"
echo "緊急解除（所有國家都可登入）：sudo ${AGENT} --disable"
