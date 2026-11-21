#!/usr/bin/env bash
# Interactive NAS backup setup, run on the host.
#
# This only collects the answers; mailcow-nas-configure.sh does the work, so this path and
# the web form cannot drift apart. The same script also generates the backup encryption key
# on first run, and this front-end is where it gets shown for escrow — the web path
# deliberately never displays it.
#
# Run once:  sudo ./helper-scripts/setup-nas-backup.sh
set -euo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURE="${MAILCOW_DIR}/helper-scripts/mailcow-nas-configure.sh"
KEY_FILE="/etc/mailcow-nas/backup.key"
WORKDIR="/run/mailcow-nassetup"

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
[[ -x "$CONFIGURE" ]] || { echo "找不到 ${CONFIGURE}" >&2; exit 1; }

if [[ ! -f /etc/mailcow-updater/passphrase.hash ]]; then
  echo "尚未設定更新密碼，網頁的備份／還原按鈕會共用它做二次驗證。" >&2
  echo "請先執行： sudo ./helper-scripts/setup-updater-agent.sh" >&2
  exit 1
fi

for pkg in mount.cifs gpg; do
  command -v "$pkg" >/dev/null 2>&1 || {
    echo "缺少 ${pkg}。請先執行： sudo apt-get install -y cifs-utils gnupg" >&2
    exit 1
  }
done

TMPCFG=""
cleanup() { [[ -n "$TMPCFG" && -f "$TMPCFG" ]] && shred -u -n1 "$TMPCFG" 2>/dev/null; rm -rf -- "$WORKDIR" 2>/dev/null; }
trap cleanup EXIT INT TERM

echo "==> NAS 連線資訊"
read -rp "    SMB 伺服器（IP 或主機名稱）： " NAS_HOST
read -rp "    分享名稱（例如 backup）：     " NAS_SHARE
read -rp "    分享內的子目錄（可留空，例如 mailcow）： " NAS_PATH
read -rp "    使用者名稱：                 " NAS_USER
read -rp "    網域／工作群組（可留空）：    " NAS_DOMAIN
read -rsp "    密碼：                       " NAS_PASS; echo
read -rp "    SMB 版本（預設 3.0，不確定按 Enter）： " NAS_VERS
read -rp "    保留幾份備份（預設 8）： " KEEP

install -d -m 0700 "$WORKDIR"
TMPCFG="${WORKDIR}/config.json"
# Build the config with python so the password never becomes a shell word or argv entry.
NAS_PASS="$NAS_PASS" python3 -I - "$TMPCFG" \
  "$NAS_HOST" "$NAS_SHARE" "$NAS_PATH" "$NAS_USER" "$NAS_DOMAIN" "${NAS_VERS:-3.0}" "${KEEP:-8}" <<'PY'
import json, os, sys
out, host, share, path, user, domain, vers, keep = sys.argv[1:9]
cfg = {"nas_host": host, "nas_share": share, "nas_path": path, "nas_user": user,
       "nas_domain": domain, "nas_pass": os.environ.get("NAS_PASS", ""),
       "nas_vers": vers or "3.0", "keep": keep or "8"}
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False)
PY
unset NAS_PASS

echo
KEY_EXISTED=0
[[ -s "$KEY_FILE" ]] && KEY_EXISTED=1

OUT="$("$CONFIGURE" --from-json "$TMPCFG" 2>&1)" && RC=0 || RC=$?
printf '%s\n' "$OUT" | grep -v '^KEY_CREATED='
cleanup; TMPCFG=""
(( RC == 0 )) || { echo; echo "設定未完成，請修正上面的問題後重試。" >&2; exit "$RC"; }

if [[ $KEY_EXISTED -eq 0 ]] && printf '%s\n' "$OUT" | grep -q '^KEY_CREATED=1'; then
  echo
  echo "    ================= 請立刻離線保管這組金鑰 ================="
  echo
  echo "      $(cat "$KEY_FILE")"
  echo
  echo "    這是備份的解密金鑰。請存進密碼管理器或列印封存。"
  echo "    金鑰遺失 = 所有備份永久無法還原。主機整台損壞時，"
  echo "    只有這組金鑰能讓你在新機器上還原。"
  echo "    =========================================================="
  echo
  read -rp "    已妥善保管？輸入 YES 繼續： " KEY_ACK
  [[ "$KEY_ACK" == "YES" ]] || { echo "未確認。金鑰保留在 ${KEY_FILE}，請自行取出保管。" >&2; exit 1; }
fi

echo
echo "完成。Spam Manager 的「總覽」分頁現在可以使用「備份到 NAS」與「從 NAS 還原」。"
echo
echo "立即備份（不經網頁）： sudo ${MAILCOW_DIR}/helper-scripts/mailcow-nas-backup.sh"
echo "排程狀態：             systemctl list-timers mailcow-backup.timer"
echo "紀錄：                 journalctl -t mailcow-backup -n 50"
echo "要更改 NAS 或保留份數：重新執行本腳本，或在頁面的「NAS 連線設定」修改。"
echo
echo "注意：備份內含 mailcow.conf（有資料庫與 Redis 密碼）。備份已以 AES256 加密，"
echo "      金鑰只在 ${KEY_FILE}（不在 NAS 上）。仍請確認該分享只有管理員能存取。"
