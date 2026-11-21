#!/usr/bin/env bash
# Privileged NAS-configuration agent — triggered by systemd when the web UI drops a request.
#
# This is the one agent that accepts real data from the web layer (the SMB connection,
# including its password), because the admin asked to configure the NAS from the page.
# Handling of that is deliberately narrow:
#   * the update passphrase is verified here, against the root-only hash
#   * every field is validated by mailcow-nas-configure.sh before it is used
#   * the request and the temp config are shredded, so the password does not survive
#   * the generated backup encryption key is NEVER written anywhere the web can read; the
#     status only says that a key now exists and must be fetched on the host
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
REQUEST="${UPDATER_DIR}/nas-setup-request.json"
STATUS="${UPDATER_DIR}/nas-setup-status.json"
LOGFILE="${UPDATER_DIR}/nas-setup.log"
SECRET_FILE="/etc/mailcow-updater/passphrase.hash"
CONFIGURE="${MAILCOW_DIR}/helper-scripts/mailcow-nas-configure.sh"
WORKDIR="/run/mailcow-nassetup"      # tmpfs: never hits the disk
MAX_AGE=180

now() { date +%s; }
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
set_status() { # state, message [, key_created]
  printf '{"state":%s,"message":%s,"updated":%s,"key_created":%s}\n' \
    "$(printf '%s' "$1" | json_escape)" "$(printf '%s' "$2" | json_escape)" "$(now)" \
    "${3:-false}" > "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

wipe() {
  [[ -n "${TMPCFG:-}" && -f "${TMPCFG:-}" ]] && shred -u -n1 "$TMPCFG" 2>/dev/null
  rm -rf -- "$WORKDIR" 2>/dev/null
}
trap wipe EXIT INT TERM

[[ -f "$REQUEST" ]] || exit 0
# Consume immediately: the request holds the SMB password in cleartext.
REQ="$(cat "$REQUEST" 2>/dev/null)"
shred -u -n1 "$REQUEST" 2>/dev/null || rm -f "$REQUEST"

install -d -m 0750 "$UPDATER_DIR" 2>/dev/null
: > "$LOGFILE"; chmod 0644 "$LOGFILE"

[[ -f "$SECRET_FILE" ]] || { set_status "error" "尚未設定更新密碼"; exit 1; }
[[ -x "$CONFIGURE" ]] || { set_status "error" "找不到 NAS 設定腳本"; exit 1; }

read -r REQ_TS REQ_USER REQ_PASS < <(printf '%s' "$REQ" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(int(d.get("ts", 0)), str(d.get("user", "?")).replace(" ", "_")[:64],
          str(d.get("passphrase", "")))
except Exception:
    print(0, "?", "")
') || { set_status "error" "請求格式不正確"; exit 1; }

AGE=$(( $(now) - REQ_TS ))
if (( REQ_TS == 0 || AGE > MAX_AGE || AGE < -60 )); then
  set_status "rejected" "請求已逾時，請重新操作"
  logger -t mailcow-nassetup "rejected stale request from ${REQ_USER}"
  exit 1
fi

SALT="$(cut -d: -f1 "$SECRET_FILE")"
WANT="$(cut -d: -f2 "$SECRET_FILE")"
GOT="$(printf '%s%s' "$SALT" "$REQ_PASS" | sha256sum | cut -d' ' -f1)"
unset REQ_PASS
if [[ "$GOT" != "$WANT" ]]; then
  unset REQ
  set_status "rejected" "更新密碼不正確"
  logger -t mailcow-nassetup "FAILED passphrase from ${REQ_USER}"
  sleep 3
  exit 1
fi

set_status "running" "正在套用設定並測試連線…"

# Strip the update passphrase out and keep only the NAS fields, on tmpfs.
install -d -m 0700 "$WORKDIR"
TMPCFG="${WORKDIR}/config.json"
if ! printf '%s' "$REQ" | python3 -I -c '
import json, os, sys
keep = ("nas_host","nas_share","nas_path","nas_user","nas_domain","nas_pass","nas_vers","keep")
try:
    d = json.loads(sys.stdin.read())
except Exception:
    sys.exit(1)
out = {k: d.get(k, "") for k in keep}
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False)
' "$TMPCFG"; then
  unset REQ
  set_status "error" "請求內容無法解析"
  exit 1
fi
unset REQ

logger -t mailcow-nassetup "applying NAS configuration requested by ${REQ_USER}"
OUT="$("$CONFIGURE" --from-json "$TMPCFG" 2>&1)"
RC=$?
# The output never contains the password; it is safe to show on the page.
printf '%s\n' "$OUT" | grep -v '^KEY_CREATED=' >> "$LOGFILE"
shred -u -n1 "$TMPCFG" 2>/dev/null; TMPCFG=""

if (( RC != 0 )); then
  MSG="$(printf '%s\n' "$OUT" | grep -vE '^(==>|KEY_CREATED=)' | tail -3 | tr '\n' ' ')"
  set_status "error" "設定未成功：${MSG:-請查看紀錄}"
  logger -t mailcow-nassetup "NAS configuration FAILED (requested by ${REQ_USER})"
  exit 1
fi

if printf '%s\n' "$OUT" | grep -q '^KEY_CREATED=1'; then
  set_status "done" "設定完成，連線測試通過。已產生備份加密金鑰 — 請在主機執行 sudo cat /etc/mailcow-nas/backup.key 取出並離線保管，金鑰遺失將無法還原任何備份。" "true"
else
  set_status "done" "設定完成，連線測試通過（沿用既有的備份加密金鑰）。" "false"
fi
logger -t mailcow-nassetup "NAS configuration OK (requested by ${REQ_USER})"
exit 0
