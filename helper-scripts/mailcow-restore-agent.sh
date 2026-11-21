#!/usr/bin/env bash
# Privileged restore agent — triggered by systemd when the web UI drops a request file.
#
# Unlike the update and backup agents this one does accept two values from the request
# (which backup, which components), so both are validated HERE against a strict whitelist
# before they reach the restore script:
#   * the backup name must match the generated pattern and exist on the share
#   * the components must be a subset of the settings-class set
# vmail and crypt are never accepted from the web, and the restore script refuses them
# again without --allow-mail, which this agent never passes. Two independent checks.
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
REQUEST="${UPDATER_DIR}/restore-request.json"
STATUS="${UPDATER_DIR}/restore-status.json"
SECRET_FILE="/etc/mailcow-updater/passphrase.hash"
JOB="${MAILCOW_DIR}/helper-scripts/mailcow-nas-restore.sh"
WEB_ALLOWED="mysql redis rspamd postfix"
MAX_AGE=180

now() { date +%s; }
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
set_status() {
  printf '{"state":%s,"message":%s,"updated":%s}\n' \
    "$(printf '%s' "$1" | json_escape)" "$(printf '%s' "$2" | json_escape)" "$(now)" \
    > "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

[[ -f "$REQUEST" ]] || exit 0
REQ="$(cat "$REQUEST" 2>/dev/null)"
rm -f "$REQUEST"

[[ -f "$SECRET_FILE" ]] || { set_status "error" "尚未設定更新密碼"; exit 1; }
[[ -x "$JOB" ]] || { set_status "error" "找不到還原腳本"; exit 1; }

read -r REQ_TS REQ_USER REQ_BACKUP REQ_COMPONENTS REQ_PASS < <(printf '%s' "$REQ" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ts = int(d.get("ts", 0))
    user = str(d.get("user", "?")).replace(" ", "_")[:64]
    backup = str(d.get("backup", ""))[:64]
    comps = ",".join(str(c) for c in (d.get("components") or []))[:128]
    pw = str(d.get("passphrase", ""))
    # Anything unexpected in these two is dropped here rather than quoted into the shell.
    if not backup.replace("-", "").isalnum(): backup = ""
    if not comps.replace(",", "").isalpha(): comps = ""
    print(ts, user, backup or "-", comps or "-", pw)
except Exception:
    print(0, "?", "-", "-", "")
') || { set_status "error" "請求格式不正確"; exit 1; }

AGE=$(( $(now) - REQ_TS ))
if (( REQ_TS == 0 || AGE > MAX_AGE || AGE < -60 )); then
  set_status "rejected" "請求已逾時，請重新操作"
  logger -t mailcow-restore "rejected stale restore request from ${REQ_USER}"
  exit 1
fi

SALT="$(cut -d: -f1 "$SECRET_FILE")"
WANT="$(cut -d: -f2 "$SECRET_FILE")"
GOT="$(printf '%s%s' "$SALT" "$REQ_PASS" | sha256sum | cut -d' ' -f1)"
unset REQ REQ_PASS
if [[ "$GOT" != "$WANT" ]]; then
  set_status "rejected" "更新密碼不正確"
  logger -t mailcow-restore "FAILED restore passphrase from ${REQ_USER}"
  sleep 3
  exit 1
fi

if [[ ! "$REQ_BACKUP" =~ ^mailcow-[0-9][0-9-]*$ ]]; then
  set_status "rejected" "備份名稱不正確"
  logger -t mailcow-restore "rejected restore: bad backup name from ${REQ_USER}"
  exit 1
fi

COMPS=""
IFS=',' read -ra WANTED <<< "$REQ_COMPONENTS"
for c in "${WANTED[@]}"; do
  [[ -n "$c" ]] || continue
  if [[ " $WEB_ALLOWED " == *" $c "* ]]; then
    COMPS+="${COMPS:+ }$c"
  else
    set_status "rejected" "元件 ${c} 不允許從網頁還原（信件類請在主機執行）"
    logger -t mailcow-restore "rejected restore: component ${c} from ${REQ_USER}"
    exit 1
  fi
done
if [[ -z "$COMPS" ]]; then
  set_status "rejected" "未選擇任何可還原的元件"
  exit 1
fi

logger -t mailcow-restore "starting restore ${REQ_BACKUP} [${COMPS}] requested by ${REQ_USER}"
if "$JOB" --backup "$REQ_BACKUP" --components "$COMPS"; then
  logger -t mailcow-restore "restore finished OK (requested by ${REQ_USER})"
else
  logger -t mailcow-restore "restore FAILED (requested by ${REQ_USER})"
  exit 1
fi
