#!/usr/bin/env bash
# Privileged backup agent — triggered by systemd when the web UI drops a request file.
#
# A backup is a protective action with a fixed destination the web layer cannot change, so
# unlike update/restore it does NOT require the update passphrase — admins run it often and
# the worst outcome is one more encrypted copy on the NAS.
#
# What it can still do is interrupt mail, because mailcow's backup stops dovecot, postfix,
# redis and rspamd for a while. So a compromised web layer must not be able to trigger it
# repeatedly: MIN_INTERVAL bounds that regardless of how the previous run ended, flock
# prevents overlap, and every run mails the admin.
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
REQUEST="${UPDATER_DIR}/backup-request.json"
STATUS="${UPDATER_DIR}/backup-status.json"
SECRET_FILE="/etc/mailcow-updater/passphrase.hash"
JOB="${MAILCOW_DIR}/helper-scripts/mailcow-nas-backup.sh"
MAX_AGE=180          # seconds a request stays valid
COOLDOWN=900         # seconds between successful backups
MIN_INTERVAL=300     # seconds between runs of ANY outcome — bounds a repeated-trigger DoS

now() { date +%s; }
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

set_status() { # state, message — keep the shape the page already reads
  local state="$1" msg="$2"
  printf '{"state":%s,"message":%s,"updated":%s}\n' \
    "$(printf '%s' "$state" | json_escape)" \
    "$(printf '%s' "$msg" | json_escape)" \
    "$(now)" > "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

[[ -f "$REQUEST" ]] || exit 0

# Consume the request immediately so it cannot be processed twice.
REQ="$(cat "$REQUEST" 2>/dev/null)"
rm -f "$REQUEST"

if [[ ! -f "$SECRET_FILE" ]]; then
  set_status "error" "尚未設定更新密碼，請在主機執行 setup-updater-agent.sh"
  exit 1
fi
if [[ ! -x "$JOB" ]]; then
  set_status "error" "找不到備份腳本，請在主機執行 setup-nas-backup.sh"
  exit 1
fi

read -r REQ_TS REQ_USER REQ_PASS < <(printf '%s' "$REQ" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ts = int(d.get("ts", 0)); user = str(d.get("user", "?")).replace(" ", "_")[:64]
    pw = str(d.get("passphrase", ""))
    print(ts, user, pw)
except Exception:
    print(0, "?", "")
') || { set_status "error" "請求格式不正確"; exit 1; }

AGE=$(( $(now) - REQ_TS ))
if (( REQ_TS == 0 || AGE > MAX_AGE || AGE < -60 )); then
  set_status "rejected" "請求已逾時，請重新操作"
  logger -t mailcow-backup "rejected stale backup request from ${REQ_USER}"
  exit 1
fi

unset REQ REQ_PASS

# Two limits, read from the status file the previous run left behind:
#   * COOLDOWN after a SUCCESSFUL backup — no point repeating it so soon
#   * MIN_INTERVAL after ANY run — this is the one that bounds repeated triggering
if [[ -f "$STATUS" ]]; then
  read -r LAST_TS LAST_STATE < <(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(int(d.get("updated",0)), str(d.get("state","")))
except Exception:
    print(0,"")' "$STATUS" 2>/dev/null || echo "0 ")
  SINCE=$(( $(now) - ${LAST_TS:-0} ))
  if [[ "${LAST_STATE:-}" == "done" ]] && (( LAST_TS > 0 && SINCE < COOLDOWN )); then
    set_status "rejected" "距離上次成功備份未滿 $((COOLDOWN/60)) 分鐘，請稍後再試"
    exit 1
  fi
  if (( LAST_TS > 0 && SINCE < MIN_INTERVAL )); then
    set_status "rejected" "距離上次備份作業未滿 $((MIN_INTERVAL/60)) 分鐘，請稍後再試"
    logger -t mailcow-backup "throttled backup request from ${REQ_USER} (${SINCE}s since last run)"
    exit 1
  fi
fi

logger -t mailcow-backup "starting NAS backup requested by ${REQ_USER}"
if "$JOB"; then
  logger -t mailcow-backup "backup finished OK (requested by ${REQ_USER})"
else
  logger -t mailcow-backup "backup FAILED (requested by ${REQ_USER})"
  exit 1
fi
