#!/usr/bin/env bash
# Privileged updater agent — triggered by systemd when the web UI drops a request file.
#
# Security model:
#   * The web UI (php-fpm, www-data) can only WRITE a request file. It never runs anything.
#   * This agent runs exactly ONE fixed script and accepts NO parameters from the request,
#     so a compromised web UI cannot turn this into arbitrary command execution.
#   * The update passphrase is verified HERE against a salted hash stored root-only, so a
#     stolen admin session alone is not enough to trigger an update.
#   * Requests older than MAX_AGE are rejected (limits replay of a captured request file).
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
REQUEST="${UPDATER_DIR}/request.json"
STATUS="${UPDATER_DIR}/status.json"
LOGFILE="${UPDATER_DIR}/update.log"
LOCK="${UPDATER_DIR}/.lock"
SECRET_FILE="/etc/mailcow-updater/passphrase.hash"
UPDATE_SCRIPT="${MAILCOW_DIR}/helper-scripts/mailcow-oneclick-update.sh"
MAX_AGE=180          # seconds a request stays valid
COOLDOWN=600         # seconds between successful runs

now() { date +%s; }
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' ; }

set_status() { # state, message
  local state="$1" msg="$2"
  printf '{"state":%s,"message":%s,"updated":%s}\n' \
    "$(printf '%s' "$state" | json_escape)" \
    "$(printf '%s' "$msg" | json_escape)" \
    "$(now)" > "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

[[ -f "$REQUEST" ]] || exit 0

# Consume the request immediately so it cannot be processed twice.
REQ="$(cat "$REQUEST" 2>/dev/null)"
rm -f "$REQUEST"

# "verify" re-runs the post-update checks and changes nothing, so it takes no
# passphrase. It accepts no parameters either: the request can only select this fixed,
# read-only script, never the update itself. It writes its own status file and leaves
# the update status (the record of the last update) untouched.
REQ_ACTION="$(printf '%s' "$REQ" | python3 -I -c '
import json, sys
try: print(str(json.loads(sys.stdin.read()).get("action", "update")))
except Exception: print("update")' 2>/dev/null)"
if [[ "$REQ_ACTION" == "verify" ]]; then
  read -r V_TS V_USER < <(printf '%s' "$REQ" | python3 -I -c '
import json, re, sys
try:
    d = json.loads(sys.stdin.read())
    print(int(d.get("ts", 0)), re.sub(r"[^A-Za-z0-9@._-]", "_", str(d.get("user", "?")))[:64])
except Exception:
    print(0, "?")')
  V_AGE=$(( $(now) - V_TS ))
  (( V_TS == 0 || V_AGE > MAX_AGE || V_AGE < -60 )) && { logger -t mailcow-updater "rejected stale verify request"; exit 1; }
  V_LAST=$(python3 -I -c 'import json,sys
try: print(int(json.load(open(sys.argv[1])).get("verified",0)))
except Exception: print(0)' "${UPDATER_DIR}/verify-status.json" 2>/dev/null || echo 0)
  (( V_LAST > 0 && $(now) - V_LAST < 120 )) && { logger -t mailcow-updater "verify request within cooldown ignored"; exit 0; }
  exec 9>"$LOCK"
  flock -n 9 || { logger -t mailcow-updater "verify skipped: update in progress"; exit 0; }
  logger -t mailcow-updater "starting verification requested by ${V_USER}"
  "${MAILCOW_DIR}/helper-scripts/mailcow-verify.sh" "$V_USER"
  exit 0
fi
[[ "$REQ_ACTION" == "update" ]] || { set_status "rejected" "不支援的動作"; exit 1; }

if [[ ! -f "$SECRET_FILE" ]]; then
  set_status "error" "尚未設定更新密碼，請在主機執行 setup-updater-agent.sh"
  exit 1
fi

# Parse the request without letting its contents reach the shell.
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
  logger -t mailcow-updater "rejected stale update request from ${REQ_USER}"
  exit 1
fi

# Verify the passphrase against the salted hash (format: salt:sha256(salt+passphrase)).
SALT="$(cut -d: -f1 "$SECRET_FILE")"
WANT="$(cut -d: -f2 "$SECRET_FILE")"
GOT="$(printf '%s%s' "$SALT" "$REQ_PASS" | sha256sum | cut -d' ' -f1)"
unset REQ REQ_PASS
if [[ "$GOT" != "$WANT" ]]; then
  set_status "rejected" "更新密碼不正確"
  logger -t mailcow-updater "FAILED update passphrase from ${REQ_USER}"
  sleep 3   # slow down guessing
  exit 1
fi

# Cooldown between successful runs.
if [[ -f "$STATUS" ]]; then
  LAST_OK=$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(d.get("updated",0) if d.get("state")=="done" else 0)
except Exception:
    print(0)' "$STATUS" 2>/dev/null || echo 0)
  if (( LAST_OK > 0 && $(now) - LAST_OK < COOLDOWN )); then
    set_status "rejected" "距離上次更新未滿 $((COOLDOWN/60)) 分鐘，請稍後再試"
    exit 1
  fi
fi

exec 9>"$LOCK"
if ! flock -n 9; then
  set_status "running" "已有更新正在執行"
  exit 0
fi

logger -t mailcow-updater "starting mailcow update requested by ${REQ_USER}"
set_status "running" "更新進行中，網頁服務會短暫中斷…"
: > "$LOGFILE"
chmod 0644 "$LOGFILE"

if "$UPDATE_SCRIPT" --force >> "$LOGFILE" 2>&1; then
  set_status "done" "更新完成（由 ${REQ_USER} 觸發）"
  logger -t mailcow-updater "update finished OK"
else
  set_status "error" "更新未成功結束，請查看紀錄"
  logger -t mailcow-updater "update FAILED"
fi
chmod 0644 "$LOGFILE" "$STATUS" 2>/dev/null
