#!/usr/bin/env bash
# Privileged host-maintenance agent — triggered by systemd when the web UI drops a request.
#
# Accepts exactly one value from the request: the action, validated against a two-item
# whitelist. Everything else about what runs is fixed here. The passphrase is verified
# against the root-only hash, as with the mailcow updater.
#
# "check" is deliberately NOT web-triggerable: it runs on a daily timer instead, so the
# page always has fresh data without exposing a root apt operation to the web layer.
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
REQUEST="${UPDATER_DIR}/host-request.json"
STATUS="${UPDATER_DIR}/host-status.json"
SECRET_FILE="/etc/mailcow-updater/passphrase.hash"
JOB="${MAILCOW_DIR}/helper-scripts/mailcow-host-update.sh"
MAX_AGE=180
COOLDOWN=600

now() { date +%s; }
json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
# Keep the keys the page already reads; a bare state file is enough for a rejection.
set_status() {
  python3 -I - "$STATUS" "$1" "$2" "$(now)" <<'PY'
import io, json, sys
path, state, msg, ts = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    with io.open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    if not isinstance(d, dict):
        d = {}
except Exception:
    d = {}
d.update({"state": state, "message": msg, "updated": ts})
with io.open(path + ".tmp", "w", encoding="utf-8") as fh:
    json.dump(d, fh, ensure_ascii=False)
PY
  mv -f "${STATUS}.tmp" "$STATUS" 2>/dev/null
  chmod 0644 "$STATUS" 2>/dev/null
}

[[ -f "$REQUEST" ]] || exit 0
REQ="$(cat "$REQUEST" 2>/dev/null)"
rm -f "$REQUEST"

[[ -f "$SECRET_FILE" ]] || { set_status "error" "尚未設定更新密碼"; exit 1; }
[[ -x "$JOB" ]] || { set_status "error" "找不到主機更新腳本"; exit 1; }

read -r REQ_TS REQ_USER REQ_ACTION REQ_PASS < <(printf '%s' "$REQ" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ts = int(d.get("ts", 0))
    user = str(d.get("user", "?")).replace(" ", "_")[:64]
    action = str(d.get("action", ""))[:16]
    pw = str(d.get("passphrase", ""))
    if not action.isalpha(): action = ""
    print(ts, user, action or "-", pw)
except Exception:
    print(0, "?", "-", "")
') || { set_status "error" "請求格式不正確"; exit 1; }

AGE=$(( $(now) - REQ_TS ))
if (( REQ_TS == 0 || AGE > MAX_AGE || AGE < -60 )); then
  set_status "rejected" "請求已逾時，請重新操作"
  logger -t mailcow-host-update "rejected stale request from ${REQ_USER}"
  exit 1
fi

SALT="$(cut -d: -f1 "$SECRET_FILE")"
WANT="$(cut -d: -f2 "$SECRET_FILE")"
GOT="$(printf '%s%s' "$SALT" "$REQ_PASS" | sha256sum | cut -d' ' -f1)"
unset REQ REQ_PASS
if [[ "$GOT" != "$WANT" ]]; then
  set_status "rejected" "更新密碼不正確"
  logger -t mailcow-host-update "FAILED passphrase from ${REQ_USER}"
  sleep 3
  exit 1
fi

case "$REQ_ACTION" in
  apply|reboot) ;;
  *) set_status "rejected" "不支援的動作"
     logger -t mailcow-host-update "rejected action '${REQ_ACTION}' from ${REQ_USER}"
     exit 1;;
esac

# Cooldown applies to apply only; a reboot request should never be delayed.
if [[ "$REQ_ACTION" == "apply" && -f "$STATUS" ]]; then
  LAST_OK=$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(d.get("updated",0) if d.get("state")=="done" else 0)
except Exception:
    print(0)' "$STATUS" 2>/dev/null || echo 0)
  if (( LAST_OK > 0 && $(now) - LAST_OK < COOLDOWN )); then
    set_status "rejected" "距離上次主機更新未滿 $((COOLDOWN/60)) 分鐘，請稍後再試"
    exit 1
  fi
fi

logger -t mailcow-host-update "starting ${REQ_ACTION} requested by ${REQ_USER}"
if "$JOB" "--${REQ_ACTION}"; then
  logger -t mailcow-host-update "${REQ_ACTION} finished OK (requested by ${REQ_USER})"
else
  logger -t mailcow-host-update "${REQ_ACTION} FAILED (requested by ${REQ_USER})"
  exit 1
fi
