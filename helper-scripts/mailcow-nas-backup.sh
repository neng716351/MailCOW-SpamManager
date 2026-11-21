#!/usr/bin/env bash
# Back mailcow up to the remote SMB/CIFS NAS, encrypted.
#
# Order matters: the backup is written and encrypted LOCALLY first, and only the encrypted
# files are copied to the share. Encrypting in place on the NAS would leave the plaintext
# there first, which is exactly what we are trying to avoid.
#
# Encryption is gpg symmetric AES256 with the key in /etc/mailcow-nas/backup.key (root
# 0600). The key is deliberately NOT on the NAS, which is what makes this worth doing:
# whoever can read the share still cannot read the mail or the passwords.
#   *** Losing that key means every backup is permanently unreadable. ***
#
# Run as root:  sudo ./helper-scripts/mailcow-nas-backup.sh [--local <dir>] [--no-encrypt]
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Container names follow the compose project name, which differs per install; read it
# from mailcow.conf instead of assuming the default "mailcowdockerized".
MC_PROJECT="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | tail -1 | tr -d '"'"'"'\r ')"
MC_PROJECT="${MC_PROJECT:-mailcowdockerized}"
CONF_DIR="/etc/mailcow-nas"
CRED_FILE="${CONF_DIR}/credentials"
TARGET_FILE="${CONF_DIR}/target.conf"
KEY_FILE="${CONF_DIR}/backup.key"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
STATUS="${UPDATER_DIR}/backup-status.json"
LOGFILE="${UPDATER_DIR}/backup.log"
LOCK="${UPDATER_DIR}/.backup.lock"
BACKUP_SH="${MAILCOW_DIR}/helper-scripts/backup_and_restore.sh"
BACKUP_IMAGE="ghcr.io/mailcow/backup:latest"
STAGE_ROOT="${MAILCOW_DIR}/mailcow-local-fixes/.staging"
THREADS="${THREADS:-$(nproc 2>/dev/null || echo 2)}"
ENC_MARKER="ENCRYPTION"
ENC_TAG="gpg-symmetric-aes256"
LOCAL_DIR=""; ENCRYPT=1; MOUNTED=0; STAGE=""; ENCDIR=""

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)      LOCAL_DIR="${2:-}"; shift 2 || true;;
    --no-encrypt) ENCRYPT=0; shift;;
    *) echo "未知參數：$1" >&2; exit 1;;
  esac
done

now() { date +%s; }
log() { printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOGFILE"; }
json_str() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'; }

set_status() { # state, message [extra]
  local state="$1" msg="$2" extra="${3:-}"
  {
    printf '{"state":%s,"message":%s,"updated":%s,"target":%s,"retention":%s,"encrypted":%s' \
      "$(printf '%s' "$state" | json_str)" "$(printf '%s' "$msg" | json_str)" "$(now)" \
      "$(printf '%s' "${TARGET_DESC:-未設定}" | json_str)" "${KEEP:-0}" \
      "$([[ $ENCRYPT -eq 1 ]] && echo true || echo false)"
    [[ -n "$extra" ]] && printf ',%s' "$extra"
    printf '}\n'
  } > "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

# Plaintext must not survive a failure, so wipe staging on every exit path.
cleanup() {
  for d in "$STAGE" "$ENCDIR"; do
    [[ -n "$d" && -d "$d" ]] || continue
    find "$d" -type f -exec shred -u -n1 {} + 2>/dev/null || rm -rf -- "$d" 2>/dev/null
    rm -rf -- "$d" 2>/dev/null
  done
  if [[ $MOUNTED -eq 1 ]]; then
    sync
    umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null
    MOUNTED=0; log "已卸載 NAS"
  fi
}
trap cleanup EXIT INT TERM

notify() { # subject, body
  local subj="$1" body="$2" to="" rp host
  rp="$(grep -E '^REDISPASS=' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | cut -d= -f2-)"
  if [[ -n "$rp" ]]; then
    for key in BACKUP_NOTIFY REJECTED_HOLD_NOTIFY; do
      to="$(docker exec ${MC_PROJECT}-redis-mailcow-1 redis-cli -a "$rp" --no-auth-warning GET "$key" 2>/dev/null | tr -d '\r')"
      [[ -n "$to" && "$to" != "(nil)" ]] && break || to=""
    done
  fi
  [[ -n "$to" ]] || { log "未設定通知收件人，略過寄信"; return 0; }
  host="$(grep -E '^MAILCOW_HOSTNAME=' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | cut -d= -f2-)"
  {
    printf 'To: %s\nFrom: Mail Backup <postmaster@%s>\n' "$to" "${host:-localhost}"
    printf 'Subject: =?UTF-8?B?%s?=\n' "$(printf '%s' "$subj" | base64 -w0)"
    printf 'Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n'
    printf '%s' "$body" | base64 -w0; printf '\n'
  } | docker exec -i ${MC_PROJECT}-postfix-mailcow-1 sendmail -t -i 2>/dev/null \
    && log "已寄出通知給 ${to}" || log "警告：通知寄送失敗"
}

fail_out() {
  log "失敗：$1"
  set_status "error" "$1"
  notify "【Mailcow 備份失敗】" "備份未成功完成。

目標：${TARGET_DESC:-未設定}
時間：$(date '+%F %T')
原因：$1

紀錄：journalctl -t mailcow-backup -n 50
      ${LOGFILE}

備份失敗代表目前沒有新的可用備份，請儘快處理。"
  exit 1
}

install -d -m 0750 "$UPDATER_DIR" 2>/dev/null
: > "$LOGFILE"; chmod 0644 "$LOGFILE"
exec 9>"$LOCK"
flock -n 9 || { log "已有備份正在執行，結束本次"; exit 0; }

# --- preconditions ------------------------------------------------------------------
if [[ $ENCRYPT -eq 1 ]]; then
  command -v gpg >/dev/null 2>&1 || fail_out "找不到 gpg，無法加密備份"
  [[ -s "$KEY_FILE" ]] || fail_out "找不到加密金鑰 ${KEY_FILE}，請執行 setup-nas-backup.sh"
  [[ "$(stat -c '%a' "$KEY_FILE")" == "600" ]] || fail_out "${KEY_FILE} 權限必須是 600"
fi

if [[ -n "$LOCAL_DIR" ]]; then
  KEEP="${KEEP:-8}"; MOUNTPOINT=""
  DEST="$LOCAL_DIR"; TARGET_DESC="本機：${LOCAL_DIR}"
  mkdir -p "$DEST" 2>/dev/null; [[ -d "$DEST" ]] || fail_out "無法建立 ${DEST}"
  log "本機模式，不掛載 NAS"
else
  [[ -f "$TARGET_FILE" ]] || { echo "尚未設定 NAS，請先執行 setup-nas-backup.sh" >&2; exit 1; }
  # shellcheck disable=SC1090
  source "$TARGET_FILE"
  TARGET_DESC="//${NAS_HOST}/${NAS_SHARE}${NAS_PATH:+/$NAS_PATH}"
  log "目標：${TARGET_DESC}（保留 ${KEEP} 份，加密：$([[ $ENCRYPT -eq 1 ]] && echo 是 || echo 否)）"
  set_status "running" "正在掛載 NAS…"
  mountpoint -q "$MOUNTPOINT" && { umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null; }
  mount -t cifs "//${NAS_HOST}/${NAS_SHARE}" "$MOUNTPOINT" \
    -o "credentials=${CRED_FILE},vers=${NAS_VERS},uid=0,gid=0,file_mode=0600,dir_mode=0700,nosetuids,noexec,nodev" \
    || fail_out "無法掛載 //${NAS_HOST}/${NAS_SHARE}（請確認 NAS 開機、網路可達、帳密與 SMB 版本）"
  MOUNTED=1; log "已掛載 ${MOUNTPOINT}"
  DEST="${MOUNTPOINT}${NAS_PATH:+/$NAS_PATH}"
  mkdir -p "$DEST" 2>/dev/null
  [[ -d "$DEST" ]] || fail_out "無法在 NAS 上建立目錄 ${DEST}"
fi

# --- space: both the local staging area and the target need room --------------------
space_ok() { # path, label
  local path="$1" label="$2" avail need last
  avail="$(df --output=avail -k "$path" 2>/dev/null | tail -1 | tr -d ' ')"
  last="$(du -sk "$DEST"/mailcow-* 2>/dev/null | sort -rn | head -1 | cut -f1)"
  need=$(( ${last:-0} * 2 )); (( need < 2097152 )) && need=2097152
  if [[ -n "$avail" ]] && (( avail < need )); then
    fail_out "${label}空間不足：可用 $((avail/1024)) MB，需要約 $((need/1024)) MB"
  fi
  log "${label}可用空間 $((${avail:-0}/1024)) MB"
}
install -d -m 0700 "$STAGE_ROOT" || fail_out "無法建立暫存目錄"
space_ok "$STAGE_ROOT" "本機暫存"
space_ok "$DEST" "目標"

# --- 1. local backup ----------------------------------------------------------------
set_status "running" "備份進行中（dovecot／postfix／redis／rspamd 會短暫停止）…"
STAGE="$(mktemp -d "${STAGE_ROOT}/backup-XXXXXX")" || fail_out "無法建立暫存目錄"
# mailcow's own backup script refuses a location whose mode does not end in 5-7, because
# the backup containers write into it as a non-root user. 0755 satisfies that, and the
# plaintext stays unreachable to local users because STAGE_ROOT above is 0700 root-owned —
# the Docker daemon runs as root, so the bind mount is unaffected by that.
chmod 0755 "$STAGE"
log "本機暫存：${STAGE}（父目錄 0700，僅 root 與 Docker 可達）"
# PIPESTATUS must be read by the very next command: anything in between, even ":",
# overwrites it, which would silently turn a failed backup into a reported success.
# grep itself exits 1 when it filters out every line, so only element 0 is meaningful.
MAILCOW_BACKUP_LOCATION="$STAGE" THREADS="$THREADS" \
  "$BACKUP_SH" backup all 2>&1 \
  | grep --line-buffered -vE '^(/|\./)(vmail|redis|rspamd|postfix|crypt|var)/' \
  >> "$LOGFILE"
BACKUP_RC=${PIPESTATUS[0]}
if (( BACKUP_RC != 0 )); then
  fail_out "backup_and_restore.sh 回報失敗（結束碼 ${BACKUP_RC}），詳見紀錄"
fi
SRC_DIR="$(ls -1d "$STAGE"/mailcow-* 2>/dev/null | head -1)"
[[ -n "$SRC_DIR" && -d "$SRC_DIR" ]] || fail_out "備份結束但找不到產生的備份目錄"
NAME="$(basename "$SRC_DIR")"
log "已產生 ${NAME}"

# --- 2. verify the plaintext archives before encrypting -----------------------------
set_status "running" "正在驗證壓縮檔完整性…"
docker run --rm -v "${SRC_DIR}:/b:ro" "$BACKUP_IMAGE" \
  sh -c 'set -e; n=0; for f in /b/*.tar.zst; do [ -e "$f" ] || continue; zstd -t "$f"; n=$((n+1)); done; [ "$n" -gt 0 ]' \
  >>"$LOGFILE" 2>&1 || fail_out "壓縮檔完整性驗證失敗（zstd -t），不上傳這份備份"
log "壓縮檔完整性驗證通過"

# --- 3. encrypt locally -------------------------------------------------------------
if [[ $ENCRYPT -eq 1 ]]; then
  set_status "running" "正在加密…"
  ENCDIR="$(mktemp -d "${STAGE_ROOT}/enc-XXXXXX")" || fail_out "無法建立加密暫存目錄"
  chmod 0700 "$ENCDIR"
  OUT="${ENCDIR}/${NAME}"; mkdir -p "$OUT"
  shopt -s dotglob     # keep the hidden ".<arch>" marker; unset after the upload
  for f in "$SRC_DIR"/*; do
    [[ -f "$f" ]] || continue
    b="$(basename "$f")"
    # .tar.zst and the dump are already compressed; compressing again just costs time.
    if ! gpg --batch --yes --quiet --symmetric --cipher-algo AES256 --compress-algo none \
           --passphrase-file "$KEY_FILE" -o "${OUT}/${b}.gpg" "$f" 2>>"$LOGFILE"; then
      fail_out "加密 ${b} 失敗"
    fi
  done
  printf '%s\n' "$ENC_TAG" > "${OUT}/${ENC_MARKER}"
  # Hashes of the ENCRYPTED files, so integrity can be checked on the NAS without the key.
  ( cd "$OUT" && sha256sum ./*.gpg > SHA256SUMS ) || fail_out "無法寫入 SHA256SUMS"
  UPLOAD_FROM="$OUT"
  log "已加密 $(ls -1 "$OUT"/*.gpg | wc -l) 個檔案（AES256）"
else
  ( cd "$SRC_DIR" && sha256sum ./*.tar.zst > SHA256SUMS ) 2>/dev/null
  UPLOAD_FROM="$SRC_DIR"
  log "未加密（--no-encrypt）"
fi

# --- 4. upload and verify on the target ---------------------------------------------
set_status "running" "正在上傳到目標…"
TARGET_PATH="${DEST}/${NAME}"
mkdir -p "$TARGET_PATH" 2>/dev/null
[[ -d "$TARGET_PATH" ]] || fail_out "無法在目標建立 ${NAME}"
# "/." copies the contents including dotfiles, whatever the glob settings are.
cp -a "$UPLOAD_FROM"/. "$TARGET_PATH"/ 2>>"$LOGFILE" || fail_out "上傳失敗"
shopt -u dotglob
sync
if ! ( cd "$TARGET_PATH" && sha256sum -c --quiet SHA256SUMS ) >>"$LOGFILE" 2>&1; then
  rm -rf -- "$TARGET_PATH"
  fail_out "上傳後校驗不符，已移除目標上這份不完整的備份"
fi
log "上傳完成並通過 SHA256 校驗"
TOTAL="$(du -sh "$TARGET_PATH" 2>/dev/null | cut -f1)"

# Wipe the local plaintext now; it is no longer needed.
find "$STAGE" -type f -exec shred -u -n1 {} + 2>/dev/null
rm -rf -- "$STAGE"; STAGE=""
[[ -n "$ENCDIR" ]] && { rm -rf -- "$ENCDIR"; ENCDIR=""; }
log "已清除本機暫存（明文已覆寫刪除）"

# --- 5. prune -----------------------------------------------------------------------
mapfile -t ALL < <(ls -1d "$DEST"/mailcow-* 2>/dev/null | sort -r)
PRUNED=0
if (( ${#ALL[@]} > KEEP )); then
  for old in "${ALL[@]:KEEP}"; do
    rm -rf -- "$old" && { log "已刪除過期備份 $(basename "$old")"; PRUNED=$((PRUNED+1)); }
  done
fi

LIST_JSON="$(cd "$DEST" && ls -1d mailcow-* 2>/dev/null | sort -r | head -20 | while read -r d; do
  printf '%s\t%s\t%s\n' "$d" "$(du -sh "$d" 2>/dev/null | cut -f1)" "$([[ -f "$d/ENCRYPTION" ]] && echo 1 || echo 0)"
done | python3 -c '
import sys, json
out=[]
for line in sys.stdin:
    p=line.rstrip("\n").split("\t")
    if p and p[0]:
        out.append({"name":p[0],"size":p[1] if len(p)>1 else "","encrypted":(len(p)>2 and p[2]=="1")})
print(json.dumps(out, ensure_ascii=False))')"

cleanup
set_status "done" "備份完成：${NAME}（${TOTAL}${ENCRYPT:+，已加密}）" \
  "\"last_success\":$(now),\"last_name\":$(printf '%s' "$NAME" | json_str),\"last_size\":$(printf '%s' "${TOTAL:-}" | json_str),\"pruned\":${PRUNED},\"backups\":${LIST_JSON:-[]}"
log "完成。保留 ${KEEP} 份，本次刪除 ${PRUNED} 份"
logger -t mailcow-backup "backup OK: ${NAME} (${TOTAL}) encrypted=${ENCRYPT} → ${TARGET_DESC}"
exit 0
