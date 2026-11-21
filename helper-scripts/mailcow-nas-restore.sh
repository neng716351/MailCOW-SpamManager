#!/usr/bin/env bash
# Restore mailcow from a backup held on the remote SMB NAS.
#
# Scope on purpose: the WEB UI may only restore the settings-class components
# (mysql, redis, rspamd, postfix). Restoring vmail or crypt can overwrite every mailbox,
# or leave mail unreadable when the crypt key no longer matches vmail, so those require
# --allow-mail, which only a human on the host can pass.
#
# Before touching anything this script verifies the archives, then snapshots the current
# mysql+redis locally so a bad restore can be rolled back.
#
# Usage (root):
#   mailcow-nas-restore.sh --backup mailcow-2026-10-30-12-00-00 --components "mysql redis"
#   ... [--allow-mail] [--no-snapshot] [--local <dir>]
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="/etc/mailcow-nas"
CRED_FILE="${CONF_DIR}/credentials"
TARGET_FILE="${CONF_DIR}/target.conf"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
STATUS="${UPDATER_DIR}/restore-status.json"
LOGFILE="${UPDATER_DIR}/restore.log"
LOCK="${UPDATER_DIR}/.restore.lock"
BACKUP_SH="${MAILCOW_DIR}/helper-scripts/backup_and_restore.sh"
BACKUP_IMAGE="ghcr.io/mailcow/backup:latest"
COMPOSE_FILE="${MAILCOW_DIR}/docker-compose.yml"
ENV_FILE="${MAILCOW_DIR}/.env"
SNAP_ROOT="${MAILCOW_DIR}/mailcow-local-fixes"
STAGE_ROOT="${MAILCOW_DIR}/mailcow-local-fixes/.staging"
KEY_FILE="${CONF_DIR}/backup.key"
ENC_MARKER="ENCRYPTION"
DECRYPTED=""
THREADS="${THREADS:-$(nproc 2>/dev/null || echo 2)}"
ARCH="$(uname -m)"

WEB_ALLOWED="mysql redis rspamd postfix"
MAIL_ONLY="vmail crypt"

BACKUP_NAME=""; COMPONENTS=""; LOCAL_DIR=""; ALLOW_MAIL=0; SNAPSHOT=1; MOUNTED=0

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup)     BACKUP_NAME="${2:-}"; shift 2 || true;;
    --components) COMPONENTS="${2:-}"; shift 2 || true;;
    --local)      LOCAL_DIR="${2:-}"; shift 2 || true;;
    --allow-mail) ALLOW_MAIL=1; shift;;
    --no-snapshot) SNAPSHOT=0; shift;;
    *) echo "未知參數：$1" >&2; exit 1;;
  esac
done

now() { date +%s; }
log() { printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOGFILE"; }
json_str() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'; }

set_status() { # state, message [extra]
  local state="$1" msg="$2" extra="${3:-}"
  {
    printf '{"state":%s,"message":%s,"updated":%s,"backup":%s,"components":%s' \
      "$(printf '%s' "$state" | json_str)" "$(printf '%s' "$msg" | json_str)" "$(now)" \
      "$(printf '%s' "${BACKUP_NAME}" | json_str)" "$(printf '%s' "${COMPONENTS}" | json_str)"
    [[ -n "$extra" ]] && printf ',%s' "$extra"
    printf '}\n'
  } > "${STATUS}.tmp" && mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

cleanup() {
  # Decrypted archives are plaintext mail and passwords; never leave them behind.
  if [[ -n "$DECRYPTED" && -d "$DECRYPTED" ]]; then
    find "$DECRYPTED" -type f -exec shred -u -n1 {} + 2>/dev/null
    rm -rf -- "$DECRYPTED" 2>/dev/null
    log "已覆寫刪除本機解密暫存"
    DECRYPTED=""
  fi
  if [[ $MOUNTED -eq 1 ]]; then
    sync
    umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null
    MOUNTED=0
    log "已卸載 NAS"
  fi
}
trap cleanup EXIT INT TERM

notify() { # subject, body
  local subj="$1" body="$2" to="" rp host
  rp="$(grep -E '^REDISPASS=' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | cut -d= -f2-)"
  if [[ -n "$rp" ]]; then
    for key in BACKUP_NOTIFY REJECTED_HOLD_NOTIFY; do
      to="$(docker exec mailcowdockerized-redis-mailcow-1 redis-cli -a "$rp" --no-auth-warning GET "$key" 2>/dev/null | tr -d '\r')"
      [[ -n "$to" && "$to" != "(nil)" ]] && break || to=""
    done
  fi
  [[ -n "$to" ]] || return 0
  host="$(grep -E '^MAILCOW_HOSTNAME=' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | cut -d= -f2-)"
  {
    printf 'To: %s\nFrom: Mail Restore <postmaster@%s>\n' "$to" "${host:-localhost}"
    printf 'Subject: =?UTF-8?B?%s?=\n' "$(printf '%s' "$subj" | base64 -w0)"
    printf 'Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n'
    printf '%s' "$body" | base64 -w0; printf '\n'
  } | docker exec -i mailcowdockerized-postfix-mailcow-1 sendmail -t -i 2>/dev/null || true
}

fail_out() {
  log "失敗：$1"
  set_status "error" "$1"
  notify "【Mailcow 還原失敗】" "還原未完成。

備份：${BACKUP_NAME:-未指定}
元件：${COMPONENTS:-未指定}
時間：$(date '+%F %T')
原因：$1

還原前快照：${SNAP_DIR:-未建立}
紀錄：${LOGFILE}"
  exit 1
}

install -d -m 0750 "$UPDATER_DIR" 2>/dev/null
: > "$LOGFILE"; chmod 0644 "$LOGFILE"

exec 9>"$LOCK"
flock -n 9 || { echo "已有還原正在執行" >&2; exit 0; }

# --- validate -----------------------------------------------------------------------
[[ -n "$BACKUP_NAME" ]] || { echo "請以 --backup 指定備份名稱" >&2; exit 1; }
[[ "$BACKUP_NAME" =~ ^mailcow-[0-9][0-9-]*$ ]] || { echo "備份名稱格式不正確：${BACKUP_NAME}" >&2; exit 1; }
[[ -n "$COMPONENTS" ]] || { echo "請以 --components 指定元件" >&2; exit 1; }

for c in $COMPONENTS; do
  if [[ " $WEB_ALLOWED " == *" $c "* ]]; then continue; fi
  if [[ " $MAIL_ONLY " == *" $c "* ]]; then
    if [[ $ALLOW_MAIL -eq 1 ]]; then continue; fi
    echo "元件 ${c} 會覆蓋信件資料，必須在主機以 --allow-mail 執行。" >&2
    exit 1
  fi
  echo "不支援的元件：${c}（可用：${WEB_ALLOWED} ${MAIL_ONLY}）" >&2
  exit 1
done

# --- locate the backup --------------------------------------------------------------
if [[ -n "$LOCAL_DIR" ]]; then
  MOUNTPOINT=""
  SRC="${LOCAL_DIR}/${BACKUP_NAME}"
  log "演練／本機模式：${SRC}"
else
  [[ -f "$TARGET_FILE" ]] || { echo "尚未設定 NAS，請先執行 setup-nas-backup.sh" >&2; exit 1; }
  # shellcheck disable=SC1090
  source "$TARGET_FILE"
  set_status "running" "正在掛載 NAS…"
  mountpoint -q "$MOUNTPOINT" && { umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null; }
  mount -t cifs "//${NAS_HOST}/${NAS_SHARE}" "$MOUNTPOINT" \
    -o "credentials=${CRED_FILE},vers=${NAS_VERS},uid=0,gid=0,file_mode=0600,dir_mode=0700,nosetuids,noexec,nodev" \
    || fail_out "無法掛載 //${NAS_HOST}/${NAS_SHARE}"
  MOUNTED=1
  SRC="${MOUNTPOINT}${NAS_PATH:+/$NAS_PATH}/${BACKUP_NAME}"
fi
[[ -d "$SRC" ]] || fail_out "找不到備份目錄：${BACKUP_NAME}"
log "來源：${SRC}"
log "要還原的元件：${COMPONENTS}"

# --- verify before touching anything ------------------------------------------------
set_status "running" "正在驗證備份完整性…"
if [[ -f "${SRC}/SHA256SUMS" ]]; then
  ( cd "$SRC" && sha256sum -c --quiet SHA256SUMS ) >>"$LOGFILE" 2>&1 \
    || fail_out "SHA256 校驗不符，這份備份已損壞，拒絕還原"
  log "SHA256 校驗通過"
else
  log "備份沒有 SHA256SUMS（舊版備份），改用 zstd -t 檢查"
fi

# --- decrypt, if this backup is encrypted -------------------------------------------
# The archives are decrypted into a local staging area, never back onto the share.
if [[ -f "${SRC}/${ENC_MARKER}" ]]; then
  log "這是加密備份（$(cat "${SRC}/${ENC_MARKER}" 2>/dev/null)）"
  command -v gpg >/dev/null 2>&1 || fail_out "找不到 gpg，無法解密備份"
  [[ -s "$KEY_FILE" ]] || fail_out "找不到加密金鑰 ${KEY_FILE}。若要在新主機還原，請先放回當初保管的金鑰"
  set_status "running" "正在解密到本機暫存…"
  install -d -m 0700 "$STAGE_ROOT" || fail_out "無法建立暫存目錄"
  AVAIL_KB="$(df --output=avail -k "$STAGE_ROOT" 2>/dev/null | tail -1 | tr -d ' ')"
  NEED_KB="$(du -sk "$SRC" 2>/dev/null | cut -f1)"
  NEED_KB=$(( ${NEED_KB:-0} * 2 ))
  if [[ -n "$AVAIL_KB" ]] && (( AVAIL_KB < NEED_KB )); then
    fail_out "本機暫存空間不足：可用 $((AVAIL_KB/1024)) MB，解密需要約 $((NEED_KB/1024)) MB"
  fi
  DECRYPTED="$(mktemp -d "${STAGE_ROOT}/restore-XXXXXX")" || fail_out "無法建立解密暫存目錄"
  chmod 0700 "$DECRYPTED"
  n=0
  for f in "$SRC"/*.gpg; do
    [[ -f "$f" ]] || continue
    b="$(basename "$f" .gpg)"
    if ! gpg --batch --yes --quiet --decrypt --passphrase-file "$KEY_FILE" \
           -o "${DECRYPTED}/${b}" "$f" 2>>"$LOGFILE"; then
      fail_out "解密 ${b} 失敗（金鑰不符或檔案已損壞）"
    fi
    n=$((n+1))
  done
  (( n > 0 )) || fail_out "加密備份內沒有任何 .gpg 檔案"
  log "已解密 ${n} 個檔案到本機暫存"
  SRC="$DECRYPTED"
fi
docker run --rm -v "${SRC}:/b:ro" "$BACKUP_IMAGE" \
  sh -c 'set -e; n=0; for f in /b/*.tar.zst; do [ -e "$f" ] || continue; zstd -t "$f"; n=$((n+1)); done; [ "$n" -gt 0 ]' \
  >>"$LOGFILE" 2>&1 || fail_out "壓縮檔完整性驗證失敗，拒絕還原"
log "壓縮檔完整性驗證通過"

for c in $COMPONENTS; do
  case "$c" in
    mysql)   [[ -f "${SRC}/backup_mariadb.tar.zst" || -d "${SRC}/mysql" || -f "${SRC}/backup_mysql.gz" ]] \
               || fail_out "備份內沒有資料庫檔案，無法還原 mysql"
             [[ -f "${SRC}/mailcow.conf" ]] \
               || fail_out "備份內沒有 mailcow.conf，上游還原邏輯需要它來對齊資料庫參數";;
    redis)   [[ -f "${SRC}/backup_redis.tar.zst"   ]] || fail_out "備份內沒有 redis 檔案";;
    rspamd)  [[ -f "${SRC}/backup_rspamd.tar.zst"  ]] || fail_out "備份內沒有 rspamd 檔案";;
    postfix) [[ -f "${SRC}/backup_postfix.tar.zst" ]] || fail_out "備份內沒有 postfix 檔案";;
    vmail)   [[ -f "${SRC}/backup_vmail.tar.zst"   ]] || fail_out "備份內沒有 vmail 檔案";;
    crypt)   [[ -f "${SRC}/backup_crypt.tar.zst"   ]] || fail_out "備份內沒有 crypt 檔案";;
  esac
done
log "元件檔案齊備"

# --- rollback snapshot --------------------------------------------------------------
SNAP_DIR=""
if [[ $SNAPSHOT -eq 1 ]]; then
  set_status "running" "正在快照目前的 mysql 與 redis（供退回用）…"
  SNAP_DIR="${SNAP_ROOT}/pre-restore-$(date +%Y%m%d-%H%M%S)"
  # 0755 for the same reason as the backup staging area: mailcow's script requires the
  # location to be writable by others. SNAP_ROOT is the mailcow dir, so keep the contents
  # restrictive instead — the archives themselves are written 0600/0644 by the containers.
  install -d -m 0755 "$SNAP_DIR" || fail_out "無法建立快照目錄"
  cp -p "${MAILCOW_DIR}/mailcow.conf" "${SNAP_DIR}/mailcow.conf.live" 2>/dev/null
  for part in mysql redis; do
    if ! MAILCOW_BACKUP_LOCATION="$SNAP_DIR" THREADS="$THREADS" \
          "$BACKUP_SH" backup "$part" >>"$LOGFILE" 2>&1; then
      fail_out "還原前快照失敗（${part}），為安全起見中止還原"
    fi
  done
  log "還原前快照完成：${SNAP_DIR}"
else
  log "已略過還原前快照（--no-snapshot）"
fi

# --- restore ------------------------------------------------------------------------
CMPS_PRJ="$(grep -E '^COMPOSE_PROJECT_NAME=' "${MAILCOW_DIR}/mailcow.conf" | cut -d= -f2- | tr -cd '[0-9A-Za-z-_]')"
[[ -n "$CMPS_PRJ" ]] || fail_out "無法取得 COMPOSE_PROJECT_NAME"
vol() { docker volume ls -qf "name=^${CMPS_PRJ}_${1}$"; }

untar_into() { # archive, volume, container-path
  local archive="$1" volume="$2" cpath="$3"
  local v; v="$(vol "$volume")"
  [[ -n "$v" ]] || fail_out "找不到 volume ${CMPS_PRJ}_${volume}"
  docker run -i --rm -v "${SRC}:/backup:ro,z" -v "${v}:${cpath}:z" \
    "$BACKUP_IMAGE" /bin/tar --use-compress-program="zstd -d -T${THREADS}" \
    -Pxvf "/backup/${archive}" >>"$LOGFILE" 2>&1
}

docker stop "$(docker ps -qf name=watchdog-mailcow)" >/dev/null 2>&1 && log "已停止 watchdog"

for c in $COMPONENTS; do
  set_status "running" "正在還原 ${c}…"
  log "還原 ${c}"
  case "$c" in
    redis)
      docker stop "$(docker ps -qf name=redis-mailcow)" >/dev/null 2>&1
      untar_into backup_redis.tar.zst redis-vol-1 /redis || fail_out "redis 還原失敗"
      docker start "$(docker ps -aqf name=redis-mailcow)" >/dev/null 2>&1
      ;;
    rspamd)
      # Upstream skips rspamd when the backup came from another CPU architecture.
      BK_ARCH="$(find "$SRC" \( -name '*x86*' -o -name '*aarch*' \) -exec basename {} \; 2>/dev/null | sed 's/^\.*//' | head -1)"
      if [[ -n "$BK_ARCH" && "$BK_ARCH" != "$ARCH" ]]; then
        log "略過 rspamd：備份架構 ${BK_ARCH} 與本機 ${ARCH} 不同"
        continue
      fi
      docker stop "$(docker ps -qf name=rspamd-mailcow)" >/dev/null 2>&1
      untar_into backup_rspamd.tar.zst rspamd-vol-1 /rspamd || fail_out "rspamd 還原失敗"
      docker start "$(docker ps -aqf name=rspamd-mailcow)" >/dev/null 2>&1
      ;;
    postfix)
      docker stop "$(docker ps -qf name=postfix-mailcow)" >/dev/null 2>&1
      untar_into backup_postfix.tar.zst postfix-vol-1 /postfix || fail_out "postfix 還原失敗"
      docker start "$(docker ps -aqf name=postfix-mailcow)" >/dev/null 2>&1
      ;;
    crypt)
      docker stop "$(docker ps -qf name=dovecot-mailcow)" >/dev/null 2>&1
      untar_into backup_crypt.tar.zst crypt-vol-1 /crypt || fail_out "crypt 還原失敗"
      docker start "$(docker ps -aqf name=dovecot-mailcow)" >/dev/null 2>&1
      ;;
    vmail)
      docker stop "$(docker ps -qf name=dovecot-mailcow)" >/dev/null 2>&1
      untar_into backup_vmail.tar.zst vmail-vol-1 /vmail || fail_out "vmail 還原失敗"
      docker start "$(docker ps -aqf name=dovecot-mailcow)" >/dev/null 2>&1
      log "提醒：信箱若有異常，可在主機執行 docker exec \$(docker ps -qf name=dovecot-mailcow) doveadm force-resync -A '*'"
      ;;
    mysql)
      SQLIMAGE="$(grep -iEo '(mysql|mariadb):.+' "$COMPOSE_FILE" | head -1)"
      [[ -n "$SQLIMAGE" ]] || fail_out "無法判斷 SQL image 版本"
      log "停止整個 stack（mysql 還原需要）"
      docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down >>"$LOGFILE" 2>&1 \
        || fail_out "無法停止 stack"
      MV="$(vol mysql-vol-1)"
      [[ -n "$MV" ]] || fail_out "找不到 mysql volume"
      if ! docker run --rm -v "${MV}:/backup_mariadb/:rw,z" --entrypoint= \
            -v "${SRC}:/backup:ro,z" "$SQLIMAGE" \
            /bin/bash -c "shopt -s dotglob; /bin/rm -rf /backup_mariadb/*; /bin/tar --use-compress-program='zstd -d -T${THREADS}' -Pxvf /backup/backup_mariadb.tar.zst" \
            >>"$LOGFILE" 2>&1; then
        docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d >>"$LOGFILE" 2>&1
        fail_out "資料庫還原失敗，已嘗試重新啟動 stack"
      fi
      # Align the live DB parameters with the restored dump, as upstream does. The live
      # file was copied into the snapshot above, so this stays reversible.
      log "依備份的 mailcow.conf 對齊資料庫參數"
      cp -p "${MAILCOW_DIR}/mailcow.conf" "${MAILCOW_DIR}/mailcow.conf.pre-restore-$(date +%Y%m%d-%H%M%S)"
      # Never eval or sed-interpolate values that came from the share: a tampered backup
      # would be command injection / pattern injection. Parse and rewrite in python.
      if ! python3 -I - "${SRC}/mailcow.conf" "${MAILCOW_DIR}/mailcow.conf" <<'PYRW'
import io, re, sys
src, live = sys.argv[1], sys.argv[2]
want = ("DBNAME", "DBUSER", "DBPASS", "DBROOT")
vals = {}
with io.open(src, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.rstrip("\n")
        for k in want:
            if line.startswith(k + "="):
                vals[k] = line[len(k) + 1:]
missing = [k for k in want if k not in vals]
if missing:
    sys.exit("備份的 mailcow.conf 缺少：" + ",".join(missing))
with io.open(live, encoding="utf-8") as fh:
    text = fh.read()
for k, v in vals.items():
    pattern = re.compile(r"^" + k + r"=.*$", re.M)
    if pattern.search(text):
        text = pattern.sub(lambda m, v=v, k=k: k + "=" + v, text, count=1)
    else:
        text = text.rstrip("\n") + "\n" + k + "=" + v + "\n"
with io.open(live, "w", encoding="utf-8") as fh:
    fh.write(text)
print("已更新 " + ", ".join(sorted(vals)))
PYRW
      then
        fail_out "無法依備份的 mailcow.conf 更新資料庫參數"
      fi
      log "重新啟動 stack"
      docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d >>"$LOGFILE" 2>&1 \
        || fail_out "stack 無法重新啟動，請立即在主機檢查"
      ;;
  esac
  log "${c} 還原完成"
done

docker start "$(docker ps -aqf name=watchdog-mailcow)" >/dev/null 2>&1 && log "已啟動 watchdog"

sleep 10
DOWN="$(docker ps -a --filter name=mailcowdockerized --filter status=exited --format '{{.Names}}' | tr '\n' ' ')"
cleanup
if [[ -n "$DOWN" ]]; then
  set_status "error" "還原完成但有容器未運行：${DOWN}"
  notify "【Mailcow 還原後有容器未運行】" "還原流程結束，但以下容器未運行：${DOWN}

備份：${BACKUP_NAME}
元件：${COMPONENTS}
還原前快照：${SNAP_DIR:-未建立}
紀錄：${LOGFILE}"
  exit 1
fi

set_status "done" "還原完成：${BACKUP_NAME}（${COMPONENTS}）" \
  "\"snapshot\":$(printf '%s' "${SNAP_DIR}" | json_str)"
log "全部完成。還原前快照：${SNAP_DIR:-未建立}"
logger -t mailcow-restore "restore OK: ${BACKUP_NAME} [${COMPONENTS}]"
notify "【Mailcow 還原完成】" "已還原 ${BACKUP_NAME}
元件：${COMPONENTS}
還原前快照：${SNAP_DIR:-未建立}

請確認：管理介面可登入、郵件可收發、設定是否為預期的內容。"
exit 0
