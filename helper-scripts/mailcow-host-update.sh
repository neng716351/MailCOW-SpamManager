#!/usr/bin/env bash
# Host OS maintenance for the mailcow machine.
#
# Division of labour, decided deliberately:
#   * unattended-upgrades applies everything that CANNOT interrupt mail. mailcow runs
#     entirely in containers, so host libraries, GNOME, fonts etc. are irrelevant to it.
#     A new kernel also installs safely, because installing one does not activate it.
#   * The packages whose INSTALL immediately restarts the container runtime
#     (docker.io, containerd, runc) are held back from the automatic path and only
#     applied here, when an admin asks for it.
#   * Rebooting is a separate explicit action, never automatic.
#
# Usage (root):
#   mailcow-host-update.sh --check     # refresh package lists, report, change nothing
#   mailcow-host-update.sh --apply     # apply everything incl. the deferred runtime pkgs
#   mailcow-host-update.sh --reboot    # reboot the host (activates a new kernel)
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
STATUS="${UPDATER_DIR}/host-status.json"
LOGFILE="${UPDATER_DIR}/host-update.log"
LOCK="${UPDATER_DIR}/.host-update.lock"
APT_CHECK="/usr/lib/update-notifier/apt_check.py"
# Packages whose upgrade restarts the container runtime, i.e. interrupts mail.
DEFERRED=(docker.io docker-ce docker-ce-cli containerd containerd.io runc)
ACTION=""

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)  ACTION="check";  shift;;
    --apply)  ACTION="apply";  shift;;
    --reboot) ACTION="reboot"; shift;;
    *) echo "未知參數：$1（可用 --check／--apply／--reboot）" >&2; exit 1;;
  esac
done
[[ -n "$ACTION" ]] || { echo "請指定 --check／--apply／--reboot" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

now() { date +%s; }
log() { printf '%s  %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOGFILE"; }
json_str() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'; }

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
    printf 'To: %s\nFrom: Host Maintenance <postmaster@%s>\n' "$to" "${host:-localhost}"
    printf 'Subject: =?UTF-8?B?%s?=\n' "$(printf '%s' "$subj" | base64 -w0)"
    printf 'Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n'
    printf '%s' "$body" | base64 -w0; printf '\n'
  } | docker exec -i mailcowdockerized-postfix-mailcow-1 sendmail -t -i 2>/dev/null || true
}

# --- facts about what is pending ----------------------------------------------------
collect() {
  AVAIL=0; SEC=0
  if [[ -x "$APT_CHECK" ]]; then
    # apt_check prints "total;security" on stderr
    local out; out="$("$APT_CHECK" 2>&1 | tail -1)"
    AVAIL="${out%%;*}"; SEC="${out##*;}"
    [[ "$AVAIL" =~ ^[0-9]+$ ]] || AVAIL=0
    [[ "$SEC"   =~ ^[0-9]+$ ]] || SEC=0
  else
    AVAIL="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
  fi
  # Which of the deferred packages actually have an upgrade waiting
  PENDING_DEFERRED=()
  local sim; sim="$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | awk '{print $2}')"
  for p in "${DEFERRED[@]}"; do
    grep -qx "$p" <<< "$sim" && PENDING_DEFERRED+=("$p")
  done
  REBOOT=false; REBOOT_PKGS=""
  if [[ -f /var/run/reboot-required ]]; then
    REBOOT=true
    REBOOT_PKGS="$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
  fi
  KERNEL_RUN="$(uname -r)"
  KERNEL_NEW="$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's#/boot/vmlinuz-##' | sort -V | tail -1)"
}

set_status() { # state, message
  local state="$1" msg="$2" dj
  # Build the array as JSON from arguments, not through a pipeline: with pipefail an empty
  # array made grep exit 1, the `||` fallback also fired, and the file got "[]" twice.
  dj="$(python3 -I -c 'import json,sys; print(json.dumps([a for a in sys.argv[1:] if a], ensure_ascii=False))' "${PENDING_DEFERRED[@]:-}")"
  [[ -n "$dj" ]] || dj='[]'

  cat > "${STATUS}.tmp" <<JSON
{"state":$(printf '%s' "$state" | json_str),
 "message":$(printf '%s' "$msg" | json_str),
 "updated":$(now),
 "available":${AVAIL:-0},
 "security":${SEC:-0},
 "deferred":${dj:-[]},
 "reboot_required":${REBOOT:-false},
 "reboot_pkgs":$(printf '%s' "${REBOOT_PKGS:-}" | json_str),
 "kernel_running":$(printf '%s' "${KERNEL_RUN:-}" | json_str),
 "kernel_installed":$(printf '%s' "${KERNEL_NEW:-}" | json_str),
 "checked":$(now)}
JSON
  mv -f "${STATUS}.tmp" "$STATUS"
  chmod 0644 "$STATUS" 2>/dev/null
}

install -d -m 0750 "$UPDATER_DIR" 2>/dev/null
exec 9>"$LOCK"
flock -n 9 || { echo "已有主機維護作業正在執行" >&2; exit 0; }

case "$ACTION" in
  check)
    : > "$LOGFILE"; chmod 0644 "$LOGFILE"
    log "重新讀取套件清單"
    collect; set_status "checking" "正在檢查…"
    apt-get update -qq >>"$LOGFILE" 2>&1 || log "警告：apt-get update 有錯誤，以下數字可能不是最新"
    collect
    log "待更新 ${AVAIL} 個（安全性 ${SEC} 個）"
    [[ ${#PENDING_DEFERRED[@]} -gt 0 ]] && log "延後中（需你按下套用）：${PENDING_DEFERRED[*]}" || log "沒有延後中的中斷型更新"
    [[ "$REBOOT" == "true" ]] && log "有待生效的更新需重開機：${REBOOT_PKGS}" || log "不需重開機"
    set_status "idle" "最後檢查：$(date '+%F %H:%M')"
    ;;

  apply)
    : > "$LOGFILE"; chmod 0644 "$LOGFILE"
    collect; set_status "applying" "正在套用主機更新（容器會短暫重啟）…"
    log "開始套用主機更新"
    log "注意：升級 docker.io／containerd 會重啟容器執行環境，郵件服務會短暫中斷"
    apt-get update -qq >>"$LOGFILE" 2>&1 || log "警告：apt-get update 有錯誤"
    if ! apt-get "${APT_OPTS[@]}" upgrade >>"$LOGFILE" 2>&1; then
      collect; set_status "error" "apt-get upgrade 失敗，詳見紀錄"
      log "失敗：apt-get upgrade"
      notify "【主機更新失敗】" "apt-get upgrade 未成功。

時間：$(date '+%F %T')
紀錄：${LOGFILE}
       journalctl -t mailcow-host-update -n 50"
      exit 1
    fi
    apt-get "${APT_OPTS[@]}" autoremove >>"$LOGFILE" 2>&1 || log "警告：autoremove 有錯誤"
    log "等待容器回復"
    sleep 20
    DOWN="$(docker ps -a --filter name=mailcowdockerized --filter status=exited --format '{{.Names}}' | tr '\n' ' ')"
    UP="$(docker ps --filter name=mailcowdockerized -q | wc -l)"
    collect
    if [[ -n "$DOWN" ]]; then
      set_status "error" "更新完成但有容器未運行：${DOWN}"
      log "警告：未運行的容器：${DOWN}"
      notify "【主機更新後有容器未運行】" "主機套件已更新，但以下容器未運行：${DOWN}

時間：$(date '+%F %T')
紀錄：${LOGFILE}"
      exit 1
    fi
    log "容器 ${UP} 個運行中"
    if [[ "$REBOOT" == "true" ]]; then
      set_status "done" "更新完成（${UP} 個容器正常）。有更新需重開機才生效，請自行選擇時機。"
      log "完成。仍需重開機才能讓部分更新（如核心）生效：${REBOOT_PKGS}"
      notify "【主機更新完成，待重開機】" "主機套件更新完成，容器 ${UP} 個運行中。

以下更新需要重開機才生效：${REBOOT_PKGS}
執行中核心：${KERNEL_RUN}
已安裝最新核心：${KERNEL_INSTALLED:-${KERNEL_NEW}}

重開機不會自動進行。請在離峰時段由 Spam Manager 頁面或主機觸發。"
    else
      set_status "done" "更新完成（${UP} 個容器正常），不需重開機。"
      log "完成，不需重開機"
      notify "【主機更新完成】" "主機套件更新完成，容器 ${UP} 個運行中，不需重開機。

時間：$(date '+%F %T')"
    fi
    logger -t mailcow-host-update "apply finished: containers=${UP} reboot_required=${REBOOT}"
    ;;

  reboot)
    collect
    log "已收到重開機指示"
    notify "【主機重開機】" "mailcow 主機正在重開機以讓更新生效。

執行中核心：${KERNEL_RUN}
已安裝核心：${KERNEL_NEW}
待生效套件：${REBOOT_PKGS:-（未列出）}

重開期間郵件服務中斷，容器設定為 always 重啟，開機後會自動回復。"
    set_status "rebooting" "主機正在重開機…"
    logger -t mailcow-host-update "reboot requested; rebooting now"
    log "立即重開機"
    # Immediate, by request (2026-11-21). --no-block queues the reboot job with systemd
    # and returns, so this oneshot unit finishes cleanly instead of being torn down
    # mid-run. (A backgrounded "sleep; reboot" never worked here: systemd kills leftover
    # processes in the unit's cgroup when the unit ends.)
    systemctl reboot --no-block || { set_status "error" "無法重開機，請在主機執行 sudo reboot"; exit 1; }
    ;;
esac
exit 0
