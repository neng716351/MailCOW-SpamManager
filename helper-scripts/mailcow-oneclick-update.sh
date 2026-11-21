#!/usr/bin/env bash
# One-click mailcow update that preserves this host's local customizations.
#
# Why this exists: update.sh runs `git merge -X theirs`, so tracked files we modified
# (rspamd metadata_exporter.conf, init_db.inc.php, postfix master.cf) can be reverted to
# the upstream version. This wrapper snapshots them, runs the official update, then
# re-applies the customizations idempotently and verifies the result.
#
# Run as root:  sudo ./helper-scripts/mailcow-oneclick-update.sh [update.sh args...]
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
SNAP_DIR="${MAILCOW_DIR}/mailcow-local-fixes/pre-update-${TS}"
LOG="${SNAP_DIR}/update.log"
REAPPLY="${MAILCOW_DIR}/helper-scripts/reapply-local-customizations.py"
TESTS="${MAILCOW_DIR}/helper-scripts/test-spammanager-release.php"

# Tracked files we have modified locally; these are what an update can revert.
CUSTOM_TRACKED=(
  "data/conf/rspamd/local.d/metadata_exporter.conf"
  "data/web/inc/init_db.inc.php"
  "data/web/templates/base.twig"
  "data/conf/postfix/master.cf"
  "data/conf/dovecot/auth/passwd-verify.lua"
  "data/conf/rspamd/custom/global_mime_from_whitelist.map"
  "data/web/inc/functions.rspamd.inc.php"
  "data/conf/rspamd/dynmaps/settings.php"
  "data/conf/rspamd/meta_exporter/pipe.php"
  "data/conf/rspamd/local.d/multimap.conf"
  "data/web/inc/vars.inc.php"
  "data/web/templates/qhandler.twig"
  "data/conf/rspamd/custom/global_smtp_from_blacklist.map"
)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*" | tee -a "$LOG"; }
info() { printf '    %s\n' "$*" | tee -a "$LOG"; }
PROBLEMS=0
fail() { PROBLEMS=$((PROBLEMS+1)); printf '\n\033[1;31m!!  %s\033[0m\n' "$*" | tee -a "$LOG"; }

if [[ $EUID -ne 0 ]]; then
  echo "請以 root 執行：sudo $0" >&2
  exit 1
fi
if [[ ! -x "${MAILCOW_DIR}/update.sh" ]]; then
  echo "找不到 ${MAILCOW_DIR}/update.sh" >&2
  exit 1
fi

mkdir -p "$SNAP_DIR"
cd "$MAILCOW_DIR" || exit 1

# A stray directory at /etc/gitconfig makes every git call fail, which would look exactly
# like a broken update. Catch it here with a clear message instead.
if [[ -d /etc/gitconfig ]]; then
  fail "/etc/gitconfig 是目錄而非檔案，git 無法運作。請先執行：sudo rmdir /etc/gitconfig"
  exit 1
fi

# We run as root but the repo is owned by the desktop user, so git refuses to work on it
# ("detected dubious ownership"). update.sh makes dozens of git calls, so without this the
# update silently does nothing. Scoped to this one directory.
export HOME="${HOME:-/root}"
if ! git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$MAILCOW_DIR"; then
  git config --global --add safe.directory "$MAILCOW_DIR"
  GIT_SAFE_ADDED=1
fi

say "Mailcow 一鍵更新 — ${TS}"
info "目錄：${MAILCOW_DIR}"
info "紀錄：${LOG}"
info "目前版本：$(git describe --tags 2>/dev/null || echo 'unknown')"
[[ -n "${GIT_SAFE_ADDED:-}" ]] && info "已將本目錄加入 git safe.directory（root 的 ~/.gitconfig）"

# ---------------------------------------------------------------- 1. 更新前快照
say "步驟 1/5：備份目前的自訂設定"
for f in "${CUSTOM_TRACKED[@]}"; do
  if [[ -f "$f" ]]; then
    mkdir -p "${SNAP_DIR}/$(dirname "$f")"
    cp -p "$f" "${SNAP_DIR}/$f"
    info "已備份 $f"
  fi
done
git status --porcelain > "${SNAP_DIR}/git-status-before.txt" 2>/dev/null
git describe --tags > "${SNAP_DIR}/version-before.txt" 2>/dev/null
info "快照目錄：${SNAP_DIR}"

say "步驟 2/5：更新前的自訂設定檢查"
python3 -I "$REAPPLY" --check 2>&1 | tee -a "$LOG"

# ---------------------------------------------------------------- 3. 官方更新
say "步驟 3/5：執行官方 update.sh（可能需要你確認，並會重啟服務）"
UPD_OUT="${SNAP_DIR}/update-sh.out"
./update.sh "$@" 2>&1 | tee -a "$LOG" "$UPD_OUT"
UPDATE_RC=${PIPESTATUS[0]}
# Newer update.sh first refreshes its own _modules and exits 2 asking to be restarted
# (seen 2026-11-21). That is not a failure: run it once more with the new modules.
if [[ $UPDATE_RC -eq 2 ]] && grep -qF "_modules have been updated" "$UPD_OUT"; then
  info "update.sh 已先更新自身模組並要求重新執行，自動再執行一次"
  ./update.sh "$@" 2>&1 | tee -a "$LOG"
  UPDATE_RC=${PIPESTATUS[0]}
fi
if [[ $UPDATE_RC -ne 0 ]]; then
  fail "update.sh 結束碼為 ${UPDATE_RC}。仍會檢查自訂設定，但請先確認上面的訊息。"
fi
info "更新後版本：$(git describe --tags 2>/dev/null || echo 'unknown')"

# ---------------------------------------------------------------- 4. 重新套用
say "步驟 4/5：重新套用本機自訂設定"
python3 -I "$REAPPLY" --apply 2>&1 | tee -a "$LOG"
REAPPLY_RC=${PIPESTATUS[0]}

say "重啟受影響的服務"
docker exec mailcowdockerized-php-fpm-mailcow-1 sh -c 'rm -rf /web/templates/cache/*' >/dev/null 2>&1 \
  && info "已清除 Twig 編譯快取" || info "略過 Twig 快取清除（容器尚未就緒）"
# The JS bundle in php-fpm /tmp can outlive a file change (see 2026-11-17); rebuilt on demand.
docker exec mailcowdockerized-php-fpm-mailcow-1 sh -c 'rm -f /tmp/*.js' >/dev/null 2>&1 \
  && info "已清除 JS 打包快取" || info "略過 JS 打包快取清除"
for c in rspamd-mailcow postfix-mailcow php-fpm-mailcow; do
  if docker restart "mailcowdockerized-${c}-1" >/dev/null 2>&1; then
    info "已重啟 ${c}"
  else
    fail "無法重啟 ${c}，請手動確認"
  fi
done

# ---------------------------------------------------------------- 5. 驗證
say "步驟 5/5：驗證"
sleep 15

if docker exec mailcowdockerized-rspamd-mailcow-1 rspamadm configtest 2>&1 | tee -a "$LOG" | grep -q "syntax OK"; then
  info "rspamd 設定：syntax OK"
else
  fail "rspamd configtest 未通過 — 請檢查 ${LOG}"
fi

DOWN=$(docker ps --filter "name=mailcowdockerized" --filter "status=exited" --format '{{.Names}}')
if [[ -n "$DOWN" ]]; then
  fail "以下容器未運行：${DOWN}"
else
  info "所有 mailcow 容器運行中（$(docker ps --filter 'name=mailcowdockerized' -q | wc -l) 個）"
fi

if [[ -f "$TESTS" ]]; then
  # The suite writes a real request.json; disarm the trigger so systemd does not race it.
  TRIGGER_WAS_ACTIVE=0
  if systemctl is-active --quiet mailcow-updater.path 2>/dev/null; then
    TRIGGER_WAS_ACTIVE=1
    systemctl stop mailcow-updater.path >/dev/null 2>&1 && info "已暫停更新觸發器以進行測試"
  fi

  TEST_OUT="$(docker exec -i mailcowdockerized-php-fpm-mailcow-1 php < "$TESTS" 2>&1)"
  printf '%s\n' "$TEST_OUT" | tee -a "$LOG"

  MISSED=""
  for marker in "ALL PASS" "PART B PASS" "NOTIFY PASS" "CUSTOMIZATIONS PASS" \
                "INBOUND NOTIFY PASS"; do
    printf '%s\n' "$TEST_OUT" | grep -qF "$marker" || MISSED="${MISSED} ${marker};"
  done
  # The web-update group submits a real request, which the product code refuses while an
  # update is in progress. Run from inside the update, "skipped" is the correct outcome.
  if ! printf '%s\n' "$TEST_OUT" | grep -qE "WEB UPDATE (PASS|SKIPPED)"; then
    MISSED="${MISSED} WEB UPDATE;"
  elif printf '%s\n' "$TEST_OUT" | grep -qF "WEB UPDATE SKIPPED"; then
    info "（網頁更新那組在更新進行中無法測試，已略過 — 這是預期行為）"
  fi
  # The NAS groups skip themselves when no NAS is configured yet.
  for grp in "NAS BACKUP" "NAS RESTORE" "HOST UPDATE" "NAS SETUP"; do
    if ! printf '%s\n' "$TEST_OUT" | grep -qE "${grp} (PASS|SKIPPED)"; then
      MISSED="${MISSED} ${grp};"
    fi
  done

  if [[ -z "$MISSED" ]]; then
    info "Spam Manager 功能測試：六組全部通過"
  else
    fail "Spam Manager 功能測試未通過，缺少：${MISSED}"
  fi

  if [[ $TRIGGER_WAS_ACTIVE -eq 1 ]]; then
    rm -f "${MAILCOW_DIR}/data/updater/request.json"
    systemctl start mailcow-updater.path >/dev/null 2>&1 && info "已恢復更新觸發器"
  fi
fi

# Files the update changed even after re-apply. Expected for files upstream edited and we
# re-patched; a map file (.map) listed here lost local entries -- restore it from the snapshot.
CHANGED=""
for f in "${CUSTOM_TRACKED[@]}"; do
  if [[ -f "${SNAP_DIR}/$f" ]] && ! cmp -s "${SNAP_DIR}/$f" "$f"; then CHANGED="${CHANGED} $f"; fi
done
if [[ -n "$CHANGED" ]]; then
  info "與更新前快照不同的自訂檔案（重新套用後）：${CHANGED}"
  for f in $CHANGED; do
    [[ "$f" == *.map ]] && fail "名單檔 $f 被更新改動，本機條目可能遺失；請比對 ${SNAP_DIR}/$f"
  done
else
  info "所有自訂檔案與更新前快照一致"
fi

say "完成"
python3 -I "$REAPPLY" --check 2>&1 | tee -a "$LOG"
info "完整紀錄：${LOG}"
info "更新前備份：${SNAP_DIR}"
if [[ $REAPPLY_RC -eq 2 ]]; then
  fail "有項目需要人工確認（見上方 NEEDS-MANUAL / MISSING）。"
fi
if [[ $UPDATE_RC -ne 0 ]]; then
  fail "update.sh 本身未成功（結束碼 ${UPDATE_RC}），這次並未完成版本更新。"
fi
echo

if [[ $PROBLEMS -gt 0 ]]; then
  fail "共 ${PROBLEMS} 項問題，請查看紀錄後再重試。"
  exit 1
fi
info "未發現問題。"
exit 0
