#!/usr/bin/env bash
# Re-verify the system after an update, without changing anything.
#
# The update page keeps showing the result of the LAST update run, so a problem that
# was fixed afterwards (e.g. a customisation re-applied by hand) stays red forever.
# This runs the same checks as step 5 of mailcow-oneclick-update.sh and records the
# outcome separately, so the page can show "resolved since" next to the old result.
#
# Read-only by design: it runs checks and the test suite, and never re-applies,
# restarts or edits anything. Triggered from the web through mailcow-updater-agent.sh
# (action "verify"), or by hand:  sudo ./helper-scripts/mailcow-verify.sh
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Container names follow the compose project name, which differs per install; read it
# from mailcow.conf instead of assuming the default "mailcowdockerized".
MC_PROJECT="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "${MAILCOW_DIR}/mailcow.conf" 2>/dev/null | tail -1 | tr -d '"'"'"'\r ')"
MC_PROJECT="${MC_PROJECT:-mailcowdockerized}"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
LOG="${UPDATER_DIR}/verify.log"
STATUS="${UPDATER_DIR}/verify-status.json"
REAPPLY="${MAILCOW_DIR}/helper-scripts/reapply-local-customizations.py"
TESTS="${MAILCOW_DIR}/helper-scripts/test-spammanager-release.php"
BY="${1:-host}"

[[ $EUID -eq 0 ]] || { echo "請以 root 執行：sudo $0" >&2; exit 1; }
cd "$MAILCOW_DIR" || exit 1
export HOME="${HOME:-/root}"

: > "$LOG"; chmod 0644 "$LOG"
CHECKS=()      # "ok|name|detail" or "bad|name|detail"
say()  { printf '\n==> %s\n' "$*" >> "$LOG"; }
info() { printf '    %s\n' "$*" >> "$LOG"; }
check() { CHECKS+=("$1|$2|$3"); [[ $1 == ok ]] && info "✓ $2：$3" || printf '!!  %s：%s\n' "$2" "$3" >> "$LOG"; }

write_status() { # state
  python3 -I - "$STATUS" "$1" "$BY" "${CHECKS[@]+"${CHECKS[@]}"}" <<'PY'
import json, sys, time
path, state, by, items = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
checks = []
for it in items:
    ok, name, detail = (it.split("|", 2) + ["", ""])[:3]
    checks.append({"ok": ok == "ok", "name": name, "detail": detail})
problems = [f'{c["name"]}：{c["detail"]}' for c in checks if not c["ok"]]
d = {"state": state, "verified": int(time.time()), "by": by, "checks": checks,
     "problems": problems,
     "result": "" if state == "running" else ("ok" if not problems else "problems")}
with open(path + ".tmp", "w", encoding="utf-8") as fh:
    json.dump(d, fh, ensure_ascii=False)
PY
  mv -f "${STATUS}.tmp" "$STATUS"; chmod 0644 "$STATUS"
}

write_status running
say "重新驗證 — $(date '+%Y-%m-%d %H:%M:%S')（由 ${BY} 觸發）"
info "版本：$(git describe --tags 2>/dev/null || echo unknown)"

say "1/4 本機自訂設定"
OUT="$(python3 -I "$REAPPLY" --check 2>&1)"; RC=$?
printf '%s\n' "$OUT" >> "$LOG"
if [[ $RC -eq 0 ]] && ! printf '%s' "$OUT" | grep -qE 'NEEDS-MANUAL|MISSING'; then
  pending=$(printf '%s\n' "$OUT" | grep -cE '^\s+.+\s{2,}APPLIED\s' || true)
  if [[ $pending -gt 0 ]]; then check bad "自訂設定" "${pending} 項待重新套用（執行 reapply-local-customizations.py --apply）"
  else check ok "自訂設定" "全部到位"; fi
else
  bad=$(printf '%s\n' "$OUT" | grep -E 'NEEDS-MANUAL|MISSING' | sed -E 's/^\s*-?\s*//; s/\s{2,}/ /g' | sort -u | head -3 | paste -sd'；')
  check bad "自訂設定" "${bad:-檢查失敗（結束碼 ${RC}）}"
fi

say "2/4 rspamd 設定"
if docker exec ${MC_PROJECT}-rspamd-mailcow-1 rspamadm configtest 2>&1 | tee -a "$LOG" | grep -q "syntax OK"; then
  check ok "rspamd 設定" "syntax OK"
else
  check bad "rspamd 設定" "configtest 未通過"
fi

say "3/4 容器狀態"
DOWN=$(docker ps -a --filter "name=${MC_PROJECT}" --format '{{.Names}} {{.Status}}' | grep -vE ' Up ' | awk '{print $1}' | paste -sd' ')
UP=$(docker ps --filter "name=${MC_PROJECT}" -q | wc -l)
if [[ -z "$DOWN" ]]; then check ok "容器" "${UP} 個全部運作中"; else check bad "容器" "未運作：${DOWN}"; fi

say "4/4 Spam Manager 功能測試"
if [[ -f "$TESTS" ]]; then
  # The suite submits a real request.json. We are running under mailcow-updater.service
  # (started by its path unit), so disarm the path unit or it would re-fire on that file.
  ARMED=0
  if systemctl is-active --quiet mailcow-updater.path; then ARMED=1; systemctl stop mailcow-updater.path; fi
  TEST_OUT="$(docker exec -i ${MC_PROJECT}-php-fpm-mailcow-1 php < "$TESTS" 2>&1)"
  rm -f "${UPDATER_DIR}/request.json"
  [[ $ARMED -eq 1 ]] && systemctl start mailcow-updater.path
  printf '%s\n' "$TEST_OUT" | grep -vE '^ok: ' >> "$LOG"
  printf '    （%s 項逐項檢查通過，已省略）\n' "$(printf '%s\n' "$TEST_OUT" | grep -c '^ok: ')" >> "$LOG"
  MISSED=""
  for m in "ALL PASS" "PART B PASS" "NOTIFY PASS" "CUSTOMIZATIONS PASS" "INBOUND NOTIFY PASS"; do
    printf '%s\n' "$TEST_OUT" | grep -qF "$m" || MISSED="${MISSED} ${m%% PASS}"
  done
  for g in "WEB UPDATE" "NAS BACKUP" "NAS RESTORE" "HOST UPDATE" "NAS SETUP"; do
    printf '%s\n' "$TEST_OUT" | grep -qE "${g} (PASS|SKIPPED)" || MISSED="${MISSED} ${g}"
  done
  FATAL=$(printf '%s\n' "$TEST_OUT" | grep -m1 -oE 'FAIL: [^"]{0,100}' || true)
  if [[ -z "$MISSED" ]]; then check ok "功能測試" "十組全部通過"
  else check bad "功能測試" "未通過：${MISSED# }${FATAL:+（${FATAL}）}"; fi
else
  check bad "功能測試" "找不到測試檔"
fi

write_status done
say "完成"
exit 0
