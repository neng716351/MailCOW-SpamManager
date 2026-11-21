#!/usr/bin/env bash
# Apply a NAS backup configuration non-interactively.
#
# Single implementation shared by the interactive host setup and the web agent, so the two
# paths cannot drift. Everything that touches secrets happens here, as root:
#   * the SMB password is written only to /etc/mailcow-nas/credentials (0600)
#   * the backup encryption key is generated here if missing and NEVER echoed to a caller
#     that did not ask for it, because the web layer must not see it
#
# Input is a root-only JSON file so no secret ever appears in a command line (argv is
# world-readable via /proc). Keys:
#   nas_host, nas_share, nas_path, nas_user, nas_domain, nas_pass, nas_vers, keep
#
# Usage (root):  mailcow-nas-configure.sh --from-json /root-only/path.json
set -uo pipefail

MAILCOW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="/etc/mailcow-nas"
CRED_FILE="${CONF_DIR}/credentials"
TARGET_FILE="${CONF_DIR}/target.conf"
KEY_FILE="${CONF_DIR}/backup.key"
MOUNTPOINT="/mnt/mailcow-nas"
UPDATER_DIR="${MAILCOW_DIR}/data/updater"
JOB="${MAILCOW_DIR}/helper-scripts/mailcow-nas-backup.sh"
AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-backup-agent.sh"
RESTORE_AGENT="${MAILCOW_DIR}/helper-scripts/mailcow-restore-agent.sh"
PHP_UID=82
JSON=""
KEY_CREATED=0

[[ $EUID -eq 0 ]] || { echo "請以 root 執行" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-json) JSON="${2:-}"; shift 2 || true;;
    *) echo "未知參數：$1" >&2; exit 1;;
  esac
done
[[ -n "$JSON" && -f "$JSON" ]] || { echo "找不到設定檔：${JSON}" >&2; exit 1; }

command -v gpg        >/dev/null 2>&1 || { echo "缺少 gnupg，備份加密需要它" >&2; exit 1; }
command -v mount.cifs >/dev/null 2>&1 || { echo "缺少 cifs-utils（mount.cifs）" >&2; exit 1; }

# --- read and validate --------------------------------------------------------------
# Validation lives in python so the values never touch the shell before they are checked.
VALID="$(python3 -I - "$JSON" <<'PY'
import io, json, re, sys
try:
    with io.open(sys.argv[1], encoding="utf-8") as fh:
        d = json.load(fh)
except Exception as e:
    sys.exit("設定檔無法解析：%s" % e)

def get(k, default=""):
    v = d.get(k, default)
    return "" if v is None else str(v)

host   = get("nas_host").strip()
share  = get("nas_share").strip()
path   = get("nas_path").strip().strip("/")
user   = get("nas_user").strip()
domain = get("nas_domain").strip()
pw     = get("nas_pass")
vers   = get("nas_vers", "3.0").strip() or "3.0"
keep   = get("keep", "8").strip() or "8"

errs = []
if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", host):
    errs.append("伺服器位址只能是主機名稱或 IP（英數、點、底線、減號）")
if not re.fullmatch(r"[A-Za-z0-9._$ -]{1,80}", share):
    errs.append("分享名稱含不允許的字元")
if path and (not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", path) or ".." in path):
    errs.append("子目錄只能是英數、點、底線、減號與斜線，且不可含 ..")
if not re.fullmatch(r"[A-Za-z0-9._@\\-]{1,128}", user):
    errs.append("使用者名稱含不允許的字元")
if domain and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", domain):
    errs.append("網域含不允許的字元")
if not pw:
    errs.append("密碼不可為空")
elif "\n" in pw or "\r" in pw:
    errs.append("密碼不可含換行")          # would break the credentials file format
elif len(pw) > 256:
    errs.append("密碼過長")
if vers not in ("1.0", "2.0", "2.1", "3.0", "3.02", "3.1.1"):
    errs.append("SMB 版本不在允許清單內")
if not re.fullmatch(r"[1-9][0-9]?", keep):
    errs.append("保留份數必須是 1-99 的整數")
if errs:
    sys.exit("；".join(errs))

# Emit the non-secret values for the shell; the password stays in the JSON file.
print("\n".join([host, share, path, user, domain, vers, keep]))
PY
)" || { echo "設定內容有問題：${VALID:-未知}" >&2; exit 1; }

{ read -r NAS_HOST; read -r NAS_SHARE; read -r NAS_PATH; read -r NAS_USER
  read -r NAS_DOMAIN; read -r NAS_VERS; read -r KEEP; } <<< "$VALID"

echo "==> 套用 NAS 設定：//${NAS_HOST}/${NAS_SHARE}${NAS_PATH:+/$NAS_PATH}（保留 ${KEEP} 份）"
install -d -m 0700 "$CONF_DIR"

# --- encryption key: generate if missing, never overwrite ----------------------------
# Overwriting it would make every existing backup permanently unreadable.
if [[ ! -s "$KEY_FILE" ]]; then
  ( umask 077; head -c 48 /dev/urandom | base64 -w0 > "$KEY_FILE"; printf '\n' >> "$KEY_FILE" )
  chmod 0600 "$KEY_FILE"
  KEY_CREATED=1
  echo "    已產生備份加密金鑰：${KEY_FILE}"
else
  echo "    已存在加密金鑰，保留不變（覆寫會使現有備份無法解密）"
fi

# --- credentials --------------------------------------------------------------------
# Written by python straight from the JSON, so the password never becomes a shell word.
python3 -I - "$JSON" "$CRED_FILE" "$NAS_DOMAIN" <<'PY' || { echo "無法寫入認證檔" >&2; exit 1; }
import io, json, os, sys
cfg, out, domain = sys.argv[1], sys.argv[2], sys.argv[3]
with io.open(cfg, encoding="utf-8") as fh:
    d = json.load(fh)
lines = ["username=%s" % str(d.get("nas_user", "")).strip(),
         "password=%s" % str(d.get("nas_pass", ""))]
if domain:
    lines.append("domain=%s" % domain)
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
chmod 0600 "$CRED_FILE"
echo "    認證已寫入（root 專屬 0600）"

cat > "$TARGET_FILE" <<CONF
# Written by mailcow-nas-configure.sh. No secrets here; the password is in credentials.
NAS_HOST="${NAS_HOST}"
NAS_SHARE="${NAS_SHARE}"
NAS_PATH="${NAS_PATH}"
NAS_VERS="${NAS_VERS}"
MOUNTPOINT="${MOUNTPOINT}"
KEEP="${KEEP}"
CONF
chmod 0640 "$TARGET_FILE"
install -d -m 0755 "$MOUNTPOINT"

# --- prove it works before we claim success -----------------------------------------
echo "==> 測試掛載與寫入"
mountpoint -q "$MOUNTPOINT" && { umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null; }
if ! mount -t cifs "//${NAS_HOST}/${NAS_SHARE}" "$MOUNTPOINT" \
      -o "credentials=${CRED_FILE},vers=${NAS_VERS},uid=0,gid=0,file_mode=0600,dir_mode=0700,nosetuids,noexec,nodev"; then
  echo "    掛載失敗：請確認 NAS 開機、網路可達、帳密正確，或改用其他 SMB 版本（2.1／3.1.1）" >&2
  exit 1
fi
PROBE="${MOUNTPOINT}${NAS_PATH:+/$NAS_PATH}"
mkdir -p "$PROBE" 2>/dev/null     # cifs rejects chmod; mode comes from the mount options
if [[ ! -d "$PROBE" ]]; then
  echo "    掛載成功但無法建立 ${NAS_PATH}，請檢查分享權限" >&2
  umount "$MOUNTPOINT" 2>/dev/null; exit 1
fi
if ! ( echo probe > "${PROBE}/.mailcow-write-test" && rm -f "${PROBE}/.mailcow-write-test" ); then
  echo "    掛載成功但無法寫入，請檢查分享權限" >&2
  umount "$MOUNTPOINT" 2>/dev/null; exit 1
fi
FREE="$(df -h --output=avail "$PROBE" 2>/dev/null | tail -1 | tr -d ' ')"
umount "$MOUNTPOINT" 2>/dev/null || umount -l "$MOUNTPOINT" 2>/dev/null
echo "    掛載、寫入、卸載測試通過。NAS 可用空間：${FREE:-未知}"

# --- hand the non-secret description to the web layer -------------------------------
install -d -m 0750 "$UPDATER_DIR"
chown "${PHP_UID}:${PHP_UID}" "$UPDATER_DIR"
cat > "${UPDATER_DIR}/backup-target.json" <<JSON
{"target":"//${NAS_HOST}/${NAS_SHARE}${NAS_PATH:+/$NAS_PATH}","retention":${KEEP},"schedule":"每週日 03:00","configured":true,"encrypted":true,"free":"${FREE:-}"}
JSON
chmod 0644 "${UPDATER_DIR}/backup-target.json"

# --- systemd units ------------------------------------------------------------------
echo "==> 安裝 systemd 單元"
cat > /etc/systemd/system/mailcow-backup.service <<UNIT
[Unit]
Description=Mailcow backup to the remote SMB NAS
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${JOB}
TimeoutStartSec=10800
UNIT

cat > /etc/systemd/system/mailcow-backup-agent.service <<UNIT
[Unit]
Description=Mailcow backup agent (verifies the passphrase, runs the NAS backup)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${AGENT}
TimeoutStartSec=10800
UNIT

cat > /etc/systemd/system/mailcow-backup-agent.path <<UNIT
[Unit]
Description=Watch for a backup request from the mailcow web UI

[Path]
PathExists=${UPDATER_DIR}/backup-request.json
Unit=mailcow-backup-agent.service

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/mailcow-restore-agent.service <<UNIT
[Unit]
Description=Mailcow restore agent (verifies the passphrase and the requested scope)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${RESTORE_AGENT}
TimeoutStartSec=10800
UNIT

cat > /etc/systemd/system/mailcow-restore-agent.path <<UNIT
[Unit]
Description=Watch for a restore request from the mailcow web UI

[Path]
PathExists=${UPDATER_DIR}/restore-request.json
Unit=mailcow-restore-agent.service

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/mailcow-backup.timer <<UNIT
[Unit]
Description=Weekly mailcow backup to the remote SMB NAS

[Timer]
OnCalendar=Sun 03:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now mailcow-backup-agent.path mailcow-restore-agent.path mailcow-backup.timer >/dev/null 2>&1
echo "    已啟用備份／還原 agent 與每週排程"

[[ $KEY_CREATED -eq 1 ]] && echo "KEY_CREATED=1"
exit 0
