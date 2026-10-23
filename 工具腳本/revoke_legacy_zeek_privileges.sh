#!/usr/bin/env bash
# 撤銷舊版 Zeek/ML 服務帳號可直接修改防火牆的權限。
#
# 用法：
#   sudo bash 工具腳本/revoke_legacy_zeek_privileges.sh <舊服務帳號> --confirm-revoke
#
# 只處理三個精確目標；不遞迴刪除。舊檔移到 root-only 備份目錄，方便
# 管理者在查錯時回復。若另有 sudoers 規則仍引用舊 helper，腳本會失敗，
# 不會把「部分撤權」誤報為完成。
set -euo pipefail

if (( EUID != 0 )); then
  echo "請以 sudo 執行撤權工具" >&2
  exit 1
fi
if (( $# != 2 )) || [[ "$2" != "--confirm-revoke" ]]; then
  echo "用法：sudo bash 工具腳本/revoke_legacy_zeek_privileges.sh <舊服務帳號> --confirm-revoke" >&2
  exit 2
fi

CALLER="$1"
if [[ ! "$CALLER" =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || ! id "$CALLER" >/dev/null 2>&1; then
  echo "無效或不存在的服務帳號：$CALLER" >&2
  exit 2
fi

readonly DEST_DIR="/usr/local/libexec/dds-monitor"
readonly LEGACY_BLOCK="$DEST_DIR/block-source"
readonly LEGACY_DOS="$DEST_DIR/dos-firewall"
readonly LEGACY_SUDOERS="/etc/sudoers.d/dds-monitor-block-${CALLER}"
readonly BACKUP_ROOT="/var/backups/dds-monitor-revoked"

# 防止後續維護時把目標改成寬廣或非預期路徑。
[[ "$LEGACY_BLOCK" == "/usr/local/libexec/dds-monitor/block-source" ]]
[[ "$LEGACY_DOS" == "/usr/local/libexec/dds-monitor/dos-firewall" ]]
[[ "$LEGACY_SUDOERS" == "/etc/sudoers.d/dds-monitor-block-${CALLER}" ]]

command -v install >/dev/null 2>&1 || {
  echo "缺少 install 指令" >&2
  exit 1
}
command -v visudo >/dev/null 2>&1 || {
  echo "缺少 visudo；無法安全驗證撤權後設定" >&2
  exit 1
}
command -v sudo >/dev/null 2>&1 || {
  echo "缺少 sudo；無法驗證服務帳號剩餘授權" >&2
  exit 1
}

if ! visudo -cf /etc/sudoers >/dev/null; then
  echo "目前 sudoers 原本就無法通過驗證；尚未移動任何檔案" >&2
  exit 1
fi
if [[ -L "$BACKUP_ROOT" || ( -e "$BACKUP_ROOT" && ! -d "$BACKUP_ROOT" ) ]]; then
  echo "備份根目錄不是可信的一般目錄：$BACKUP_ROOT" >&2
  exit 1
fi
install -d -o root -g root -m 0700 "$BACKUP_ROOT"
if [[ -L "$BACKUP_ROOT" || "$(stat -c '%u:%g:%a' "$BACKUP_ROOT")" != "0:0:700" ]]; then
  echo "備份根目錄 owner／mode 驗證失敗：$BACKUP_ROOT" >&2
  exit 1
fi
BACKUP_DIR="$(mktemp -d "$BACKUP_ROOT/revoke-XXXXXX")"
chmod 0700 "$BACKUP_DIR"

move_to_backup() {
  local source="$1"
  local backup_name="$2"
  if [[ -e "$source" || -L "$source" ]]; then
    if [[ ! -L "$source" && -d "$source" ]]; then
      echo "拒絕移動意外的目錄目標：$source" >&2
      exit 1
    fi
    if [[ ! -L "$source" ]] && command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$source"; then
      echo "拒絕移動 mount point：$source" >&2
      exit 1
    fi
    mv -- "$source" "$BACKUP_DIR/$backup_name"
    echo "已撤下：$source"
  else
    echo "原本不存在：$source"
  fi
}

move_to_backup "$LEGACY_BLOCK" "block-source"
move_to_backup "$LEGACY_DOS" "dos-firewall"
move_to_backup "$LEGACY_SUDOERS" "sudoers-dds-monitor-block-${CALLER}"

if ! visudo -cf /etc/sudoers >/dev/null; then
  RESTORE_SOURCE="$BACKUP_DIR/sudoers-dds-monitor-block-${CALLER}"
  if [[ -f "$RESTORE_SOURCE" && ! -L "$RESTORE_SOURCE" ]]; then
    mv -- "$RESTORE_SOURCE" "$LEGACY_SUDOERS"
    chown root:root "$LEGACY_SUDOERS"
    chmod 0440 "$LEGACY_SUDOERS"
    if ! visudo -cf /etc/sudoers >/dev/null; then
      echo "重大錯誤：sudoers 回復後仍無法通過驗證；helper 維持撤下，請立即人工檢查" >&2
      exit 1
    fi
    echo "撤權後 sudoers 驗證失敗；已回復並重新驗證該帳號的舊規則，helper 維持撤下" >&2
  else
    echo "撤權後 sudoers 驗證失敗；不回復非一般檔案，helper 維持撤下，請人工檢查" >&2
  fi
  exit 1
fi

if [[ -e "$LEGACY_BLOCK" || -L "$LEGACY_BLOCK" ||
      -e "$LEGACY_DOS" || -L "$LEGACY_DOS" ||
      -e "$LEGACY_SUDOERS" || -L "$LEGACY_SUDOERS" ]]; then
  echo "撤權後仍發現舊目標，停止並請人工檢查" >&2
  exit 1
fi

SUDO_LIST_FILE="$BACKUP_DIR/sudo-list-${CALLER}.txt"
if ! sudo -n -l -U "$CALLER" >"$SUDO_LIST_FILE" 2>&1; then
  echo "無法列出 $CALLER 的剩餘 sudo 權限；舊 helper 維持撤下，但不宣告驗證完成" >&2
  exit 1
fi
SUDO_LIST="$(<"$SUDO_LIST_FILE")"
if grep -Fq "$LEGACY_BLOCK" <<< "$SUDO_LIST" || grep -Fq "$LEGACY_DOS" <<< "$SUDO_LIST"; then
  echo "仍有其他 sudoers 規則引用舊 helper；未宣告撤權完成：" >&2
  printf '%s\n' "$SUDO_LIST" >&2
  exit 1
fi

# send-line 不需要 sudo，因此正式 Zeek/ML 服務帳號不應保留任何 sudo command。
# sudo -l 的 executable 規格以縮排後的 `(runas) command` 顯示；發現任何一條
# 都不把此帳號宣告為可用的低權限 runtime 身分。
if grep -Eq '^[[:space:]]+\([^)]*\)[[:space:]]+' "$SUDO_LIST_FILE"; then
  echo "舊 helper 權限已撤，但 $CALLER 仍有其他 sudo command；不得作為 Zeek/ML 服務帳號" >&2
  echo "完整列權結果保存在：$SUDO_LIST_FILE" >&2
  exit 4
fi

echo "舊版直接防火牆權限已撤銷，且服務帳號沒有可列出的 sudo command。"
echo "可回復備份與列權紀錄位於：$BACKUP_DIR"
