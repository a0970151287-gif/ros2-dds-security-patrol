#!/usr/bin/env bash
# 安裝 Zeek 使用的低權限通知 helper。
#
# 用法：
#   sudo bash 工具腳本/install_zeek_helpers.sh
#
# 舊版 block-source 接受裸 IP/TTL，無法驗證完整 signed evidence/ticket，
# 已停止安裝，也不再建立任何 NOPASSWD 規則。主動封鎖 backend 未完成前，
# Zeek/ML 僅能提出回應請求，不能直接取得 root 防火牆權限。
set -euo pipefail

if (( EUID != 0 )); then
  echo "請以 sudo 執行此安裝器" >&2
  exit 1
fi

if (( $# != 0 )); then
  echo "用法：sudo bash 工具腳本/install_zeek_helpers.sh（不再接受封鎖帳號）" >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
LINE_SOURCE="$REPO_DIR/Zeek監控/send_line.py"
DEST_DIR="/usr/local/libexec/dds-monitor"
LEGACY_BLOCK="$DEST_DIR/block-source"
LEGACY_DOS="$DEST_DIR/dos-firewall"

# 升級保護：只停止「繼續安裝」，不在一般 installer 裡偷偷刪系統檔。
# 管理者必須使用獨立 revocation 工具，指定舊服務帳號並保存可回復備份。
legacy_paths=()
for legacy_path in "$LEGACY_BLOCK" "$LEGACY_DOS"; do
  if [[ -e "$legacy_path" || -L "$legacy_path" ]]; then
    legacy_paths+=("$legacy_path")
  fi
done
shopt -s nullglob
legacy_sudoers=(/etc/sudoers.d/dds-monitor-block-*)
shopt -u nullglob
legacy_paths+=("${legacy_sudoers[@]}")
if (( ${#legacy_paths[@]} > 0 )); then
  echo "偵測到舊版高權限 helper／sudoers，拒絕安裝：" >&2
  printf '  %s\n' "${legacy_paths[@]}" >&2
  echo "請先執行：sudo bash 工具腳本/revoke_legacy_zeek_privileges.sh <舊服務帳號> --confirm-revoke" >&2
  exit 3
fi

for source in "$LINE_SOURCE"; do
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "拒絕安裝缺少或為 symlink 的來源：$source" >&2
    exit 1
  }
done
command -v install >/dev/null 2>&1 || {
  echo "缺少 install 指令" >&2
  exit 1
}

install -d -o root -g root -m 0755 "$DEST_DIR"
install -o root -g root -m 0755 "$LINE_SOURCE" "$DEST_DIR/send-line"

echo "已安裝："
echo "  $DEST_DIR/send-line"
echo "未安裝：block-source / dos-firewall / sudoers NOPASSWD 規則"
echo "Zeek 請以非 root 帳號執行；封包擷取權限另用 capability/受限服務設定。"
echo "主動封鎖維持停用，直到 signed-ticket backend 通過跨程序驗票與復原測試。"
