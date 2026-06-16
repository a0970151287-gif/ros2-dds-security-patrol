#!/usr/bin/env bash
# ============================================================================
# SROS2 啟用 — 根治紅隊 F1–F6（身分驗證 + 存取控制 + 加密）
# 對應後續計劃表「階段二：根治型防禦」
#
# 教訓（來自紅隊 N26）：CA 私鑰若 644 世界可讀 → 身分/權限全可偽造。
# 本腳本產完 keystore 後強制 chmod 600 鎖私鑰。
#
# 用法（目標機）：
#   bash 展示指令/10_SROS2啟用.sh            # 建 keystore + enclave + 鎖權限
#   source 展示指令/10_SROS2啟用.sh enforce  # 在本 shell 開啟 Enforce 環境變數
# ============================================================================
set -euo pipefail

WS="$HOME/ros2_ws"
KEYSTORE="$WS/sros2_keystore"

# legit 節點（要跑安全的）——依實際 demo 節點調整
ENCLAVES=(
  "/talker"
  "/listener"
  "/burger_env_top"
  "/dds_security_monitor"
)

enable_enforce_env() {
  export ROS_SECURITY_KEYSTORE="$KEYSTORE"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce   # Enforce：沒有效憑證的節點一律拒絕加入
  echo "✅ 本 shell 已開啟 SROS2 Enforce："
  echo "   KEYSTORE = $ROS_SECURITY_KEYSTORE"
  echo "   ENABLE   = $ROS_SECURITY_ENABLE"
  echo "   STRATEGY = $ROS_SECURITY_STRATEGY"
}

# 若被 source 且帶 enforce 參數 → 只設環境變數後返回
if [[ "${1:-}" == "enforce" ]]; then
  enable_enforce_env
  return 0 2>/dev/null || exit 0
fi

source /opt/ros/jazzy/setup.bash
[[ -f "$WS/install/setup.bash" ]] && source "$WS/install/setup.bash"

if ! ros2 security -h >/dev/null 2>&1; then
  echo "❌ 找不到 ros2 security，請先："
  echo "   sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ros-jazzy-sros2 ros-jazzy-sros2-cmake"
  exit 1
fi

# ── 1) 建 keystore（含 CA）──────────────────────────────────────────────
if [[ ! -d "$KEYSTORE" ]]; then
  echo "→ 建立 keystore: $KEYSTORE"
  ros2 security create_keystore "$KEYSTORE"
else
  echo "→ keystore 已存在，沿用：$KEYSTORE"
fi

# ── 2) 為每個 legit 節點建 enclave（身分憑證 + 預設權限）────────────────
for e in "${ENCLAVES[@]}"; do
  if [[ ! -d "$KEYSTORE/enclaves$e" ]]; then
    echo "→ 建立 enclave: $e"
    ros2 security create_enclave "$KEYSTORE" "$e"
  else
    echo "→ enclave 已存在：$e"
  fi
done

# ── 3) 鎖權限（關鍵！私鑰絕不可世界可讀，呼應 N26 教訓）────────────────
echo "→ 鎖 keystore 權限（私鑰 600 / 目錄 700）"
chmod -R go-rwx "$KEYSTORE"
find "$KEYSTORE" -type f -name "*.pem" -exec chmod 600 {} \;
find "$KEYSTORE" -name "key.pem" -exec chmod 600 {} \;

echo
echo "========================================================"
echo "✅ SROS2 keystore 就緒：$KEYSTORE"
echo "   CA / 私鑰權限："
find "$KEYSTORE" -name "*.pem" -maxdepth 3 -exec ls -l {} \; 2>/dev/null | head -8
echo
echo "下一步——在「要跑安全節點」的 shell 開啟 Enforce："
echo "   source 展示指令/10_SROS2啟用.sh enforce"
echo "再用對應 enclave 跑節點，例如："
echo "   ros2 run demo_nodes_cpp listener --ros-args --enclave /listener"
echo
echo "攻防驗證：攻擊機沒有本 CA 簽的憑證 → Enforce 下無法加入 →"
echo "   偵察/注入/參數竄改全部在 DDS 認證層就被擋（根治 F1–F6）。"
echo "========================================================"
