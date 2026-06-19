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
POLICY="$WS/展示指令/sros2_policy.xml"   # 存取控制政策（放行合法節點的 topic）
DOMAIN="${ROS_DOMAIN_ID:-30}"            # 實驗室 domain（governance + permissions 必須一致！）

# legit 節點（要跑安全的）——依實際 demo 節點調整
ENCLAVES=(
  "/talker"
  "/listener"
  "/burger_env_top"
  "/dds_security_monitor"
  # ── 實際系統的 6 個節點 + Gazebo stack（全系統 Enforce 用）──
  "/sensor_hub_node"
  "/patrol_node"
  "/mission_manager"
  "/system_status_node"
  "/intelligent_defense_node"
  "/gazebo"            # gazebo.launch.py 整包(bridge+robot_state_publisher+gz) 共用此 enclave
)

enable_enforce_env() {
  export ROS_SECURITY_KEYSTORE="$KEYSTORE"
  export ROS_SECURITY_ENABLE=true
  export ROS_SECURITY_STRATEGY=Enforce   # Enforce：沒有效憑證的節點一律拒絕加入
  export ROS_DOMAIN_ID="$DOMAIN"         # 必須與 governance/permissions 的 domain 一致
  echo "✅ 本 shell 已開啟 SROS2 Enforce："
  echo "   KEYSTORE  = $ROS_SECURITY_KEYSTORE"
  echo "   ENABLE    = $ROS_SECURITY_ENABLE"
  echo "   STRATEGY  = $ROS_SECURITY_STRATEGY"
  echo "   DOMAIN_ID = $ROS_DOMAIN_ID"
}

# 若被 source 且帶 enforce 參數 → 只設環境變數後返回
if [[ "${1:-}" == "enforce" ]]; then
  enable_enforce_env
  return 0 2>/dev/null || exit 0
fi

set +u   # ROS setup.bash 會引用未定義變數，sourcing 時暫關 nounset
source /opt/ros/jazzy/setup.bash
[[ -f "$WS/install/setup.bash" ]] && source "$WS/install/setup.bash"
set -u

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

# ── 2b) 用政策簽存取控制權限（domain 必須 = DOMAIN）─────────────────────
# create_enclave 的預設權限太窄（連 ros_discovery_info 都沒放行）→ 合法節點也跑不起來。
# 改用政策檔簽 permissions，並指定 ROS_DOMAIN_ID 讓 permissions 綁到實驗室 domain。
if [[ -f "$POLICY" ]]; then
  for e in "${ENCLAVES[@]}"; do
    echo "→ 簽存取控制權限: $e (domain $DOMAIN)"
    ROS_DOMAIN_ID="$DOMAIN" ros2 security create_permission "$KEYSTORE" "$e" "$POLICY" >/dev/null
  done
else
  echo "⚠️ 找不到政策檔 $POLICY，沿用預設權限（可能連 ros_discovery_info 都沒放行）"
fi

# ── 2c) 把 governance 的 domain 改成 DOMAIN 並重簽（關鍵！）──────────────
# create_keystore 產的 governance 綁 domain 0；若實驗室跑非 0 domain，
# governance 規則對不上 → discovery 保護判定異常、合法節點被自己擋下。
GOV_XML="$KEYSTORE/enclaves/governance.xml"
GOV_P7S="$KEYSTORE/enclaves/governance.p7s"
if [[ -f "$GOV_XML" ]] && [[ "$DOMAIN" != "0" ]]; then
  echo "→ governance domain 改為 $DOMAIN 並重簽"
  sed -i "s#<id>0</id>#<id>$DOMAIN</id>#" "$GOV_XML"
  openssl smime -sign -in "$GOV_XML" -text -out "$GOV_P7S" \
    -signer "$KEYSTORE/public/permissions_ca.cert.pem" \
    -inkey "$KEYSTORE/private/permissions_ca.key.pem" >/dev/null 2>&1
fi

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
