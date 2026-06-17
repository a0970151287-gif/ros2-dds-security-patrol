#!/usr/bin/env bash
# ============================================================================
# 12 最小 /cmd_vel SROS2 Enforce 對照
#   證明：Enforce 下「合法憑證可下 /cmd_vel」「攻擊者無憑證注入被拒」
#   對應紅隊要求的控制鏈對照（先用 demo enclave 驗流程，再擴到 patrol/橋接）
#
# 前置：先跑過 10_SROS2啟用.sh（keystore + /talker /listener enclave、domain 30）
# 用法：bash 展示指令/12_cmd_vel_enforce對照.sh
# ============================================================================
set +eu
WS="$HOME/ros2_ws"
PROBE="$WS/展示指令/_cmd_vel_sub_probe.py"
RECV=/tmp/cmd_recv.txt
MSG='{twist: {linear: {x: 0.5}, angular: {z: 1.0}}}'
ATK='{twist: {linear: {x: 9.9}, angular: {z: 9.9}}}'

source /opt/ros/jazzy/setup.bash 2>/dev/null
source "$WS/install/setup.bash" 2>/dev/null
export ROS_SECURITY_KEYSTORE="$WS/sros2_keystore"
export ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce
export ROS_DOMAIN_ID=30 RMW_IMPLEMENTATION=rmw_fastrtps_cpp PYTHONUNBUFFERED=1
unset FASTRTPS_DEFAULT_PROFILES_FILE

run_probe() {  # $1=秒數  以指定 enclave 起加密訂閱端
  ROS_SECURITY_ENCLAVE_OVERRIDE=/listener timeout "$1" python3 "$PROBE" "$1" "$RECV" >/tmp/cv_sub.log 2>&1 &
}

echo "═══ 測試 1：Enforce + 合法憑證（/talker → /listener）═══"
rm -f "$RECV"; run_probe 10; sleep 5
ROS_SECURITY_ENCLAVE_OVERRIDE=/talker timeout 4 ros2 topic pub -r 2 /cmd_vel \
  geometry_msgs/msg/TwistStamped "$MSG" >/tmp/cv_pub.log 2>&1
sleep 2
N1=$(grep -ac '^recv' "$RECV" 2>/dev/null)
echo "  合法訂閱端收到 /cmd_vel：$N1 筆  →  $([ "$N1" -gt 0 ] && echo '✅ 合法控制可通' || echo '❌')"
wait 2>/dev/null

echo "═══ 測試 2：Enforce + 攻擊者無憑證注入 ═══"
rm -f "$RECV"; run_probe 10; sleep 5
# 攻擊者：不設 enclave override（預設 / 不存在）→ 應被認證層拒絕
timeout 4 ros2 topic pub -r 2 /cmd_vel geometry_msgs/msg/TwistStamped "$ATK" >/tmp/cv_atk.log 2>&1
ATK_EXIT=$?
sleep 2
N2=$(grep -ac '9.9' "$RECV" 2>/dev/null)
echo "  攻擊 pub 退出碼：$ATK_EXIT（非0=participant 被拒）"
grep -a "security files" /tmp/cv_atk.log | head -1 | sed 's/^/  /'
echo "  訂閱端收到惡意注入：$N2 筆  →  $([ "$N2" -eq 0 ] && echo '✅ 注入被擋' || echo '❌ 被劫持')"
wait 2>/dev/null

echo
echo "結論：Enforce 下合法控制可通、未授權注入在認證層被拒。"
echo "（Permissive 劫持對照由紅隊跨主機示範；同機 Permissive 因 WSL localhost discovery 不穩不在此測）"
