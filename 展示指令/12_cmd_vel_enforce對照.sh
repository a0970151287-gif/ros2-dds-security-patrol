#!/usr/bin/env bash
# ============================================================================
# 12 /cmd_vel Enforce 離線安全 gate
#
# 這支腳本不偽造「live 攻防結果」。它驗證目前實際簽進 keystore 的政策：
#   1. SROS2 結構、CA、簽章及 canonical policy 完全一致
#   2. 只有 /velocity_guard_node 能發布 final /cmd_vel
#   3. patrol / Nav2 / TQC 只能寫各自的私有控制 topic
#
# 真正的 live Enforce 驗證仍要在 01c 場景啟動後，以無憑證 participant
# 注入 private 與 final topic，並保存雙方 log；未執行時不得宣稱已完封。
#
# 用法：bash 展示指令/12_cmd_vel_enforce對照.sh
# ============================================================================
set -euo pipefail

WS="${ROS2_WS:-$HOME/ros2_ws}"
KS="$WS/sros2_keystore"
AUDIT="$WS/展示指令/sros2_稽核.sh"

fail() {
  echo "❌ $1" >&2
  exit 1
}

[[ -x "$AUDIT" || -f "$AUDIT" ]] || fail "找不到 $AUDIT"
[[ -d "$KS/enclaves" ]] || fail "找不到 keystore；先跑 10_SROS2啟用.sh"

echo "═══ 1/3：SROS2 簽章與 canonical policy ═══"
bash "$AUDIT"

echo
echo "═══ 2/3：final /cmd_vel 唯一發布者 ═══"
mapfile -t final_writers < <(
  for permissions in "$KS"/enclaves/*/permissions.xml; do
    if awk '
      /<publish>/ { in_publish=1 }
      /<\/publish>/ { in_publish=0 }
      in_publish && /<topic>rt\/cmd_vel<\/topic>/ { found=1 }
      END { exit(found ? 0 : 1) }
    ' "$permissions"; then
      basename "$(dirname "$permissions")"
    fi
  done | sort
)
[[ "${#final_writers[@]}" -eq 1 ]] \
  || fail "final /cmd_vel 發布者不是唯一：${final_writers[*]:-(none)}"
[[ "${final_writers[0]}" == "velocity_guard_node" ]] \
  || fail "final /cmd_vel 發布者應為 velocity_guard_node，實際是 ${final_writers[0]}"
echo "✅ 唯一 final writer：/velocity_guard_node"

echo
echo "═══ 3/3：控制器只能寫私有 topic ═══"
grep -q '<topic>rt/cmd_vel/patrol</topic>' \
  "$KS/enclaves/patrol_node/permissions.xml" \
  || fail "patrol_node 缺少 private /cmd_vel/patrol"
grep -q '<topic>rt/cmd_vel/tqc</topic>' \
  "$KS/enclaves/burger_env_top/permissions.xml" \
  || fail "burger_env_top 缺少 private /cmd_vel/tqc"
grep -q '<topic>rt/cmd_vel/nav2</topic>' \
  "$KS/enclaves/velocity_guard_node/permissions.xml" \
  || fail "velocity guard 缺少 private /cmd_vel/nav2 input"
echo "✅ patrol、Nav2、TQC 都經 private input → velocity guard → final /cmd_vel"

echo
echo "離線 gate 通過。這證明簽章政策的唯一 writer 不變式；"
echo "不等同於完整 Gazebo live 長時間攻防，live 證據仍須另行保存。"
