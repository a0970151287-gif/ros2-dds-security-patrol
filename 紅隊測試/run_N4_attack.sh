#!/usr/bin/env bash
# N4 — Cross-channel signature confusion 整合測試
# 同時 retest N1/N2/N3 驗證修補生效

set +u
DOMAIN_ID=99
ROS2_WS=$HOME/ros2_ws
RT=$ROS2_WS/紅隊測試
LOG=/tmp/N_attacks
mkdir -p $LOG

unset ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE
unset ROS_SECURITY_ENCLAVE_OVERRIDE LINE_CHANNEL_TOKEN LINE_USER_ID
source /opt/ros/jazzy/setup.bash
source $ROS2_WS/install/setup.bash
export ROS_DOMAIN_ID=$DOMAIN_ID

banner() { echo; echo "════════════════════════════════════════════════════════════════"; echo "  $1"; echo "════════════════════════════════════════════════════════════════"; }
cleanup() {
    pkill -9 -f "monitor_node|intelligent_defense_node|patrol_node|demo_nodes_py|N[1-4]_|attacker_" 2>/dev/null
    sleep 1
}
trap cleanup EXIT

# ============================================================
# N4 — Cross-channel signature confusion (heartbeat → alert)
# ============================================================
attack_N4() {
    banner "攻擊 N4 — Cross-channel signature confusion"
    echo "  漏洞：sign_alert envelope 不綁定 topic，receiver 各自的 ReplayCache 獨立。"
    echo "  攻擊：拿 monitor 自己每 2s 發的 heartbeat bytes → 灌到 /security/alerts"
    echo "        patrol 的 alert_cache 從未見過這個 nonce → 通過驗章 → 停車"
    cleanup
    > $LOG/N4_monitor.log
    > $LOG/N4_patrol.log
    > $LOG/N4_attacker.log

    ros2 run dds_security_monitor monitor_node \
        --ros-args -p emergency_stop_enabled:=false \
        > $LOG/N4_monitor.log 2>&1 &
    MON=$!
    ros2 run dds_security_monitor patrol_node \
        > $LOG/N4_patrol.log 2>&1 &
    PAT=$!
    sleep 6

    echo "  monitor + patrol 啟動完成。發動 N4..."
    python3 $RT/N4_channel_confusion.py 40 > $LOG/N4_attacker.log 2>&1 &
    AT=$!

    echo "  等 35 秒觀察 patrol（正常 30s 後應 resume，若永久 paused 則 N4 成功）..."
    sleep 35
    kill $PAT $AT 2>/dev/null
    pkill -9 -f "monitor_node" 2>/dev/null
    wait 2>/dev/null

    echo
    echo "  攻擊者輸出："
    grep -E '捕獲|注入' $LOG/N4_attacker.log | head -5 | sed 's/^/    /'
    INJ_N=$(grep -c '注入 #' $LOG/N4_attacker.log)
    echo "    cross-channel 注入次數: $INJ_N"
    echo
    echo "  patrol 反應："
    PAUSE_N=$(grep -c '安全警報' $LOG/N4_patrol.log)
    RESUME_N=$(grep -c '安全暫停解除' $LOG/N4_patrol.log)
    REJECT_N=$(grep -c '未簽章/重放/過期' $LOG/N4_patrol.log)
    echo "    收到合法簽章 alert（含 cross-channel 注入）次數: $PAUSE_N"
    echo "    拒絕（replay/freshness 失敗）次數:               $REJECT_N"
    echo "    安全暫停解除次數:                                 $RESUME_N"
    if [ "$RESUME_N" = "0" ] && [ "$PAUSE_N" -ge 1 ] && [ "$INJ_N" -ge 5 ]; then
        echo "    ✗✗✗ 攻擊成功 — patrol 永久停車（cross-channel 注入繞過 ReplayCache）"
    elif [ "$RESUME_N" -gt 0 ]; then
        echo "    ✓ patrol 已 resume → 攻擊失敗（修補有效）"
    elif [ "$REJECT_N" -gt 0 ] && [ "$PAUSE_N" = "0" ]; then
        echo "    ✓ patrol 從頭到尾沒收到任何「合法」alert → N4 被擋"
    else
        echo "    ? 結果不明確：PAUSE=$PAUSE_N REJECT=$REJECT_N RESUME=$RESUME_N INJ=$INJ_N"
    fi
}

# ============================================================
# Regression — retest 舊 N1 / N2 / N3 是否真的被擋
# ============================================================
regression_N1() {
    banner "Regression N1 — 確認 heartbeat replay 已被擋"
    cleanup
    > $LOG/R1_ids.log
    > $LOG/R1_attacker.log
    ros2 run dds_security_monitor monitor_node \
        --ros-args -p emergency_stop_enabled:=false > $LOG/R1_monitor.log 2>&1 &
    MON=$!
    ros2 run dds_security_monitor intelligent_defense_node \
        > $LOG/R1_ids.log 2>&1 &
    IDS=$!
    sleep 5
    python3 $RT/N1_heartbeat_replay.py 20 > $LOG/R1_attacker.log 2>&1 &
    AT=$!
    sleep 4
    pkill -9 -f "monitor_node" 2>/dev/null
    sleep 15
    kill $IDS $AT 2>/dev/null
    wait 2>/dev/null

    D5_HITS=$(grep -c 'monitor 心跳已' $LOG/R1_ids.log)
    echo "    D5 alert 次數: $D5_HITS"
    if [ "$D5_HITS" -ge 1 ]; then
        echo "    ✓ N1 已被擋（replay 沒騙過 IDS，D5 watchdog 正確 fire）"
    else
        echo "    ✗ N1 仍可行（D5 沒 fire — 修補沒用）"
    fi
}

regression_N2() {
    banner "Regression N2 — 確認 _ros2cli_ 名字後門已封"
    cleanup
    > $LOG/R2_monitor.log
    > $LOG/R2_attacker.log
    ros2 run dds_security_monitor monitor_node \
        --ros-args -p poll_interval_sec:=1.5 -p emergency_stop_enabled:=false \
        > $LOG/R2_monitor.log 2>&1 &
    MON=$!
    # 等 monitor 完成 baseline snapshot + grace period(15s)，再啟動偽裝節點
    # 這樣才能驗證「monitor 在 normal mode 仍會抓到 _ros2cli_evil」
    sleep 18
    python3 $RT/N2_ros2cli_regex_bypass.py _ros2cli_evil_99999_deadbeefcafe 8 \
        > $LOG/R2_attacker.log 2>&1 &
    sleep 10
    kill $MON 2>/dev/null
    wait 2>/dev/null

    if grep -q '_ros2cli_evil' $LOG/R2_monitor.log; then
        echo "    ✓ N2 已被擋（monitor 抓到 _ros2cli_evil — 沒有 regex 後門）"
    else
        echo "    ✗ N2 仍可行（monitor 看不到 _ros2cli_evil — 後門還在）"
    fi
}

regression_N3() {
    banner "Regression N3 — 確認 alert replay 已被擋"
    cleanup
    > $LOG/R3_patrol.log
    > $LOG/R3_attacker.log
    ros2 run dds_security_monitor monitor_node \
        --ros-args -p poll_interval_sec:=1.5 -p emergency_stop_enabled:=false \
        > $LOG/R3_monitor.log 2>&1 &
    MON=$!
    ros2 run dds_security_monitor patrol_node > $LOG/R3_patrol.log 2>&1 &
    PAT=$!
    sleep 5
    python3 $RT/N3_alert_replay_dos.py 40 > $LOG/R3_attacker.log 2>&1 &
    AT=$!
    sleep 2
    ros2 run demo_nodes_py listener \
        --ros-args --remap __node:=trigger_node_for_replay > /dev/null 2>&1 &
    TRIG=$!
    sleep 5
    kill $TRIG 2>/dev/null
    sleep 3
    pkill -9 -f "monitor_node" 2>/dev/null
    sleep 35
    kill $PAT $AT 2>/dev/null
    wait 2>/dev/null

    REJECT_N=$(grep -c '未簽章/重放/過期' $LOG/R3_patrol.log)
    REPLAY_N=$(grep -c '重放 #' $LOG/R3_attacker.log)
    RESUME_N=$(grep -c '安全暫停解除' $LOG/R3_patrol.log)
    echo "    攻擊者重放次數:    $REPLAY_N"
    echo "    patrol 拒絕次數:   $REJECT_N (因 nonce LRU 或 ts 過期)"
    echo "    patrol 安全解除:   $RESUME_N"
    if [ "$REJECT_N" -ge 1 ] && [ "$RESUME_N" -ge 1 ]; then
        echo "    ✓ N3 已被擋（replay 被 ReplayCache 拒絕 + patrol 在 30s 後 resume）"
    elif [ "$REJECT_N" -ge 1 ]; then
        echo "    ✓ N3 已被擋（replay 被拒，但 patrol 還沒到 resume 時間）"
    else
        echo "    ✗ N3 仍可行（patrol 沒拒絕任何 replay）"
    fi
}

case "${1:-N4}" in
    N4)        attack_N4 ;;
    regress)   regression_N1; regression_N2; regression_N3 ;;
    all)       regression_N1; regression_N2; regression_N3; attack_N4 ;;
    *) echo "用法: $0 [N4|regress|all]"; exit 1 ;;
esac
