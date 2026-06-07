#!/usr/bin/env bash
# Auto-resume wrapper for SAC training.
# 訓練意外中斷時自動 resume from latest checkpoint，最多 retry RETRY_MAX 次。
#
# Usage:
#     source ~/.config/dds-monitor/credentials   (optional, for LINE alerts)
#     source ~/dqn_env/bin/activate
#     source ~/ros2_ws/install/setup.bash
#     bash train_sac_auto.sh
#
# 中斷類型與處理：
#   - Ctrl+C            → 不 retry，直接退出（exit code 130）
#   - Gazebo crash      → 等 10 秒讓 Gazebo 重新就緒，自動 resume
#   - Python exception  → 等 5 秒，自動 resume
#   - OOM               → 不 retry，需人工介入

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRAIN_SCRIPT="${SCRIPT_DIR}/train_sac.py"
LOG_DIR="${SCRIPT_DIR}/logs_sac"
RETRY_LOG="${LOG_DIR}/auto_retry.log"
RETRY_MAX=20
RETRY_COUNT=0

mkdir -p "${LOG_DIR}"

echo "$(date -Iseconds) === train_sac_auto.sh 啟動 ===" | tee -a "${RETRY_LOG}"
echo "  TRAIN_SCRIPT = ${TRAIN_SCRIPT}"  | tee -a "${RETRY_LOG}"
echo "  RETRY_MAX    = ${RETRY_MAX}"     | tee -a "${RETRY_LOG}"

while true; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ "${RETRY_COUNT}" -gt "${RETRY_MAX}" ]; then
        echo "$(date -Iseconds) [FATAL] 連續失敗 ${RETRY_MAX} 次，放棄。" | tee -a "${RETRY_LOG}"
        exit 1
    fi

    echo "$(date -Iseconds) [Try ${RETRY_COUNT}/${RETRY_MAX}] 啟動 train_sac.py" | tee -a "${RETRY_LOG}"

    python3 "${TRAIN_SCRIPT}"
    EXIT_CODE=$?

    if [ "${EXIT_CODE}" -eq 0 ]; then
        echo "$(date -Iseconds) ✅ 訓練正常結束（exit=0）" | tee -a "${RETRY_LOG}"
        exit 0
    fi

    # Ctrl+C → 130，使用者主動中斷，不 retry
    if [ "${EXIT_CODE}" -eq 130 ] || [ "${EXIT_CODE}" -eq 143 ]; then
        echo "$(date -Iseconds) ⚠️  使用者中斷（exit=${EXIT_CODE}），不 retry" | tee -a "${RETRY_LOG}"
        exit "${EXIT_CODE}"
    fi

    # OOM → 137（被 OOM killer 殺掉），不 retry（記憶體不夠繼續跑也沒用）
    if [ "${EXIT_CODE}" -eq 137 ]; then
        echo "$(date -Iseconds) ❌ OOM kill (exit=137)，需人工介入" | tee -a "${RETRY_LOG}"
        exit 137
    fi

    SLEEP_SEC=10
    echo "$(date -Iseconds) ⚠️  訓練中斷 (exit=${EXIT_CODE})，${SLEEP_SEC}s 後 resume from latest checkpoint" \
        | tee -a "${RETRY_LOG}"
    sleep "${SLEEP_SEC}"
done
