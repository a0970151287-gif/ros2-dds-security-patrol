#!/bin/bash
# ============================================================
# 打包給工程師 Review 用
#
# 排除：密鑰 / token / 訓練模型 / build artifacts / venv / pycache
# 包含：src/ tests/ pytest.ini 紅隊測試/ 展示指令/ REVIEW_README.md
#
# 使用：
#   bash 打包給工程師.sh
# 輸出：
#   ~/ros2_review_<日期>.tar.gz
# ============================================================

set -e

WS="/home/jesse/ros2_ws"
DATE=$(date +%Y%m%d_%H%M)
OUT="$HOME/ros2_review_${DATE}.tar.gz"

cd "$WS"

# ── 步驟 1：安全檢查 — 確認 src/ 內沒有意外的敏感檔 ─────────────
echo "▶ Step 1/4: 掃描 src/ 內是否殘留敏感檔..."
SUSPECTS=$(find src tests 紅隊測試 展示指令 -type f \
    \( -name "*secret*" -o -name "alert_secret*" -o -name "line_token*" \
       -o -name "*.pem" -o -name "*.key" -o -name "id_rsa*" \) 2>/dev/null || true)

if [ -n "$SUSPECTS" ]; then
    echo "❌ 偵測到疑似敏感檔！中止打包："
    echo "$SUSPECTS"
    echo ""
    echo "請先確認這些檔案，移除後再重跑。"
    exit 1
fi
echo "  ✓ 無敏感檔殘留"

# ── 步驟 2：檢查 REVIEW_README.md 存在 ─────────────────────────
echo "▶ Step 2/4: 檢查 REVIEW_README.md..."
if [ ! -f REVIEW_README.md ]; then
    echo "❌ 找不到 REVIEW_README.md，請先建立。"
    exit 1
fi
echo "  ✓ REVIEW_README.md 存在"

# ── 步驟 3：打包 ──────────────────────────────────────────────
echo "▶ Step 3/4: 打包中..."
tar czf "$OUT" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='*.egg-info' \
    --exclude='.pytest_cache' \
    --exclude='build' \
    --exclude='install' \
    --exclude='log' \
    --exclude='runs_top' \
    --exclude='runs_sac' \
    --exclude='models_sac' \
    --exclude='logs_sac' \
    --exclude='logs' \
    --exclude='checkpoints' \
    --exclude='*.zip' \
    --exclude='*.pkl' \
    --exclude='*.sha256.hmac' \
    --exclude='.venv' \
    --exclude='dqn_env' \
    --exclude='.git' \
    --exclude='turtlebot3' \
    --exclude='turtlebot3_simulations' \
    -C "$WS" \
    src/ tests/ pytest.ini 紅隊測試/ 展示指令/ REVIEW_README.md

echo "  ✓ 打包完成"

# ── 步驟 4：驗證打包內容 ──────────────────────────────────────
echo "▶ Step 4/4: 驗證打包內容..."

SIZE=$(du -sh "$OUT" | cut -f1)
COUNT=$(tar tzf "$OUT" | wc -l)

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✅ 打包成功"
echo "════════════════════════════════════════════════════════════"
echo "  輸出檔: $OUT"
echo "  大小:   $SIZE"
echo "  檔案數: $COUNT"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "▶ 二次驗證：tar 內是否有敏感檔..."
LEAK=$(tar tzf "$OUT" | grep -E "(alert_secret|line_token|\.pem$|\.key$|id_rsa)" || true)
if [ -n "$LEAK" ]; then
    echo "❌ tar 內偵測到敏感檔！立刻刪除："
    echo "$LEAK"
    rm "$OUT"
    exit 1
fi
echo "  ✓ tar 內無敏感檔"
echo ""

echo "▶ 前 15 個檔案預覽："
tar tzf "$OUT" | head -15
echo "  ..."
echo ""

echo "▶ 大目錄分佈："
tar tzf "$OUT" | awk -F/ '{print $1"/"$2}' | sort | uniq -c | sort -rn | head -10
echo ""

echo "════════════════════════════════════════════════════════════"
echo "  下一步："
echo "════════════════════════════════════════════════════════════"
echo "  傳給工程師（任選）："
echo "    scp $OUT user@host:~/"
echo "    rsync -P $OUT user@host:~/"
echo "    （或用 Google Drive / OneDrive 上傳）"
echo ""
echo "  工程師收到後："
echo "    tar xzf $(basename $OUT)"
echo "    cat REVIEW_README.md   # 第一個看這個"
echo "════════════════════════════════════════════════════════════"
