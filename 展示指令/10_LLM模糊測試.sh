#!/bin/bash
# ============================================================
# 10  LLM 智慧模糊測試系統（早期工具，輔助）
#
#  ⚠️ 定位說明：本系統資安驗證的「主力」是紅隊 N1–N24 PoC
#     （見 ~/ros2_ws/紅隊測試/，18 漏洞 CVSS + pytest 24 全綠）。
#     這支 LLM Fuzzer 是早期做的「通用 C 程式模糊測試」展示工具，
#     對的是獨立靶機（~/llm_fuzzer），不是直接打 ROS2 系統。
#     介紹時：主講紅隊 N1–N24 + 行為 IDS，LLM Fuzzer 當輔助佐證即可。
#
#  架構：MutationAgent(GPT-4o-mini) → asyncio.Queue → 4×Consumer
#        → Docker 沙箱(ASan) → TriageAgent(GPT-4o) → SQLite
# ============================================================

# ── 前置：確認 Docker 可用 ────────────────────────────────────
docker info > /dev/null 2>&1 || echo "Docker 未啟動，請先開啟 Docker Desktop"
docker image ls fuzzer-target:latest              # 確認靶機映像存在

# ── 前置：首次建置靶機映像（只需執行一次）────────────────────
cd ~/llm_fuzzer
docker build -f Dockerfile.target -t fuzzer-target:latest .

# ── 終端 1：啟動模糊測試 ─────────────────────────────────────
cd ~/llm_fuzzer
export OPENAI_API_KEY="sk-proj-你的真實金鑰"      # 貼上真實金鑰
PYTHONUTF8=1 .venv/bin/python3 orchestrator.py    # Ctrl+C 優雅關機，可續傳

# ── 終端 2：即時查看報告 ──────────────────────────────────────
cd ~/llm_fuzzer
.venv/bin/python3 report.py                        # 摘要（crash 數、嚴重程度分布）
.venv/bin/python3 report.py -v | less -R           # 完整 Markdown 報告（q 退出）
.venv/bin/python3 report.py -v -s HIGH | less -R   # 只看 HIGH / CRITICAL
.venv/bin/python3 report.py -v -o crash_reports.md # 匯出成 Markdown 檔

# ── 手動測試靶機（驗證 Docker 沙箱正常）──────────────────────
# 正常輸入（exit 0）
docker run --rm \
  -e FUZZ_INPUT='{"username":"admin","age":25,"data":"hello"}' \
  fuzzer-target:latest

# 觸發 heap-buffer-overflow（exit 134 + ASan 報告）
docker run --rm \
  -e FUZZ_INPUT='{"username":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","age":1,"data":"x"}' \
  fuzzer-target:latest

# 觸發 stack-buffer-overflow（data 超過 64 bytes）
docker run --rm \
  -e FUZZ_INPUT='{"username":"admin","age":1,"data":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}' \
  fuzzer-target:latest

# 觸發 integer overflow（age 為負數）
docker run --rm \
  -e FUZZ_INPUT='{"username":"admin","age":-1,"data":"x"}' \
  fuzzer-target:latest

# ── 斷點續傳（Ctrl+C 後重啟）────────────────────────────────
# 直接重跑即可，SQLite 已記錄已執行 hash，不會重複發送
cd ~/llm_fuzzer
PYTHONUTF8=1 .venv/bin/python3 orchestrator.py

# ── 查看 SQLite 原始資料（進階除錯）────────────────────────────
sqlite3 ~/llm_fuzzer/fuzzer_state.db "SELECT COUNT(*) FROM executed_hashes;"
sqlite3 ~/llm_fuzzer/fuzzer_state.db "SELECT severity, COUNT(*) FROM crash_reports GROUP BY severity;"
sqlite3 ~/llm_fuzzer/fuzzer_state.db "SELECT id, crash_type, severity FROM crash_reports ORDER BY created_at DESC LIMIT 5;"
