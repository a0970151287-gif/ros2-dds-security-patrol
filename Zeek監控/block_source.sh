#!/usr/bin/env bash
# 舊版直接接收「來源 IP + 秒數」的 root helper 已永久停用。
#
# 原介面無法驗證 AI 判定、證據來源、模型/政策版本、一次性票證或
# shared-IP 風險，因此任何能執行它的帳號都可能繞過 response authorizer。
# 真正的主動封鎖只能在具備跨程序驗票、nonce 防重放、原子 claim、
# 核心層到期解封與重啟復原的 backend 完成後，改由新的 helper 提供。
#
# 此檔保留為 fail-closed stub，避免舊設定誤呼叫時真的改動防火牆。
set -euo pipefail

echo "legacy block-source is disabled: signed-ticket backend required" >&2
exit 78
