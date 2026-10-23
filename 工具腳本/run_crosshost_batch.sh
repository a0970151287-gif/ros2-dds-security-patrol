#!/usr/bin/env bash
# 跨主機身份證據批次收集（防守端）
#
# 用法： run_crosshost_batch.sh [輪數] [窗長秒] [週期秒]
#        預設 80 輪 × 300 秒窗 × 360 秒週期 ≈ 8 小時
#
# ── 為什麼對絕對時間排程 ──────────────────────────────────────────
# 第一版用相對 sleep，讓攻擊端週期比防守端略長，靠窗的餘裕吸收漂移。20 輪還
# 行（累積約 140 秒），但 80 輪會累積到 600 秒——攻擊會完全掉出窗外，後半段
# 全是 void，而那看起來會很像「防禦停止運作」。
#
# 兩邊改成對齊 UTC 的絕對邊界：每輪在 (epoch % 週期 == 0) 開窗，攻擊端在同一
# 個邊界 +60 秒動手。UTC 是兩台共用的，所以**永不漂移**，跑多久都一樣。
#
# ── 為什麼要退化偵測 ──────────────────────────────────────────────
# 無人值守八小時，若 mirrored 中途掛掉，會安靜地產出幾十輪 void。這個專案已經
# 被「沒有證據」與「防禦成功」外觀相同咬過八次，所以連續 void 或位址消失就
# 立刻停下並講清楚，不要留下一批看起來像結論的空資料。

set -uo pipefail   # 刻意不要 -e：單輪失敗要繼續

ROUNDS="${1:-80}"
WINDOW="${2:-300}"
PERIOD="${3:-360}"
ATTACKER="${ATTACKER_IP:-192.168.0.30}"
MAX_CONSECUTIVE_VOID="${MAX_CONSECUTIVE_VOID:-6}"
WS="$HOME/ros2_ws"

if (( WINDOW >= PERIOD )); then
  echo "⛔ 窗長必須小於週期，否則兩輪會重疊" >&2
  exit 2
fi

BATCH="$HOME/crosshost_batch/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BATCH"

# 介面每次都現看，而且每輪重驗。WSL 重啟會重新編號（一晚之內看過 eth2→eth1），
# 照抄舊名字會擷取到空的。
detect_iface() {
  dumpcap -D 2>/dev/null | awk '/eth[0-9]/{print $2; exit}'
}
iface_address() {
  ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1
}

IFACE="$(detect_iface)"
ADDR="$(iface_address "$IFACE")"
if [[ -z "$IFACE" || "$ADDR" != 192.168.* ]]; then
  echo "⛔ 沒有區網介面（iface='$IFACE' addr='$ADDR'）——mirrored 沒生效，不要開始" >&2
  exit 2
fi

echo "=================================================="
echo " 跨主機批次收集"
echo "=================================================="
echo "  介面      : $IFACE ($ADDR)"
echo "  攻擊機    : $ATTACKER"
echo "  排程      : $ROUNDS 輪，每 ${PERIOD}s 一輪，窗長 ${WINDOW}s"
echo "  對齊方式  : UTC 絕對邊界（epoch %% $PERIOD == 0），不會漂移"
echo "  預計時長  : 約 $(( ROUNDS * PERIOD / 3600 )) 小時 $(( ROUNDS * PERIOD % 3600 / 60 )) 分"
echo "  輸出      : $BATCH"
echo "  開始      : $(date -u +%H:%M:%SZ)"
echo

consecutive_void=0

for round in $(seq 1 "$ROUNDS"); do
  # 睡到下一個絕對邊界。攻擊端用同一條公式 +60 秒，兩邊因此永遠對齊。
  now=$(date -u +%s)
  boundary=$(( (now / PERIOD + 1) * PERIOD ))
  sleep $(( boundary - now ))

  # 每輪重驗網路。mirrored 中途掛掉就停，不要繼續產出空證據。
  IFACE="$(detect_iface)"
  ADDR="$(iface_address "$IFACE")"
  if [[ -z "$IFACE" || "$ADDR" != 192.168.* ]]; then
    echo "⛔ 第 $round 輪：區網介面消失（iface='$IFACE' addr='$ADDR'）"
    echo "   mirrored 很可能掛了。停止批次——繼續跑只會產生看起來像結論的空資料。"
    break
  fi

  echo "───── 第 $round/$ROUNDS 輪  $(date -u +%H:%M:%SZ)  ($IFACE) ─────"
  ATTACKER_IP="$ATTACKER" bash "$WS/工具腳本/run_crosshost_identity.sh" \
      "$IFACE" "$WINDOW" >>"$BATCH/round_${round}.log" 2>&1
  session="$(grep -oE '[0-9]{8}T[0-9]+Z_crosshost_[0-9a-f]+' "$BATCH/round_${round}.log" | head -1)"
  echo "$round ${session:-none}" >>"$BATCH/sessions.txt"

  ok=""
  if [[ -n "$session" ]]; then
    ok="$(python3 -c "
import json
try:
    d = json.load(open('$HOME/crosshost/$session/crosscheck.json'))
    print('yes' if d.get('source_ip_attribution_verified') else 'no')
except Exception:
    print('no')
" 2>/dev/null)"
  fi

  if [[ "$ok" == "yes" ]]; then
    consecutive_void=0
    echo "  ✅ $session  attestation 成立"
  else
    consecutive_void=$(( consecutive_void + 1 ))
    echo "  ❌ ${session:-無 session}  沒有 attestation（連續第 $consecutive_void 次）"
    if (( consecutive_void >= MAX_CONSECUTIVE_VOID )); then
      echo
      echo "⛔ 連續 $consecutive_void 輪沒有 attestation，停止批次。"
      echo "   可能是攻擊端的迴圈結束了、時鐘不同步、或網路變了。"
      echo "   **這不是防禦成功的證據**——沒有證據就是沒有證據。"
      break
    fi
  fi
done

echo
echo "=================================================="
echo " 彙總"
echo "=================================================="
python3 - "$BATCH" "$ATTACKER" <<'PYEOF'
import json, os, sys
from pathlib import Path

batch, attacker = Path(sys.argv[1]), sys.argv[2]
home = Path(os.path.expanduser("~"))
rows = []
path = batch / "sessions.txt"
if path.exists():
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] == "none":
            rows.append((parts[0] if parts else "?", None, None))
            continue
        target = home / "crosshost" / parts[1] / "crosscheck.json"
        try:
            rows.append((parts[0], parts[1], json.loads(target.read_text(encoding="utf-8"))))
        except Exception:
            rows.append((parts[0], parts[1], None))

verified = [r for r in rows if r[2] and r[2].get("source_ip_attribution_verified")]
blocked = [r for r in verified if attacker in (r[2].get("blockable_ips") or [])]
# 防守方自己的位址每輪都滿足唯一 GUID 與兩個綁定條件，只差沒有拒絕記錄——
# 它是這批資料裡免費的陰性對照，任何一輪被判可封鎖都是嚴重問題。
false_positive = [r for r in verified
                  if any(ip != attacker for ip in (r[2].get("blockable_ips") or []))]
guid_counts = sorted({
    info.get("guid_count")
    for _r, _s, d in verified
    for ip, info in (d.get("per_ip") or {}).items() if ip == attacker
})

print(f"  總輪數                     : {len(rows)}")
print(f"  attestation 成立           : {len(verified)}")
print(f"  攻擊者 IP 判為可封鎖       : {len(blocked)}")
print(f"  ⚠️ 誤把其他 IP 判為可封鎖  : {len(false_positive)}   ← 必須是 0")
print(f"  攻擊者每輪的 GUID 數       : {guid_counts or '-'}   ← 應該都是 [1]")
print()
for round_id, session, d in rows:
    if d is None:
        print(f"  {round_id:>3}  {session or '(無 session)'}  —")
        continue
    mark = "✅" if d.get("source_ip_attribution_verified") else "❌"
    reach = (d.get("attacker_reachability") or {}).get("verdict", "?")
    print(f"  {round_id:>3}  {session}  {mark}  {reach}")
PYEOF

echo
echo "  全部產物在 $BATCH 與 ~/crosshost/"
echo "  結束 $(date -u +%H:%M:%SZ)"
