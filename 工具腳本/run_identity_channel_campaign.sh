#!/usr/bin/env bash
# identity_abuse ＋ normal 重跑，帶 sidecar 觀測者的認證證據通道。
#
# 用法： run_identity_channel_campaign.sh [每類場次] [輸出根目錄]
#        預設 50 場 identity_abuse ＋ 50 場 normal（Enforce），約兩小時
#
# ## 為什麼跑這一批
#
# `identity_abuse` 在 Enforce 下**完全沒有任何遙測訊號**——2026-08-30 實測一場
# 攻擊 session 的六個視窗裡，18 個 telemetry 特徵只有 sros_auth_fail_rate 非零，
# 其餘全零。那正是它 test recall 0.467、Enforce 識別 0.4155 的原因：攻擊在
# handshake 就被擋，應用層看不到東西。
#
# sidecar 觀測者繞過 rmw 拿得到 DDS 認證判定，observer_deny_adapter 把它轉成
# sros2_deny，features.py 既有的映射就會讓 sros_auth_fail_rate 活過來。
# 四場驗證：normal 場 0、identity_abuse 場每場 18 筆。
#
# ## 三個一定要記住的前提（都是 2026-08-30 踩過的）
#
# 1. **campaign 不啟動 ROS stack。** orchestrator 與 campaign 都沒有 live_stack
#    引用，docstring 寫 "external stack"。少了它 session 會跑完但 telemetry 只有
#    collector 自己的 tick，訓練閘門以 not_eligible:runtime_telemetry 擋下。
# 2. **觀測者不可釘傳輸。** OBSERVER_INTERFACE_ADDRESS 會關掉 builtin transports，
#    觀測者只剩 UDP、沒有 SHM，而 ROS 2 同機走 SHM——握手走不起來，**每個合法
#    節點都會被記成 UNAUTHORIZED**，特徵就毀了。
# 3. **requested_counts 依 scenario_id 分組**，每組 {total, permissive, enforce}
#    且與 entries 完全相符，否則 validate_campaign_plan 拒收。
#
# ## 隔離
#
# 全程 ROS_LOCALHOST_ONLY=1，攻擊流量鎖在 loopback（runners.attacker_environment
# 不剝除這個變數，已確認），--confirm-isolated-lab 因此站得住。擷取介面用 lo。

set -uo pipefail

PER_CLASS="${1:-50}"
OUT="${2:-/home/jesse/identity_channel_$(date -u +%Y%m%dT%H%M%SZ)}"
WS="$HOME/ros2_ws"
RUNTIME="/home/jesse/.local/share/sros2-firewall/live_runtime"
SOCK="$RUNTIME/runtime_telemetry.sock"
E="$WS/sros2_keystore/enclaves/security_readiness_probe"
OBSERVER_BIN="${OBSERVER_BIN:-$HOME/observer_build/security_observer}"
# 觀測者要活過整批。每場約 65 秒，留兩倍餘裕。
OBS_SECONDS=$(( PER_CLASS * 2 * 130 ))

mkdir -p "$OUT"
[ -x "$OBSERVER_BIN" ] || { echo "⛔ 找不到觀測者：$OBSERVER_BIN" >&2; exit 2; }

source "$WS/工具腳本/load_ros_environment.sh" >/dev/null || { echo "⛔ ROS 環境載入失敗" >&2; exit 1; }
export ROS_LOCALHOST_ONLY=1
export FIREWALL_LIVE_RUNTIME="$RUNTIME"
export ROS_SECURITY_KEYSTORE="$WS/sros2_keystore"
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_DOMAIN_ID=30
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
export SROS2_FIREWALL_LIVE_ACK=I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE
export SROS2_FIREWALL_TELEMETRY_SOCKET="$SOCK"
unset FASTRTPS_DEFAULT_PROFILES_FILE
unset OBSERVER_INTERFACE_ADDRESS

cleanup() {
  trap - EXIT INT TERM
  [ -n "${OBS:-}" ] && kill -TERM "$OBS" 2>/dev/null
  [ -n "${ADAPTER:-}" ] && kill -TERM "$ADAPTER" 2>/dev/null
  bash "$WS/firewall_lab/live_stack.sh" stop enforce >/dev/null 2>&1
  pkill -f 'security_observer' 2>/dev/null
  pkill -f 'dds_security_monitor|gazebo.launch|gzserver' 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "=================================================="
echo " identity_abuse 證據通道重跑"
echo "=================================================="
echo "  每類場次 : $PER_CLASS（Enforce）"
echo "  觀測者   : 不釘傳輸，存活 ${OBS_SECONDS}s"
echo "  輸出     : $OUT"
echo "  開始     : $(date -u +%H:%M:%SZ)"
echo

# ── 1. 計畫 ──────────────────────────────────────────────────────────
python3 - "$OUT/plan.json" "$PER_CLASS" <<'PYEOF'
import json, subprocess, sys, tempfile
from pathlib import Path
target = int(sys.argv[2])
tmp = Path(tempfile.mkdtemp()) / "full.json"
# plan 會把場次平分到兩個 security_mode，所以要兩倍才拿得到 target 個 enforce。
subprocess.run([sys.executable, "-m", "firewall_lab.campaign", "plan",
                "--output", str(tmp), "--normal-sessions", str(target * 2),
                "--attack-sessions-per-scenario", str(target * 2),
                "--seed", "20260830"],
               cwd=str(Path.home() / "ros2_ws"), check=True,
               stdout=subprocess.DEVNULL)
plan = json.loads(tmp.read_text(encoding="utf-8"))
keep = [e for e in plan["entries"]
        if e["security_mode"] == "enforce"
        and e["attack_class"] in ("normal", "identity_abuse")]
normal = [e for e in keep if e["attack_class"] == "normal"][:target]
attack = [e for e in keep if e["attack_class"] != "normal"][:target]
ordered = []
for pair in zip(normal, attack):      # 交錯，避免兩類落在不同的環境漂移段
    ordered.extend(pair)
plan["entries"] = ordered
counts = {}
for entry in ordered:
    per = counts.setdefault(entry["scenario_id"],
                            {"total": 0, "permissive": 0, "enforce": 0})
    per["total"] += 1
    per[entry["security_mode"]] += 1
plan["requested_counts"] = counts
Path(sys.argv[1]).write_text(json.dumps(plan, indent=2), encoding="utf-8")
print(f"  計畫：{len(ordered)} 場（normal {len(normal)} / identity_abuse {len(attack)}），交錯")
PYEOF
[ -s "$OUT/plan.json" ] || { echo "⛔ 計畫產生失敗"; exit 1; }

# ── 2. ROS stack ─────────────────────────────────────────────────────
echo "  啟動 SROS2 Enforce stack…"
bash "$WS/firewall_lab/live_stack.sh" start enforce >"$OUT/stack.log" 2>&1
ready=0
for _ in $(seq 1 45); do
  grep -q "SROS2 Enforce readiness 通過" "$RUNTIME/enforce.log" 2>/dev/null && { ready=1; break; }
  sleep 3
done
[ "$ready" -eq 1 ] || { echo "⛔ readiness 失敗"; tail -5 "$OUT/stack.log"; exit 1; }
echo "  readiness 通過"

# ── 3. 觀測者（不釘傳輸）＋ deny adapter ─────────────────────────────
OBSERVER_IDENTITY_CA="$E/identity_ca.cert.pem" \
OBSERVER_CERTIFICATE="$E/cert.pem" \
OBSERVER_PRIVATE_KEY="$E/key.pem" \
OBSERVER_GOVERNANCE="$E/governance.p7s" \
OBSERVER_PERMISSIONS="$E/permissions.p7s" \
OBSERVER_PERMISSIONS_CA="$E/permissions_ca.cert.pem" \
OBSERVER_AUDIT_LOG="$OUT/audit.log" \
OBSERVER_EVENTS_LOG="$OUT/observer_events.jsonl" \
"$OBSERVER_BIN" 30 "$OBS_SECONDS" >"$OUT/observer.log" 2>&1 &
OBS=$!
sleep 3
kill -0 "$OBS" 2>/dev/null || { echo "⛔ 觀測者沒起來：$(head -1 "$OUT/observer.log")"; exit 1; }
grep -q 'transport not pinned' "$OUT/observer.log" || {
  echo "⛔ 觀測者釘了傳輸——合法節點會被全部誤判，中止"; exit 1; }
echo "  觀測者執行中（已確認未釘傳輸）"

touch "$OUT/observer_events.jsonl"
( cd "$WS" && python3 -m firewall_lab.observer_deny_adapter \
    --socket "$SOCK" --follow "$OUT/observer_events.jsonl" \
    --stop-after-sec "$OBS_SECONDS" ) >"$OUT/adapter.log" 2>&1 &
ADAPTER=$!
echo "  deny adapter 執行中"
echo

# ── 4. campaign ──────────────────────────────────────────────────────
echo "  開始 campaign（$(( PER_CLASS * 2 )) 場）$(date -u +%H:%M:%SZ)"
( cd "$WS" && python3 -m firewall_lab.campaign run \
    --plan "$OUT/plan.json" --dataset "$OUT/dataset" \
    --security-mode enforce --capture-interface lo \
    --confirm-isolated-lab ) >"$OUT/campaign.log" 2>&1
rc=$?
echo "  campaign rc=$rc  $(date -u +%H:%M:%SZ)"

kill -TERM "$OBS" "$ADAPTER" 2>/dev/null; sleep 3

# ── 5. 逐場檢查通道有沒有中途斷掉 ────────────────────────────────────
echo
echo "=================================================="
python3 - "$OUT/dataset" <<'PYEOF'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
rows = []
for d in sorted(root.glob("*/")):
    tele = d / "telemetry_events.jsonl"
    man = d / "manifest.json"
    if not tele.exists() or not man.exists():
        continue
    try:
        klass = json.loads(man.read_text(encoding="utf-8")).get("attack_class", "?")
    except Exception:
        klass = "?"
    deny = 0
    for line in tele.read_text(encoding="utf-8").splitlines():
        try:
            if json.loads(line).get("event_type") == "sros2_deny":
                deny += 1
        except ValueError:
            pass
    rows.append((d.name, klass, deny))

atk = [(n, d) for n, k, d in rows if k != "normal"]
nor = [(n, d) for n, k, d in rows if k == "normal"]
print(f"  session 總數        : {len(rows)}")
print(f"  identity_abuse      : {len(atk)}")
print(f"  normal              : {len(nor)}")
print()
# 通道若中途斷掉，會表現為後半段的攻擊場 deny=0——那和「防禦擋下了」外觀相同，
# 所以逐場列出而不是只報平均。
dead = [n for n, d in atk if d == 0]
noisy = [n for n, d in nor if d > 0]
print(f"  攻擊場 deny=0（通道可能斷了）: {len(dead)}")
print(f"  正常場 deny>0（不該發生）    : {len(noisy)}")
if atk:
    counts = sorted(d for _n, d in atk)
    print(f"  攻擊場 deny 分布    : min {counts[0]}  中位數 {counts[len(counts)//2]}  max {counts[-1]}")
for n in dead[:5]:
    print(f"      斷掉: {n}")
for n in noisy[:5]:
    print(f"      污染: {n}")
print()
if dead:
    print("  ⛔ 有攻擊場拿不到認證證據——通道中途斷了，這批不可直接使用")
elif noisy:
    print("  ⛔ 正常場出現認證拒絕——來源不純，要查清楚才可用")
else:
    print("  ✅ 通道全程有效：每一場攻擊都有證據，每一場正常都乾淨")
PYEOF
echo "  產物在 $OUT"
echo "  結束 $(date -u +%H:%M:%SZ)"
