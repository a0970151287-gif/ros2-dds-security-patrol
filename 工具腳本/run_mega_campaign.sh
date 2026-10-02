#!/usr/bin/env bash
# 大型資料集 campaign 的監督器（自適應攻擊者 ＋ 場次抖動）。⚠️ 會產生 live 攻擊流量，需要 Jesse 的授權。
#
# 用法（背景執行，脫離目前的 shell）：
#     nohup bash 工具腳本/run_mega_campaign.sh > ~/mega_supervisor.log 2>&1 &
#
# 看進度：
#     ls -d ~/dataset_mega/*/ | wc -l          # 已完成幾場
#     tail -5 ~/mega_supervisor.log
#
# 停下來：
#     pkill -f "[r]un_mega_campaign.sh"; cd ~/ros2_ws
#     bash firewall_lab/live_stack.sh stop permissive
#     bash firewall_lab/live_stack.sh stop enforce
#
# ⚠️ 筆電休眠會讓它停住（2026-09-17 發生過）。醒來之後照上面的用法重跑即可，
#    campaign 會接著跑 plan 裡還沒完成的場次，已完成的不會重做。

ROS_SETUP="${ROS_SETUP:-/opt/ros/jazzy/setup.bash}"
. "$ROS_SETUP"
set -u
REPO="${REPO:-/home/jesse/ros2_ws}"
cd "$REPO" || exit 1
export PYTHONUTF8=1
export FIREWALL_LIVE_RUNTIME="$HOME/.sros2_live_runtime"
mkdir -p "$FIREWALL_LIVE_RUNTIME"

PLAN="${PLAN:-$HOME/mega_plan.json}"
DATASET="${DATASET:-$HOME/dataset_mega}"
CHUNK="${CHUNK:-40}"
LOG="${LOG:-$HOME/mega_campaign.log}"
mkdir -p "$DATASET"

# stack 會起來的所有行程。`live_stack.sh` 用 pid 檔殺**行程群組**,那對它自己
# 啟動的那一輪有效;但一輪 readiness 失敗、下一輪覆蓋掉 pid 檔之後,上一輪的
# 殘留就**結構上再也殺不到**。2026-09-20 實測就是這樣一路累積:
#   36 → 42 → 48 → 54 → 60 → 66 個行程,每輪 +6,連續 19 輪什麼都沒產出。
# 所以監督器自己要有一道按名字的兜底清除。
#
# ⚠️ 只列**夠特定**的名字。`create`、`component_container` 這種通用字會誤殺
# 使用者自己的行程,寧可漏殺也不要誤殺。
STACK_PATTERNS='gz sim|gzserver|ros_gz_sim|ros_gz_bridge|parameter_bridge|
robot_state_publisher|monitor_node|intelligent_defense|velocity_guard|
patrol_node|sensor_hub|mission_manager|system_status_node|dumpcap|
live_telemetry_collector|sros2_deny_adapter'
STACK_PATTERNS=$(printf '%s' "$STACK_PATTERNS" | tr -d '
')

count_stack_processes() {
  # ⚠️ 不要用 `pgrep -c ... || echo 0`。沒有命中時 `pgrep -c` **自己會印 0**
  # 而且**退出碼是 1**，於是 `|| echo 0` 再印一次——回傳值變成兩行的 0 與 0，
  # 下游的 `[ "$left" -eq 0 ]` 就炸成 `integer expression expected`。
  # 2026-09-20 重啟監督器時第一輪就撞到。`wc -l` 永遠只印一個整數。
  pgrep -u "$(id -u)" -f "$STACK_PATTERNS" 2>/dev/null | wc -l
}

clear_stale_dds_shm() {
  # Fast DDS 的 SHM transport 會在 /dev/shm 開 port 檔並上鎖。行程被硬殺之後
  # 鎖可能留著,下一次啟動就是滿螢幕的
  #     RTPS_TRANSPORT_SHM Error: Failed init_port fastrtps_portNNNN:
  #     open_and_lock_file failed
  # 而**症狀是 readiness 失敗**,看起來像 Gazebo 或 monitor 壞了。
  #
  # ⚠️ 只在**完全沒有** stack 行程時清。有行程活著就清掉它正在用的段,
  # 那是把一個還能救的 stack 弄死。
  local left
  left=$(count_stack_processes)
  if [ "${left:-0}" -ne 0 ]; then return 0; fi
  local n
  n=$(ls /dev/shm 2>/dev/null | grep -c '^fastrtps' || true)
  if [ "${n:-0}" -gt 0 ]; then
    rm -f /dev/shm/fastrtps_* 2>/dev/null
    echo "  ♻️ 清掉 $n 個殘留的 Fast DDS 共享記憶體段" | tee -a "$LOG"
  fi
  rm -f /tmp/fastrtps_* 2>/dev/null
}

assert_no_other_campaign() {
  # `<plan>.lock` 防的是「兩個 campaign 同時寫同一份計畫」，但它只防得住
  # **遵守它的人**。2026-09-20 我自己在重啟腳本裡 `rm -f` 掉那個鎖，理由寫著
  # 「前面已確認沒有 campaign 行程」——而那一步只查了 `run_mega_campaign.sh`，
  # 沒有查 `firewall_lab.campaign`。於是舊監督器留下的孤兒 campaign 還活著，
  # 新的又起一個，**同一秒有兩場 session 都是 status=running**。
  #
  # 鎖不夠，因為刪鎖的人正是我。改成直接數行程：多於一個就不要開始這一批。
  local mine others
  mine=$$
  others=$(pgrep -u "$(id -u)" -f "firewall_lab.campaign run" 2>/dev/null \
           | grep -v "^${mine}$" | wc -l)
  if [ "${others:-0}" -gt 0 ]; then
    echo "  ⛔ 已經有 $others 個 campaign 行程在跑，這一批不啟動" | tee -a "$LOG"
    pgrep -u "$(id -u)" -af "firewall_lab.campaign run" | sed 's/^/     /' \
      | tee -a "$LOG"
    return 1
  fi
  return 0
}

stack_up() {   # $1 = mode
  clear_stale_dds_shm
  local out="$HOME/.mega_stack_start.$1.log"
  if ! bash firewall_lab/live_stack.sh start "$1" > "$out" 2>&1; then
    echo "  ⛔ $1 live_stack.sh start 直接失敗：" | tee -a "$LOG"
    tail -5 "$out" | sed 's/^/     /' | tee -a "$LOG"
    return 1
  fi
  for i in $(seq 1 60); do
    s=$(bash firewall_lab/live_stack.sh status "$1" 2>&1 | head -1)
    case "$s" in *readiness=ready*) return 0;; esac
    sleep 5
  done
  # 逾時。把原因記下來——原本這裡整個 `>/dev/null`,所以日誌只會寫
  # 「起不來」,而真正的原因（SHM 上鎖失敗）躺在另一個檔案裡沒人看。
  echo "  ⛔ $1 readiness 逾時（200s）。stack 日誌最後幾行：" | tee -a "$LOG"
  tail -4 "$HOME/.sros2_live_runtime/$1.log" 2>/dev/null     | cut -c1-160 | sed 's/^/     /' | tee -a "$LOG"
  local shm
  shm=$(ls /dev/shm 2>/dev/null | grep -c '^fastrtps' || true)
  echo "     （/dev/shm 的 fastrtps 段：${shm:-0}；stack 行程：$(count_stack_processes)）"     | tee -a "$LOG"
  return 1
}
clear_stale_lock() {
  # campaign 用 `<plan>.lock` 防止兩個執行者同時寫壞資料集,而鎖是在
  # `__exit__` 釋放的——行程被 kill（或筆電休眠後被收掉）就會留下陳舊的鎖,
  # 之後每一次執行都直接 RuntimeError。多天執行一定會遇到,而且是**安靜地
  # 卡住**:監督器照跑,但每一批都失敗。
  #
  # ⚠️ 不可以無條件刪。鎖檔裡寫了 `pid=`,只有那個行程**確實不在**才清掉;
  # 還活著就讓它留著並跳過這一批。
  local lock="${PLAN}.lock"
  [ -e "$lock" ] || return 0
  local pid
  pid=$(sed -n 's/^pid=\([0-9]\+\).*/\1/p' "$lock" 2>/dev/null | head -1)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "  ⛔ 鎖被 pid=$pid 持有且它還活著,跳過" | tee -a "$LOG"
    return 1
  fi
  echo "  ♻️ 清掉陳舊的鎖（pid=${pid:-未知} 已不存在）" | tee -a "$LOG"
  rm -f "$lock"
  return 0
}

stack_down() {   # $1 = mode
  bash firewall_lab/live_stack.sh stop "$1" >/dev/null 2>&1 || true
  # 等到行程真的消失，不要用固定秒數。
  # 2026-09-20 實測：收尾後 3 秒仍有 1 個行程活著（再幾秒才退）。殘留會污染
  # 下一批——C2C-044 記過，沒收乾淨的 stack 讓三輪 live 全部作廢，而症狀是
  # 「Gazebo readiness failed」，看起來像模擬器壞了。
  local left=0
  for _ in $(seq 1 15); do
    left=$(count_stack_processes)
    if [ "${left:-0}" -eq 0 ]; then return 0; fi
    sleep 2
  done

  # ⚠️ 到這裡代表 `live_stack.sh stop` 收不掉。它殺的是 pid 檔記錄的**行程
  # 群組**，而上一輪 readiness 失敗、這一輪又覆蓋掉 pid 檔之後，舊的孤兒
  # **結構上再也殺不到**，只會愈積愈多。2026-09-20 實測 36→42→48→54→60→66，
  # 連續 19 輪、80 分鐘零產出。
  #
  # 所以按名字兜底：先 TERM 再 KILL，中間留時間讓它們自己收乾淨。
  echo "  ⚠️ live_stack 收不乾淨（剩 $left 個），改用名字清除" | tee -a "$LOG"
  pkill -u "$(id -u)" -TERM -f "$STACK_PATTERNS" 2>/dev/null || true
  sleep 5
  left=$(count_stack_processes)
  if [ "${left:-0}" -gt 0 ]; then
    pkill -u "$(id -u)" -KILL -f "$STACK_PATTERNS" 2>/dev/null || true
    sleep 3
  fi
  left=$(count_stack_processes)
  clear_stale_dds_shm
  if [ "${left:-0}" -eq 0 ]; then
    echo "  ✅ 名字清除成功，殘留 0" | tee -a "$LOG"
    return 0
  fi
  echo "  ⛔ 連 SIGKILL 都還剩 $left 個行程——下一批一定受污染" | tee -a "$LOG"
  return 1
}

quarantine_empty_sessions() {
  # stack 若在一批中途死掉，campaign 仍會**繼續產生場次**——只是那些場次的
  # 遙測是空的。而「零事件」與「防禦擋下了一切」在資料上長得一模一樣，
  # 這個專案已經被同一個混淆咬過好幾次。
  #
  # 2026-09-20 實測發生過：一個壞掉的探針讓我誤判 campaign 已死，於是把
  # stack 收掉，而 campaign 其實還活著，又寫了好幾場沒有防禦在跑的資料。
  #
  # 所以每一批之後掃一次，把遙測過小的場次**移到隔離區**（不是刪除——
  # raw 證據不刪，這是專案的規矩）。
  local void="${DATASET}_void"
  local moved=0 d tel
  mkdir -p "$void"
  for d in "$DATASET"/*/; do
    [ -d "$d" ] || continue
    tel="$d/telemetry_events.jsonl"
    if [ ! -s "$tel" ] || [ "$(stat -c %s "$tel" 2>/dev/null || echo 0)" -lt 2048 ]; then
      mv "$d" "$void"/ 2>/dev/null && moved=$((moved + 1))
    fi
  done
  if [ "$moved" -gt 0 ]; then
    echo "  ⚠️ 隔離了 $moved 場遙測為空的場次 → $void" | tee -a "$LOG"
  fi
}

round=0
# 連續幾批「一場都沒完成」就停下來。
#
# 2026-09-20 的教訓：stack 起不來之後監督器**照樣每四分鐘再試一次**，連續
# 19 輪、80 分鐘完全零產出，而日誌只寫「起不來」。無人值守的批次必須會
# 大聲失敗（C2C-049 對跨主機批次就是這樣設計的，這支當初漏掉了）。
#
# 4 批 ≈ 16 分鐘。低於這個數會被單次偶發失敗誤觸；高於這個數就開始浪費夜。
MAX_BARREN_BATCHES="${MAX_BARREN_BATCHES:-4}"
barren=0

# 連續幾批「場次明顯變慢」就停下來。
#
# 2026-09-24 量出來的缺口：2026-09-19 那次 run 從約 95 秒一場退化成約 385 秒
# 一場，連續 103 場、約十小時。上面那個熔斷器**完全看不到**——它數的是
# 「有沒有產出場次」，而退化的 campaign 還是有在產出，只是慢四倍。
#
# 「什麼都沒產出」與「全部產出但太慢」是兩種失效，原本只守了第一種。
#
# ⚠️ 2026-09-24 稍晚：判準從「絕對中位數」改成「殘差」（實際減去擷取量模型
# 的預測），因為場次牆鐘追著 pcap 大小走——300 MB 光量體就要 198 秒,絕對門檻
# 會把任何一批重型情境誤判成退化。
#
# 門檻也跟著換單位。健康殘差是 −2.8 秒（p75 +6.3）,2026-09-19 那次退化是
# +116.8 秒,所以 +60 秒離兩邊都很遠。
#
# 沿用舊的 200 會讓閘門放寬三倍多——那個數字是為絕對時間選的,拿來當殘差門檻
# 就連 09-19 那次都抓不到。3 批 ≈ 12 分鐘。
MAX_SLOW_BATCHES="${MAX_SLOW_BATCHES:-3}"
SLOW_SESSION_SEC="${SLOW_SESSION_SEC:-90}"
slow=0

session_count() { ls -d "$DATASET"/*/ 2>/dev/null | wc -l; }

# 回傳 0＝步調正常或資料不足，4＝明顯變慢。
check_pace() {
  python3 "$REPO/工具腳本/recent_session_pace.py"     --dataset "$DATASET" --window 10     --slow-threshold-sec "$SLOW_SESSION_SEC" 2>&1 | tee -a "$LOG"
  return "${PIPESTATUS[0]}"
}

while :; do
  round=$((round + 1))
  for mode in permissive enforce; do
    echo "===== round $round / $mode / $(date -u +%H:%M:%SZ) =====" | tee -a "$LOG"
    before=$(session_count)
    if ! stack_up "$mode"; then
      echo "  ⛔ $mode stack 起不來,跳過這一批" | tee -a "$LOG"
      stack_down "$mode"
      barren=$((barren + 1))
      if [ "$barren" -ge "$MAX_BARREN_BATCHES" ]; then
        echo "⛔⛔ 連續 $barren 批沒有產出任何場次，停止監督器。" | tee -a "$LOG"
        echo "    再試下去只會空轉。診斷順序：" | tee -a "$LOG"
        echo "    1) ls /dev/shm | grep fastrtps   （殘留的 SHM 段）" | tee -a "$LOG"
        echo "    2) pgrep -af 'monitor_node|gz sim'（殘留的 stack 行程）" | tee -a "$LOG"
        echo "    3) tail -40 ~/.sros2_live_runtime/$mode.log" | tee -a "$LOG"
        exit 3
      fi
      continue
    fi
    if ! assert_no_other_campaign; then stack_down "$mode"; continue; fi
    if ! clear_stale_lock; then stack_down "$mode"; continue; fi
    # 計畫若把持證內鬼排進 Permissive，那一批會**整批**以 ValueError 中止
    # （`execute_campaign` 對場次失敗是 fail-closed 的,不是跳過一場）。
    # 2026-09-20 實測：160 個這種 entry 讓 12.4 小時裡 permissive 只完成
    # 54 場而 enforce 有 136 場。產生器已經修好,這一行是給既有計畫的自癒,
    # 沒東西可修時它什麼都不做。
    python3 -m firewall_lab.campaign repair --plan "$PLAN" >> "$LOG" 2>&1       || echo "  ⚠️ repair 跳過（拿不到鎖或計畫有更深的問題）" | tee -a "$LOG"
    for phase in "" "--retry-failed"; do
      # shellcheck disable=SC2086
      python3 -m firewall_lab.campaign run         --plan "$PLAN" --dataset "$DATASET"         --security-mode "$mode" --capture-interface lo         --limit "$CHUNK" --jitter --adaptive --confirm-isolated-lab $phase         >> "$LOG" 2>&1
      echo "  $mode $phase rc=$?" | tee -a "$LOG"
    done
    stack_down "$mode"
    quarantine_empty_sessions
    n=$(session_count)
    echo "  累計場次 = $n" | tee -a "$LOG"
    if [ "$n" -gt "$before" ]; then
      barren=0
    else
      barren=$((barren + 1))
      echo "  ⚠️ 這一批沒有新增場次（連續 $barren／$MAX_BARREN_BATCHES）"         | tee -a "$LOG"
      if [ "$barren" -ge "$MAX_BARREN_BATCHES" ]; then
        echo "⛔⛔ 連續 $barren 批沒有產出任何場次，停止監督器。" | tee -a "$LOG"
        exit 3
      fi
    fi

    # 步調檢查刻意放在產出檢查**之後**：一批可能同時是「有產出」與「太慢」，
    # 而那正是要抓的組合。
    if check_pace; then
      slow=0
    else
      slow=$((slow + 1))
      echo "  ⚠️ 這一批的場次明顯變慢（連續 $slow／$MAX_SLOW_BATCHES）"         | tee -a "$LOG"
      if [ "$slow" -ge "$MAX_SLOW_BATCHES" ]; then
        echo "⛔⛔ 連續 $slow 批場次過慢，停止監督器。"           | tee -a "$LOG"
        echo "    2026-09-19 的退化就是這個形態：場次照樣產出，只是慢四倍，"           | tee -a "$LOG"
        echo "    十小時後才被人發現。殘留 SHM 段與孤兒行程是第一個要查的。"           | tee -a "$LOG"
        exit 4
      fi
    fi
  done
done
