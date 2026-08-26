#!/usr/bin/env bash
# 第二層守衛的完整循環：放行 → 封鎖 → **解除** → 恢復放行。
#
# 重點在第三步。只證明「擋得住」是不夠的——`ignore_participant` 也擋得住，
# 但它不可逆。本專題要的是**可撤銷**，所以必須量出解除之後有沒有真的恢復，
# 以及花多久。
source /opt/ros/jazzy/setup.bash
set -u

export ROS_DOMAIN_ID=77
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp

BL=/home/jesse/guard_blocklist.txt
DEC=/home/jesse/guard_decisions.jsonl
rm -f "$BL" "$DEC" /home/jesse/guard_talker.log

/home/jesse/observer_build/guard_filter --ros-args \
  -p guarded_topic:=chatter \
  -p blocklist_path:="$BL" \
  -p decisions_path:="$DEC" \
  -p reload_sec:=0.2 > /home/jesse/guard_stdout.log 2>&1 &
GUARD=$!
sleep 3

timeout 40 ros2 run demo_nodes_cpp talker > /home/jesse/guard_talker.log 2>&1 &
TALK=$!
sleep 8
echo "PHASE allow-1 done"

# 從決策日誌取出實際看到的發送者 GUID——不要用猜的。
GID=$(python3 - "$DEC" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    row = json.loads(line)
    if row.get("event") == "decision":
        print(row["guid_prefix"])
        break
PYEOF
)
echo "observed publisher prefix: $GID"

date +%s.%N > /home/jesse/guard_block_at.txt
echo "$GID" > "$BL"
sleep 8
echo "PHASE blocked done"

date +%s.%N > /home/jesse/guard_unblock_at.txt
rm -f "$BL"
sleep 8
echo "PHASE released done"

kill $TALK 2>/dev/null
sleep 1
kill $GUARD 2>/dev/null
sleep 1
echo "=== decisions ==="
wc -l < "$DEC"
