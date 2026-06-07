#!/bin/bash
# ============================================================
# 08 TQC 深度強化學習訓練（Tier-1 頂尖版）
# 演算法：Truncated Quantile Critics（sb3-contrib，SAC 後繼者）
# 表徵：raw 180-beam LiDAR + 1D-Conv encoder + frame stack K=4 + LayerNorm
# 訓練：potential-based shaping + DR + 5% 對抗 + 自適應 curriculum
# GPU：RTX 5070（CUDA）
# 目標：2,000,000 timesteps（SPL plateau 後可提早 Ctrl+C）
# ============================================================
# 設計重點：
#   • TQC：top_quantiles_to_drop_per_net=2，抑制 Q overestimation
#   • Reward = γ·Φ(s') - Φ(s) + smooth + sparse（Ng-Harada-Russell 1999）
#     → 理論上保證最佳策略不變，論文可直接引用
#   • Domain Randomization：lidar noise / dropout / max-vel 隨機化 → sim2real
#   • 對抗訓練：5% episode 注入 subtle lidar bias / noise burst / action jam
#     → 對應 DDS 攻擊 K 的端到端 robust policy
#   • Curriculum 1→5 waypoints，stage success ≥ 0.7 → 自動升級
#   • Best-by-SPL 存檔（只在 top stage），即時 HMAC 簽章
#   • 載入 model/buffer 前 HMAC 驗章，篡改 → 拒絕載入
#   • Boot banner 印 HMAC fingerprint，跨節點不一致立刻可見
# ============================================================

# ── 終端 1：啟動 Gazebo 模擬器 ──────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py

# ── 確認 /scan 跟 /odom 都活著（再開訓練！）────────────────
source ~/ros2_ws/install/setup.bash
ros2 topic hz /scan -w 1     # 約 5 Hz
ros2 topic hz /odom -w 1     # 約 50 Hz

# ── 終端 2：開始 / 接續 TQC 訓練 ──────────────────────────
# 整段 source 已包在 train_top.sh 內，直接一條：
bash ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/train_top.sh

# 啟動後應看到：
#   ▶ Sanity check: /scan publishing?       ✓ /scan alive
#   ▶ Sanity check: /odom publishing?       ✓ /odom alive
#   🔐  HMAC secret loaded   fingerprint=sha256:xxxxxxxx
#   ▶ Fresh start TQC training
#     Target steps : 2,000,000
#     Device       : cuda    Params: 1,209,992
# fingerprint 跟 monitor_node / patrol_node 印的不一樣 → secret 沒對齊立刻修

# 純執行版（不檢查 /scan /odom，假設你自己確認過）：
#   python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/train_top.py

# ── 終端 3：TensorBoard 監控 ──────────────────────────────
source ~/dqn_env/bin/activate
tensorboard --logdir ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/runs_top/logs/tensorboard
# 瀏覽器開 http://localhost:6006
# 核心指標看 scoreboard/*：
#   spl_mean              ← 主要決策指標（Habitat 標準，越高越好）
#   success_rate          ← 全部 waypoint 到達率
#   collision_rate        ← 碰撞率（目標 < 5%）
#   timeout_rate
#   curriculum_stage      ← 自動升級的目前難度（1..5）
#   mean_clearance        ← 平均最近障礙距離（越大越安全）
#   mean_reward / mean_waypoints

# 停訓判準（取代「跑滿 N steps」）：
#   • SPL > 0.85 且連續 100K steps 沒上升  → Ctrl+C 收工
#   • SPL 卡 0.5 超過 300K steps           → 停，回去調 hyperparam
#   • Curriculum 升到 stage 5 + SPL > 0.8  → 可寫論文

# ── 終端機計分板（訓練時自動每 20 ep 印一次）──────────────
#   ╔══════════════════════════════════════════════════════════════════════════════╗
#   ║  TQC TIER-1 SCOREBOARD                                                       ║
#   ╠══════════════════════════════════════════════════════════════════════════════╣
#   ║  Episode    500   Step    125,000 / 2,000,000  (  6.3%)                      ║
#   ║  Curriculum stage: 3/5 waypoints  (window n=100)                             ║
#   ║  SPL              ████████████░░░░  76.5%   (best @ top-stage:  0.0%)        ║
#   ║  Success rate     ███████░░░░░░░░░  45.2%                                    ║
#   ║  Collision rate   ██░░░░░░░░░░░░░░  12.3%                                    ║
#   ║  ...                                                                         ║
#   ╚══════════════════════════════════════════════════════════════════════════════╝

# ── 評估訓練成果（簡報數字必從這跑，不用 rolling mean）──────
source ~/dqn_env/bin/activate && source ~/ros2_ws/install/setup.bash
python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py --episodes 50 --max-wp 5
# 預設載 runs_top/models/tqc_best.zip，啟動會先驗 HMAC，篡改則 sys.exit(2)
# 輸出範例：
#   SPL              : 0.873     [95% CI 0.821, 0.918]
#   Success rate     :  92.0 %   [95% CI  84.0,  98.0]
#   Collision rate   :   4.0 %   [95% CI   0.0,   8.0]
#   Mean steps       : 124.3
# 同時把 per-episode 結果寫到 runs_top/models/eval_tqc_best_n50.csv

# 評不同難度（做 ablation 用）：
#   python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py --episodes 30 --max-wp 1
#   python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py --episodes 30 --max-wp 3
#   python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/eval_top.py --episodes 50 --max-wp 5

# ── 確認環境（GPU + SB3 + sb3-contrib）──────────────────
source ~/dqn_env/bin/activate
python3 -c "
import torch, stable_baselines3, sb3_contrib
print('CUDA   :', torch.cuda.is_available())
print('GPU    :', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'N/A')
print('SB3    :', stable_baselines3.__version__)
print('sb3_ctr:', sb3_contrib.__version__)
"

# ── 訓練中產出的檔案 ────────────────────────────────────
# runs_top/
#   models/
#     tqc_latest.zip                    ← 最新狀態（Ctrl+C / 結束時存）
#     tqc_latest.zip.sha256.hmac        ← HMAC 簽章
#     tqc_best.zip                      ← 歷史最佳 SPL（已簽章）
#     tqc_best.zip.sha256.hmac
#     tqc_buffer.pkl                    ← replay buffer（已簽章，防 pickle RCE）
#     tqc_buffer.pkl.sha256.hmac
#     checkpoints/tqc_*_steps.zip       ← 每 25k 步 snapshot
#     eval_tqc_best_n50.csv             ← eval_top.py 輸出
#   logs/
#     tensorboard/TQC_*                 ← TensorBoard event
#     monitor/                          ← SB3 Monitor csv

# ── 手動傳送機器人回安全位置（卡住時用）─────────────────────
GZ_IP=127.0.0.1 gz service -s /world/default/set_pose \
  --reqtype gz.msgs.Pose \
  --reptype gz.msgs.Boolean \
  --timeout 3000 \
  --req 'name: "burger", position: {x: -0.5, y: -0.5, z: 0.05}, orientation: {x: 0.0, y: 0.0, z: 0.0, w: 1.0}'

# ── 從零重訓（砍掉所有產出）─────────────────────────────
# rm -rf ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/runs_top/
