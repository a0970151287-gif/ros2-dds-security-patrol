#!/bin/bash
# ============================================================
# 08 SAC 深度強化學習訓練
# 演算法：Soft Actor-Critic（Stable Baselines3）
# 論文：reiniscimurs/DRL-Robot-Navigation-ROS2
# GPU：RTX 5070（CUDA）
# 目標：3,000,000 timesteps
# 網路：[512, 512]，buffer 1M（完全對齊論文）
# ============================================================

# ── 終端 1：啟動 Gazebo 模擬器 ──────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash
export TURTLEBOT3_MODEL=burger
ros2 launch dds_security_monitor gazebo.launch.py

# ── 終端 2：開始 / 接續 SAC 訓練 ────────────────────────────
source ~/.config/dds-monitor/credentials
source ~/dqn_env/bin/activate
source ~/ros2_ws/install/setup.bash
python3 ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/train_sac.py
# • 每 50,000 steps 自動存 checkpoint（含 replay buffer）
# • Ctrl+C 中斷後自動儲存，下次執行自動從斷點接續

# ── 終端 3：TensorBoard 監控（另開）────────────────────────
source ~/dqn_env/bin/activate
tensorboard --logdir ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/logs_sac/tensorboard
# 瀏覽器開 http://localhost:6006

# ── 確認 GPU + SB3 ────────────────────────────────────────
source ~/dqn_env/bin/activate
python3 -c "
import torch, stable_baselines3
print('CUDA:', torch.cuda.is_available())
print('GPU :', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'N/A')
print('SB3 :', stable_baselines3.__version__)
"

# ── 手動傳送機器人回安全位置（卡住時用）─────────────────────
GZ_IP=127.0.0.1 gz service -s /world/default/set_pose \
  --reqtype gz.msgs.Pose \
  --reptype gz.msgs.Boolean \
  --timeout 3000 \
  --req 'name: "burger", position: {x: -0.5, y: -0.5, z: 0.05}, orientation: {x: 0.0, y: 0.0, z: 0.0, w: 1.0}'
