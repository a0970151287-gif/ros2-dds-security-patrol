#!/bin/bash
# ============================================================
# 09 環境設定與套件管理
# ============================================================

# ── 每個終端都要先執行的 source ─────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/ros2_ws/install/setup.bash

# ── DQN 訓練終端 ────────────────────────────────────────────
source ~/.config/dds-monitor/credentials && source ~/dqn_env/bin/activate && source ~/ros2_ws/install/setup.bash

# ── Python 虛擬環境（DQN 訓練專用，只需建一次）────────────
python3 -m venv ~/dqn_env --system-site-packages
source ~/dqn_env/bin/activate
# GPU 版（RTX 5070 / CUDA）
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu128
pip install gymnasium matplotlib

# 確認 GPU
python3 -c "import torch; print('CUDA:', torch.cuda.is_available()); print('GPU:', torch.cuda.get_device_name(0))"

# ── Build ROS2 套件 ──────────────────────────────────────────
cd ~/ros2_ws
colcon build --packages-select dds_security_monitor --symlink-install
colcon build --symlink-install

# ── 安全變數確認 ─────────────────────────────────────────────
echo "ROS_SECURITY_ENABLE=$ROS_SECURITY_ENABLE"
echo "ROS_SECURITY_STRATEGY=$ROS_SECURITY_STRATEGY"
echo "ROS_SECURITY_KEYSTORE=$ROS_SECURITY_KEYSTORE"
echo "ROS_DOMAIN_ID=$ROS_DOMAIN_ID"
