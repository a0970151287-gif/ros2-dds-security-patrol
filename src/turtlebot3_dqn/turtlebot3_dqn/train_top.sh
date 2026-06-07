#!/bin/bash
# Tier-1 TQC training launcher.
#
# Prereqs:
#   1. Gazebo Burger world already running with ros_gz_bridge → /scan + /odom + /cmd_vel
#   2. ~/dqn_env Python venv with sb3-contrib installed
#   3. ROS2 overlay sourced (~/ros2_ws/install/setup.bash)
#
# Tensorboard:
#   tensorboard --logdir ~/ros2_ws/src/turtlebot3_dqn/turtlebot3_dqn/runs_top/logs/tensorboard
# -u (nounset) is intentionally OFF: ROS2 setup.bash + venv activate
# both reference unset internal vars and would abort under nounset.
set -eo pipefail

cd "$(dirname "$0")"

# Idempotent sources — safe even if already active.
source ~/.config/dds-monitor/credentials 2>/dev/null || true
source ~/dqn_env/bin/activate
source ~/ros2_ws/install/setup.bash 2>/dev/null || true
export TURTLEBOT3_MODEL=burger

echo "▶ Sanity check: /scan publishing?"
# echo --once exits 0 after one message; timeout exits non-zero only if
# no message arrives within the window. `topic hz` never self-exits and
# would always look "failed" under timeout, regardless of actual state.
if ! timeout 5 ros2 topic echo --once /scan --no-arr >/dev/null 2>&1; then
    echo "  ✗ /scan not publishing — start Gazebo + ros_gz_bridge first."
    exit 1
fi
echo "  ✓ /scan alive"

echo "▶ Sanity check: /odom publishing?"
if ! timeout 5 ros2 topic echo --once /odom >/dev/null 2>&1; then
    echo "  ✗ /odom not publishing — check robot_state_publisher / ros_gz_bridge."
    exit 1
fi
echo "  ✓ /odom alive"

echo
echo "▶ Launching TQC training (target 2M steps; Ctrl+C anytime to stop)"
exec python3 train_top.py
