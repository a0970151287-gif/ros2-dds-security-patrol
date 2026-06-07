"""pytest 共享設定。"""
import os
import sys
from pathlib import Path

# 把 ROS2 build 後的 site-packages 加進來
_ROS_PKG = Path.home() / "ros2_ws" / "install" / "dds_security_monitor" / "lib" / "python3.12" / "site-packages"
if _ROS_PKG.exists() and str(_ROS_PKG) not in sys.path:
    sys.path.insert(0, str(_ROS_PKG))
