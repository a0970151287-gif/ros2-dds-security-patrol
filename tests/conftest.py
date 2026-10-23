"""pytest 共享設定。

測試優先載入目前工作樹的 Python package，避免綁死 ``~/ros2_ws``、
特定 Python 小版本，或誤測到舊的 ``install/`` 產物。
ROS2 本身仍需先 ``source /opt/ros/jazzy/setup.bash``。
"""
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PACKAGE = _REPO_ROOT / "src" / "dds_security_monitor"

if _SOURCE_PACKAGE.is_dir() and str(_SOURCE_PACKAGE) not in sys.path:
    sys.path.insert(0, str(_SOURCE_PACKAGE))
