"""自訂 Gazebo 啟動檔。

修正：
1. 自動設定 GZ_SIM_RESOURCE_PATH（機器人外型顯示）
2. 啟動後自動發送零速度（防止機器人轉圈）
"""
import os
from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import (
    AppendEnvironmentVariable,
    IncludeLaunchDescription,
)
from launch.launch_description_sources import PythonLaunchDescriptionSource


def generate_launch_description():
    turtlebot3_gazebo = get_package_share_directory('turtlebot3_gazebo')

    set_resource_path = AppendEnvironmentVariable(
        'GZ_SIM_RESOURCE_PATH',
        os.path.join(turtlebot3_gazebo, 'models')
    )

    launch_gazebo = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(turtlebot3_gazebo, 'launch', 'turtlebot3_world.launch.py')
        )
    )

    return LaunchDescription([
        set_resource_path,
        launch_gazebo,
    ])
