"""
統一啟動檔：TurtleBot3 導航系統 + DDS 安全監控

使用方式：
  # 模擬模式（不需要實體機器人）
  ros2 launch dds_security_monitor full_system.launch.py

  # 實體機器人模式
  ros2 launch dds_security_monitor full_system.launch.py with_hardware:=true

  # 指定機器人型號與地圖
  ros2 launch dds_security_monitor full_system.launch.py model:=waffle map:=/path/to/map.yaml
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, GroupAction, IncludeLaunchDescription
from launch.conditions import IfCondition
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration


def generate_launch_description():
    # ── 參數宣告 ──────────────────────────────────────────────────────────────
    model_arg = DeclareLaunchArgument(
        'model', default_value='burger',
        description='TurtleBot3 型號 (burger / waffle / waffle_pi)'
    )
    map_arg = DeclareLaunchArgument(
        'map',
        default_value=os.path.join(
            get_package_share_directory('turtlebot3_navigation2'),
            'map', 'map.yaml'
        ),
        description='地圖檔案路徑'
    )
    use_sim_time_arg = DeclareLaunchArgument(
        'use_sim_time', default_value='false',
        description='使用模擬時間（Gazebo 模擬時設為 true）'
    )
    with_hardware_arg = DeclareLaunchArgument(
        'with_hardware', default_value='false',
        description='是否啟動實體機器人驅動（需要接 TurtleBot3）'
    )
    with_patrol_arg = DeclareLaunchArgument(
        'with_patrol', default_value='true',
        description='是否啟動自主巡邏節點'
    )

    model         = LaunchConfiguration('model')
    map_path      = LaunchConfiguration('map')
    use_sim_time  = LaunchConfiguration('use_sim_time')
    with_hardware = LaunchConfiguration('with_hardware')
    with_patrol   = LaunchConfiguration('with_patrol')

    # ── 套件路徑 ──────────────────────────────────────────────────────────────
    nav2_pkg    = get_package_share_directory('turtlebot3_navigation2')
    bringup_pkg = get_package_share_directory('turtlebot3_bringup')
    monitor_pkg = get_package_share_directory('dds_security_monitor')

    # ── 子啟動檔 ──────────────────────────────────────────────────────────────

    # 1. 實體機器人硬體驅動（選用）
    hardware_launch = GroupAction(
        condition=IfCondition(with_hardware),
        actions=[
            IncludeLaunchDescription(
                PythonLaunchDescriptionSource(
                    os.path.join(bringup_pkg, 'launch', 'robot.launch.py')
                ),
            )
        ]
    )

    # 2. Nav2 導航堆疊
    nav2_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(nav2_pkg, 'launch', 'navigation2.launch.py')
        ),
        launch_arguments={
            'model':        model,
            'map':          map_path,
            'use_sim_time': use_sim_time,
        }.items()
    )

    # 3. DDS 安全監控節點
    monitor_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(monitor_pkg, 'launch', 'monitor.launch.py')
        )
    )

    # 4. 自主巡邏節點（選用）
    from launch_ros.actions import Node
    patrol_node = GroupAction(
        condition=IfCondition(with_patrol),
        actions=[
            Node(
                package='dds_security_monitor',
                executable='patrol_node',
                name='patrol_node',
                parameters=[os.path.join(monitor_pkg, 'config', 'config.yaml')],
                output='screen',
                emulate_tty=True,
            )
        ]
    )

    return LaunchDescription([
        model_arg,
        map_arg,
        use_sim_time_arg,
        with_hardware_arg,
        with_patrol_arg,
        hardware_launch,
        nav2_launch,
        monitor_launch,
        patrol_node,
    ])
