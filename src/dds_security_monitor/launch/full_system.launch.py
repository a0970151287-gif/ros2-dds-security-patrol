"""
統一啟動檔：TurtleBot3 單一控制軌 + DDS 安全監控

使用方式：
  # 模擬模式（不需要實體機器人）
  ros2 launch dds_security_monitor full_system.launch.py

  # 實體機器人模式
  ros2 launch dds_security_monitor full_system.launch.py \
    with_hardware:=true use_sim_time:=false with_patrol:=false \
    control_source:=none

  # 改用 Nav2 控制軌（Nav2 輸出先進 velocity guard）
  ros2 launch dds_security_monitor full_system.launch.py \
    with_nav2:=true with_patrol:=false control_source:=nav2 \
    map:=/path/to/map.yaml
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import (
    DeclareLaunchArgument,
    GroupAction,
    IncludeLaunchDescription,
    OpaqueFunction,
    SetEnvironmentVariable,
)
from launch.conditions import IfCondition, UnlessCondition
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.actions import Node, SetRemap
from launch_ros.substitutions import FindPackageShare


def _validate_controller_choice(context):
    """Fail before launch on an unsafe controller or security configuration."""
    security_enabled = os.environ.get(
        'ROS_SECURITY_ENABLE', ''
    ).strip().lower() in {'1', 'true', 'yes', 'on'}
    security_strategy = os.environ.get(
        'ROS_SECURITY_STRATEGY', ''
    ).strip().lower()
    if security_enabled and security_strategy == 'enforce':
        raise RuntimeError(
            'full_system.launch.py is the Permissive/application launcher and '
            'cannot assign a distinct SROS2 enclave to every included process. '
            'Use bash 展示指令/01c_啟動系統_enforce.sh for Enforce mode.'
        )

    nav2 = LaunchConfiguration('with_nav2').perform(context).strip().lower()
    patrol = LaunchConfiguration('with_patrol').perform(context).strip().lower()
    hardware = LaunchConfiguration('with_hardware').perform(context).strip().lower()
    hardware_motion = LaunchConfiguration(
        'allow_hardware_motion').perform(context).strip().lower()
    sim_time = LaunchConfiguration('use_sim_time').perform(context).strip().lower()
    source = LaunchConfiguration('control_source').perform(context).strip().lower()
    model = LaunchConfiguration('model').perform(context).strip()
    truthy = {'1', 'true', 'yes', 'on'}
    if model != 'burger':
        raise RuntimeError(
            f"security thresholds/policy are calibrated only for TurtleBot3 Burger; "
            f"refusing model={model!r}")
    if nav2 in truthy and patrol in truthy:
        raise RuntimeError(
            'with_nav2 and with_patrol are mutually exclusive: both publish/control '
            'a private velocity input. Choose at most one controller track.')
    if source not in {'patrol', 'nav2', 'tqc', 'none'}:
        raise RuntimeError(
            'control_source must be patrol, nav2, tqc, or none')
    if patrol in truthy and source != 'patrol':
        raise RuntimeError(
            'with_patrol=true requires control_source:=patrol')
    if nav2 in truthy and source != 'nav2':
        raise RuntimeError(
            'with_nav2=true requires control_source:=nav2')
    if source == 'patrol' and patrol not in truthy:
        raise RuntimeError(
            'control_source:=patrol requires with_patrol=true')
    if source == 'nav2' and nav2 not in truthy:
        raise RuntimeError(
            'control_source:=nav2 requires with_nav2=true')
    if hardware in truthy and sim_time in truthy:
        raise RuntimeError(
            'with_hardware=true requires use_sim_time=false; otherwise Nav2 and '
            'hardware timestamps can wait forever for a Gazebo /clock.')
    if (
        hardware in truthy
        and source != 'none'
        and hardware_motion not in truthy
    ):
        raise RuntimeError(
            'hardware motion is fail-closed by default. Set '
            'allow_hardware_motion:=true explicitly after physical safety checks, '
            'or use control_source:=none with controllers disabled.')
    return []


def generate_launch_description():
    # ── 參數宣告 ──────────────────────────────────────────────────────────────
    model_arg = DeclareLaunchArgument(
        'model', default_value='burger',
        description='TurtleBot3 型號（安全政策與 D1 門檻目前只允許 burger）'
    )
    map_arg = DeclareLaunchArgument(
        'map',
        default_value=PathJoinSubstitution([
            FindPackageShare('turtlebot3_navigation2'), 'map', 'map.yaml',
        ]),
        description='地圖檔案路徑'
    )
    use_sim_time_arg = DeclareLaunchArgument(
        'use_sim_time', default_value='true',
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
    with_nav2_arg = DeclareLaunchArgument(
        'with_nav2', default_value='false',
        description='是否啟動 Nav2；不可與 with_patrol 同時為 true'
    )
    control_source_arg = DeclareLaunchArgument(
        'control_source', default_value='patrol',
        description='velocity guard 唯一接受的來源 (patrol/nav2/tqc/none)'
    )
    hardware_motion_arg = DeclareLaunchArgument(
        'allow_hardware_motion', default_value='false',
        description='實機移動的明確 opt-in；預設 fail-closed'
    )

    model         = LaunchConfiguration('model')
    map_path      = LaunchConfiguration('map')
    use_sim_time  = LaunchConfiguration('use_sim_time')
    with_hardware = LaunchConfiguration('with_hardware')
    with_patrol   = LaunchConfiguration('with_patrol')
    with_nav2     = LaunchConfiguration('with_nav2')
    control_source = LaunchConfiguration('control_source')

    # ── 套件路徑 ──────────────────────────────────────────────────────────────
    monitor_pkg = get_package_share_directory('dds_security_monitor')

    # ── 子啟動檔 ──────────────────────────────────────────────────────────────

    # 1. 模擬世界（預設）；實體模式才略過
    gazebo_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(monitor_pkg, 'launch', 'gazebo.launch.py')
        ),
        condition=UnlessCondition(with_hardware),
    )

    # 2. 實體機器人硬體驅動（選用）
    hardware_launch = GroupAction(
        condition=IfCondition(with_hardware),
        actions=[
            IncludeLaunchDescription(
                PythonLaunchDescriptionSource(
                    PathJoinSubstitution([
                        FindPackageShare('turtlebot3_bringup'),
                        'launch',
                        'robot.launch.py',
                    ])
                ),
            )
        ]
    )

    # 3. Nav2 導航堆疊
    nav2_launch = GroupAction(
        condition=IfCondition(with_nav2),
        actions=[
            SetRemap(src='/cmd_vel', dst='/cmd_vel/nav2'),
            IncludeLaunchDescription(
                PythonLaunchDescriptionSource(
                    PathJoinSubstitution([
                        FindPackageShare('turtlebot3_navigation2'),
                        'launch',
                        'navigation2.launch.py',
                    ])
                ),
                launch_arguments={
                    'map':          map_path,
                    'use_sim_time': use_sim_time,
                }.items()
            ),
        ],
    )

    # 4. DDS 安全監控節點
    monitor_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(monitor_pkg, 'launch', 'monitor.launch.py')
        )
    )

    # 5. 自主巡邏節點（選用）
    patrol_node = GroupAction(
        condition=IfCondition(with_patrol),
        actions=[
            Node(
                package='dds_security_monitor',
                executable='patrol_node',
                name='patrol_node',
                # Security watchdog/control timers intentionally remain on wall
                # time so a paused/attacked Gazebo /clock cannot freeze them.
                parameters=[os.path.join(monitor_pkg, 'config', 'config.yaml')],
                output='screen',
                emulate_tty=True,
            )
        ]
    )

    # 6. 應用層六 topic、D1–D6 與狀態鏈所需的其餘節點。
    # Security watchdogs intentionally stay on wall time: an attacked/paused
    # Gazebo /clock must not freeze heartbeat, freshness or recovery timers.
    application_nodes = GroupAction(actions=[
        Node(
            package='dds_security_monitor',
            executable='velocity_guard_node',
            name='velocity_guard_node',
            parameters=[{'active_source': control_source}],
            output='screen',
            emulate_tty=True,
        ),
        Node(
            package='dds_security_monitor',
            executable='sensor_hub_node',
            name='sensor_hub_node',
            output='screen',
            emulate_tty=True,
        ),
        Node(
            package='dds_security_monitor',
            executable='mission_manager',
            name='mission_manager_node',
            output='screen',
            emulate_tty=True,
        ),
        Node(
            package='dds_security_monitor',
            executable='system_status_node',
            name='system_status_node',
            output='screen',
            emulate_tty=True,
        ),
        Node(
            package='dds_security_monitor',
            executable='intelligent_defense_node',
            name='intelligent_defense_node',
            output='screen',
            emulate_tty=True,
        ),
    ])

    return LaunchDescription([
        model_arg,
        map_arg,
        use_sim_time_arg,
        with_hardware_arg,
        with_patrol_arg,
        with_nav2_arg,
        control_source_arg,
        hardware_motion_arg,
        OpaqueFunction(function=_validate_controller_choice),
        # Both TurtleBot3 Gazebo and navigation2 select their model from this
        # environment variable; set it from the validated launch argument so
        # Gazebo/Nav2 cannot silently start different robot variants.
        SetEnvironmentVariable('TURTLEBOT3_MODEL', model),
        gazebo_launch,
        hardware_launch,
        nav2_launch,
        monitor_launch,
        patrol_node,
        application_nodes,
    ])
