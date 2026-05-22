import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    config_default = os.path.join(
        get_package_share_directory('dds_security_monitor'),
        'config', 'config.yaml',
    )

    return LaunchDescription([
        DeclareLaunchArgument('config', default_value=config_default,
                              description='Path to monitor config YAML'),
        Node(
            package='dds_security_monitor',
            executable='monitor_node',
            name='dds_security_monitor',
            parameters=[LaunchConfiguration('config')],
            output='screen',
            emulate_tty=True,
        ),
    ])
