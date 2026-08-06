"""TurtleBot3 Gazebo launch with a headless-by-default data-collection mode.

The upstream world launch includes the Gazebo server and GUI through two
separate ``ros_gz_sim`` launch files.  Each inclusion scans every installed ROS
package to build Gazebo paths, which is especially slow on a WSL-mounted
workspace.  Formal dataset collection needs only the server, so the GUI is an
explicit opt-in launch argument.
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import (
    AppendEnvironmentVariable,
    DeclareLaunchArgument,
    IncludeLaunchDescription,
)
from launch.conditions import IfCondition
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration


def generate_launch_description():
    turtlebot3_gazebo = get_package_share_directory("turtlebot3_gazebo")
    ros_gz_sim = get_package_share_directory("ros_gz_sim")
    launch_dir = os.path.join(turtlebot3_gazebo, "launch")
    world = os.path.join(
        turtlebot3_gazebo,
        "worlds",
        "turtlebot3_world.world",
    )

    set_resource_path = AppendEnvironmentVariable(
        "GZ_SIM_RESOURCE_PATH",
        os.path.join(turtlebot3_gazebo, "models"),
    )

    launch_server = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(ros_gz_sim, "launch", "gz_sim.launch.py")
        ),
        launch_arguments={
            "gz_args": ["-r -s -v2 ", world],
            "on_exit_shutdown": "true",
        }.items(),
    )
    launch_client = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(ros_gz_sim, "launch", "gz_sim.launch.py")
        ),
        launch_arguments={
            "gz_args": "-g -v2",
            "on_exit_shutdown": "true",
        }.items(),
        condition=IfCondition(LaunchConfiguration("gui")),
    )
    launch_robot_state = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(launch_dir, "robot_state_publisher.launch.py")
        ),
        launch_arguments={"use_sim_time": "true"}.items(),
    )
    launch_spawn_and_bridge = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(launch_dir, "spawn_turtlebot3.launch.py")
        ),
        launch_arguments={
            "x_pose": LaunchConfiguration("x_pose"),
            "y_pose": LaunchConfiguration("y_pose"),
        }.items(),
    )

    return LaunchDescription(
        [
            DeclareLaunchArgument(
                "gui",
                default_value="false",
                description="Start the Gazebo GUI; disabled for formal data",
            ),
            DeclareLaunchArgument("x_pose", default_value="-2.0"),
            DeclareLaunchArgument("y_pose", default_value="-0.5"),
            set_resource_path,
            launch_server,
            launch_client,
            launch_spawn_and_bridge,
            launch_robot_state,
        ]
    )
