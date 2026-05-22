#!/usr/bin/env python3
"""ROS2 DDS Security Monitor Node.

Polls the ROS2 node graph and sends LINE alerts when unknown nodes appear.
When emergency_stop_enabled=true, publishes zero velocity to /cmd_vel and
cancels active Nav2 goals on any security alert.

Credentials: env vars LINE_CHANNEL_TOKEN and LINE_USER_ID (priority over YAML).
"""
import json
import os
import threading
import urllib.error
import urllib.request

import rclpy
from action_msgs.msg import GoalInfo
from action_msgs.srv import CancelGoal
from geometry_msgs.msg import TwistStamped
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String


class DDSSecurityMonitor(Node):
    def __init__(self):
        super().__init__('dds_security_monitor')

        self.declare_parameter('poll_interval_sec', 5.0)
        self.declare_parameter('line_token', '')
        self.declare_parameter('line_user_id', '')
        self.declare_parameter('alert_on_node_exit', False)
        self.declare_parameter('emergency_stop_enabled', True)
        self.declare_parameter('emergency_stop_duration_sec', 3.0)
        self.declare_parameter('whitelist', [
            'bt_navigator', 'planner_server', 'controller_server', 'map_server',
            'amcl', 'behavior_server', 'waypoint_follower', 'velocity_smoother',
            'lifecycle_manager_navigation', 'lifecycle_manager_localization',
            'robot_state_publisher', 'joint_state_publisher', 'rviz2',
            'cartographer_node', 'cartographer_occupancy_grid_node',
            'turtlebot3_node', 'diff_drive_controller', 'teleop_keyboard',
            'turtlebot3_patrol_server', 'my_nav_client', 'dds_security_monitor', 'patrol_node',
            'ros_gz_bridge', 'ros_gz_image', 'ros_gz_point_cloud', 'ros_gz_sim',
            'gazebo', 'gzserver', 'gzclient',
            'sensor_hub_node', 'mission_manager_node', 'system_status_node',
            'dqn_environment',
        ])

        self._poll_interval = self.get_parameter('poll_interval_sec').value
        self._line_token = (
            os.environ.get('LINE_CHANNEL_TOKEN')
            or self.get_parameter('line_token').value
        )
        self._line_user_id = (
            os.environ.get('LINE_USER_ID')
            or self.get_parameter('line_user_id').value
        )
        self._whitelist: set[str] = set(self.get_parameter('whitelist').value)
        self._alert_on_exit: bool = self.get_parameter('alert_on_node_exit').value
        self._emergency_stop: bool = self.get_parameter('emergency_stop_enabled').value
        self._stop_duration: float = self.get_parameter('emergency_stop_duration_sec').value

        self._known_nodes: set[str] = set()
        self._initialized = False
        self._stop_timer = None
        self._stop_ticks = 0

        qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._alert_pub = self.create_publisher(String, '/security/alerts', qos)
        self._cmd_vel_pub = self.create_publisher(TwistStamped, '/cmd_vel', 10)

        # Nav2 goal cancellation client
        self._cancel_client = self.create_client(
            CancelGoal, '/navigate_to_pose/_action/cancel_goal'
        )

        self.create_timer(self._poll_interval, self._check_graph)
        self.get_logger().info(
            f'DDS Security Monitor 啟動 '
            f'(輪詢: {self._poll_interval}s, '
            f'緊急停止: {"開啟" if self._emergency_stop else "關閉"}, '
            f'白名單: {len(self._whitelist)} 個節點)'
        )

    # ── graph polling ────────────────────────────────────────────────────────

    def _check_graph(self) -> None:
        current: set[str] = set()
        for name, namespace in self.get_node_names_and_namespaces():
            ns = namespace.rstrip('/')
            current.add(f'{ns}/{name}')

        if not self._initialized:
            self._known_nodes = current
            self._initialized = True
            self.get_logger().info(f'基準快照完成，記錄了 {len(current)} 個現有節點')
            return

        for node_full in current - self._known_nodes:
            short = node_full.rsplit('/', 1)[-1]
            if (short not in self._whitelist
                    and not short.startswith('_')
                    and not short.startswith('ros_gz')
                    and not short.startswith('dqn')
                    and not short.startswith('transform_listener_impl')
                    and not short.startswith('launch_ros')):
                self._alert_new_node(node_full, len(current))

        if self._alert_on_exit:
            for node_full in self._known_nodes - current:
                short = node_full.rsplit('/', 1)[-1]
                if short not in self._whitelist:
                    self._alert_node_exit(node_full)

        self._known_nodes = current

    # ── alert helpers ────────────────────────────────────────────────────────

    def _alert_new_node(self, node_full: str, total: int) -> None:
        text = (
            f'🤖 [DDS 節點警報]\n'
            f'發現未知 ROS2 節點加入網路！\n'
            f'> 節點名稱: {node_full}\n'
            f'> 目前網路節點總數: {total}'
        )
        self.get_logger().warn(f'偵測到未知節點: {node_full}')
        self._publish(text)
        self._send_line(text)
        if self._emergency_stop:
            self._trigger_emergency_stop()

    def _alert_node_exit(self, node_full: str) -> None:
        text = (
            f'⚠️ [節點離線警報]\n'
            f'ROS2 節點已從網路消失！\n'
            f'> 節點名稱: {node_full}'
        )
        self.get_logger().warn(f'節點離線: {node_full}')
        self._publish(text)
        self._send_line(text)

    def _publish(self, text: str) -> None:
        msg = String()
        msg.data = text
        self._alert_pub.publish(msg)

    # ── emergency stop ───────────────────────────────────────────────────────

    def _trigger_emergency_stop(self) -> None:
        self.get_logger().error('🛑 安全威脅！執行緊急停止...')

        # Cancel active Nav2 navigation goal
        if self._cancel_client.service_is_ready():
            req = CancelGoal.Request()
            req.goal_info = GoalInfo()  # Empty = cancel all goals
            self._cancel_client.call_async(req)
            self.get_logger().error('🛑 已取消 Nav2 導航目標')

        # Publish zero velocity repeatedly for stop_duration seconds
        self._stop_ticks = int(self._stop_duration / 0.1)
        if self._stop_timer is not None:
            self._stop_timer.cancel()
        self._stop_timer = self.create_timer(0.1, self._publish_stop)

    def _publish_stop(self) -> None:
        msg = TwistStamped()
        msg.header.stamp    = self.get_clock().now().to_msg()
        msg.header.frame_id = 'base_link'
        self._cmd_vel_pub.publish(msg)  # All zeros = full stop
        self._stop_ticks -= 1
        if self._stop_ticks <= 0:
            self._stop_timer.cancel()
            self._stop_timer = None
            self.get_logger().warn('緊急停止指令發送完畢')

    # ── LINE notification ────────────────────────────────────────────────────

    def _send_line(self, text: str) -> None:
        if not self._line_token or not self._line_user_id:
            self.get_logger().debug('LINE 憑證未設定，略過通知')
            return
        # 用獨立執行緒發送，避免 HTTP 請求阻塞 ROS2 執行器
        threading.Thread(target=self._send_line_sync, args=(text,), daemon=True).start()

    def _send_line_sync(self, text: str) -> None:
        payload = json.dumps({
            'to': self._line_user_id,
            'messages': [{'type': 'text', 'text': text}],
        }).encode('utf-8')

        req = urllib.request.Request(
            'https://api.line.me/v2/bot/message/push',
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self._line_token}',
            },
            method='POST',
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    self.get_logger().info('✅ LINE 通知發送成功')
        except urllib.error.HTTPError as e:
            self.get_logger().error(f'❌ LINE 通知失敗: HTTP {e.code}')
        except Exception as e:
            self.get_logger().error(f'❌ LINE 通知錯誤: {e}')


def main(args=None):
    rclpy.init(args=args)
    node = DDSSecurityMonitor()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
