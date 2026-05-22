#!/usr/bin/env python3
"""產生 ROS2 DDS Topic 架構圖（節點 pub/sub 關係）"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch
import numpy as np

# ── 節點定義 ─────────────────────────────────────────────────────────────────
NODES = {
    'turtlebot3_node\n(gz-sim)': {
        'color': '#4A90D9', 'group': 'robot',
        'pub':  ['/scan', '/imu', '/odom', '/joint_states', '/tf'],
        'sub':  ['/cmd_vel'],
    },
    'robot_state\n_publisher': {
        'color': '#4A90D9', 'group': 'robot',
        'pub':  ['/tf', '/robot_description'],
        'sub':  ['/joint_states'],
    },
    'ros_gz_bridge': {
        'color': '#7B68EE', 'group': 'bridge',
        'pub':  ['/scan', '/imu', '/odom', '/clock'],
        'sub':  ['/cmd_vel'],
    },
    'patrol_node': {
        'color': '#E8A838', 'group': 'security',
        'pub':  ['/cmd_vel'],
        'sub':  ['/scan', '/security/alerts'],
    },
    'dds_security\n_monitor': {
        'color': '#E84040', 'group': 'security',
        'pub':  ['/security/alerts'],
        'sub':  [],
    },
    'sensor_hub\n_node': {
        'color': '#50C878', 'group': 'monitor',
        'pub':  ['/sensor/status'],
        'sub':  ['/scan', '/imu'],
    },
    'system_status\n_node': {
        'color': '#50C878', 'group': 'monitor',
        'pub':  ['/system/health'],
        'sub':  ['/security/alerts', '/sensor/status'],
    },
    'mission_manager\n_node': {
        'color': '#FF6B6B', 'group': 'monitor',
        'pub':  ['/mission/cmd'],
        'sub':  ['/system/health', '/security/alerts'],
    },
    'dqn_environment': {
        'color': '#9B59B6', 'group': 'ai',
        'pub':  ['/cmd_vel'],
        'sub':  ['/scan', '/security/alerts'],
    },
}

TOPICS = [
    '/cmd_vel', '/scan', '/imu', '/odom',
    '/joint_states', '/tf',
    '/security/alerts', '/sensor/status',
    '/system/health', '/mission/cmd',
]

TOPIC_COLORS = {
    '/cmd_vel':        '#FF6B35',
    '/scan':           '#1E90FF',
    '/imu':            '#20B2AA',
    '/odom':           '#9370DB',
    '/joint_states':   '#6495ED',
    '/tf':             '#B8860B',
    '/security/alerts':'#DC143C',
    '/sensor/status':  '#3CB371',
    '/system/health':  '#2E8B57',
    '/mission/cmd':    '#FF8C00',
}

GROUP_LABELS = {
    'robot':    'Robot Hardware Layer',
    'bridge':   'Gazebo Bridge Layer',
    'security': 'DDS Security Layer',
    'monitor':  'Monitor/Management Layer',
    'ai':       'AI Learning Layer',
}

# ── 版面配置 ─────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(24, 14))
ax.set_xlim(0, 21)
ax.set_ylim(1, 14)
ax.axis('off')
ax.set_facecolor('#F8F9FA')
fig.patch.set_facecolor('#F8F9FA')

ax.set_title('ROS2 DDS System Architecture — Node & Topic Pub/Sub Graph',
             fontsize=18, fontweight='bold', pad=20)

# 節點位置
NODE_POS = {
    'turtlebot3_node\n(gz-sim)':  (2.0, 10.5),
    'robot_state\n_publisher':    (2.0, 7.5),
    'ros_gz_bridge':              (2.0, 4.5),
    'patrol_node':                (10.5, 11.5),
    'dds_security\n_monitor':     (10.5, 8.5),
    'sensor_hub\n_node':          (10.5, 5.5),
    'system_status\n_node':       (17.5, 11.0),
    'mission_manager\n_node':     (17.5, 7.5),
    'dqn_environment':            (10.5, 2.5),
}

# Topic 位置（中間欄）
TOPIC_POS = {
    '/cmd_vel':        (6.5, 12.0),
    '/scan':           (6.5, 10.2),
    '/imu':            (6.5, 8.4),
    '/odom':           (6.5, 6.6),
    '/joint_states':   (6.5, 4.8),
    '/tf':             (6.5, 3.0),
    '/security/alerts':(14.2, 11.5),
    '/sensor/status':  (14.2, 9.0),
    '/system/health':  (14.2, 6.5),
    '/mission/cmd':    (14.2, 4.0),
}

# 畫節點
for name, info in NODES.items():
    x, y = NODE_POS[name]
    rect = mpatches.FancyBboxPatch(
        (x - 1.1, y - 0.45), 2.2, 0.9,
        boxstyle='round,pad=0.08',
        facecolor=info['color'], edgecolor='white',
        linewidth=2, alpha=0.92, zorder=3
    )
    ax.add_patch(rect)
    ax.text(x, y, name, ha='center', va='center',
            fontsize=9, color='white', fontweight='bold', zorder=4)

# 畫 Topic（橢圓）
for topic, (x, y) in TOPIC_POS.items():
    color = TOPIC_COLORS.get(topic, '#888888')
    ellipse = mpatches.Ellipse(
        (x, y), 2.6, 0.65,
        facecolor=color, edgecolor='white',
        linewidth=1.5, alpha=0.85, zorder=3
    )
    ax.add_patch(ellipse)
    label = topic.replace('/security/', '/sec/').replace('/sensor/', '/sns/')
    ax.text(x, y, label, ha='center', va='center',
            fontsize=8.5, color='white', fontweight='bold', zorder=4)

# 畫箭頭（pub → topic：實線；topic → sub：虛線）
arrow_kw_pub = dict(arrowstyle='->', color='#333333',
                    lw=1.2, connectionstyle='arc3,rad=0.0', zorder=2)
arrow_kw_sub = dict(arrowstyle='->', color='#666666',
                    lw=1.0, linestyle='dashed',
                    connectionstyle='arc3,rad=0.0', zorder=2)

def draw_arrow(ax, p1, p2, **kw):
    ax.annotate('', xy=p2, xytext=p1,
                arrowprops=dict(**kw))

for name, info in NODES.items():
    nx, ny = NODE_POS[name]
    for topic in info['pub']:
        if topic in TOPIC_POS:
            tx, ty = TOPIC_POS[topic]
            draw_arrow(ax, (nx, ny), (tx, ty), **arrow_kw_pub)
    for topic in info['sub']:
        if topic in TOPIC_POS:
            tx, ty = TOPIC_POS[topic]
            draw_arrow(ax, (tx, ty), (nx, ny), **arrow_kw_sub)

# 圖例
legend_items = [
    mpatches.Patch(color='#4A90D9', label='Robot Hardware Layer'),
    mpatches.Patch(color='#7B68EE', label='Gazebo Bridge Layer'),
    mpatches.Patch(color='#E8A838', label='Security Layer (Patrol)'),
    mpatches.Patch(color='#E84040', label='Security Layer (Monitor)'),
    mpatches.Patch(color='#50C878', label='Monitor/Status Layer'),
    mpatches.Patch(color='#FF6B6B', label='Mission Manager Layer'),
    mpatches.Patch(color='#9B59B6', label='AI Learning Layer (DQN)'),
    mpatches.Patch(color='#888888', label='Topic (ellipse)'),
    plt.Line2D([0], [0], color='#333333', lw=1.5, label='-> Publish'),
    plt.Line2D([0], [0], color='#666666', lw=1.2,
               linestyle='dashed', label='- - -> Subscribe'),
]
ax.legend(handles=legend_items, loc='lower right',
          fontsize=8, framealpha=0.9, ncol=2)

# 分區標籤
for group, label in GROUP_LABELS.items():
    pass  # 可選：加分區框線

plt.tight_layout()
out = '/home/jesse/ros2_ws/scripts/topic_architecture.png'
plt.savefig(out, dpi=150, bbox_inches='tight', facecolor='#F8F9FA')
print(f'已儲存：{out}')
