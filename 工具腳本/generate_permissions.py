#!/usr/bin/env python3
"""為每個節點產生最小權限的 permissions.xml 並簽名。"""
import subprocess
from pathlib import Path

KEYSTORE = Path.home() / 'ros2_security_keystore'
CA_CERT  = KEYSTORE / 'public' / 'permissions_ca.cert.pem'
CA_KEY   = KEYSTORE / 'private' / 'permissions_ca.key.pem'
NOT_BEFORE = '2026-04-27T04:19:50'
NOT_AFTER  = '2036-04-25T04:19:50'

# ROS2 每個節點都需要的基本 Topic
ROS2_BASE = [
    'rq/*/_action/cancel_goalRequest',
    'rq/*/_action/get_resultRequest',
    'rq/*/_action/send_goalRequest',
    'rr/*/_action/cancel_goalReply',
    'rr/*/_action/get_resultReply',
    'rr/*/_action/send_goalReply',
    'rq/*Request',
    'rr/*Reply',
    'rt/*/_action/feedback',
    'rt/*/_action/status',
    'rt/rosout',
    'rt/parameter_events',
    'rt/clock',
    'ros_discovery_info',
]

# 每個節點的應用層 Topic 權限（最小權限原則）
NODE_PERMISSIONS = {
    'dds_security_monitor': {
        'publish':   ['rt/security/alerts', 'rt/cmd_vel'],
        'subscribe': [],  # 使用 ROS2 Graph API 監控節點，不需訂閱特定 Topic
    },
    'patrol_node': {
        'publish':   ['rt/cmd_vel'],
        'subscribe': ['rt/scan', 'rt/security/alerts'],
    },
    'sensor_hub_node': {
        'publish':   ['rt/sensor/status'],
        'subscribe': ['rt/scan', 'rt/imu'],
    },
    'mission_manager_node': {
        'publish':   ['rt/mission/cmd'],
        'subscribe': ['rt/sensor/status', 'rt/security/alerts'],
    },
    'system_status_node': {
        'publish':   ['rt/system/health'],
        'subscribe': ['rt/sensor/status', 'rt/mission/cmd', 'rt/security/alerts'],
    },
}


def make_topic_xml(topics: list[str], tag: str) -> str:
    items = '\n'.join(f'            <topic>{t}</topic>' for t in topics)
    return f'''        <{tag}>
          <topics>
{items}
          </topics>
        </{tag}>'''


def generate_xml(node_name: str, perms: dict) -> str:
    pub_topics  = perms['publish']  + ROS2_BASE
    sub_topics  = perms['subscribe'] + ROS2_BASE

    return f'''<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_permissions.xsd">
  <permissions>
    <grant name="/{node_name}">
      <subject_name>CN=/{node_name}</subject_name>
      <validity>
        <not_before>{NOT_BEFORE}</not_before>
        <not_after>{NOT_AFTER}</not_after>
      </validity>
      <allow_rule>
        <domains><id>30</id></domains>
{make_topic_xml(pub_topics, 'publish')}
{make_topic_xml(sub_topics, 'subscribe')}
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
'''


def sign(xml_path: Path, p7s_path: Path) -> bool:
    result = subprocess.run([
        'openssl', 'smime', '-sign',
        '-in', str(xml_path),
        '-text',
        '-out', str(p7s_path),
        '-signer', str(CA_CERT),
        '-inkey', str(CA_KEY),
        '-nodetach',
    ], capture_output=True, text=True)
    return result.returncode == 0


def main():
    for node, perms in NODE_PERMISSIONS.items():
        enclave = KEYSTORE / 'enclaves' / node
        if not enclave.exists():
            print(f'⚠️  enclave 不存在: {node}，跳過')
            continue

        xml_path = enclave / 'permissions.xml'
        p7s_path = enclave / 'permissions.p7s'

        xml_path.write_text(generate_xml(node, perms))
        print(f'✅ 產生 {node}/permissions.xml')

        if sign(xml_path, p7s_path):
            print(f'✅ 簽名 {node}/permissions.p7s')
        else:
            print(f'❌ 簽名失敗: {node}')

    print('\n全部完成！')


if __name__ == '__main__':
    main()
