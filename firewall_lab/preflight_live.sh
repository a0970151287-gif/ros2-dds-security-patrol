#!/usr/bin/env bash

WORKSPACE="${ROS2_WS:-$HOME/ros2_ws}"
source /opt/ros/jazzy/setup.bash
set -u

printf 'workspace=%s\n' "$WORKSPACE"
printf 'ROS_DISTRO=%s\n' "${ROS_DISTRO:-missing}"
printf 'DISPLAY=%s\n' "${DISPLAY:-missing}"
printf 'WAYLAND_DISPLAY=%s\n' "${WAYLAND_DISPLAY:-missing}"

for tool in ros2 gz dumpcap zeek; do
  path="$(command -v "$tool" 2>/dev/null || true)"
  printf '%s=%s\n' "$tool" "${path:-missing}"
done
if [[ -x /opt/zeek/bin/zeek ]]; then
  printf 'zeek_opt=/opt/zeek/bin/zeek\n'
else
  printf 'zeek_opt=missing\n'
fi

printf '%s\n' '--- interfaces ---'
ip -brief address

printf '%s\n' '--- dumpcap capture interfaces ---'
if command -v dumpcap >/dev/null 2>&1; then
  dumpcap -D 2>&1 || true
else
  printf 'dumpcap unavailable\n'
fi

printf '%s\n' '--- relevant processes ---'
pgrep -af 'gz|gazebo|ros2|dds_security_monitor' || printf 'none\n'

printf '%s\n' '--- required project files ---'
for path in \
  "$WORKSPACE/展示指令/01b_啟動系統_跨主機.sh" \
  "$WORKSPACE/展示指令/01c_啟動系統_enforce.sh" \
  "$WORKSPACE/firewall_lab/campaign_1100.json"; do
  if [[ -f "$path" ]]; then
    printf 'ok %s\n' "$path"
  else
    printf 'missing %s\n' "$path"
  fi
done

if [[ -d "$WORKSPACE/sros2_keystore/enclaves" ]]; then
  printf 'keystore=present\n'
else
  printf 'keystore=missing\n'
fi
