# 目標機 A（這台 WSL2）設定 — 讓另一台主機打得到

> 順序：① 打通 WSL2 網路 → ② 確認可達 IP → ③ 開隔離域 target + 信標。全程 `ROS_DOMAIN_ID=42`（不是 30）。

## ① 打通 WSL2 網路（最關鍵，二選一）

### 方案 A（推薦，Windows 11）：mirrored 網路模式
在 **Windows**（不是 WSL）編輯 `C:\Users\<你>\.wslconfig`：
```ini
[wsl2]
networkingMode=mirrored
```
然後 Windows PowerShell 跑 `wsl --shutdown`，重開 WSL。
→ WSL 直接共用 Windows 主機的 LAN IP，別台主機就能連到；multicast 也比較會通。

### 方案 B（NAT 模式，multicast 常被 Wi-Fi 擋）：改用 Fast-DDS Discovery Server（單播，不靠 multicast）
在**可達 IP**上開一個 discovery server（A 或 B 哪台都行，這裡放 A）：
```bash
fastdds discovery -i 0 -l 0.0.0.0 -p 11811
```
**兩台**都設（取代 multicast 探索）：
```bash
export ROS_DISCOVERY_SERVER="<A的可達IP>:11811"
ros2 daemon stop    # 讓 daemon 重讀設定
```

## ② 確認可達 IP + 防火牆
- mirrored 模式：在 Windows 跑 `ipconfig`，取 Wi-Fi/乙太網路的 IPv4（像 `192.168.x.x`）= A 的可達 IP。
- **Windows 防火牆**預設擋入站 UDP：測試期間放行（或對 B 的 IP 放行 UDP 7400-65000）。
  PowerShell（系統管理員）暫時放行範例：
  ```powershell
  New-NetFirewallRule -DisplayName "ROS2 redteam UDP" -Direction Inbound -Protocol UDP -LocalPort 7400-65000 -Action Allow
  ```
- 用完記得移除：`Remove-NetFirewallRule -DisplayName "ROS2 redteam UDP"`。

## ③ 開隔離域 target + 連通信標（在 A 上跑，全用 domain 42）
```bash
export ROS_DOMAIN_ID=42
export ROS_LOCALHOST_ONLY=0
unset ROS_SECURITY_ENABLE          # 先測無 SROS2 的情形（最寬鬆，先確認連通）
source /home/jesse/ros2_ws/install/setup.bash

# (a) 連通信標：讓 B 用 ros2 topic echo /redteam_ping 確認看得到 A
ros2 topic pub /redteam_ping std_msgs/msg/String "{data: 'A alive on domain42'}" -r 1 &

# (b) 一個可被攻擊的 target（先用 demo listener；之後可換成真實 dds_security_monitor 節點）
ros2 run demo_nodes_cpp listener
```

## ④ 想測真實系統 / SROS2 時
- 換成真實節點：`ros2 run dds_security_monitor intelligent_defense_node` 等（記得 domain 42）。
- 測 SROS2 Enforce 跨主機：A 的節點加
  `ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce ROS_SECURITY_KEYSTORE=<域42的keystore>`，
  且 governance 要綁 domain 42。B 沒有金鑰 → 這才是「真·跨主機純網路無鑰匙」測試，
  比我本機 loopback 那輪更有說服力。

## 安全
- 只在 domain 42；隨時可 `pkill -f ros2` 收掉。測完移除防火牆規則、關 discovery server。
