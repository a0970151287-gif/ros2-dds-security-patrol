# 跨主機紅隊授權書 + 交接包（Rules of Engagement）

> 給「攻擊機（Machine B）」上的 Claude Code 看的。把這份連同下面的開場 prompt 一起交給它。

## 1. 授權聲明（Authorization）
- 本人**同時擁有並管理**下列兩台主機，授權在其上進行紅隊安全測試：
  - **目標機 A（被攻擊）**：執行 ROS2 / SROS2 的 WSL2 主機。
  - **攻擊機 B（發動端）**：執行 Claude Code 的另一台主機。
- 這是**自有系統的授權滲透測試**，目的為找漏洞讓藍方（我自己）修補。
- 全程在**隔離 DDS 域**進行，不碰生產 / 訓練流量。

## 2. 範圍（Scope）—— 只准打這些
- 目標 IP：`<在此填 A 的可達 IP>`（見第 4 節先確認連通）
- DDS 域：`ROS_DOMAIN_ID=42`（**禁止用 30** — 那是真實訓練域）
- 允許的目標：domain 42 上我特意啟動的 target 節點 / topic（例如 `/chatter`、`/scan`、`/security/*`）。
- 允許手法：DDS/ROS2 raw-topic 注入、replay、未簽章訊息、畸形/fuzz 輸入、flood/DoS、
  SROS2 未認證參與者測試、discovery 枚舉。

## 3. 禁止（Out of scope）
- ❌ 不准碰 `ROS_DOMAIN_ID=30`（真實訓練）。
- ❌ 不准攻擊這兩台以外的任何主機 / 不准掃描整個 LAN 的其他裝置。
- ❌ 不准破壞性操作（刪檔、加密勒索、改開機、清資料）。
- ❌ 不准外傳任何資料到網際網路。
- ❌ 不准嘗試讀取目標機的本機檔案/金鑰（那是 local 攻擊，本次只測「純網路」能力）。

## 4. 先確認連通（攻擊機 B 第一步）
```bash
ping <A 的可達 IP>                       # 通不通
export ROS_DOMAIN_ID=42
export ROS_LOCALHOST_ONLY=0
ros2 topic list                          # 看不看得到 A 在 domain 42 開的 topic
ros2 topic echo /redteam_ping            # A 會發這個 topic 當「連通信標」
```
若 `ros2 topic list` 看得到 A 的 topic = 跨主機 DDS 已通，可以開始。
若看不到 = 多半是 multicast 被擋或 WSL2 NAT 沒打通（見「目標機 A 設定」文件）。

## 5. 交付（B 完成後回報）
- 每個嘗試：手法、是否成功、log 證據、對應的修補建議。
- 誠實標註成功/失敗（打不穿也要報，負結果一樣有價值）。
