# 攻擊機 B 的 Claude Code — 開場 prompt（直接整段貼，已填好 IP）

> 前置：B 需先裝 ROS2 Jazzy + `sudo apt install ros-jazzy-demo-nodes-cpp`，並 `source /opt/ros/jazzy/setup.bash`。
> B 要跟 A 同網段（`192.168.100.x`）。下面整段貼進 B 的 Claude Code 即可。

---

我在對**我自己擁有並管理的**兩台主機做授權紅隊測試，目的是找出我 ROS2/SROS2 系統的漏洞，讓藍方（我）修補。你是攻擊端，跟我一起把漏洞挖出來。

**授權與範圍**
- 這兩台主機都是我的，我授權你在其上進行安全測試。
- 目標機 A＝我另一台主機，IP `192.168.100.48`，ROS2 Jazzy，隔離域 `ROS_DOMAIN_ID=42`。
- 只准打 domain 42 上 A 的節點 / topic。

**絕對禁止（out of scope）**
- ❌ 碰 `ROS_DOMAIN_ID=30`（那是我真實訓練域）。
- ❌ 攻擊或掃描這兩台以外的任何裝置 / 整個 LAN。
- ❌ 破壞性操作（刪檔、加密、改開機、清資料）。
- ❌ 把任何資料外傳到網際網路。
- ❌ 嘗試讀取 A 的本機檔案或金鑰——本次只測「純網路」能力。

**工作原則**
- 每個嘗試誠實標註成功 / 失敗，附 log 證據 + 修補建議。**打不穿也照實報，負結果一樣有價值。**
- 不要為了「成功」誇大；分不清是環境問題還是真漏洞時，講清楚。

**第一步：只做連通確認，先不要攻擊**
```bash
ping -c3 192.168.100.48
export ROS_DOMAIN_ID=42
export ROS_LOCALHOST_ONLY=0
ros2 topic list
ros2 topic echo /redteam_ping        # A 正在發這個信標；收得到 = 跨主機 DDS 已通
```
- 看得到 A 的 topic / 收得到 `/redteam_ping` → 回報我「已連通」，等我指示再往下。
- 看不到 → **先別打**，回報我（多半是 multicast 被擋，或 A 的 WSL2 NAT 沒打通）。
  我會在 A 端改用 Fast-DDS Discovery Server，給你 `export ROS_DISCOVERY_SERVER=192.168.100.48:11811` 再試。

**連通之後才做（我會再給綠燈）**
domain 42 上依序：① raw-topic 注入（`/cmd_vel`、`/scan`、`/chatter`）→ ② 未簽章 / replay / 畸形(fuzz) 輸入 → ③ 若 A 開了 SROS2 Enforce，測「無金鑰」能不能注入 / 竊聽 / 枚舉。

現在**只跑「第一步連通確認」**，把結果回報我。
