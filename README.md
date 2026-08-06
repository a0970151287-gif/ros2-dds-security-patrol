# SROS2 智慧防火牆與 ROS2／DDS 實驗平台

本專題的產品主軸是「圍繞 SROS2 的智慧防火牆」：以 Gazebo 中的 TurtleBot3 作為受測系統，自動產生正常與受控攻擊的 ROS2／DDS 流量，經 Zeek 特徵、ML 判斷與受限制的回應策略形成縱深防禦。紅隊 PoC 是訓練和驗證資料來源，不是專題本體。

新的[防火牆資料工廠](firewall_lab/README.md)會記錄每場實驗的精確標籤、SROS2 模式、PCAP、Zeek 結果與政策雜湊，並以 session 分組避免模型資料洩漏。目前有兩個清楚分層的資料集：2500 sessions／90,000 windows、22 種攻擊加 normal 的合成預訓練集；以及 20-session、Permissive／Enforce 各 10 的 Gazebo live pilot。live pilot 共擷取 168,507 個封包且 0 drop，20/20 通過證據雜湊與訓練資格 gate；它仍只是小型受控實驗，不是實體機器人或生產工廠保證。證據邊界與殘餘風險見[專題完整總報告](文件/專題完整總報告.md)。

## 系統重點

- Gazebo / TurtleBot3 提供 `/scan`、`/odom`、`/imu`，巡邏控制器發布 `/cmd_vel`。
- 六個 `std_msgs/String` topic 使用 HMAC envelope v3，綁定 channel、timestamp 與 nonce。
- `intelligent_defense_node` 以 D1–D6 偵測物理不可能行為、感測／控制矛盾與監控失效。
- SROS2 Enforce 使用雙 CA、逐節點最小權限與 DDS discovery/data 保護，是外部未授權 participant 的主要預防層。
- Zeek 從網路層偵測 DDS 偵察、注入、DoS、參數竄改與來源偽造跡象。
- 防火牆資料工廠平衡產生 Permissive／Enforce 實驗，smoke 資料永遠不得進入正式訓練。
- ML-IDS 以精確 session 標籤和 Zeek 流量特徵訓練 RandomForest／IsolationForest；回應只允許固定 adapter，低信心預設 observe-only。
- TQC 是獨立的未來工作軌，不作為 DDS 攻防成效的證據。

## 建議閱讀順序

1. [防火牆資料工廠](firewall_lab/README.md)：資料生成、1100-session campaign、品質 gate 與模型決策。
2. [專題完整總報告](文件/專題完整總報告.md)：架構、證據邊界、成果與殘餘風險。
3. [系統架構](紅隊測試/ARCHITECTURE.md)：節點、topic 與信任邊界。
4. [展示流程](展示指令/README.md)：SROS2 Enforce 與 demo 操作。
5. [ML-IDS 說明](ML防禦/README.md)：資料、模型、評估與回應安全閘。
6. [Code review 指引](REVIEW_README.md)：原始碼導覽與測試入口。

## 開發與快速驗證

主要執行環境為 Ubuntu 24.04、ROS2 Jazzy、Python 3.12。Windows 上的專案位於 `C:\Users\Jesse\Documents\專題ROS2`；WSL 端可由 `~/ros2_ws` 進入同一份工作區。

```bash
source /opt/ros/jazzy/setup.bash
cd ~/ros2_ws

# ROS2 套件
colcon build --symlink-install
source install/setup.bash

# 單元／離線測試
python3 -m pytest tests -q
```

完整 ML 測試需要鎖版的 pandas／scikit-learn／joblib。WSL 掛載的 Windows
目錄不適合放大量 Python 套件，請使用原生 WSL 虛擬環境：

```bash
cd ~/ros2_ws
bash 工具腳本/setup_ml_test_env.sh
bash 工具腳本/run_full_tests.sh -q
```

第二支腳本會同時保留專案根目錄與 ROS2 Jazzy 的 Python 路徑，避免
`firewall_lab` 或 `rclpy` 因 `PYTHONPATH` 被覆寫而在測試收集階段消失。

HMAC 金鑰只從權限受限的檔案載入，不應放進環境變數、原始碼或 Git：

```bash
install -d -m 700 ~/.config/dds-monitor
openssl rand -hex 32 > ~/.config/dds-monitor/alert_secret
chmod 600 ~/.config/dds-monitor/alert_secret
```

SROS2 結構稽核與全防護啟動：

```bash
cd ~/ros2_ws
bash 展示指令/10_SROS2啟用.sh
bash 展示指令/sros2_稽核.sh
bash 展示指令/01c_啟動系統_enforce.sh
```

稽核通過只證明憑證、政策與檔案權限結構正確；完整驗收仍須記錄 Gazebo 全節點存活、合法 topic 通訊、未授權注入遭拒，以及長時間穩定性。

## 跨主機防禦准入門檻

跨主機測試與自動 IP 處置由 `firewall_lab.cross_host_admission` 採 fail-closed 判定。動態處置必須使用受信任 collector 簽發的 HMAC evidence envelope，將來源 IP、介面、DDS 身份、特徵摘要、session/window、時間、獨立訊號、模型／政策雜湊、backend ID 與完整模型決策綁在一起；授權器驗章後才會簽發含 nonce、5 秒失效時間且可消耗的 authorization ticket。未來的提權 backend 只能從 stdin 接收 ticket，不能接收裸 IP／TTL，也不能把 ticket 暴露在命令列。裸 SHA-256、呼叫端自行勾選「已驗證」，或拿來源 A 的證據要求封鎖來源 B 都會被拒絕。

目前舊版 `block-source <IP> <TTL>` 已改成永遠拒絕的安全樁，安裝器也不再安裝封鎖 helper 或建立 `NOPASSWD` sudoers 規則。真正的 root backend、跨程序 nonce claim store 與獨立驗票服務尚未完成，因此主動 IP 封鎖保持關閉；目前 HMAC verifier 是程式介面隔離，不宣稱為 signer 與 verifier 的密碼學程序隔離。

從舊版本升級時，安裝器只要看到既有 `block-source`、`dos-firewall` 或 `dds-monitor-block-*` sudoers 就會拒絕繼續。管理者需明確執行 `sudo bash 工具腳本/revoke_legacy_zeek_privileges.sh <舊服務帳號> --confirm-revoke`；工具只移動三個精確目標到 root-only 備份，不做遞迴刪除。它會以 `visudo` 驗證設定、保存 `sudo -n -l` 結果；列權失敗或該帳號仍有任何 sudo command 都不會宣告它可作為低權限服務帳號。

```bash
python3 -m firewall_lab.cross_host_admission \
  --model <已簽章且達部署門檻的 live 模型> \
  --report firewall_lab/cross_host_admission.json
```

只有 `cross_host_test_ready=true` 才能進入隔離雙主機測試；只有 `autonomous_ip_block_ready=true` 才能啟用自動暫時封鎖。否則固定為 `observe_or_dry_run_only`。

## 目錄

| 路徑 | 內容 |
|---|---|
| `firewall_lab/` | session 資料工廠、精確標籤、campaign、特徵、訓練與受限決策 |
| `src/dds_security_monitor/` | HMAC、巡邏、行為 IDS 與 ROS2 安全節點 |
| `Zeek監控/` | DDS/RTPS 網路偵測與受控回應輔助程式 |
| `ML防禦/` | 特徵抽取、模型訓練／評估與回應引擎 |
| `紅隊測試/` | PoC、威脅模型、攻擊報告與修補紀錄 |
| `展示指令/` | Gazebo、SROS2 與驗證流程 |
| `src/turtlebot3_dqn/` | TQC 訓練與評估（獨立未來工作軌） |
| `tests/` | 可離線執行的安全回歸測試 |

## 目前必須保留的限制

- Permissive 模式下，`/cmd_vel`、`/scan`、`/odom`、`/imu` 不能套用 String envelope；來源預防依賴 SROS2 Enforce。
- N9 `/cmd_vel` race 仍有殘餘風險；目前已有一組
  Permissive／Enforce live pilot 對照，但尚不足以代表長時間穩定性。
- 應用層 HMAC 仍是集中式共享金鑰，尚缺輪替與首次安全分發機制。
- mode 0600 與禁止環境變數可減少跨帳號／`/proc` 被動曝露，但擋不住已取得同一 Unix UID 任意讀檔能力的程式；完整隔離仍需獨立服務帳號或 OS secret store。
- 倉庫既有的歷史 `.joblib` 沒有 HMAC sidecar；安全載入器會拒絕它們，須從可信資料重新訓練，不能把來源未確認的 pickle 直接補簽當成可信。
- 20-session live pilot 已完成；正式 1100-session campaign 尚待逐批
  擷取，smoke 與被 quarantine 的產物不可當作訓練資料或成效證據。
- ML-IDS 的 live 精確標註資料仍不足，不應把離線指標外推成生產保證。
- 修補後的 `01c` 全 Gazebo 長時間場景尚未完成完整紅隊回歸。

紅隊 PoC 僅能在已獲授權、隔離的 ROS domain／實驗網路執行；不要把測試腳本指向第三方或生產系統。
