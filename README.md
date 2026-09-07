# SROS2 預防＋多模態 AI 的 ROS 2／DDS 安全回應研究原型

系統短名為 **SROS2 智慧防火牆研究原型**。正式研究主軸是：SROS2 負責身分驗證與
最小權限預防後，融合 DDS 網路、機器人行為與安全遙測的多模態 AI，能否可靠偵測或
拒判已知／未知攻擊，並只在來源可被可信歸因時觸發可撤銷、可復原的安全回應。
Gazebo TurtleBot3 是受測系統；受控紅隊案例是資料與驗證來源，不是專題本體。

正式題目、單一主研究問題、三項貢獻與名稱升級條件見
[方向收斂與驗收基準](文件/專題方向收斂與驗收基準_2026-08-25.md)。在 identity→IP、
真 nftables、隔離雙主機與 Pi gateway 驗收完成前，不宣稱已建置房間級自動封鎖產品。

新的[防火牆資料工廠](firewall_lab/README.md)會記錄每場實驗的精確標籤、SROS2 模式、PCAP、Zeek 結果與政策雜湊，並以 session 分組避免模型資料洩漏。目前有兩個清楚分層的資料來源：2,500 sessions／90,000 windows、22 種攻擊加 normal 的合成預訓練集；以及已完成的 1,100-session Gazebo live campaign。正式候選資料排除一場封存後仍增長的 session，實際使用 1,099 場（Permissive 550、Enforce 549）；另有 300 場缺陷情境已用相同 scenario／seed／mode 受控重跑並在特徵層替換，不重複灌成 1,399 場。2026-08-25 的 P1 已完成平行 AI gate 與 credential／ACL-aware direct-delivery 驗票，但 family-LOO 四組設定全部未達 AI acceptance；P2 接著建立嚴格 RTPS／DDS 身份歸因契約與 session-level conformal，並確認現有 1,101 個 session 中 **0 場**具備完整身份→來源 IP 證據，兩模式的 normal conformal 校準數也未達 49 場最低解析度。所有模型仍為 observe-only、`deployment_eligible=false`，不代表實體機器人或生產環境保證。證據邊界與殘餘風險見[2026-08-21 階段完整總報告](文件/專題完整總報告_2026-08-21.md)、[P1 修正報告](文件/P1_平行AI與DirectDelivery修正_2026-08-25.md)與[P2 身份歸因／Conformal 報告](文件/P2_身份歸因與SessionConformal_2026-08-25.md)。

## 系統重點

- Gazebo / TurtleBot3 提供 `/scan`、`/odom`、`/imu`，巡邏控制器發布 `/cmd_vel`。
- 六個 `std_msgs/String` topic 使用 HMAC envelope v3，綁定 channel、timestamp 與 nonce。
- `intelligent_defense_node` 以 D1–D6 偵測物理不可能行為、感測／控制矛盾與監控失效。
- SROS2 Enforce 使用雙 CA、逐節點最小權限與 DDS discovery/data 保護，是外部未授權 participant 的主要預防層。
- Zeek 從網路層偵測 DDS 偵察、注入、DoS、參數竄改與來源偽造跡象。
- 防火牆資料工廠平衡產生 Permissive／Enforce 實驗，smoke 資料永遠不得進入正式訓練。
- ML-IDS 以精確 session 標籤和 Zeek／robot telemetry 特徵訓練分層模型；模型輸出與
  動作授權隔離，低信心、未知來源或證據不足一律 observe-only。
- TQC 是獨立的未來工作軌，不作為 DDS 攻防成效的證據。

## 建議閱讀順序

1. [方向收斂與驗收基準](文件/專題方向收斂與驗收基準_2026-08-25.md)：題目、主 RQ、貢獻、名稱與驗收閘門。
2. [主計畫與 WBS](文件/專題主計畫與WBS_2026-08-17.md)：唯一 canonical 進度、路線圖與 Jesse 待辦。
3. [防火牆資料工廠](firewall_lab/README.md)：資料生成、1100-session campaign、品質 gate 與模型決策。
4. [P1 修正報告](文件/P1_平行AI與DirectDelivery修正_2026-08-25.md)：平行 AI gate、family-LOO 失敗結果與 direct-delivery v2 邊界。
5. [P2 身份歸因／Conformal 報告](文件/P2_身份歸因與SessionConformal_2026-08-25.md)：可信來源歸因契約、現有資料缺口與有限樣本校準門檻。
6. [階段完整總報告](文件/專題完整總報告_2026-08-21.md)：架構、證據邊界、成果與殘餘風險。
7. [系統架構](紅隊測試/ARCHITECTURE.md)：節點、topic 與信任邊界。
8. [展示流程](展示指令/README.md)：SROS2 Enforce 與 demo 操作。
9. [ML-IDS 說明](ML防禦/README.md)：資料、模型、評估與回應安全閘。
10. [Code review 指引](REVIEW_README.md)：原始碼導覽與測試入口。

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
2026-08-25 P2 checkpoint 的完整離線回歸為 **665 passed、0 failed、265 warnings**；
warning 是載入既有 joblib 時的 NumPy 2.5 deprecation，不是測試失敗。

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

P2 已建立 RTPS／DDS 身份歸因輸入契約，但既有 1,101 個 session 中沒有
`rtps_identity.jsonl`、`identity_attestation.json` 或 `dds_security_audit.jsonl`，Zeek
也沒有 GUID／entity／topic／identity subject 欄位。五元組不能替代受信任身份→IP
綁定，因此目前兩個 readiness flag 仍固定為 false。

## 目錄

每個帶 📑 的目錄都有自己的索引，找東西從那裡進去。

| 路徑 | 內容 |
|---|---|
| [`文件/`](文件/README.md) 📑 | 報告、證據總帳、稽核、簡報。**86 個項目，先看索引** |
| [`工具腳本/`](工具腳本/README.md) 📑 | 38 支腳本，依用途分類；標「需授權」的會產生 live 流量 |
| [`紅隊測試/`](紅隊測試/README.md) 📑 | 27 支 PoC、威脅模型、攻擊報告與修補紀錄 |
| [`firewall_lab/`](firewall_lab/README.md) 📑 | session 資料工廠、精確標籤、campaign、特徵、訓練與受限決策 |
| [`展示指令/`](展示指令/README.md) 📑 | Gazebo、SROS2 與驗證流程 |
| [`Zeek監控/`](Zeek監控/README.md) 📑 | DDS/RTPS 網路偵測與受控回應輔助程式 |
| [`ML防禦/`](ML防禦/README.md) 📑 | 特徵抽取、模型訓練／評估與回應引擎 |
| `src/dds_security_monitor/` | HMAC、巡邏、行為 IDS 與 ROS2 安全節點 |
| `firewall_lab/security_observer/` | 獨立的 Fast DDS 安全觀測者與第二層守衛（C++） |
| `src/turtlebot3_dqn/` | TQC 訓練與評估（獨立未來工作軌） |
| `tests/` | 可離線執行的安全回歸測試 |
| `跨主機紅隊/`、`網路記錄/` | 跨主機攻擊設定、Zeek 輸出 |

⚠️ `文件/` 底下的檔案被證據總帳以路徑＋SHA-256 釘住，**不要移動或改名**。

## 目前必須保留的限制

- Permissive 模式下，`/cmd_vel`、`/scan`、`/odom`、`/imu` 不能套用 String envelope；來源預防依賴 SROS2 Enforce。
- N9 `/cmd_vel` race 仍有殘餘風險；目前已有一組
  Permissive／Enforce live pilot 對照，但尚不足以代表長時間穩定性。
- 應用層 HMAC 仍是集中式共享金鑰，尚缺輪替與首次安全分發機制。
- mode 0600 與禁止環境變數可減少跨帳號／`/proc` 被動曝露，但擋不住已取得同一 Unix UID 任意讀檔能力的程式；完整隔離仍需獨立服務帳號或 OS secret store。
- 倉庫既有的歷史 `.joblib` 沒有 HMAC sidecar；安全載入器會拒絕它們，須從可信資料重新訓練，不能把來源未確認的 pickle 直接補簽當成可信。
- 20-session pilot 與 1,100-session live campaign 均已完成；正式候選為
  1,099 場。smoke、被 quarantine 的產物與 300 場被替換的缺陷版本不可重複計入
  訓練規模或成效證據。
- live 資料仍是同機 Gazebo 受控實驗，不具企業現場、隔離跨主機、Pi 5 或生產環境代表性；
  不應把離線指標外推成自動封鎖保證。
- 修補後的 `01c` 全 Gazebo 長時間場景尚未完成完整紅隊回歸。

紅隊 PoC 僅能在已獲授權、隔離的 ROS domain／實驗網路執行；不要把測試腳本指向第三方或生產系統。
