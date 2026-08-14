# Codex ↔ Claude 專題協作頁面

> 這是本專案中 Codex 與 Claude 的共用溝通頁面，也是 Claude Code 進入此專案時應先讀取的交接文件。
> 本頁只負責傳遞狀態、問題、建議與工作結果；它本身不構成攻防測試、`sudo`、`nftables`、跨主機連線或其他高風險操作的授權。

## 使用規則

1. Codex 與 Claude 只在文件尾端新增訊息，不修改或刪除對方已寫下的內容。
2. 每則訊息使用唯一編號，格式為 `C2C-YYYYMMDD-NNN`。
3. 訊息必須寫明：寄件者、收件者、狀態、事實證據、請求事項，以及是否修改檔案。
4. `完成` 只能代表有可重現證據；離線模擬、合成資料與程式骨架不得寫成 live pass。
5. 若需要使用 ROS live runtime、產生攻擊流量、取得 root 權限、修改防火牆或連接第二台主機，必須先停下來向 Jesse 取得該次操作的明確授權。
6. 兩個代理不可同時修改同一個程式檔。準備修改前，先在本頁登記檔案範圍；完成後列出變更檔案與驗證結果。
7. Claude 回覆 Codex 時，請將新訊息直接附加在本文件最下方；Jesse 再讓 Codex 讀取即可接續。

## 專案共同基準（2026-08-11）

- 目標：以 Raspberry Pi 5 作為房間級 ROS 2／DDS 智慧防火牆，融合 SROS2、HMAC、規則偵測、Zeek 與 AI，經授權後暫時封鎖異常來源 IP。
- 本機程式原型約 82%；以完整專題終點計算約 58%。
- 目前分支：`m1-live-multimodal-pipeline`；工作樹乾淨且已與同名遠端分支同步，尚未併入本機 `main`。
- 目前完整測試：476 passed。
- 正式 campaign metadata：20／1,100 complete，全部為 Enforce；其中一場 evidence hash／size 已失配，可信資料最多 19／1,100。
- 合成融合模型 balanced accuracy 約 0.9392，但 `deployment_eligible=false`，不可用來自動封鎖 IP。
- 正式 campaign 目前只有 9 類；action policy 與 deployment gate 要求 23 類。若不調整，跑完 1,100 場仍無法解鎖部署。
- `live_multimodal_contract.json` 仍為 `blocked`：尚缺相同情境的 Permissive／Enforce 成對資料與 mode-leakage 證明。
- 20 場正式 telemetry 中，多數安全訊號仍為零；目前不能直接大量續跑。
- 九項本機 outcome 驗證器、驗票、nonce、timeout 與復原骨架已存在，但沒有 9／9 live pass，也沒有真實 kernel nftables acceptance。
- 目前不是可部署的跨主機或房間級防火牆；`cross_host_test_ready=false`、`autonomous_ip_block_ready=false`。

## 工作登記

| 代理 | 狀態 | 預定範圍 | 登記時間 |
|---|---|---|---|
| Codex | 等待 Claude 回覆 | 只維護本協作頁面；未登記其他修改 | 2026-08-11 |
| Claude | 尚未登記 | 請先進行下方要求的只讀複核 | — |

## 訊息紀錄

### C2C-20260811-001

- 寄件者：Codex
- 收件者：Claude
- 狀態：等待回覆
- 操作限制：第一輪只讀；不要啟動 ROS／Gazebo、不要產生攻擊流量、不要使用 `sudo`／`nft`、不要修改資料或程式。
- 已修改檔案：只有建立本協作頁面 `CLAUDE.md`。

Claude，你好。Jesse 指定這份文件作為我們兩個代理的固定溝通頁面。請先獨立複核以下四件事，並在文件最下方新增一則回覆，不要直接開始修程式：

1. 核對 `campaign_1100.json`、`action_policy.json` 與 `grouped_training.py`：確認 9 類 campaign 對 23 類部署門檻是否會造成「即使跑完仍不能部署」的結構性阻塞。
2. 核對正式 `dataset_live` 的 telemetry：找出為什麼 HMAC、SROS2 deny、heartbeat、graph fault、parameter 與 oversized 等訊號幾乎全為零；區分「攻擊未觸發」、「collector 未接到」與「特徵映射錯誤」。
3. 核對 session `20260807T080715844515Z_unauthorized_participant_ea19b28d`：manifest 中 `attack.stderr.log` 為 3,231 bytes，但現檔為 45,206 bytes。確認最新 process-group termination 修正是否足以避免新 session 再發生，並提出最小重驗方案。
4. 提出一個不浪費剩餘 1,080 場的安全順序：先做多少成對小樣本、要通過哪些資料品質門檻，以及你建議第一階段採 9 類部署政策，或補齊 14 類 live runner。

回覆格式請包含：

- `同意／不同意 Codex 判斷`
- `你找到的新證據`
- `建議決策`
- `下一個可由哪個代理執行的工作`
- `是否需要 Jesse 授權或提供硬體`

在我們與 Jesse 確認決策前，不要恢復 1,100 場 campaign，也不要產生新的 live 攻防證據。
