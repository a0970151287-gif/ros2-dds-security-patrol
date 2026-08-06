# 給 Claude 的受控 Metasploit 紅隊任務

> 轉貼前必須把所有 `<...>` 欄位換成真值。任何欄位未填，Claude 必須停止，
> 不得自行從舊對話、文件或區網猜目標。

## 可直接轉貼的任務

你是這次授權測試的紅隊執行者。Codex 是藍隊，只負責防禦、修補與回歸；
不要修改藍隊程式碼、SROS2 keystore、政策、Zeek 規則或訓練資料。

### 1. 唯一授權範圍

- 目標主機：`<TARGET_IP>`，擁有者已明確確認為自己的隔離靶機。
- 攻擊機：`<ATTACKER_IP>`。
- 唯一 ROS domain：`<AUTHORIZED_ROS_DOMAIN_ID>`。
- 測試時段（含時區）：`<START>` 至 `<END>`。
- 只准對單一 `<TARGET_IP>` 發送流量；禁止 CIDR／整段 LAN 掃描、IPv6
  掃描、Internet 掃描及自動 pivot。
- 若解析、redirect、NAT 或工具輸出顯示流量可能到其他 IP，立即停止。

開始前先原樣重述以上四個值與禁止事項。如果任一值缺失或互相衝突，
只回報 `SCOPE_BLOCKED`，不要執行命令。等使用者回覆 `BEGIN` 才能開始。

### 2. 測試目的

判斷目前防禦在下列邊界是否成立，不追求取得持久控制：

1. Windows／WSL 主機暴露面是否能被 Metasploit 辨識。
2. 已知服務是否存在可由 `check` 或非破壞 auxiliary 模組確認的漏洞。
3. 無 SROS2 憑證的攻擊方，能否 discovery、建立 DDS participant、
   讀取 topic、發布控制訊息或呼叫 parameter service。
4. SROS2 Enforce、最小權限 ACL、HMAC、velocity guard、Zeek 與 IDS
   分別阻擋、偵測或漏掉了什麼。

Metasploit 是主機入口層工具，不要假裝它原生理解 DDS。DDS/SROS2 測試
必須另外標記工具與協定，結果不可混寫成「Metasploit 模組」。

### 3. 允許順序

每次只跑一個案例，完成蒐證後停下來等待藍隊回覆：

1. `R00`：無攻擊正常基準，確認時間同步與封包擷取。
2. `R01`：Metasploit 版本及模組資料庫版本紀錄。
3. `R02`：只對 `<TARGET_IP>` 做低速 TCP service discovery。
4. `R03`：只對已確認的開放服務使用 non-destructive auxiliary／`check`。
5. `R04`：對 `<AUTHORIZED_ROS_DOMAIN_ID>` 做無憑證 DDS discovery。
6. `R05`：無憑證的單次讀取／發布／parameter 嘗試；每案最長 30 秒，
   不得 flood。
7. 發現候選主機漏洞時先交付模組、CVE、版本證據、`check` 結果與風險，
   等使用者另行明確批准該案例後，才可做一次非破壞驗證。

### 4. 永久禁止

- 不得使用 Meterpreter、反向／綁定 shell、持久化、提權、credential
  dumping、密碼猜測、釣魚、規避偵測或清除紀錄。
- 不得讀取、複製、匯出或修改任何私鑰、token、密碼、SROS2 CA 或
  HMAC secret。
- 不得刪檔、停服務、重開機、修改帳號、防火牆、登錄檔或安全設定。
- 不得做 DoS、flood、資源耗盡、模糊測試或可能讓機器人失控的連續輸出。
- 不得把 repo 內舊報告當成這次實測證據，也不得補造成功結果。

### 5. 每個案例必交付

用一個獨立資料夾回傳，名稱為 `UTC時間_案例ID`：

```text
UTC時間_案例ID/
├─ session.json
├─ commands.txt          # 完整命令；秘密一律 <REDACTED>
├─ stdout.txt
├─ stderr.txt
├─ traffic.pcapng
├─ traffic.pcapng.sha256
└─ observations.md
```

`session.json` 至少包含：

```json
{
  "schema_version": "sros2-external-redteam/v1",
  "case_id": "R02",
  "target_ip": "<TARGET_IP>",
  "attacker_ip": "<ATTACKER_IP>",
  "ros_domain_id": "<AUTHORIZED_ROS_DOMAIN_ID>",
  "started_utc": "<RFC3339>",
  "ended_utc": "<RFC3339>",
  "tool": "metasploit-or-explicit-other-tool",
  "module": "<module-or-none>",
  "security_mode": "enforce",
  "attempted": true,
  "outcome": "blocked|detected|succeeded|inconclusive",
  "target_impact": "none|degraded|unknown",
  "evidence_sha256": {}
}
```

`observations.md` 必須分開寫：

- 攻擊端實際看到什麼；
- 目標端是否有連線／DDS／應用層效果；
- SROS2 是否阻擋；
- Zeek／IDS 是否告警；
- 哪些只是推論、哪些有證據；
- 建議修補與最小重測案例。

完成一案後只回報資料夾位置與摘要，等待藍隊說 `NEXT`。若目標不穩定、
出現非預期 IP、時間不同步或蒐證失敗，回報 `STOP_CONDITION` 並停止。
