# 紅隊 Phase 2 資料收集 — 邀請與流程

- **目的**：目前 ML-IDS 的混淆矩陣是 bootstrap 弱標籤（來源身分推得），要拿到真正乾淨、可信的多類別標籤，需要紅隊配合**每類攻擊隔離跑 + 精確標時間戳**。
- **現況查證**（2026-07-04）：Gazebo / Zeek / 6個安全節點目前**都沒在跑**，`labels.txt` 不存在（乾淨狀態，可以直接開始）。

---

## 給紅隊的訊息（請轉發）

> 你好，藍隊這邊準備進行第二輪資料收集，這次會**逐一標記時間戳**，麻煩配合：
> 1. 每次只跑**一種**攻擊類型，不要混打（混打會讓標籤不準）。
> 2. 藍隊會先說「開始 X」才開始跑，跑完說「結束」再停手，中間留幾秒空檔。
> 3. 順序：偵察(recon) → DoS → 指令注入(inject) → 參數竄改(param) → 來源偽造(spoof) → 隱形DoS(stealth_dos)。
> 4. 每種抓 3-5 分鐘即可，不用求快求量，乾淨比多更重要。

---

## 藍隊(這邊)操作流程

### 前置：啟動全系統
```bash
# 1. 全系統 SROS2 Enforce
bash 展示指令/01c_啟動系統_enforce.sh

# 2. Zeek 監聽（另開終端機，務必先 cd 網路記錄）
cd ~/ros2_ws/網路記錄 && sudo /opt/zeek/bin/zeek -i eth0 ../Zeek監控/dds_monitor.zeek
```

### 收集迴圈（每種攻擊重複這個模式）
```bash
cd ML防禦/資料收集

# 開場先錄一段乾淨基線（無攻擊，系統正常巡邏）
bash label.sh start normal
#（等 2-3 分鐘，確認系統正常運作、無攻擊）
bash label.sh end normal

# 每個攻擊類型：先標 start，請紅隊開始，紅隊說結束後才標 end
bash label.sh start recon
#（跟紅隊說「開始 recon」，等紅隊跑完說「結束」）
bash label.sh end recon

bash label.sh start dos
#（同上）
bash label.sh end dos

bash label.sh start inject
bash label.sh end inject

bash label.sh start param
bash label.sh end param

bash label.sh start spoof
bash label.sh end spoof

bash label.sh start stealth_dos
bash label.sh end stealth_dos
```

### 收集完成後
```bash
# 精確標註 + 重抽特徵（用真實時間窗，取代 bootstrap 猜測）
/home/jesse/ml_ids_env/bin/python 精確標註_重抽特徵.py \
  ../../網路記錄/conn.log labels.txt ../輸出/features_precise.csv 8

# 重新訓練，跟現有弱標籤結果對照
/home/jesse/ml_ids_env/bin/python ../訓練.py ../輸出/features_precise.csv
```

跑完貼結果給我，我會更新 `文件/AI評估_ML-IDS何時有用.md` 的第三節，把弱標籤版本換成 Phase 2 乾淨標註版本，並在報告裡明確標註兩者差異（這正是驗證「資料瓶頸」論點最後一塊拼圖）。

---

## 注意事項

- **時間同步**：`label.sh` 用的是這台機器（10.10.10.2）的本地時間戳，紅隊回報「開始/結束」時盡量口頭同步、不要有太大延遲落差。
- **紅隊白名單仍生效**：`回應引擎.py` 的 `game_allowlist={"10.10.10.1"}` 這次收集期間不會自動封鎖紅隊，可以放心打。
- **若中途系統當掉/停止**：先確認是不是又踩到已知漏洞（N24/N24b/N25 皆已修補，若是新現象請截圖記錄）。
