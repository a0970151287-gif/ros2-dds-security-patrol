# DoS / DDoS 防禦策略 — ROS2/DDS 智慧工廠

**威脅**：紅隊 N-DoS（SPDP 風暴 40 participant/8s、342 SPDP）、N15 log storm、N18 記憶體耗盡、N19 參數服務洪水、N20 驗章洪水、N21 偵測器誘導 DoS。
**核心認知**：**可用性（DoS）沒有銀彈**。策略是「多層遞減」——讓攻擊在每一層被削弱，並把「偵測」升級成「偵測→阻斷」與「事前限流」。

---

## 分層防禦（由外到內）

| 層 | 機制 | 擋什麼 | 狀態 |
|---|---|---|---|
| L1 邊界限流 | `dos_firewall.sh`：允許清單 + per-source hashlimit(50/s) + 連線數上限 | 單一來源/未知來源的封包洪水（含 SPDP 多播風暴） | ✅ 已實作（需 sudo） |
| L2 偵測→阻斷 | Zeek `DOS_BLOCK_ENABLED`：偵測 SPDP 風暴 → `block_source.sh` 動態封鎖來源 N 秒 | 已上線的洪水來源（自動封 + 自動解封） | ✅ 已實作（Zeek root 可下 iptables） |
| L3 認證隔離 | SROS2 Enforce：未認證 participant 無法加入 | N19/N20 等「應用層」洪水（攻擊者連不進來就發不了 param/verify 洪水） | ✅ 已建（01c） |
| L4 資源上限 | 應用層硬上限 | 耗盡型 DoS | ✅ 部分（見下） |

### L4 已有的應用層資源上限
- **ReplayCache LRU 4096 + TTL**：N1/N3 重放洪水不會無限長大快取。
- **N24 scan 截斷 SCAN_MAX_POINTS=4096**：超大 scan 不再爆記憶體/CPU。
- **告警 cooldown 60s + cascade quiet-window**（ROSEC-2026-011）：N15 log storm / N21 偵測器誘導 DoS 不會把告警/急停刷爆。
- **/patrol/reload 預設關閉 + 5s rate-limit**（G4/ROSEC-2026-015）：服務濫用洪水受限。

---

## DDoS（分散式 / 多來源偽造）策略

單一來源好擋（封 IP）；DDoS 難在「來源是分散或偽造的」。對策：

1. **允許清單優先於黑名單**（L1）：直連實驗室只有一個合法對端(10.10.10.1)。**非預期來源打 DDS 埠一律 DROP** → 偽造成大量隨機來源 IP 也全被擋（不是逐一封，是預設拒絕）。
2. **per-source + 聚合限速**（hashlimit）：就算來源在允許範圍，單來源 >50/s 就削；可再加聚合上限防「很多合法樣貌來源」。
3. **消滅 SPDP 多播洪水面 — Fast-DDS Discovery Server**（進階，建議）：把探索從「多播」改成「中央 Discovery Server」。攻擊者狂噴 `239.255.0.1:14900` 時**沒人在多播上聽** → SPDP 風暴失去著力點。用 `ROS_DISCOVERY_SERVER` + `fastdds discovery` 啟動。
4. **SROS2 Enforce 縮小可放大面**：未認證者無法建立 reader/writer → 無法觸發「驗章洪水(N20)/參數洪水(N19)」這類**需要互動才放大**的 DoS。

---

## 誠實的限制（不能不講）

- **WSL2 mirrored 模式**：host 端 iptables 可能**不攔截**鏡像流量（網路在 Windows 層）。此時 L1/L2 的 iptables 要改用 **Windows 端防火牆**（`New-NetFirewallRule` 封來源、`Set-NetFirewallHyperVVMSetting`），或在**原生 Linux** 機器上才完全有效。
- **網路層 SPDP 洪水無法 100% 消除**：封包仍會到網卡、消耗少量 CPU/頻寬。L1 限流 + L3 Discovery Server 是把它**削到無害**，不是讓它「不存在」。
- **L2 自動封鎖有 FP 風險**：故預設 `DOS_BLOCK_ENABLED=F`，只在 DoS 防禦 demo 時開；門檻(25/8s)遠高於正常(Gazebo ~15)以降誤封。

---

## 操作（DoS 防禦 demo）

```bash
# L1 事前限流（目標機 sudo）
sudo bash 跨主機紅隊/dos_firewall.sh on        # demo 後: ... off

# L2 偵測→自動阻斷（目標機 sudo Zeek，開啟 BLOCK）
sudo /opt/zeek/bin/zeek -i eth0 Zeek監控/dds_monitor.zeek DOS_BLOCK_ENABLED=T

# 攻擊機發 N-DoS 風暴 → 預期：Zeek 告警 + 「🛡️ 已封鎖 10.10.10.1」+ 後續封包被 DROP
```

---

_對應實作：`Zeek監控/dds_monitor.zeek`(L2)、`Zeek監控/block_source.sh`(L2 helper)、`跨主機紅隊/dos_firewall.sh`(L1)、應用層上限見各節點 N1/N24/G4 修補。_
