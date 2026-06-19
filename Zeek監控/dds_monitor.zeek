##! ROS2 DDS 網路安全監控腳本
##!
##! 內容：
##!   - 憑證改用環境變數，不再寫死在程式碼中
##!   - 獨立 Python 輔助腳本透過 stdin 傳遞訊息，避免 shell injection
##!   - 速率限制：同一來源 60 秒內只發一次警報
##!   - IMDS / 蜜罐來源 IP 去重（每個 IP 只警報一次）
##!   - 加入時間戳記與節點計數
##!   - zeek_done 事件輸出統計摘要
##!
##! 使用前請設定環境變數：
##!   export LINE_CHANNEL_TOKEN="your_channel_access_token"
##!   export LINE_USER_ID="your_line_user_or_group_id"
##!
##! 執行方式 (live)：
##!   sudo zeek -i <interface> /home/jesse/ros2_ws/zeek/dds_monitor.zeek
##! 執行方式 (pcap)：
##!   zeek -r capture.pcap /home/jesse/ros2_ws/zeek/dds_monitor.zeek

@load base/utils/exec

# ── 可調整設定 ────────────────────────────────────────────────────────────────

## 發送 LINE 通知的 Python 輔助腳本路徑
const SEND_LINE_SCRIPT = "/home/jesse/ros2_ws/Zeek監控/send_line.py" &redef;

## 蜜罐監聽的 TCP port
const HONEYPOT_PORT: port = 8888/tcp &redef;

## DDS/ROS2 使用的 UDP port 範圍
## RTPS 埠公式: 7400 + 250*domainId + offset。
## domain 0 → 7400-7649；domain 30 → 14900-15149（本實驗用 domain 30）。
## 範圍涵蓋 domain 0~30，確保跨主機 domain-30 流量也會觸發。
const DDS_PORT_LOW:  count = 7400 &redef;
const DDS_PORT_HIGH: count = 15200 &redef;

## 同一觸發條件的最短重複警報間隔
const ALERT_COOLDOWN: interval = 60sec &redef;

## 信任的 DDS 來源 IP（自己/合法節點）——其探索多播不視為攻擊，是 FPR 的關鍵。
## 目標機自身 10.10.10.2：Gazebo+patrol 啟動會噴大量 SPDP，必須白名單否則自我誤報。
const TRUSTED_DDS_HOSTS: set[addr] = { 10.10.10.2, 127.0.0.1 } &redef;

## 【F7 修補】信任 IP 的合法 MAC（IP↔MAC 綁定）。
## 攻擊者在直連 L2 可偽造來源 IP=10.10.10.2 繞過 IP 白名單；但若未同時偽造 MAC，
## 此處即抓到「信任 IP 配到非預期 MAC」= 偽造嫌疑。殘留風險(IP+MAC 全偽造)→ 需 SROS2。
const TRUSTED_DDS_MACS: table[addr] of string = {
    [10.10.10.2] = "34:5a:60:96:c3:ca",
} &redef;

## 【F1 修補】參數竄改服務簽章：未授權 set_parameters 服務呼叫
## （可遠端改速度上限/感測校正/PID/安全旗標），原三類規則的偵測盲區。
const PARAM_TAMPER_SIGNATURE: string = "set_parameters" &redef;

## SPDP 多播探索位址 / 埠（domain 30）
const SPDP_MCAST: addr = 239.255.0.1 &redef;
const SPDP_PORT:  count = 14900 &redef;

## 注入攻擊的 payload 簽章（受控實驗中攻擊機在 DATA 開頭標記）
const INJECT_SIGNATURE: string = "INJECTED" &redef;

## DoS（SPDP 風暴）判定：WINDOW 內非白名單來源的 SPDP 流量數超過 THRESHOLD 即告警
const DOS_WINDOW:    interval = 8sec &redef;
const DOS_THRESHOLD: count    = 25 &redef;   # 正常 Gazebo 啟動 ~15；攻擊 ~40

## DoS 主動阻斷：偵測到風暴 → 呼叫 iptables 封鎖來源（升級「偵測→阻斷」）
## 預設關閉，避免展示時誤封；要做 DoS 防禦 demo 時 redef 成 T（需 root 跑 Zeek）。
const DOS_BLOCK_ENABLED: bool = F &redef;
const DOS_BLOCK_SECS:    count = 300 &redef;
const BLOCK_SCRIPT: string = "/home/jesse/ros2_ws/Zeek監控/block_source.sh" &redef;

# 讓 Zeek 把所有 UDP payload 交給 udp_contents 事件（注入內容比對用）
redef udp_content_deliver_all_orig = T;

# ── 狀態全域變數 ─────────────────────────────────────────────────────────────

## 已見過的 DDS 節點 IP（每個 IP 只警報一次）
global seen_dds_nodes: set[addr];

## 已見過的 IMDS 探測來源 IP
global imds_seen: set[addr];

## 蜜罐觸發速率限制表（key = "honeypot_<ip>"）
global cooldown_table: table[string] of time;

## DoS 偵測：近期非白名單 SPDP 流量的時間戳（滑動視窗）
global spdp_burst_times: vector of time;

## 已對其發過注入告警的來源（每來源 60s 一次，靠 rate_limited）
## 統計用：注入/DoS/參數竄改/IP偽造 累計次數
global inject_alert_count: count = 0;
global dos_alert_count:    count = 0;
global param_alert_count:  count = 0;
global spoof_alert_count:  count = 0;

## 已告警過的 (信任IP|實際MAC) 偽造組合，避免洗版
global spoof_seen: set[string];

# ── 工具函式 ──────────────────────────────────────────────────────────────────

function rate_limited(key: string): bool
{
    if ( key in cooldown_table &&
         network_time() - cooldown_table[key] < ALERT_COOLDOWN )
        return T;
    cooldown_table[key] = network_time();
    return F;
}

function now_str(): string
{
    return strftime("%Y-%m-%d %H:%M:%S", network_time());
}

## 透過 Python 輔助腳本發送 LINE 通知。
## 訊息以 stdin 傳遞，完全避免 shell injection 風險。
function send_line_alert(text: string)
{
    local cmd = Exec::Command(
        $cmd   = fmt("python3 %s", SEND_LINE_SCRIPT),
        $stdin = text
    );

    when [cmd] ( local res = Exec::run(cmd) )
    {
        if ( res$exit_code == 0 )
            print " LINE 通知發送成功";
        else
        {
            local err = res?$stderr && |res$stderr| > 0
                        ? res$stderr[0]
                        : "(無錯誤訊息)";
            print fmt(" LINE 通知失敗 (exit=%d): %s", res$exit_code, err);
        }
    }
}

## 印出訊息並送出 LINE 警報。
function do_alert(text: string)
{
    print fmt("[%s] %s", now_str(), text);
    send_line_alert(text);
}

# ── 主要偵測邏輯 ──────────────────────────────────────────────────────────────

## DoS 偵測：在滑動視窗 DOS_WINDOW 內累計非白名單 SPDP 流量，
## 超過 DOS_THRESHOLD 即判定為 SPDP 探索風暴（DoS）。
function check_spdp_dos(orig: addr)
{
    local now = network_time();
    spdp_burst_times += now;

    # 修剪掉視窗外的舊時間戳
    local fresh: vector of time;
    for ( i in spdp_burst_times )
        if ( now - spdp_burst_times[i] <= DOS_WINDOW )
            fresh += spdp_burst_times[i];
    spdp_burst_times = fresh;

    if ( |spdp_burst_times| >= DOS_THRESHOLD &&
         !rate_limited("dos_spdp_storm") )
    {
        ++dos_alert_count;
        do_alert(fmt(" [DoS 攻擊 — SPDP 探索風暴]\n時間: %s\n滑動視窗內偵測到 %d 筆 SPDP 探索流量（門檻 %d）！\n> 最新來源: %s\n> 研判: 大量偽造 participant 灌爆探索通道",
            now_str(), |spdp_burst_times|, DOS_THRESHOLD, orig));

        # 升級：偵測 → 主動阻斷（封鎖洪水來源 IP，DOS_BLOCK_SECS 秒後自動解封）
        if ( DOS_BLOCK_ENABLED )
        {
            local bmsg = fmt("  🛡️ DoS 主動阻斷: 已封鎖 %s (%d 秒)", orig, DOS_BLOCK_SECS);
            local bcmd = Exec::Command($cmd = fmt("bash %s %s %d", BLOCK_SCRIPT, orig, DOS_BLOCK_SECS));
            when [bcmd, bmsg] ( local br = Exec::run(bcmd) )
            { print bmsg; }
            timeout 10sec { print "  ⚠️ 阻斷腳本逾時"; }
        }
    }
}

## 【F7】IP↔MAC 綁定偵測：信任 IP 若配到非預期 MAC = 來源 IP 偽造嫌疑。
## raw_packet 每封包觸發，能拿到 L2 來源 MAC（new_connection/udp_contents 拿不到）。
event raw_packet(p: raw_pkt_hdr)
{
    if ( ! p?$ip || ! p$l2?$src )
        return;

    local sip = p$ip$src;
    if ( sip !in TRUSTED_DDS_MACS )
        return;                      # 只檢查「信任 IP」是否被冒用

    local actual_mac = p$l2$src;
    if ( actual_mac == TRUSTED_DDS_MACS[sip] )
        return;                      # MAC 相符 = 真的是自己/合法節點

    local key = fmt("%s|%s", sip, actual_mac);
    if ( key in spoof_seen )
        return;
    add spoof_seen[key];
    ++spoof_alert_count;
    do_alert(fmt(" [偵測器告警 — 來源 IP 偽造嫌疑 / F7]\n時間: %s\n信任 IP 出現非預期 MAC，研判攻擊者偽造白名單 IP 試圖繞過偵測！\n> 宣稱來源 IP: %s\n> 合法 MAC:    %s\n> 實際 MAC:    %s\n> 殘留風險: IP+MAC 全偽造需靠 SROS2 身分驗證根治",
        now_str(), sip, TRUSTED_DDS_MACS[sip], actual_mac));
}

event new_connection(c: connection)
{
    local orig   = c$id$orig_h;
    local resp   = c$id$resp_h;
    local resp_p = c$id$resp_p;

    # 規則一：IMDS 雲端中繼資料探測（每個攻擊者 IP 只警報一次）
    if ( resp == 169.254.169.254 && orig !in imds_seen )
    {
        add imds_seen[orig];
        do_alert(fmt(" [IMDS 探測警報]\n時間: %s\n系統偵測到嘗試竊取雲端憑證的行為！\n> 來源 IP:  %s\n> 目標 Port: %s",
            now_str(), orig, resp_p));
    }

    # 規則二：蜜罐誘捕 (TCP 8888)，速率限制 60 秒
    else if ( resp_p == HONEYPOT_PORT &&
              !rate_limited(fmt("honeypot_%s", orig)) )
    {
        do_alert(fmt(" [蜜罐觸發警報]\n時間: %s\n偵測到對虛擬後台的惡意掃描！\n> 攻擊者 IP: %s\n> 目標 Port: %s",
            now_str(), orig, resp_p));
    }

    # 規則三：DDS/ROS2 流量（UDP 7400-15200，涵蓋 domain 0~30）
    else if ( is_udp_port(resp_p) &&
              port_to_count(resp_p) >= DDS_PORT_LOW &&
              port_to_count(resp_p) <= DDS_PORT_HIGH )
    {
        # 白名單來源（自己/合法節點）的探索流量不視為攻擊 → 壓 FPR
        if ( orig in TRUSTED_DDS_HOSTS )
            return;

        # ── 3a 偵察：非白名單來源首次出現在 DDS 網路（每 IP 一次）──
        if ( orig !in seen_dds_nodes )
        {
            add seen_dds_nodes[orig];
            do_alert(fmt(" [偵察攻擊 — DDS 節點警報]\n時間: %s\n偵測到白名單外的新 DDS participant 加入網路！\n> 節點 IP:    %s\n> 目標 Port:  %s\n> 已知未授權節點數: %d",
                now_str(), orig, resp_p, |seen_dds_nodes|));
        }

        # ── 3b DoS：非白名單來源的 SPDP 多播風暴 ──
        if ( (resp == SPDP_MCAST || port_to_count(resp_p) == SPDP_PORT) )
            check_spdp_dos(orig);
    }
}

## 注入偵測：檢查 UDP payload 是否含注入簽章（受控實驗中攻擊機標記 DATA）。
## 純 DDS 網路層無 RTPS 解析時，以內容簽章作為注入的可靠訊號（FPR 最低）。
event udp_contents(u: connection, is_orig: bool, contents: string)
{
    local orig = u$id$orig_h;
    if ( orig in TRUSTED_DDS_HOSTS )
        return;

    if ( INJECT_SIGNATURE in contents &&
         !rate_limited(fmt("inject_%s", orig)) )
    {
        ++inject_alert_count;
        do_alert(fmt(" [注入攻擊 — 偽造 DATA 警報]\n時間: %s\n偵測到白名單外來源送出帶注入簽章的 DATA！\n> 來源 IP:   %s\n> 目標 Port: %s\n> 簽章:      %s",
            now_str(), orig, u$id$resp_p, INJECT_SIGNATURE));
    }

    # 【F1】未授權參數竄改：白名單外來源呼叫 set_parameters 服務
    if ( PARAM_TAMPER_SIGNATURE in contents &&
         !rate_limited(fmt("param_%s", orig)) )
    {
        ++param_alert_count;
        do_alert(fmt(" [參數竄改攻擊 — set_parameters / F1]\n時間: %s\n偵測到白名單外來源呼叫參數服務（可遠端改速度上限/感測校正/安全旗標）！\n> 來源 IP:   %s\n> 目標 Port: %s\n> 服務簽章:  %s",
            now_str(), orig, u$id$resp_p, PARAM_TAMPER_SIGNATURE));
    }
}

# ── 結束報告 ──────────────────────────────────────────────────────────────────

event zeek_init()
{
    print " Zeek DDS 安全監控腳本已載入，開始監聽...";
    print fmt("  ✦ DDS 埠範圍: %d-%d ｜ 信任來源: %s", DDS_PORT_LOW, DDS_PORT_HIGH, TRUSTED_DDS_HOSTS);
    print fmt("  ✦ 三類偵測: 偵察(白名單外新節點) / 注入(簽章 '%s') / DoS(%s 內 SPDP>%d)", INJECT_SIGNATURE, DOS_WINDOW, DOS_THRESHOLD);
    print fmt("  ✦ 強化: F1 參數竄改(簽章 '%s') / F7 IP↔MAC 綁定抓來源 IP 偽造", PARAM_TAMPER_SIGNATURE);
}

event zeek_done()
{
    print "\n========================================";
    print fmt(" [Zeek 會話結束報告] — %s", now_str());
    print fmt("  ✦ 偵察 — 白名單外 DDS 節點 IP 數: %d", |seen_dds_nodes|);
    print fmt("  ✦ 注入 — 簽章告警次數: %d", inject_alert_count);
    print fmt("  ✦ DoS  — SPDP 風暴告警次數: %d", dos_alert_count);
    print fmt("  ✦ F1 參數竄改 — 告警次數: %d", param_alert_count);
    print fmt("  ✦ F7 來源 IP 偽造 — 告警次數: %d", spoof_alert_count);
    print fmt("  ✦ 唯一 IMDS 探測來源: %d", |imds_seen|);

    if ( |seen_dds_nodes| > 0 )
    {
        print "  ── DDS 節點清單 ──";
        for ( node in seen_dds_nodes )
            print fmt("    • %s", node);
    }
    print "========================================\n";
}
