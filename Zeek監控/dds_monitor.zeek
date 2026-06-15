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
const SEND_LINE_SCRIPT = "/home/jesse/ros2_ws/zeek/send_line.py" &redef;

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

# ── 狀態全域變數 ─────────────────────────────────────────────────────────────

## 已見過的 DDS 節點 IP（每個 IP 只警報一次）
global seen_dds_nodes: set[addr];

## 已見過的 IMDS 探測來源 IP
global imds_seen: set[addr];

## 蜜罐觸發速率限制表（key = "honeypot_<ip>"）
global cooldown_table: table[string] of time;

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

    # 規則三：DDS/ROS2 節點連線監控 (UDP 7400-7500)，每個 IP 只警報一次
    else if ( is_udp_port(resp_p) &&
              port_to_count(resp_p) >= DDS_PORT_LOW &&
              port_to_count(resp_p) <= DDS_PORT_HIGH &&
              orig !in seen_dds_nodes )
    {
        add seen_dds_nodes[orig];
        do_alert(fmt(" [DDS 節點警報]\n時間: %s\n發現新的 DDS 節點加入網路！\n> 節點 IP:    %s\n> 目標 Port:  %s\n> 已知節點數: %d",
            now_str(), orig, resp_p, |seen_dds_nodes|));
    }
}

# ── 結束報告 ──────────────────────────────────────────────────────────────────

event zeek_init()
{
    print " Zeek DDS 安全監控腳本已載入，開始監聽...";
}

event zeek_done()
{
    print "\n========================================";
    print fmt(" [Zeek 會話結束報告] — %s", now_str());
    print fmt("  ✦ 唯一 DDS 節點 IP 數: %d", |seen_dds_nodes|);
    print fmt("  ✦ 唯一 IMDS 探測來源: %d", |imds_seen|);

    if ( |seen_dds_nodes| > 0 )
    {
        print "  ── DDS 節點清單 ──";
        for ( node in seen_dds_nodes )
            print fmt("    • %s", node);
    }
    print "========================================\n";
}
