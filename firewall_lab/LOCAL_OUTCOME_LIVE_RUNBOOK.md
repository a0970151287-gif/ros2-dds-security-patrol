# 九項本機防禦結果：安全實測流程

目前程式已能「從原始事件重算結果」，但**尚未產生任何真實 ROS／Gazebo 通過證據**。沒有真實事件、缺階段、來源錯誤、collector 中斷、hash 改變或只寫 `passed: true`，都會 fail closed，跨主機 admission 仍為阻擋。

## 安全邊界

- 只在自己的同一台主機、`ROS_LOCALHOST_ONLY=1`、SROS2 `Enforce` 使用。
- observer 只訂閱 topic、讀一次 `dds_security_monitor.whitelist`、查 ROS graph，證據只送往 mode `0600` 的 Unix datagram socket。
- observer 不發布 ROS topic、不改 parameter、不啟動攻擊、不使用 sudo、不改防火牆。
- 每個 stage 最長 60 秒；observer 單次最長 300 秒。
- marker 只有 `check_id / stage / start|end`，沒有 facts 或 pass 欄位。

## 第一次實跑前的使用者動作

這三步涉及你的 ROS 環境與 SROS2 私鑰，必須由你在自己的終端執行，Codex 不會代跑：

1. 重新 build `dds_security_monitor`，讓 `local_outcome_observer` entry point 生效。
2. 重新執行 canonical SROS2 provisioning，建立新 `/local_outcome_probe` enclave 並重新簽 permissions。它只有 `/scan`、`/odom`、`/imu`、`/cmd_vel`、`/chatter` 訂閱和一個 `get_parameters` request，沒有控制發布權。
3. 啟動原本的本機 Gazebo + SROS2 Enforce stack；不要接外部網路或跨主機。

## 一個 campaign 的資料流

整個九項驗證必須共用**同一個 collector session_id 與同一份停止後的 telemetry JSONL**：

1. 啟動 `firewall_lab.live_telemetry_collector` 的本機 Unix socket。
2. 設定：

   ```bash
   export ROS_LOCALHOST_ONLY=1
   export ROS_SECURITY_ENABLE=true
   export ROS_SECURITY_STRATEGY=Enforce
   export SROS2_FIREWALL_LIVE_ACK=I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE
   ```

3. 以 `/local_outcome_probe` enclave 啟動 bounded observer：

   ```bash
   ros2 run dds_security_monitor local_outcome_observer --ros-args \
     --enclave /local_outcome_probe -p duration_sec:=300.0
   ```

4. 每個 stage 前後只放 fact-free marker：

   ```bash
   python3 -m firewall_lab.local_outcome_marker \
     --socket <runtime_telemetry.sock> \
     --check-id <check_id> --stage <stage> --boundary start \
     --live-loopback-ack I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE

   # 在這個 bounded window 執行既有 allowlisted scenario；一次只做一案。

   python3 -m firewall_lab.local_outcome_marker \
     --socket <runtime_telemetry.sock> \
     --check-id <check_id> --stage <stage> --boundary end \
     --live-loopback-ack I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE
   ```

5. 停止 collector 後才重算，避免 hash 在分析途中改變：

   ```bash
   python3 -m firewall_lab.local_outcome_campaign \
     --evidence-root <campaign_dir> \
     --telemetry <campaign_dir>/telemetry_events.jsonl \
     --observations <campaign_dir>/observations.jsonl \
     --session-id <同一個 session_id> \
     --live-loopback-ack I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE

   python3 -m firewall_lab.local_outcomes \
     --observations <campaign_dir>/observations.jsonl \
     --evidence-root <campaign_dir> \
     --report <campaign_dir>/local_defense_outcomes.json \
     --live-loopback-ack I_CONFIRM_LIVE_SAME_HOST_LOOPBACK_EVIDENCE
   ```

## 九項證據如何重算

| 結果 | 必須存在的原始資料 |
|---|---|
| 正常流量保留 | `/scan`、`/odom`、`/imu`、final `/cmd_vel` 計數；唯一合法 final publisher；驗證成功 heartbeat；guard output |
| 未授權 participant 被拒 | SROS2 deny 分類事件；`/chatter` correlation count 為 0；前後 runtime-state digest；合法 monitor 健康 |
| HMAC 偽造丟棄 | verifier 的 `invalid_signature` 結果；前後 runtime-state digest；下一筆 valid HMAC 成功 |
| replay 丟棄 | verifier 的 `nonce_reuse_or_capacity` 結果；前後 runtime-state digest；下一筆 fresh nonce 成功 |
| oversized input 丟棄 | SensorHub rejection-branch 的 oversized counter；程序健康；state digest 未變；下一窗 valid scan |
| parameter 不變 | observer 兩次讀到的 whitelist canonical digest 相同；target veto 或 SROS2 permission deny；monitor 健康 |
| guard 歸零 | 已驗證 `guard_lock` action 到第一筆 blocked zero output 的延遲；持續零速樣本 |
| guard 解除與恢復 | monitor fault latch；fresh authenticated heartbeat；authenticated clear；fresh input；non-zero unblocked output 與恢復延遲 |
| graph fault fail-safe | **真實** graph exception、D4 incident、guard lock/zero、graph recovery、monitor healthy |

## 目前保留的 blocker

`graph_failure_fail_safe` 沒有提供「假造 graph fault」或會殺節點的觸發器。只有真的出現 graph inspection exception 時才能形成證據；否則 campaign 會在 preflight 停止，不會把 fixture 或人工 JSON 當通過。若要可重複測試，下一步要另行設計一個不殺程序、不改 production graph 的明確 fault-injection seam，經老師／使用者同意後才實作。

