# Zeek DDS/RTPS 監控

`dds_monitor.zeek` 從網路層偵測 DDS reconnaissance、payload injection、
SPDP DoS、`set_parameters` 竄改與來源偽造。規則告警可送 LINE；Zeek
不具備直接封鎖權限，只能把候選事件交給 response authorizer。

## 權限模型

- Zeek 以非 root 帳號執行；封包擷取權限由管理者以受限 service/capability
  提供。
- Zeek 不執行 workspace 內的提權腳本。
- LINE helper 固定在 `/usr/local/libexec/dds-monitor/send-line`，由 root
  安裝且不可由 group/other 寫入。
- 舊版裸 IP／TTL 的 `block-source` 已改成永遠拒絕的安全樁，安裝器不會
  安裝它，也不會建立 `NOPASSWD` sudoers 規則。
- 未來主動處置只接受短效、一次性、綁定來源／模型／政策／backend 的
  signed ticket；跨程序驗票與 kernel timeout backend 完成前固定停用。

從專案根目錄安裝固定 helper（一次性管理動作）：

```bash
sudo bash 工具腳本/install_zeek_helpers.sh
```

這個安裝器只安裝 LINE helper，不授予防火牆權限。

若是從舊版升級且安裝器偵測到殘留，先指定當時的服務帳號撤權；舊檔會
移到 root-only 備份而非直接刪除：

```bash
sudo bash 工具腳本/revoke_legacy_zeek_privileges.sh <舊服務帳號> --confirm-revoke
sudo bash 工具腳本/install_zeek_helpers.sh
```

## 執行

先把 token 放在執行 Zeek 的帳號下：

```bash
install -d -m 700 ~/.config/dds-monitor
printf '%s' '<LINE channel token>' > ~/.config/dds-monitor/line_token
printf '%s' '<LINE user id>' > ~/.config/dds-monitor/line_user_id
chmod 600 ~/.config/dds-monitor/line_token
```

PCAP 離線分析不需要封包擷取提權：

```bash
cd ~/ros2_ws/網路記錄
zeek -r capture.pcap ../Zeek監控/dds_monitor.zeek
```

Live 監控（管理者先完成受限 capture 權限）：

```bash
cd ~/ros2_ws/網路記錄
zeek -i eth0 ../Zeek監控/dds_monitor.zeek
```

若為了相容舊展示把 `DOS_BLOCK_ENABLED` 設為 `T`，也只會輸出被抑制的
response request，不會修改防火牆：

```bash
zeek -i eth0 ../Zeek監控/dds_monitor.zeek DOS_BLOCK_ENABLED=T
```

成功啟動、離線規則測試或 dry-run 都不等於長時間 live 場景已驗證；正式
報告要保存 Zeek log、受害端 log、授權結果、處置到期與復原證據。
