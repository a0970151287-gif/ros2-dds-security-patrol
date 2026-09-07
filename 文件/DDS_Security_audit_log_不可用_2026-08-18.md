# DDS Security audit log 在 ROS 2 + rmw_fastrtps 下無法啟用

日期：2026-08-18
結論：**這不是設定錯誤，是整合層的架構限制。**
`sros_auth_fail_rate` 與 `sros_permission_deny_rate` 在本技術棧下**沒有可用來源**。

---

## 一、為什麼要查這個

1,100 場正式資料中，這兩個特徵恆為零。deny adapter 讀了 **249,670 行**
（Enforce 123,787／Permissive 125,883）卻一行都分類不出來。
先前的判斷是「沒有配置獨立的 security audit sink」，聽起來是個設定問題。

`identity_abuse` 因此沒有專屬證據，test recall 只有 **0.2333**。
若能補上這個來源，那一類的識別率應該會改善——所以值得查。

---

## 二、屬性名稱：從安裝版抽出，不靠文件

```
LogOptions.h 宣告的欄位   : distribute / log_level / log_file
libfastrtps.so 實際的字面值: logging_level / log_file / distribute
```

**`log_level` 與 `logging_file` 在二進位裡不存在。** 寫錯的話 XML 解析器會照收，
然後靜默忽略——與本專案先前「註解裡一個 `--` 讓整份 profile 失效」是同一類陷阱。

正確的屬性組：

| 屬性 | 值 |
|---|---|
| `dds.sec.log.plugin` | `builtin.DDS_LogTopic` |
| `dds.sec.log.builtin.DDS_LogTopic.logging_level` | `WARNING_LEVEL` |
| `dds.sec.log.builtin.DDS_LogTopic.log_file` | 絕對路徑 |
| `dds.sec.log.builtin.DDS_LogTopic.distribute` | `false` |

記錄型別 `BuiltinLoggingType` 帶 `facility=0x0A`（標示 sec/auth）、severity、
timestamp、hostname、hostip、appname、procid、msgid、message。
這正是「固定 header 與來源身分」，任意應用日誌給不出來。

---

## 三、實測：三組對照

在同一台機器、同一個 profile 檔，只改環境：

| # | 條件 | audit 檔是否建立 |
|---|---|---|
| A | 無 profile（對照組） | ❌ 無（符合預期） |
| B | 有 profile，**未啟用 SROS2** | ✅ **有**（0 bytes，plugin 已初始化） |
| C | 有 profile ＋ **SROS2 Enforce** | ❌ **無** |
| D | 同 C，加 `RMW_FASTRTPS_USE_QOS_FROM_XML=1` | ❌ **無** |

**B 證明 profile 本身正確**——property 名稱對、XML 可解析、plugin 會初始化。
**C 證明 SROS2 一啟用就失效。**

---

## 四、根因

`librmw_fastrtps_shared_cpp.so` 中出現的 security property 字面值：

```
dds.sec.auth.plugin
dds.sec.auth.builtin.PKI-DH.identity_ca
dds.sec.auth.builtin.PKI-DH.identity_certificate
dds.sec.auth.builtin.PKI-DH.identity_crl
dds.sec.auth.builtin.PKI-DH.private_key
dds.sec.access.plugin
dds.sec.access.builtin.Access-Permissions.governance
dds.sec.access.builtin.Access-Permissions.permissions
dds.sec.access.builtin.Access-Permissions.permissions_ca
dds.sec.crypto.plugin
```

**`dds.sec.log.plugin` 不在其中。**

RMW 層在啟用安全時會自行從 keystore 組出 participant 的 property 清單，
XML profile 的 `propertiesPolicy` 不會被保留。它既不支援 logging plugin，
也不提供讓使用者附加額外 property 的途徑。

---

## 五、後果與處置

### 對特徵契約

`sros_auth_fail_rate`、`sros_permission_deny_rate` 應標為
**`source_unavailable`，且原因是「本技術棧不可能提供」**，不是「尚未配置」。
建議從 V1 特徵契約移除，而不是留著兩個永遠為零的欄位。

**不可以把既有的 0 回填成 true negative**——那會宣稱「量測到沒有拒絕」，
但實際上是「沒有量測」。

### 對 `identity_abuse`

它不會透過這條路取得專屬證據。剩下的可能途徑：

| 途徑 | 可行性 |
|---|---|
| 節點圖層（`participant_change` / `unknown_node`） | **已在用**，但與其他六類共用，不具排他性 |
| 網路封包層（RTPS 分析） | 文獻 P3（HCRL 2023）的做法；本專題**未實作**，是明確的深化方向 |
| 修改 rmw_fastrtps 讓它傳遞額外 property | 超出大學專題範圍 |
| 不經 ROS，直接用 Fast DDS API 建 participant | 會失去整個 ROS 生態，不合理 |

### 對程式碼

`fastdds_security_log.xml` 與其測試**保留**，作為此次調查的可重現證據，
但**不再接進任何啟動腳本**——掛一個實測無效的 profile 只會增加
「靜默退回預設」的風險，且會誤導後人以為 sink 是啟用的。

兩個啟動腳本改回 `unset FASTRTPS_DEFAULT_PROFILES_FILE` 並註明原因。
`orchestrator` 對 audit log 的偏好也已撤回。

---

## 六、這是個可以寫進報告的結果

負面結果，但可驗證、可重現，而且解釋了一個長期存在的資料缺口：

> 本研究嘗試啟用 Fast DDS 內建的 DDS Security audit log，以取得
> authentication／permission 拒絕的直接證據。屬性設定經二進位驗證正確，
> 且在未啟用 SROS2 時可成功初始化；但一旦啟用 SROS2，
> `rmw_fastrtps_shared_cpp` 會自行組出 participant 的安全屬性清單，
> 其中不含 logging plugin，XML profile 的設定不被保留。
> 因此在 ROS 2 Jazzy ＋ rmw_fastrtps_cpp 的組合下，
> **DDS Security 稽核日誌無法透過受支援的設定方式啟用**，
> 相關兩個特徵在本研究中標記為來源不可得。

這同時說明了為何 `identity_abuse` 的識別率無法靠「補設定」改善——
需要的是換一個觀測層（封包層），那是後續工作。
