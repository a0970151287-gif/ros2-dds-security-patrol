# Enforce 資料缺口的真因：readiness 的三層等待窗反轉了

- 日期：2026-10-02（稽核 2026-09-26 → 09-28 那一輪 campaign 的失敗批次）
- 全程離線唯讀分析 ＋ 離線修正。未啟動 ROS、未產生攻擊流量、未使用 `sudo`。
- 出貨設定一個位元未改。

---

## 〇、摘要

Enforce 的合格場次每類只有 **5 場**（Permissive 最少 36 場），而那不是
「Enforce 比較難跑」——是 readiness 的三層等待窗**內層先到期**，
所以外層那 200 秒永遠用不到。

| 層 | 原值 | 新值 |
|---|---:|---:|
| readiness probe 自己的上限 `timeout_sec` | 120s | **240s** |
| 外層 `timeout --signal=TERM` | 130s | **250s** |
| 監督器輪詢 `seq 1 N × sleep 5` | 200s | **300s** |

---

## 一、不是 Enforce 專屬，是逐輪惡化

| round | permissive | enforce |
|---:|---|---|
| 1–3 | rc=0 | rc=1（有跑） |
| 4 | rc=1 | **⛔ 起不來** |
| 5–6 | rc=0 | **⛔ 起不來** |
| **7** | **⛔ 起不來** | **⛔ 起不來** |
| 8 | rc=0 | ⛔ 起不來 |
| **9** | **⛔ 起不來** | **⛔ 起不來** |

**Permissive 到第 7 輪也開始失敗。** Enforce 排在 Permissive 之後，
所以先被吃到——這就是 Permissive 588／Enforce 98 的來源。

---

## 二、⚠️ `⛔ enforce stack 起不來` 這句話錯了兩次

從失敗那次的 stack 日誌（692 行，**讀開頭不是讀尾端**）：

```
行   1: → 等待 Gazebo/bridge/RSP 五條必要資料流...
行   2: [INFO] [launch]: All log files can be found below …
行 5-12: Found security directory × 8          ← 八個 enclave 全部找到
行 14-30: 七個節點全部回報啟動
          HMAC 指紋全部 7b0b2834216e9d78      ← 簽章通道是通的
行  32: sensor_hub_node: ⚠️ 危險：LiDAR 尚未收到有效資料；IMU 尚未收到有效資料
        （這一類重複 104 次，跨約 105 秒）
行 468: ⛔ Enforce readiness 失敗；不宣告系統可用，正在停止整組
行 469: security_readiness_probe: readiness probe failed closed
行 577+: rcl_shutdown already called（6 次）
```

**`readiness 通過` 在整份日誌裡出現 0 次。**

> stack **起得來**，而且它是**被刻意停掉的**——fail-closed 正確運作。
> 真正缺的是 Gazebo 的五條資料流。

---

## 三、Gazebo 在 118 秒內一個行程都沒啟動

共用日誌第 2 行指名了 launch 系統的日誌目錄。去讀它：

```
launch.log  = 207 bytes，兩行
  [INFO] [launch]: All log files can be found below …
  [INFO] [launch]: Default logging verbosity is set to INFO
```

**沒有任何 `process started`，也沒有任何子行程的輸出檔。**

時間軸：

| 時刻 | 事件 |
|---|---|
| 08:41:23 | `gazebo.launch.py` 起來，印橫幅與 `urdf_file_name : turtlebot3_burger.urdf` |
| 08:41:27–40 | 七個 stack 節點全部正常啟動 |
| …118 秒… | **Gazebo 一個 `process started` 都沒有** |
| 08:43:21 | probe 在 **120 秒**上限放棄 → stack fail-closed |
| （永遠不到） | 監督器的 200 秒輪詢窗還有 **80 秒**沒用到 |

`gazebo.launch.py` 的 docstring **自己寫了為什麼慢**：

> Each inclusion scans every installed ROS package to build Gazebo paths,
> **which is especially slow on a WSL-mounted workspace.**

C2C-062 量過它要 **39 秒**，而那是機器輕鬆的時候。

---

## 四、⚠️ 四層診斷介面依序誤導，第四層是我自己造的

| 看到的 | 實際 |
|---|---|
| `⛔ enforce stack 起不來` | stack 正常，是被刻意停掉的 |
| `tail -4` 的 `rcl_shutdown already called` | fail-closed **收尾的連鎖**（6 次＝六個行程），不是成因 |
| traceback 像 `sensor_hub` 在跑 `velocity_guard` 的 main | 八個節點**寫同一份共用日誌**，traceback 逐行交錯；而 `sensor_hub_node.py:359` **本來就是** `rclpy.shutdown()` |
| **我的探針說 10 支 console_script 接錯線** | **探針壞了**——`load_entry_point(spec, group, name)` 是 colcon 的通用包裝，那三個是變數名不是目標。`setup.py` 其實是對的 |

**第四個最值得記：「10 支全部中」就是探針壞了的徵兆**，而我差一步就把
「console_scripts 接錯線」寫成結論。

而共用日誌那一條是結構性的：`live_stack.sh:69,71` 是
`: > "$LOG_FILE"` 加 `>"$LOG_FILE"`，**八個節點的 stdout／stderr 全導進同一份檔案**。

> **那份日誌的 traceback 在結構上就不可信。** 要看個別行程得去 `~/.ros/log/<stamp>/`。

---

## 五、修法：釘住順序，不是釘住秒數

三層改成 **240／250／300**，並用 9 個測試釘住**層與層的關係**：

| 測試守的性質 | 為什麼 |
|---|---|
| probe 上限 < 外層 wrapper | wrapper 先殺的話，probe 來不及說出缺哪一條流 |
| wrapper < 監督器輪詢窗 | **這就是反轉**：130 對 200 讓外層永遠用不到 |
| probe 上限 > 118 × 1.5 | 118 秒是**沉默的下界**不是逾時，邊際不能貼著它 |
| 兩個模式用同一組數字 | 否則一個計時問題會被誤讀成 SROS2 的性質 |
| 監督器的輪詢**仍然有界**（≤ 600s） | C2C-049：無人值守的批次必須大聲失敗。放大窗不可以變成拿掉窗 |

另有一個變異測試餵回修正前的 `130 / 200 / 120`，確認**邊際檢查會拒絕它**
——那組數字的順序其實是對的，所以 bug 很隱微：**順序成立而邊際不足**。

⚠️ 施工時 CRLF 一度把 enforce 腳本弄壞：Windows Python 的 `write_text` 把 `\n`
翻成 `\r\n`，`bash -n` 報 `syntax error near unexpected token $'{\r'`。已清回 LF
（從 git 確認原版是 LF）。

---

## 六、不可宣稱

- **沒有 live 證據。** 判準已寫下：readiness 不該再在 120 秒被砍；
  若新一輪在 **240 秒**也失敗，那就不是「慢」而是真的起不來。
- **「為什麼逐輪變慢」仍然未解。** drvfs 快取被 1,522 場的 pcap 擠掉、
  **357 個 `~/.ros/log` 目錄**、SHM 洩漏（每輪清掉 214–984 段）都是候選。
  窗放大是讓它**不致命**，不是修好它。
- **240／250／300 不是量到 Gazebo 需要多久**——我們從來沒看到它成功的那一刻，
  這組數字是從「118 秒的沉默」加安全邊際推出來的。
- **百分比不動。** 這是資料產出端的工具問題，不是模型能力。
