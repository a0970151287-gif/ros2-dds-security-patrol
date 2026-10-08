# Enforce readiness 失敗的真因：94 個 talker 孤兒（2026-10-08）

`文件/Enforce的readiness_是participant規模不是Gazebo_2026-10-09.md` 把這件事
收斂成「participant 規模依賴」並列出七個被排除的候選，**其中有一個排錯了**。

真因是 **94 個 `talker` 孤兒行程，全部在 `ROS_DOMAIN_ID=30`**——正是 campaign
用的 domain——從 `Oct 8 00:27` 起每 10 秒一個，`ROS_SECURITY_ENABLE` 未設。

---

## 一、事前預測與判定

預測寫在清掉它們**之前**：

> 若 94 個 talker 是成因，重啟後 enforce readiness 應該通過
> （當天量到的是必敗 3／3，耗時 236–247 秒）。

`wsl --shutdown` 清掉它們之後，同一個 `live_stack.sh start enforce`：

```
✅ enforce READY，耗時 87 秒
   停完殘留節點 0            （先前是 3）
```

⇒ **預測成立。**

---

## 二、機制，以及它為什麼完美符合那個被歸因錯的對照

| | 結果 | 為什麼 |
|---|---|---|
| **permissive** 整組 | ✅ 108 秒 ready | **不做安全握手** ⇒ 94 個無憑證 participant 對它無所謂 |
| **enforce** 整組 | ⛔ 必敗 3／3 | 每個 secure participant 都要對那 94 個逐一嘗試認證**並失敗** |

那個對照我當天就量到了，而我把它歸因成「規模 × SROS2 的交互作用」——
**方向對，數字錯**：我以為額外的 participant 是 8 個防守節點，
實際上背景有 **94 個**，而防守節點只是把它推過門檻的最後一根稻草。

時間線也吻合：10-07 13:33Z 重啟後 enforce 的 `attack_process` 失敗率還是
**4／80 = 5.0%**（C2C-096），而 **Oct 8 00:27 之後**才變成 readiness 必敗。

---

## 三、⚠️ 我的孤兒檢查為什麼回報乾淨

當天的檢查逐項列出要數的行程名：

```
dds_security_monitor / velocity_guard / sensor_hub / intelligent_defense
mission_manager / patrol_node / readiness_probe / parameter_bridge
robot_state_pub / gz sim
```

**`talker` 不在清單裡**，所以它回報 0 個孤兒，而我據此寫下「不是孤兒」。

> **一個只涵蓋預期清單的檢查，對清單外的東西永遠回報乾淨。**

這與 C2C-090 §④（我的 console_script 探針把 10 支全部標錯）、
C2C-098（`manifest["adaptive"]` 查一個不存在的鍵而回傳令人安心的答案）
是同一形態，而這是第 25 次。

正確的做法是**列出所有長命行程再看哪些不該在**，而不是去數想得到的那些。
那一次我是在 `wsl --shutdown` 前的例行檢查裡，用
`ps -eo pid,etimes,rss,comm | awk '$3 > 20000'`（按 RSS 排，不按名字）
才看到它們的。

---

## 四、那七個被排除的候選，六個仍然成立

| 候選 | 狀態 |
|---|---|
| Gazebo 不模擬 | ✅ 仍排除（gz 端 4／4 從 t=48s 到 t=425s） |
| 權限／domain 不符 | ✅ 仍排除（`access rule`／`denied`／`handshake` 全部 0 次） |
| 時間邊際 | ✅ 仍排除（給 7 分鐘仍 0／5） |
| 啟動順序（晚加入的發布者） | ✅ 仍排除（probe 早 8 秒起照樣通過） |
| CPU 飢餓 | ✅ 仍排除（24 核只用 4.4–8.1 核） |
| 一次性 discovery | ✅ 仍排除（第二次 probe 也失敗） |
| **殘留孤兒** | ❌ **排錯了**——見第三節 |

記憶體那一項當時是對的（`/dev/shm` 乾淨、WSL 內 available 6.4 GB），
但它與另一個問題糾纏在一起，見下一節。

---

## 五、同一輪的第二件事：features.py 的記憶體與主機的 15.7 GB

重訓的階段 0（特徵抽取，2,682 場）**跑了 71 分鐘後把整台機器卡住**：
WSL 完全無回應（`Wsl/Service/0x8007274c`），主機 15.7 GB 只剩 **0.4 GB**。
我殺掉它才恢復，而 features.py 是全有或全無 ⇒ **零產出**。

兩個因素疊加，各自都量到了：

**① `features.py:511` 每個封包一個 dict。** 最大的逐封包紀錄只有
**31.4 MB**（壓縮後），卻有 **3,737,684 個封包**；用它的做法讀進來
峰值 RSS **2.172 GB**（約 620 bytes／封包，**69 倍膨脹**）。
逐封包紀錄全資料集合計 **10.94 GB**。

⚠️ 累積**不是**成因：`observation_rows` 只在 `--include-nontrainable` 下才填
（我沒帶），其餘三個是逐視窗（2,682 場 × 約 11 列 ≈ 30,000 列）。

**② 沒有 `memory=` 上限時 WSL 拿主機 50% 並且不還。** 殺掉 features 之後
`vmmemWSL` 仍佔 **5.8 GB**（WSL 內 buff/cache 5.2 GB），而主機上還有
claude ×3 ≈ 1.1 GB、ChatGPT ×3 ≈ 0.8 GB。

⚠️ **我沒有分辨**那 6.8 GB 是 features 的 heap 還是 Linux 的 page cache。
兩者對 Windows 看起來一樣，而採用的修法同時蓋住兩種可能——但那不等於知道。

### 處置（經 Jesse 選定）：改 `.wslconfig`，不碰程式

| | 之前 | 現在 |
|---|---:|---:|
| WSL Mem total | 7,792 MB（無上限） | **8,934 MB**（硬上限 9 GB） |
| Swap | 2,048 MB | **16,384 MB** |
| `autoMemoryReclaim` | 無 | **`gradual`** |
| 主機可用（shutdown 後） | 0.4 → 1.8 GB | **7.5 GB** |

備份 `.wslconfig.bak-20261008`，檔案裡記了量到的根因與還原方式。
`memory=` 上限本身就處理 ②：它讓 WSL 不可能超過那個數，所以 Windows 永遠有剩。

⚠️ **features.py 一個位元未改。** 串流化是根本解（2.16 GB → 數十 MB），
但它是出貨核心檔案，整個資料集的特徵都來自它；要改應該配一個逐位等價檢查，
而那是獨立的一輪工作。

---

## 六、不可宣稱

- **87 秒那一次是 n=1。** 它決定性地否證了「必敗」，但不是「穩定」的證據
  ——C2C-105 記過我自己在這種推論上錯過一次（`0／154` 的上界被 7.2% 推翻）。
- **94 個 talker 是誰留下的沒有確定到那一次操作。** `Oct 8 00:27`、
  `demo_nodes_cpp/talker`、domain 30、每 10 秒一個，與跨主機鏈的工作吻合，
  但我沒有找到產生它們的那一行程式。
- 第五節 ① 的 2.172 GB 是**單場峰值**，用 `ru_maxrss` 量；
  features.py 在單場內確實持有那個 list，但我沒有量它在 2,682 場上的實際曲線。
- **出貨設定一個位元未改**：`executable_classes` 仍為空、
  `LIVE_NFT_ACTIVATION_ALLOWED` 仍為 False。
- 進度百分比不動。
