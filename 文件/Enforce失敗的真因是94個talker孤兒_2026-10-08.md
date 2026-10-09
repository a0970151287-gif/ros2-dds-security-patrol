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
- ~~94 個 talker 是誰留下的沒有確定到那一次操作~~ **已於同日確定，見第七節。
  而我當時那句「與跨主機鏈的工作吻合」是錯的——是 campaign 自己產生的。**
- 第五節 ① 的 2.172 GB 是**單場峰值**，用 `ru_maxrss` 量；
  features.py 在單場內確實持有那個 list，但我沒有量它在 2,682 場上的實際曲線。
- **出貨設定一個位元未改**：`executable_classes` 仍為空、
  `LIVE_NFT_ACTIVATION_ALLOWED` 仍為 False。
- 進度百分比不動。

---

## 七、⚠️ 來源確定了，而我前面兩個推測都錯

第六節原本寫「與跨主機鏈的工作吻合」。**那是推測，而且錯了。**
campaign 重啟後 3.5 小時，同樣的孤兒**又出現 32 個**，活了 205–215 分鐘
⇒ 它們是 **campaign 自己產生的**。

決定性證據（在清掉它們之前抓的）：

```
ppid  32 個全部 = 635                                  ← 同一個父行程
pgid  五組: 10490(7) 11352(6) 12445(8) 18308(7) 21870(4)
      ⇒ 五個 session，正好對上「重啟後 5 場 unauthorized_participant」
environ SROS2_ATTACK_DEADLINE_MONOTONIC=1290.282790619793
      ⇒ 那是 C2C-074 加的 `ATTACK_DEADLINE_ENV`，只有 orchestrator 會傳
        另有 FIREWALL_LIVE_RUNTIME 與 ROS_DOMAIN_ID=30
```

⇒ `unauthorized_participant` 的 runner 是 `ros2 run demo_nodes_cpp talker`
（`runners.py:247`），而自適應攻擊者每 7–11 秒起一個 ⇒ **每場留下 4–8 個**。

### 為什麼它們逃掉：這是 C2C-082 自己預先寫下的風險

fork 收尾讓父行程印完軌跡就 `os._exit(0)`，而
**`ManagedProcess.stop()` 送 SIGTERM 給行程群組時，父行程已經走了**。
C2C-082 當時寫下的是：

> ⚠️ 在有 DDS 執行緒的行程裡 fork 本身不安全……那時它什麼都收不掉，
> **退化成「沒有收」——與今天 45% 的場次相同，不會更糟**。

**量到它更糟。** 「沒有收」不是靜態的代價，它會累積：

| | campaign 啟動後 | 3.5 小時後 |
|---|---:|---:|
| 場次內部中位 | **126s** | **337s（2.7 倍）** |
| 速率 | 28.5 場／小時 | **23.2 場／小時** |
| 殘留 SHM（每輪清掉） | 6 | **323** |
| 結果 | — | **步調熔斷器連續 3／3 自停** |

⇒ 這同時回答了 C2C-105 擱著的那個問題。它寫「『負載』是一個描述不是機制，
**具體是什麼在累積仍然未知**」——**是 talker 孤兒**。

### 修正：兜底清除原本沒有涵蓋任何攻擊端

`run_mega_campaign.sh` 的 `STACK_PATTERNS` 原本 16 項**全是防守端**
（`gz sim`／`monitor_node`／`velocity_guard`／`dumpcap`…），
所以 `count_stack_processes` 數不到 talker ⇒ **監督器每輪都回報「殘留 0」。**

已加 `demo_nodes_cpp/talker`（第 17 項，用完整路徑——腳本自己的註解寫著
「只列夠特定的名字……寧可漏殺也不要誤殺」，而裸 `talker` 會配到使用者
任何含那個字的指令）。

三個測試，而真正防止再犯的是第一個：

| 測試 | 它守什麼 |
|---|---|
| `..._covers_every_external_process_the_attack_runners_spawn` | **從 `runners.py` 推導**而不是寫死清單 ⇒ 新增會起外部行程的 runner 而忘記更新清單就會被咬 |
| `..._2026_10_09_orphan_leak_stays_fixed` | 字面值記錄這次缺陷 |
| `..._sweep_patterns_stay_specific` | 不可以退化成裸 `talker` |

變異檢定：移除 pattern ⇒ **3 failed**；改成裸 `talker` ⇒ **2 failed**
（coverage 那條通過是對的，`talker in talker` 為真）；還原 ⇒ 16 passed。

⚠️ **而第一版的字面值測試不會咬。** 它讀整個 `source`，而這個修正自己的註解裡
就寫著 `demo_nodes_cpp/talker` ⇒ 移掉 pattern 之後它照樣通過。
是變異檢定抓到的（只咬 2 個而該咬 3 個），已改成讀**解析後的清單**。
那與 C2C-095 §六記的是同一形態的反向版本：**註解讓檢查失效。**

### 仍然不可宣稱

- **修正沒有 live 證據。** 判準：下一輪的監督器日誌應該出現
  `⚠️ live_stack 收不乾淨（剩 N 個）` 並把 talker 清掉，而場次內部中位
  不該從 126s 爬到 337s。
- **fork 收尾本身沒有改。** 修的是監督器的兜底清除，不是 N37 的收尾
  ——那會動到 C2C-082／083 量到 100% rc=0 的那個機制。
- 「每場 4–8 個」是 **n=5 場**。
- 32 個 vs 先前的 94 個：**94 那一批的來源仍然是推論**（它們在同一天早上，
  而我沒有在清掉之前抓 `environ`）。本節的證據只涵蓋這 32 個。
