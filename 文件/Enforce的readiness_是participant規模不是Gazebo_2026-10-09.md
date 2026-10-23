# Enforce 的 readiness 失敗：是 participant 規模，不是 Gazebo（2026-10-09）

campaign 連續三次自停，失敗訊息是
`enforce readiness 逾時（300s）` ＋ `missing streams: /clock, /imu, /odom, /scan, /tf`。
C2C-090 查過一次同名的失敗，當時的成因是 Gazebo 的 launch 在 118 秒內一個
`process started` 都沒有。**這一次不是那個。**

---

## 一、最後的刻畫（每一列都重現過）

| 設定 | probe | n |
|---|---|---:|
| **permissive 整組** | **✅ ready 108 秒** | 1 |
| **enforce 整組** | **⛔ 失敗 236–247 秒** | **3** |
| enforce，只有 Gazebo ＋ probe | **✅ 過 13 秒** | 3 |
| enforce，probe 比 Gazebo **早** 8 秒起 | **✅ 過（Gazebo 一出資料就過）** | 1 |
| enforce，Gazebo ＋ **1** 個防守節點 | 過 1 次、失敗 1 次 | 2 |
| **enforce，Gazebo ＋ 7–8 個防守節點** | **⛔ 失敗** | **2** |

⇒ **規模依賴**：多了那 7–8 個安全 participant 之後，**沒有任何訂閱者**收得到
bridge，而 bridge、Gazebo、權限、網路全部正常。

最後一列是在 stack **外面**用同一組 enclave、同一個 launch、同一組 probe 參數
複製出來的，所以不是腳本的問題。

---

## 二、被量測排除的候選（七個）

| 候選 | 否證它的量測 |
|---|---|
| **Gazebo 不模擬** | gz 端 `/clock /scan /odom /imu` **4/4**，從 t=48–65s 一路到 **t=425s**；`/clock` 18 筆在跳 |
| **權限／domain** | `gazebo`／`sensor_hub_node`／`security_readiness_probe` 的 permissions 都是 domain 30 且含那五條；`access rule`／`Not found`／`denied`／`handshake` 的出現次數**全部是 0** |
| **時間邊際** | 給它 **7 分鐘**（425 秒）仍然 0/5 |
| **啟動順序（晚加入的發布者）** | probe 比 Gazebo 早 8 秒起，照樣在 Gazebo 一出資料的那一刻通過 |
| **CPU 飢餓** | **24 核**，總 CPU 只用 442–813%（4.4–8.1 核），`gz sim` 自己拿到 61–169% |
| **記憶體／`/dev/shm`** | `mem_available 6.44 GB`；`/dev/shm` 上限 3.9G、**只用 66M** |
| **一次性 discovery（重試就好）** | 同一個 Gazebo、同一批節點、什麼都沒改，**第二次 probe 也失敗**（72 秒） |

另外兩個也不成立：**殘留孤兒**（campaign 時代的殘留是 0，所有觀察到的孤兒都
只活了 292–356 秒，是我自己那一輪造成的）與**殘留 SHM**（每一輪隔離測試都先
清掉 `fastrtps_*` 與 `sem.fastrtps_*`，0 個節點時照樣會過）。

---

## 三、剩下的線索，與為什麼不能自己動手

**同機的 DDS 跑在共享記憶體上**，而 `01_啟動系統.sh:25-29` 的註解記著一個量過的結果：

> A UDPv4 profile with an interfaceWhiteList of 127.0.0.1 was tried here and
> reverted: it did keep DDS off the shared segment, but only because it **broke
> discovery outright** (talker->listener delivered 0 messages vs 23 without it).
> **Do not reintroduce a transport profile without checking messages actually flow.**

而機器上有三個會被宣告的位址：`lo` 的 `10.255.255.254/32 **scope global**`
（C2C-043 量過它會讓 Fast DDS 同機 discovery 靜默失效）、`docker0 172.17.0.1/16`、
`eth0 172.30.123.103/20`。

⚠️ **每一條可能的修法都越界**：

- **換傳輸（關 SHM 或加 whitelist）** ⇒ 流量形狀改變 ⇒ **2,000+ 場既有資料的
  網路特徵不再可比**，而且 `dumpcap -i lo` 的擷取範圍會跟著變（C2C-061 確立
  所有正式資料集都是 `-i lo`、80–98% 單播）。
- **放寬 readiness 判準** ⇒ 那是通過標準。

⇒ **兩個都要 Jesse 決定。**

另一個未解釋的觀測：**`loadavg` 17.6–26.8 而 CPU 只用三成** ⇒ 行程卡在 I/O。
`/proc/pressure/io` 在機器空著時是 0.00，載著 stack 時沒有量過。

---

## 四、⚠️ 我在這一輪錯了四次

| # | 錯 | 怎麼發現的 |
|---|---|---|
| 1 | 用 `ros2 topic list` 當 Enforce 端的探針，量了好幾輪的 `ROS端=0/5` | **CLAUDE.md 自己記著 C2C-075**：Enforce 下 CLI 的臨時節點名不在 enclave 裡，**本來就看不到任何東西**。那個探針**不可能**回報非零 |
| 2 | 把「9 個孤兒 ＋ 空的 pid 檔」當成 `live_stack.sh` 的缺陷 | 讀 cleanup 的程式碼：`if [[ "$pgid" == "$$" ]]` 只在腳本自己是群組首領時才殺整組，而我**直接跑腳本繞過了 `setsid`**。是我造成的 |
| 3 | **把 `sensor_hub_node` 定為單一兇手** | 重測時它**過了**。那一輪 B/C/D/E 全失敗而節點數只有 1/1/2/3（好幾個沒起來）⇒ 整輪是退化狀態，**我把一個間歇性的失敗當成決定性的去二分** |
| 4 | 第一個 Gazebo 基準測試餵了 `model-1_4.sdf`（模型檔）當 world，得到 `Error Code 14` | 讀 launch 檔才知道真正的 world 是 `turtlebot3_world.world` |

第 1 與第 3 是同一個形態的兩種版本，而這個專案記過 22 次：
**壞掉的量測工具會偽裝成被量對象的性質**。第 3 個更值得記下來——
**間歇性的現象不能用二分法定位**，因為每一步的「失敗」都可能是雜訊。

---

## 五、不可宣稱

- **根因未定。** 本文確立的是「規模依賴」與七個被排除的候選，不是機制。
- 「7–8 個節點必然失敗」是 **n=2**（整組 stack 另有 n=3）；「1 個節點」是 1 過 1 敗，
  **那個邊界在哪裡沒有量**。
- **Enforce 曾經可用**（`dataset_mega` 有 369 場合格 enforce），所以這是回歸；
  但 `sensor_hub_node.py` 自 `8952f09` 起一行未改，**是什麼回歸的仍然未知**。
- 本輪**沒有改任何出貨程式**；`executable_classes` 仍為空、
  `LIVE_NFT_ACTIVATION_ALLOWED` 仍為 False。
- 進度百分比不動。
