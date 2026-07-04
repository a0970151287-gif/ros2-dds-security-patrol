# N24b — 變長度 scan 崩潰 IDS（N24 補丁不完整的回歸發現）

> 隔離環境：`ROS_DOMAIN_ID=99`｜攻擊者能力 L1（同 LAN 任意 ROS2 node，**無密鑰**）
> 實測日期：2026-06-13｜對象：現行 `intelligent_defense_node.py`（藍方已上 N24 補丁的版本）
> 結論：**藍方的 N24 補丁不完整，IDS 仍被一個變長度 /scan 串流整個打死。**

---

## 一、白話一句話

> 「保全系統（IDS）算雷達畫面差異時，假設**每一幀的點數都一樣多**。
> 我（攻擊者）交替送 60 點和 90 點的假雷達 →
> 它把『60 點的這幀』跟『90 點的上一幀』硬湊在一起算 → 程式當場崩潰、整個保全下線。
> 我連密鑰都不用，只送了幾個合法格式但長度不同的雷達訊息。」

---

## 二、藍方補丁為什麼沒擋住

N24 原始發現：D3/D6 對 scan 歷史做
```python
mask = np.isfinite(a) & np.isfinite(b)   # a,b 長度不同 → broadcast ValueError
```

藍方補丁（現行 code，`_detect_d3_scan_repeat` 第 203-206 行）：
```python
a = np.asarray(hist[i],   dtype=np.float32)   # ← 新增 dtype
b = np.asarray(hist[i-1], dtype=np.float32)   # ← 新增 dtype
mask = np.isfinite(a) & np.isfinite(b)        # ← 一模一樣，還是會崩
```

**補丁只加了 `dtype=np.float32` 跟 inf/nan 過濾，根本沒碰「長度不一致」這個真正的崩潰點。**
`np.isfinite(60點) & np.isfinite(90點)` 兩個不同 shape 的布林陣列做 `&` → 一定 broadcast ValueError。
而 `_evaluate()` 第 347 行 `triggered, info = fn()` **仍然沒有 try/except** → detector 一丟例外，整個 IDS timer callback 連同 executor 一起死。

離線驗證（numpy 2.4.4）：
```
np.isfinite([1.0]*90) & np.isfinite([1.0]*60)
→ ValueError: operands could not be broadcast together with shapes (90,) (60,)
```

---

## 三、攻擊手法

PoC：`紅隊測試/PoC腳本/N24b_varlen_scan_regression.py`

- 5Hz 對 `/scan` 發布，**交替長度**：偶數幀 60 點、奇數幀 90 點（兩者都 >50，所以兩種都會被 IDS 的 `_scan_cb` 存進歷史）。
- advancing stamp + 每幀微抖動（避免被別的偵測當「靜止」先擋掉）。
- 等 `scan_history` 累積到 5 幀，D3 的 last-5 視窗裡相鄰幀長度不同 → 崩。

```bash
ROS_DOMAIN_ID=99 ros2 run dds_security_monitor intelligent_defense_node   # 被攻擊端
ROS_DOMAIN_ID=99 python3 紅隊測試/PoC腳本/N24b_varlen_scan_regression.py 15  # 攻擊端
```

---

## 四、實測證據（live kill）

IDS 完整 log（已驗證，非預測）：
```
[INFO]  🛡️ 智能防禦啟動 — voting threshold=2/4, cooldown=10s ...
[INFO]  📊 status: ... scan_hist=0 ...            ← 攻擊前健康
...
[ERROR] 🛡️ [智能防禦警報] 行為層異常偵測 (strong signal):
          • D4[scan unauthorized pub: ['attacker_varlen_scan']]   ← D4 有抓到流氓 publisher
[WARN]  ⏳ 異常持續 (D4)，cooldown 中（剩 9.5s）
Traceback (most recent call last):
  ...
  File ".../intelligent_defense_node.py", line 347, in _evaluate
    triggered, info = fn()
  File ".../intelligent_defense_node.py", line 206, in _detect_d3_scan_repeat
    mask = np.isfinite(a) & np.isfinite(b)
ValueError: operands could not be broadcast together with shapes (60,) (90,)
[ros2run]: Process exited with failure 1            ← IDS 整個進程死亡
```

攻擊後 `ros2 node list` → 空；IDS 進程不存在。**整套行為層偵測下線。**

---

## 五、最諷刺的一點（報告金句）

> **D4 偵測器「成功抓到」攻擊者的流氓 scan publisher、還發了警報 —— 然後下一個 0.5s 評估週期，
> 同一串輸入就用 D3 把整個 IDS 殺掉了。**
>
> 「偵測到入侵」≠「活得下來」。IDS 自己在做數值運算時沒有輸入驗證，
> 於是它**一邊舉手喊『有壞人！』、一邊被那個壞人的同一筆輸入打死**。
> 偵測器本身就是攻擊面（呼應 N13、N24 的教訓：detector as attack surface）。

---

## 六、完整修補建議（藍方）

這次補丁失敗的根因是「只擋了表面（inf/nan），沒擋結構（長度/例外）」。三層都要補：

1. **入口正規化（最根本）**：`_scan_cb` 收 scan 時就把長度正規化成固定點數
   （像 patrol `_cb_scan` 那樣 downsample/pad 到 `SCAN_N`），讓 `scan_history` 永遠等長。
   → 從源頭消滅長度不一致，D3/D6 之後都安全。
2. **比較前對齊**：D3/D6 比較相鄰幀前，`m = min(len(a), len(b)); a=a[:m]; b=b[:m]`
   （或長度不同就 skip 該對）。防禦縱深。
3. **per-detector try/except（必補）**：`_evaluate` 對每個 `fn()` 包 try/except，
   任何 detector 丟例外只記 log + 該票作廢，**絕不能讓單一 detector 的例外殺死整個 IDS**。
   這是最便宜、最該先上的一層 —— 沒有它，未來任何 detector 的任何 bug 都是一鍵 DoS。

> 註：這是應用層 bug，**不需要 SROS2** 就能修（跟 N24 同類）。但 raw `/scan` 本身可被任意
> 偽造這件事，仍要靠 SROS2 Enforce 才能根治來源問題。
