#!/usr/bin/env python3
"""N37 — 自適應攻擊者：會看防禦反應並改變行為的驅動器。

## 為什麼需要它

2026-09-20 查出來的事實：**27 支 PoC 沒有任何一支有內部隨機性**。同一類的
兩場之間只差三樣——一個 `intensity` 純量、起止時間、以及場次順序。而每個
runner 把所有參數都綁在那一個純量上（`points = 5000 + intensity*45000`、
`rate = 1 + intensity*2`），所以**同一類的所有場次落在特徵空間的一條一維
曲線上**。

這件事與 2026-09-19 量到的東西直接衝突：Enforce 的 26 個活特徵有 **19 個是
網路層**（突發度、到達間隔變異、封包大小、埠熵），而那些現在每一類都固定。
資料集因此給了每一類一個人工的乾淨網路指紋——**識別率被高估**，真實攻擊者
不會這樣。

## 這一支怎麼「有智慧」

它不是隨機參數，是**回饋迴路**：

    偵察 → 試探 → 觀察防禦反應 → 升級 或 退避 → 再觀察 → …

### 攻擊者看得到什麼（而且只看得到這些）

一個未認證的攻擊者在網路上真的觀察得到的東西，沒有別的：

| 通道 | 看得到什麼 | 為什麼合法 |
|---|---|---|
| `/cmd_vel` | 機器人在不在動 | 公開 topic；速度歸零＝守衛鎖了 |
| `/security/alerts` | **訊息數**（不是內容） | 公開 topic；沒有金鑰驗不了簽章，但數得出來 |
| ROS graph | 有哪些節點／topic | discovery 本來就是公開的 |

⚠️ **它沒有 HMAC 金鑰，也沒有遙測 socket。** 那兩條是方法學界線不是權限：
攻擊者若能寫遙測，它就能自己偽造「防禦有反應」的證據，整批資料作廢
（C2C-053）。

⚠️ **Enforce 下它會是盲的**——未認證 participant 進不了握手，訂閱收不到
任何東西。這不是缺陷，是這個威脅模型的真實樣子，而且值得單獨記錄：
`blind=true` 會寫進決策軌跡。

### 決策規則（事前寫下，跑完不改）

每一個 burst 之後計算兩個觀察量：

    noticed   = alerts 增量速率 > 基線 × NOTICE_ALERT_FACTOR
    contained = /cmd_vel 的零速比例 > CONTAINED_ZERO_FRACTION

| 觀察 | 行為 | 像什麼樣的攻擊者 |
|---|---|---|
| 都沒有 | **升級**：intensity ×1.6，縮短間隔 | 沒被抓到就加大力道 |
| 只有 noticed | **潛行**：intensity ×0.45，拉長間隔 | 被發現就低速慢慢來 |
| contained | **暫停**再小幅試探 | 被擋住就等守衛釋放 |

### 它不換攻擊類別

一場只打一個類別。換類別會讓場次變成多標籤，而
`session_labels()` 對多標籤直接拋例外——整條管線假設一場一種攻擊。
**那個假設本身是個盲點**，但要動它是另一件事，不在這一支裡混做。

## 不重寫任何攻擊

驅動器 import `firewall_lab.runners.build_attack_argv`，用**調整後的
intensity** 去呼叫既有的 PoC。不另外維護一份參數對應表——重寫就會有兩個
版本各自漂移（C2C-054 的程式碼稽核記過這件事）。

## 決策軌跡

每一步都印到 stdout，會被收進 `attack.stdout.log` 成為場次證據。
那份軌跡本身就是「攻擊者當時看到什麼、因此決定做什麼」的紀錄。

## 用法

    python3 N37_adaptive_attacker.py <duration_sec> \\
        --scenario <id> --catalog <path> [--seed N]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time

# Taken before anything expensive runs, because the budget the factory grants
# starts when this process starts, not when this process finishes importing.
#
# Measured 2026-09-24 over 406 adaptive sessions: clean exits overshot the
# granted budget by a median of +0.01s while TEARDOWN_RESERVE_SEC promised a
# 4.0s cushion. The cushion was entirely spent on start-up -- argument parsing
# plus the firewall_lab imports, off /mnt/c where reads are slow -- so the
# effective margin was zero and the child reap alone pushed 14.3% of sessions
# past the deadline into SIGKILL.
_PROCESS_START = time.monotonic()

from pathlib import Path  # noqa: E402

WORKSPACE = Path(__file__).resolve().parents[2]
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

MAX_DURATION_SEC = 300.0
RECON_SEC = 4.0
BURST_MIN_SEC = 5.0
BURST_MAX_SEC = 10.0
# 判定「被注意到」與「被擋住」的門檻。事前宣告。
NOTICE_ALERT_FACTOR = 2.5      # 告警速率超過基線這麼多倍
CONTAINED_ZERO_FRACTION = 0.80  # /cmd_vel 的零速比例
ESCALATE = 1.6
BACK_OFF = 0.45
# 2026-09-25：4.0 → 12.0 → 回到 4.0。兩次都有量測支持,而第二次是因為第一次
# 的修法換掉了這個常數要蓋住的東西。
#
# 第一版把它加到 12.0,因為當時收尾在**這個行程裡**跑:29 場帶儀器的場次中
# 12 場死在 `observer.close()`,`wall − declared` 中位數 +3.14 秒（工廠寬限期）,
# 代表收尾至少要 7.1 秒。但 12 秒仍然不夠——實測 close 最大 10.31 秒,
# 而合格率反而從 74.4% 掉到 54.5%（SIGKILL 降到 15.9%,硬停止自己貢獻 29.5%）。
#
# 現在收尾在子行程（見 `_reap_observer_out_of_process`）,父行程只剩印軌跡、
# fork、退出——實測 0.01 秒等級。這個預留唯一還要蓋的是最後一個 burst 的
# 收子行程,而那由 `BURST_EXIT_RESERVE_SEC` 自己處理。4.0 秒因此重新夠用,
# 而且把 8 秒還給攻擊視窗。
TEARDOWN_RESERVE_SEC = 4.0
# 收掉一個 burst 子行程的**硬上限**。
#
# 2026-09-20 實測：12 場被工廠 SIGKILL（rc=-9），而 rc=-9 與「沒有
# DECISION_TRACE」完全一一對應——被砍掉的那些場次,自適應決策紀錄整份丟失。
# 根因是這裡原本寫 `wait(timeout=5)` ×2：最壞情況 10 秒,而
# `ManagedProcess.stop()` 的寬限期只有 **3 秒**。burst 結束得夠晚時,收子行程
# 就把整個預留時間吃光。
#
# 1.0 + 1.0 = 2.0 秒,連同 rclpy 收尾都塞得進 4 秒的預留。
CHILD_REAP_SEC = 1.0
# 一個 burst 結束之後、`stop_by` 之前必須留下來收子行程的時間。
#
# 2026-09-24：burst 原本可以被切成「剩餘時間的全部」,於是 `observer.pump()`
# 一結束就已經在 `stop_by` 上,而收子行程最壞還要 2 秒——必然超過。
# `heartbeat_replay` 與 `unauthorized_participant` 是被砍最多的兩類,
# 正是 C2C-024 記過「Enforce 下 RELIABLE writer 配不到訂閱者、
# `destroy_node()` 會卡住」的那些,所以它們每次都用滿這 2 秒。
BURST_EXIT_RESERVE_SEC = 2 * CHILD_REAP_SEC

# 工廠在 duration 到期時送 SIGTERM,寬限 1 秒後 SIGKILL。提早 1.5 秒自己走,
# 留下的時間足夠印完軌跡。
# 與 firewall_lab/orchestrator.py 的 ATTACK_DEADLINE_ENV 相同。刻意重複定義
# 而不是 import——PoC 是獨立行程,不該把相依綁到管線那一側。
ATTACK_DEADLINE_ENV = "SROS2_ATTACK_DEADLINE_MONOTONIC"
WATCHDOG_MARGIN_SEC = 1.5
# `observer.close()` 是 rclpy 收尾。2026-09-24 實測它會卡,而 14 場被 SIGKILL
# 的場次沒有一場走到它後面的那一行。仍然要收（殘留的 DDS 共享記憶體段會拖垮
# 後續場次）,但要有界。
CLOSE_BUDGET_SEC = 2.0

_STOP = False
# 模組層級,因為訊號處理器要看得到它。main() 直接往這一份 append。
_TRACE: list[dict] = []
_TRACE_PRINTED = False
_WATCHDOG_REASON = ""


def _on_terminate(_signum, _frame) -> None:
    global _STOP
    _STOP = True


def _factory_deadline() -> float | None:
    """工廠指定的 CLOCK_MONOTONIC 絕對期限,沒有就回 None。

    Linux 的 time.monotonic() 自開機起算且每個行程一致,所以這個值直接可以跟
    自己的 time.monotonic() 比。非 Linux 上不保證,所以只在 POSIX 採用。
    """

    raw = os.environ.get(ATTACK_DEADLINE_ENV)
    if not raw or os.name != "posix":
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    # 期限必須在未來,而且不能離譜——一個過期或荒謬的值代表傳遞出了問題,
    # 那時候退回自己推算比照著一個壞數字跑安全。
    remaining = value - time.monotonic()
    if not 0.0 < remaining <= MAX_DURATION_SEC:
        print(f"   ⚠️ 忽略不合理的期限（剩 {remaining:.1f}s）", flush=True)
        return None
    return value


def _emit_trace(step: int, elapsed: float) -> None:
    """印出這一場的證據。可以被呼叫兩次,只有第一次會輸出。"""

    global _TRACE_PRINTED
    if _TRACE_PRINTED:
        return
    _TRACE_PRINTED = True
    print(f"⏹ N37 結束：{step} 個 burst，歷時 {elapsed:.1f}s", flush=True)
    print("DECISION_TRACE " + json.dumps(_TRACE, ensure_ascii=False), flush=True)
    sys.stdout.flush()
    sys.stderr.flush()


def _on_watchdog(_signum, _frame) -> None:
    """時間到就走,不管當時卡在哪一行。

    迴圈是在固定的幾個點檢查時鐘的,所以兩次檢查之間任何一段阻塞都會撐破預算,
    而把每一個這樣的地方都找出來是打不完的仗。計時器不在乎程式在哪裡。
    """

    print(f"⏱ N37 watchdog：{_WATCHDOG_REASON}，強制結束", flush=True)
    _emit_trace(len(_TRACE), float("nan"))
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


def _arm_kernel_hard_stop(seconds: float) -> bool:
    """讓**核心**在 `seconds` 之後終止這個行程。回傳有沒有武裝成功。

    這是唯一一種「rclpy 卡在 C 擴充裡握著 GIL」時仍然有效的期限。
    Python 的訊號處理器在 bytecode 之間才跑,daemon thread 的
    `Event.wait()` 也要拿 GIL——2026-09-25 量到 12 場因此死在工廠的寬限期
    之後,`wall − declared` 中位數 +3.14 秒。

    把 SIGALRM 的**處置**設回 `SIG_DFL`,它的預設動作是終止行程,而那是核心
    做的,不經過直譯器。所以即使整個 Python 停住,期限仍然會到。

    代價要寫清楚:真的觸發時這一場的 rc 是 `-14` 而不是 0,訓練閘仍然會判它
    不合格。**但那一場本來就會被工廠 SIGKILL 成 `-9`**,而且是在工廠期限
    **之後**——那才是會拖垮整批的部分。這裡換到的是「在我們自己選的時間點死,
    而且死在工廠期限之前」,決策軌跡早已落盤。
    """

    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        return False
    if seconds <= 0:
        return False
    try:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    except (ValueError, OSError):
        return False
    return True


def _reap_observer_out_of_process(close) -> bool:
    """在**子行程**裡收 rclpy,父行程立刻走。回傳有沒有 fork 成功。

    2026-09-25 第一版把預留從 4 秒加到 12 秒並加了核心硬停止,結果合格率
    **從 74.4% 掉到 54.5%**:SIGKILL 從 25.3% 降到 15.9%,但硬停止自己貢獻了
    29.5%。有界的超時仍然是超時,`-14` 一樣過不了訓練閘。

    根本問題是**收尾一旦開始就拿不回控制權**——GIL 被 C 擴充握著,執行緒、
    訊號、計時器都進不去。任何「在這個行程裡等它」的做法都會輸一部分場次,
    加大預留只是把輸的比例換個位置。

    所以改成不等：

    * 父行程 `os._exit(0)`,**永遠**乾淨退出。決策軌跡在 fork 之前就落盤了,
      證據完整,訓練閘因此看得到這一場。
    * 子行程盡力收。收得掉就釋放 DDS 共享記憶體段（那是這件事唯一的價值——
      觀測者是純唯讀訂閱者,沒有人在等它的告別）。

    ⚠️ 子行程必須自己有界。工廠的 `ManagedProcess.stop()` 只在**父行程還活著**
    的時候才送 SIGTERM 給整個行程群組,而父行程已經走了,所以孤兒不會被收——
    那正是 C2C-069 記的「殘留行程抓著 SHM 鎖」的成因。核心硬停止在這裡是
    必要的,不是保險。

    ⚠️ 在有 DDS 執行緒的行程裡 fork 本身是不安全的:子行程可能拿到一把已經
    被持有的鎖而直接死鎖。那時它什麼都收不掉,而結果**退化成「沒有收」**
    ——與今天 45% 的場次相同,不會更糟,而且父行程仍然是 rc=0。
    """

    if not hasattr(os, "fork"):
        return False
    try:
        pid = os.fork()
    except OSError:
        return False
    if pid != 0:
        return True                      # 父行程：立刻回去 os._exit(0)

    # 子行程。不要再寫 stdout——父行程已經 flush 過,重複寫會讓證據出現兩次。
    try:
        _arm_kernel_hard_stop(CLOSE_BUDGET_SEC)
        close()
    except BaseException:                # noqa: BLE001 - 收尾絕不可以往外拋
        pass
    os._exit(0)


def _arm_watchdog(seconds: float, *, reason: str) -> None:
    """設一個 SIGALRM。seconds <= 0 代表已經逾期,立刻觸發。"""

    global _WATCHDOG_REASON
    _WATCHDOG_REASON = reason
    signal.signal(signal.SIGALRM, _on_watchdog)
    signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.01))


class Observer:
    """攻擊者的眼睛。只訂閱公開 topic，不碰遙測也不碰金鑰。"""

    def __init__(self) -> None:
        self.ok = False
        self.blind_reason = ""
        self.steps: list[tuple[str, float]] = []
        self._node = None
        self._alerts = 0
        self._cmd_total = 0
        self._cmd_zero = 0
        # ⚠️ 逐步計時,因為一個**卡住**在這裡與一個**例外**長得完全不一樣,
        # 而先前只量得到後者。
        #
        # 2026-10-02 稽核 600 場攻擊場次:75 場被 SIGKILL,其中 **73 場只印了
        # 橫幅就死了**——沒有外面那行「觀測者就緒」。而那行印在本建構子
        # **返回之後**,所以例外會被下面的 except 接住、`ok=False`、那行**仍然
        # 會印**（實測有 1 場是 `可觀測=False`）。73 場連那行都沒有 ⇒ 建構子
        # 沒有返回 ⇒ **是阻塞不是例外**,而 Python 層的 watchdog 救不了
        # （C 擴充握著 GIL,C2C-082 量過）。
        #
        # 既然擋不住,就要讓它**說出卡在哪一步**。每一步完成就記一筆並立刻
        # flush;下一輪若再卡住,最後一筆就是卡住的那一步。
        def mark(label: str, since: float) -> float:
            now = time.monotonic()
            self.steps.append((label, now - since))
            print(f"   觀測者·{label} {now - since:.2f}s", flush=True)
            return now

        try:
            t = time.monotonic()
            import rclpy
            from geometry_msgs.msg import TwistStamped
            from rclpy.node import Node
            from rclpy.parameter import Parameter
            from rclpy.qos import QoSProfile, ReliabilityPolicy
            from std_msgs.msg import String
            t = mark("import", t)

            rclpy.init()
            self._rclpy = rclpy
            t = mark("rclpy.init", t)

            # 三個開關缺一不可。這是本專案已定案的寫法,N29／N32／N33／N34／N35
            # 五支腳本都用它,而 **N37 的 Observer 先前一個都沒有**。
            #
            #   start_parameter_services=False  → 關掉六個參數服務
            #   start_type_description_service  → 只能在建構當下用 overrides 關
            #   enable_rosout=False             → 否則每筆 log 都會上 /rosout
            #
            # 漏掉 type description 那個的錯誤訊息是「Failed to initialize type
            # description service」,**一個字都不提你少關了什麼**（C2C-019 §3
            # 記成「同一個陷阱第三次出現」）。
            #
            # ⚠️ 這一步對本觀測者是**獨立成立的衛生要求**,不是為了修卡住而猜:
            # 它的 docstring 寫著「只訂閱公開 topic」,而那 14 個服務端點既不被
            # 使用、又會送流量,讓「被動」這個前提失效。
            #
            # ⚠️ 它**有可能**同時是卡住的成因（Enforce 的卡住率是 Permissive 的
            # 4.5 倍,而那些端點要對 8 個安全節點逐一嘗試配對並失敗）,
            # 但**本輪沒有證據**,所以不宣稱。上面的逐步計時就是為了判定它。
            self._node = Node(
                "n37_probe",
                start_parameter_services=False,
                enable_rosout=False,
                parameter_overrides=[
                    Parameter(
                        "start_type_description_service",
                        Parameter.Type.BOOL,
                        False,
                    )
                ],
            )
            t = mark("Node", t)

            best_effort = QoSProfile(
                depth=20, reliability=ReliabilityPolicy.BEST_EFFORT)
            self._node.create_subscription(
                String, "/security/alerts", self._on_alert, 20)
            t = mark("sub:alerts", t)
            self._node.create_subscription(
                TwistStamped, "/cmd_vel", self._on_cmd, best_effort)
            mark("sub:cmd_vel", t)
            self.ok = True
        except Exception as exc:                     # pragma: no cover
            self.blind_reason = f"{type(exc).__name__}: {exc}"

    def _on_alert(self, _msg) -> None:
        # 只數,不解析。沒有金鑰,簽章驗不了——數量本身才是訊號。
        self._alerts += 1

    def _on_cmd(self, msg) -> None:
        self._cmd_total += 1
        twist = getattr(msg, "twist", msg)
        if abs(getattr(twist.linear, "x", 0.0)) < 1e-6 and \
                abs(getattr(twist.angular, "z", 0.0)) < 1e-6:
            self._cmd_zero += 1

    def pump(self, seconds: float) -> None:
        if not self.ok:
            time.sleep(seconds)
            return
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not _STOP:
            try:
                self._rclpy.spin_once(self._node, timeout_sec=0.05)
            except Exception:
                break

    def snapshot(self) -> dict:
        total = self._cmd_total
        return {"alerts": self._alerts, "cmd_total": total,
                "zero_fraction": (self._cmd_zero / total) if total else 0.0}

    def reset_counters(self) -> None:
        self._alerts = 0
        self._cmd_total = 0
        self._cmd_zero = 0

    def close(self) -> None:
        if not self.ok:
            return
        try:
            self._node.destroy_node()
        except Exception:
            pass
        try:
            self._rclpy.shutdown()
        except Exception:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("duration_sec", nargs="?", type=float, default=45.0)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--seed", type=int, default=0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    duration = max(5.0, min(float(args.duration_sec), MAX_DURATION_SEC))
    rng = random.Random(args.seed)

    from firewall_lab.catalog import load_catalog
    from firewall_lab.runners import build_attack_argv

    scenario = load_catalog(args.catalog)[args.scenario]

    signal.signal(signal.SIGTERM, _on_terminate)
    signal.signal(signal.SIGINT, _on_terminate)

    # 從**行程啟動**起算,不是從這一行起算。兩者差了 import 的時間,
    # 而那段時間在 /mnt/c 上實測就是整個 TEARDOWN_RESERVE_SEC。
    t0 = _PROCESS_START
    startup_cost = time.monotonic() - _PROCESS_START

    # 工廠給的絕對期限優先。自己從 duration 推算看不到直譯器開機那一段,
    # 而實測那一段是 4.85 秒——比整個收尾預留還多。
    deadline = _factory_deadline()
    if deadline is None:
        deadline = t0 + duration
        boot_cost = 0.0
    else:
        boot_cost = deadline - duration - t0
    stop_by = deadline - TEARDOWN_RESERVE_SEC
    trace = _TRACE

    # 後備。正常路徑會在 stop_by 就離開迴圈,這個計時器永遠不觸發;觸發時它會
    # 在軌跡裡留下記號,所以「它救了幾次」是看得到的而不是無聲的。
    _arm_watchdog(
        deadline - WATCHDOG_MARGIN_SEC - time.monotonic(),
        reason="到達工廠期限前 "
               f"{WATCHDOG_MARGIN_SEC:.1f}s 的硬期限",
    )

    # ⚠️ 這一行必須在 `Observer()` **之前**。2026-09-25 量到 47 場被 SIGKILL 的
    # 場次是**零位元組**——連這行橫幅都沒有——而它們的 `wall − declared` 是
    # +3.07 秒,與其他被殺的場次一模一樣,也就是說它們活滿了整個視窗。
    #
    # 活滿一個視窗卻一個字都沒寫,只有一種可能:卡在第一個 flush 之前。而
    # `Observer()` 會做 rclpy.init、建節點、等 discovery,那正是唯一擋在中間的
    # 東西。SIGALRM 的 watchdog 救不了——它在 C 擴充裡不會被遞送(同一個 GIL
    # 陷阱);工廠的 SIGTERM 也一樣,所以只剩 SIGKILL。
    #
    # 把橫幅移到前面不會修好那個卡住,但會讓它**看得見**:有橫幅沒有下一行,
    # 就是卡在 Observer;兩行都沒有,才是更早的問題。這個專案記過太多次
    # 「失敗是靜默的,看起來像證據不存在,實際是程式沒跑」。
    print(f"☠️ N37 自適應攻擊者 | vector={scenario.scenario_id} "
          f"| {duration:.0f}s | seed={args.seed} "
          f"| 啟動耗時 {startup_cost:.2f}s / 開機 {boot_cost:.2f}s "
          f"/ 預留 {TEARDOWN_RESERVE_SEC:.0f}s",
          flush=True)
    _observer_started = time.monotonic()
    observer = Observer()
    print(f"   觀測者就緒 {time.monotonic() - _observer_started:.2f}s"
          f"（可觀測={observer.ok}）", flush=True)
    if startup_cost >= TEARDOWN_RESERVE_SEC:
        # 不中止:資料還是有價值,但這一場的可用視窗被啟動吃掉了,要留下紀錄。
        print(f"   ⚠️ 啟動就吃掉了整個預留（{startup_cost:.2f}s ≥ "
              f"{TEARDOWN_RESERVE_SEC:.0f}s）——攻擊視窗會比宣告的短。",
              flush=True)
    if not observer.ok:
        print(f"   ⚠️ 觀察不到任何東西（{observer.blind_reason or '訂閱收不到'}）"
              "——盲打模式。Enforce 下這是預期的。", flush=True)

    # ── 偵察：先量基線，之後的判定都相對於它 ──
    observer.pump(RECON_SEC)
    base = observer.snapshot()
    base_alert_rate = base["alerts"] / RECON_SEC
    print(f"[偵察] {RECON_SEC:.0f}s：alerts={base['alerts']} "
          f"({base_alert_rate:.2f}/s)  cmd_vel={base['cmd_total']} "
          f"零速比例={base['zero_fraction']:.2f}  盲打={not observer.ok}",
          flush=True)

    intensity = rng.uniform(scenario.intensity_min,
                            min(0.45, scenario.intensity_max))
    pause = rng.uniform(1.0, 3.0)
    step = 0
    try:
        while not _STOP and time.monotonic() < stop_by:
            step += 1
            # 收子行程要花時間,而那段時間必須落在 `stop_by` **之前**。
            remaining = stop_by - time.monotonic() - BURST_EXIT_RESERVE_SEC
            burst = min(rng.uniform(BURST_MIN_SEC, BURST_MAX_SEC), remaining)
            if burst < 2.0:
                break
            intensity = max(scenario.intensity_min,
                            min(intensity, scenario.intensity_max))
            argv = build_attack_argv(
                scenario, workspace_root=WORKSPACE,
                duration_sec=burst, intensity=intensity)
            print(f"[burst {step}] intensity={intensity:.2f} "
                  f"{burst:.1f}s", flush=True)
            observer.reset_counters()
            started = time.monotonic()
            rc = None
            if argv is not None:
                try:
                    proc = subprocess.Popen(
                        argv, cwd=str(WORKSPACE),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    observer.pump(burst)
                    proc.terminate()
                    try:
                        rc = proc.wait(timeout=CHILD_REAP_SEC)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            rc = proc.wait(timeout=CHILD_REAP_SEC)
                        except subprocess.TimeoutExpired:
                            # SIGKILL 之後還收不掉只可能是 D 狀態。再等下去
                            # 就換成**我們**被 SIGKILL,連決策軌跡都留不下來。
                            rc = "reap_timeout"
                except Exception as exc:
                    print(f"   ⚠️ burst 起不來：{exc}", flush=True)
                    observer.pump(burst)
            else:
                observer.pump(burst)

            seen = observer.snapshot()
            elapsed = max(time.monotonic() - started, 0.1)
            rate = seen["alerts"] / elapsed
            noticed = rate > max(base_alert_rate * NOTICE_ALERT_FACTOR, 0.2)
            contained = seen["zero_fraction"] > CONTAINED_ZERO_FRACTION

            if not observer.ok:
                decision = "盲打：固定節奏"
                intensity *= rng.uniform(0.9, 1.3)
                pause = rng.uniform(1.0, 4.0)
            elif contained:
                decision = "被擋住 ⇒ 暫停後小幅試探"
                intensity *= BACK_OFF
                pause = rng.uniform(3.0, 6.0)
            elif noticed:
                decision = "被注意到 ⇒ 潛行"
                intensity *= BACK_OFF
                pause = rng.uniform(2.0, 4.5)
            else:
                decision = "沒被注意 ⇒ 升級"
                intensity *= ESCALATE
                pause = rng.uniform(0.5, 2.0)

            print(f"   [觀察] alerts={seen['alerts']} ({rate:.2f}/s, "
                  f"基線 {base_alert_rate:.2f}/s)  "
                  f"零速比例={seen['zero_fraction']:.2f}  rc={rc}", flush=True)
            print(f"   [決策] {decision}  下一次 intensity≈"
                  f"{min(max(intensity, scenario.intensity_min), scenario.intensity_max):.2f}"
                  f"  間隔 {pause:.1f}s", flush=True)
            trace.append({
                "step": step, "burst_sec": round(burst, 2),
                "intensity": round(intensity, 3), "rc": rc,
                "alerts": seen["alerts"], "alert_rate": round(rate, 3),
                "zero_fraction": round(seen["zero_fraction"], 3),
                "noticed": noticed, "contained": contained,
                "decision": decision, "blind": not observer.ok,
            })
            if _STOP or time.monotonic() >= stop_by:
                break
            observer.pump(min(pause, max(stop_by - time.monotonic(), 0.0)))
    finally:
        # 先留證據再收資源。順序相反的時候,一次卡住的 rclpy 收尾就讓 14 場的
        # 決策軌跡整份消失,而那些場次的攻擊其實跑得好好的。
        _teardown_started = time.monotonic()
        _emit_trace(step, time.monotonic() - t0)
        _left = (deadline - time.monotonic()) if deadline is not None else None
        print(f"   ⏱ 收尾：trace {time.monotonic() - _teardown_started:.2f}s "
              f"距期限 {('%+.2fs' % _left) if _left is not None else 'n/a'}",
              flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
        _reap_observer_out_of_process(observer.close)
        os._exit(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
