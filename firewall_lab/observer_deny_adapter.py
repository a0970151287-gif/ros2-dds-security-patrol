#!/usr/bin/env python3
"""把 security_observer 的認證判定轉成 `sros2_deny` 遙測。

## 為什麼需要這一支

`sros_auth_fail_rate` 與 `sros_permission_deny_rate` 從專案第一天就是死的。
contract 記著實測結果：deny adapter 在 1,100 場裡讀了 **249,670 行**，
classified 為 deny 的是 **0 行**。原因不是 pattern 寫壞，是
`librmw_fastrtps_shared_cpp.so` 的 security property 只有 `dds.sec.auth.*`／
`access.*`／`crypto.*`——**`dds.sec.log.plugin` 不在其中**，所以經由 ROS 建立的
participant 永遠拿不到稽核日誌（見 `文件/DDS_Security_audit_log_不可用_2026-08-18.md`）。

`firewall_lab/security_observer` 繞過 rmw，直接用 Fast DDS API 建 participant，
因此吃得到 `DomainParticipantListener::onParticipantAuthentication`。2026-08-26
同機實測到 `UNAUTHORIZED`，2026-08-30 跨主機 79／80。**那是這個專案唯一真的
拿得到 DDS 認證判定的路徑。**

C2C-013 查過：`identity_abuse` 的定義性特徵正是這兩個，而它至今是識別率最差的
一類（test recall 0.467）。8/21 的 300 場重跑證明過，修好一條證據通道的效果
遠大於增加資料量——`replay` 0.375→1.000、`parameter_tamper` 0.429→1.000，
而通道沒被修的類別沒有動。

## ⚠️ 語意上必須揭露的事

觀測者是一個**獨立的 sidecar participant**，有自己的身分，與被防禦的 stack
共用同一個信任根。所以它的 `UNAUTHORIZED` 嚴格來說是

> 「某個遠端 participant 對**觀測者**認證失敗」

而不是

> 「某個遠端 participant 對 **monitor** 認證失敗」

同一個 CA 與 keystore 之下兩者結果應該一致，但那是推論不是量測。因此這個來源
必須標記為 **sidecar proxy**，不可以寫成「monitor 自己記錄的拒絕」。這比現況
（完全沒有來源）強，但不等於直接量到受防禦節點的拒絕。

## ⚠️ 同機執行時，觀測者**不可以**釘傳輸

`OBSERVER_INTERFACE_ADDRESS` 會設 `use_builtin_transports = false`，觀測者因此
只剩 UDPv4、沒有共享記憶體，而 ROS 2 同機預設走 SHM——握手走不起來，**每一個
合法節點都會被記成 `UNAUTHORIZED`**。2026-08-30 同一個 stack 上的對照：

| 觀測者傳輸 | 判定 |
|---|---|
| 釘 `127.0.0.1` | UNAUTHORIZED × 16（8 個合法節點） |
| 不釘 | AUTHORIZED × 9，加上 wrong-CA 攻擊者才有 1 個 UNAUTHORIZED |

釘著跑就會讓這個特徵在**每一場正常場**都亮，比沒有來源更糟——看起來像通道
修好了，實際上不帶任何鑑別資訊。

跨主機的需求相反（不釘的話 mirrored 的 `10.255.255.254` 會被宣告出去而
discovery 靜默失敗），所以**沒有安全的預設值**，必須依情境選，並在證據裡記錄
用的是哪一種。

## 計數語意

每一筆 `UNAUTHORIZED` 事件算一次拒絕。同一個 GUID 重複出現算多次——那是多次
握手嘗試各被拒絕一次，不是同一件事被報三遍。實測一輪 40 秒的 N28 會產生 3 筆，
與 SPDP 重新宣告的節奏相符。摘要另外報 `distinct_guids`，任何人都能看出比例，
不必相信這段說明。
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

# 觀測者事件裡，只有這個 event 帶認證判定。
AUTHENTICATION_EVENT = "participant_authentication"
# 只有明確的 AUTHORIZED 算通過；其他一律視為拒絕（與 crosscheck 的
# split_authentication 同一條規則，兩邊不可以分歧）。
AUTHORIZED_STATUS = "AUTHORIZED"


def classify_observer_event(row: dict) -> str | None:
    """回傳這一列對應的 `sros2_deny` kind，或 None 表示不是拒絕。

    目前只映射 authentication。permission 需要的是「認證通過、但對某個 topic
    的存取被拒」，Fast DDS 的 participant listener 給不到那個層級，所以
    `sros_permission_deny_rate` **仍然沒有來源**——不要在這裡假裝有。
    """
    if not isinstance(row, dict):
        return None
    if row.get("event") != AUTHENTICATION_EVENT:
        return None
    if not str(row.get("guid", "")).strip():
        # 沒有 GUID 的判定無法歸因到任何 participant，不計入。
        return None
    if row.get("status") == AUTHORIZED_STATUS:
        return None
    return "authentication"


class ObserverDenyAdapter:
    """消化觀測者事件，把認證拒絕送成 `sros2_deny` 遙測。"""

    def __init__(self, emit) -> None:
        self._emit = emit
        self.rows_seen = 0
        self.authorized_seen = 0
        self.denies_emitted = 0
        self.send_failures = 0
        self.malformed = 0
        self._distinct_guids: set[str] = set()

    def consume_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        self.rows_seen += 1
        try:
            row = json.loads(line)
        except ValueError:
            self.malformed += 1
            return
        if (
            isinstance(row, dict)
            and row.get("event") == AUTHENTICATION_EVENT
            and row.get("status") == AUTHORIZED_STATUS
        ):
            self.authorized_seen += 1
            return
        kind = classify_observer_event(row)
        if kind is None:
            return
        self._distinct_guids.add(str(row.get("guid", "")))
        if self._emit(kind):
            self.denies_emitted += 1
        else:
            # 送不出去要記下來。遙測走 Unix datagram，尖峰會掉，而靜靜掉一筆
            # 的後果是特徵少一個計數卻沒有人知道——這個專案已經被同一類問題
            # 咬過（偵測器轉換在送出前就記成已宣告）。
            self.send_failures += 1

    def summary(self) -> dict:
        return {
            "rows_seen": self.rows_seen,
            "authorized_seen": self.authorized_seen,
            "denies_emitted": self.denies_emitted,
            "distinct_guids": len(self._distinct_guids),
            "send_failures": self.send_failures,
            "malformed": self.malformed,
            "source_kind": "sidecar_observer_proxy",
            "observability": (
                "no_authentication_events_observed"
                if self.denies_emitted == 0 and self.authorized_seen == 0
                else "authentication_events_observed"
            ),
        }


def _socket_emitter(socket_path: Path, source: str):
    """回傳一個 emit(kind) -> bool，直接送 runtime telemetry 封包。"""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "dds_security_monitor"))
    from dds_security_monitor.runtime_telemetry import RuntimeTelemetryProducer

    producer = RuntimeTelemetryProducer(source=source, socket_path=str(socket_path))

    def emit(kind: str) -> bool:
        return bool(producer.emit_sros2_deny(kind))

    return emit, producer


def follow(path: Path, adapter: ObserverDenyAdapter, *, poll_sec: float,
           stop_after_sec: float | None = None) -> None:
    """只讀新增的位元組。整檔重讀在長跑時會變成 O(檔案大小) 的輪詢。"""
    deadline = None if stop_after_sec is None else time.monotonic() + stop_after_sec
    offset = 0
    pending = ""
    while deadline is None or time.monotonic() < deadline:
        try:
            with path.open("r", encoding="utf-8") as handle:
                handle.seek(offset)
                chunk = handle.read()
                offset = handle.tell()
        except FileNotFoundError:
            chunk = ""
        if chunk:
            pending += chunk
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                adapter.consume_line(line)
        else:
            time.sleep(poll_sec)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--source", default="observer_deny_adapter")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="讀完一個既有檔案就結束")
    source.add_argument("--follow", type=Path, help="持續跟隨觀測者事件檔")
    parser.add_argument("--poll-sec", type=float, default=0.2)
    parser.add_argument("--stop-after-sec", type=float, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    emit, producer = _socket_emitter(args.socket, args.source)
    adapter = ObserverDenyAdapter(emit)
    try:
        if args.input is not None:
            for line in args.input.read_text(encoding="utf-8").splitlines():
                adapter.consume_line(line)
        else:
            follow(args.follow, adapter, poll_sec=args.poll_sec,
                   stop_after_sec=args.stop_after_sec)
    finally:
        producer.close()
    print(json.dumps(adapter.summary(), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
