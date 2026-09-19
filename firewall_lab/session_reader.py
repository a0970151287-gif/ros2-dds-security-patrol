"""讀 live session 的共用入口：manifest、telemetry 事件、訊號編碼。

## 為什麼需要它

2026-09-03 的稽核量到：**21 個檔案各自實作「讀 manifest 取 attack_class ＋
掃 telemetry_events.jsonl」**，9 個檔案各自走訪 `details` 欄位。不是死程式碼，
是同一段邏輯寫了二十幾遍。

而那正是缺陷的來源。同一天發生的三個錯誤都出在這裡：

| 錯誤 | 後果 |
|---|---|
| 某支工具用 `dataset_live` 而不是重跑後的資料 | 把一個**已修好的**歷史缺陷報成現況（6／28 對 2／28） |
| 臨時腳本讀 `details["result"]` 而實際欄位是 `reason` | 「攻擊沒有第二層證據」——判定正確，欄位錯 |
| gate 走訪 details 的方式與 `features.py` 不同 | 兩邊對同一份證據算出不同的訊號 |

**每一個都是「自己重寫一次讀取邏輯」造成的。**

## 這個模組不做什麼

不取代 `features.py` 的特徵計算，也不取代 `live_telemetry_collector` 的
schema 驗證。它只負責**把證據讀出來**，讓上層不必各自重寫。

`signal_counts` 的編碼與 `工具腳本/check_evidence_exclusivity.py` 一致
（含 2026-09-02 加入的欄位配對），並由測試釘住兩者相同。
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping


class SessionReadError(RuntimeError):
    """證據讀不出來。刻意不吞——讀不到與「沒有東西」是兩件事。"""


@dataclass(frozen=True)
class Session:
    """一場 live session 的入口。"""

    directory: Path
    manifest: Mapping[str, object]

    @property
    def session_id(self) -> str:
        return str(self.manifest["session_id"])

    @property
    def attack_class(self) -> str:
        return str(self.manifest["attack_class"])

    @property
    def scenario_id(self) -> str:
        return str(self.manifest["scenario_id"])

    @property
    def security_mode(self) -> str:
        return str(self.manifest["security_mode"])

    @property
    def status(self) -> str:
        return str(self.manifest.get("status", ""))

    @property
    def attack_return_code(self) -> int | None:
        result = self.manifest.get("result")
        if not isinstance(result, dict):
            return None
        process = result.get("attack_process")
        if not isinstance(process, dict):
            return None
        code = process.get("return_code")
        return int(code) if isinstance(code, int) else None

    def telemetry(self) -> Iterator[Mapping[str, object]]:
        """逐筆產出 telemetry 事件。

        壞掉的行**跳過而不是中止**：JSONL 的最後一行可能因行程被砍而截斷，
        而那不該讓整場證據讀不出來。但檔案不存在會拋——那是缺證據，
        與「事件數為零」是兩件事。
        """
        path = self.directory / "telemetry_events.jsonl"
        if not path.is_file():
            raise SessionReadError(f"telemetry file missing: {path}")
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict):
                    yield event


def iter_sessions(
    root: str | Path,
    *,
    complete_only: bool = True,
    security_mode: str | None = None,
    attack_class: str | None = None,
) -> Iterator[Session]:
    """走訪一個 dataset 目錄下的 session。

    `complete_only` 預設為真：跑到一半的場次證據還沒寫完，把它算進統計會
    低估。要看失敗場次時明確關掉它。
    """
    base = Path(root)
    if not base.is_dir():
        raise SessionReadError(f"dataset root is not a directory: {base}")
    for manifest_path in sorted(base.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SessionReadError(f"unreadable manifest {manifest_path}: {exc}")
        if not isinstance(manifest, dict):
            raise SessionReadError(f"manifest is not an object: {manifest_path}")
        session = Session(manifest_path.parent, manifest)
        if complete_only and session.status != "complete":
            continue
        if security_mode is not None and session.security_mode != security_mode:
            continue
        if attack_class is not None and session.attack_class != attack_class:
            continue
        yield session


def detail_tokens(details: Mapping[str, object]) -> list[str]:
    """把一則事件的 `details` 編成訊號 token。

    三種型別各有語意，不可混用：

    - `bool` → `欄位=True/False`
    - 數值 → `欄位>0` 或 `欄位=0`。看的是**零與非零**，不是值本身：
      `count=7` 與 `count=8` 是同一件事，而「計數器從恆零變成有值」才是
      「這個攻擊讓系統產生了它專屬的東西」。
    - 非空字串 → `欄位=值`
    """
    tokens: list[str] = []
    for field, value in details.items():
        if isinstance(value, bool):
            tokens.append(f"{field}={value}")
        elif isinstance(value, (int, float)):
            tokens.append(f"{field}" + (">0" if value else "=0"))
        elif isinstance(value, str) and value:
            tokens.append(f"{field}={value}")
    return tokens


def signal_counts(
    session: Session, *, include_pairs: bool = True
) -> collections.Counter:
    """一場 session 裡每種訊號的出現次數。

    編碼與 `工具腳本/check_evidence_exclusivity.py` 一致：事件型別本身、
    每個 `details` 欄位、以及**同一則事件裡的欄位兩兩組合**。

    配對是 2026-09-02 加的，理由是：正常流量本來就在 `system/health` 與
    `mission/cmd` 上驗章，所以 `channel=X` 單獨不排他；有判別力的是
    「在那個頻道上被判 malformed_envelope」。逐欄位編碼會把配對丟掉。
    """
    counts: collections.Counter = collections.Counter()
    for event in session.telemetry():
        kind = event.get("event_type")
        if not kind:
            continue
        counts[str(kind)] += 1
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        tokens = detail_tokens(details)
        for token in tokens:
            counts[f"{kind}.{token}"] += 1
        if include_pairs:
            for i in range(len(tokens)):
                for j in range(i + 1, len(tokens)):
                    counts[f"{kind}.{tokens[i]}&{tokens[j]}"] += 1
    return counts


def count_events(session: Session, event_type: str, *, field: str = "count") -> int:
    """數某種事件的總量，優先用 details 裡的計數欄位。

    缺 `count` 欄位時算一次。**寧可高估，不可低估**——低估會把「有反應」
    讀成「沉默」，而那正是 2026-09-01 內鬼量測要防的誤讀。
    """
    total = 0
    for event in session.telemetry():
        if event.get("event_type") != event_type:
            continue
        details = event.get("details")
        value = details.get(field) if isinstance(details, dict) else None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            total += 1
        else:
            total += int(value)
    return total
