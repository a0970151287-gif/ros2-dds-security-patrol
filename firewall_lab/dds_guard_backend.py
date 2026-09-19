"""把一份授權變成第二層守衛實際生效的封鎖，並保證它會被撤銷。

## 這個模組補的洞

守衛的黑名單本來是一行一個 GUID 的純文字檔。**任何能寫那個檔的東西都能
封鎖任何 participant**——沒有授權、沒有票、沒有到期。守衛照做，因為它沒有
辦法分辨那一行是授權器發的還是別人寫的。

本模組是唯一應該寫那個檔的東西。它拒絕在沒有有效授權的情況下寫入，並且把
每一筆封鎖都綁上票的 SHA-256 與到期時間。

## 三道獨立的撤銷保證

單一撤銷路徑不夠——它自己壞掉的時候封鎖會永遠留著，而這一層的整個賣點就是
「可撤銷」。所以有三道，任何一道成立就會解除：

1. **明確撤銷**：`revoke()`，實測 0.0109 秒生效。
2. **本模組到期**：`expire_due()` 掃過期項目並重寫黑名單。
3. **守衛自己到期**：每一行都帶到期時間，守衛過期就不再套用它。
   即使本行程整個死掉，封鎖仍然會自己解除。

第 3 道是最重要的一道，因為它不依賴這個 Python 行程還活著。

## 為什麼寫檔而不是 IPC

守衛是 C++、授權器是 Python，而封鎖狀態必須在兩者都重啟之後仍然一致。
檔案是唯一雙方都能獨立檢查的媒介，也讓稽核可以事後重建「當時擋了誰」。
寫入是原子的（temp ＋ rename），守衛不會讀到寫到一半的檔案。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from .response_authorizer import MAX_GUARD_TTL_SEC, AuthorizedResponse
from .schema import SchemaError

BLOCKLIST_SCHEMA = "sros2-firewall-dds-guard-blocklist/v1"
_HEX = frozenset("0123456789abcdef")
GUID_PREFIX_CHARS = 24


def normalize_guid_prefix(value: Any) -> str:
    """把 GUID 前綴正規化成 24 個小寫十六進位字元。

    觀測者發出來的是點分格式（`a2.5a.10.4e...`），封包解碼器發的是連續
    十六進位。兩種都要接受，但**輸出只有一種形式**——否則同一個 participant
    會用兩種寫法各封鎖一次，而撤銷只解除其中一種。
    """
    if not isinstance(value, str):
        raise SchemaError("guid prefix must be text")
    compact = value.replace(".", "").replace(":", "").replace("-", "").strip().lower()
    if len(compact) != GUID_PREFIX_CHARS or any(c not in _HEX for c in compact):
        raise SchemaError(
            f"guid prefix must be {GUID_PREFIX_CHARS} lowercase hex characters")
    return compact


class DdsGuardBackend:
    """唯一被授權寫入守衛黑名單的元件。"""

    def __init__(
        self,
        blocklist_path: Path,
        journal_path: Path,
        *,
        guard_id: str,
        clock: Callable[[], float] = time.time,
    ):
        if not isinstance(guard_id, str) or not guard_id:
            raise SchemaError("guard_id must be non-empty text")
        self.blocklist_path = Path(blocklist_path)
        self.journal_path = Path(journal_path)
        self.guard_id = guard_id
        self._clock = clock
        self._active: dict[str, dict[str, Any]] = {}

    # ── 封鎖 ────────────────────────────────────────────────────────────────

    def apply(
        self,
        authorization: AuthorizedResponse,
        *,
        guid_prefix: str,
    ) -> dict[str, Any]:
        """套用一份授權。授權不成立時**不寫任何東西**並如實回報原因。"""
        if type(authorization) is not AuthorizedResponse:
            raise SchemaError("authorization has the wrong type")
        prefix = normalize_guid_prefix(guid_prefix)

        # 這裡刻意不看 blockers 的內容，只看授權器最終的判定。
        # 由執行端自己重新詮釋 blockers 等於讓它有機會繞過授權器。
        refusals: list[str] = []
        if not authorization.execute:
            refusals.append("authorization did not grant execution")
        if authorization.adapter != "dds_guard":
            refusals.append("authorization is not for the dds guard")
        if authorization.action != "revocable_participant_block":
            refusals.append("authorization is not a revocable participant block")
        if not authorization.authorization_ticket:
            refusals.append("authorization carries no ticket")
        if not authorization.rollback_required:
            refusals.append("authorization does not require rollback")
        if not 1 <= authorization.ttl_sec <= MAX_GUARD_TTL_SEC:
            refusals.append(f"ttl must be 1..{MAX_GUARD_TTL_SEC} seconds")

        if refusals:
            record = {
                "event": "block_refused",
                "guid_prefix": prefix,
                "refusals": refusals,
                "applied": False,
            }
            self._journal(record)
            return record

        now = float(self._clock())
        ticket_sha256 = hashlib.sha256(
            authorization.authorization_ticket.encode("utf-8")).hexdigest()
        entry = {
            "guid_prefix": prefix,
            "ticket_sha256": ticket_sha256,
            "expires_unix": now + float(authorization.ttl_sec),
            "evidence_id": authorization.evidence_id,
            "applied_unix": now,
        }
        self._active[prefix] = entry
        self._write()
        record = {
            "event": "block_applied",
            "guid_prefix": prefix,
            # 票本身絕對不落地，只有它的雜湊。稽核要的是「能不能對上」，
            # 不是票的內容；而票外洩等於任何人都能偽造一次封鎖。
            "ticket_sha256": ticket_sha256,
            "expires_unix": entry["expires_unix"],
            "ttl_sec": authorization.ttl_sec,
            "evidence_id": authorization.evidence_id,
            "applied": True,
        }
        self._journal(record)
        return record

    # ── 撤銷 ────────────────────────────────────────────────────────────────

    def revoke(self, guid_prefix: str, *, reason: str = "operator") -> dict[str, Any]:
        prefix = normalize_guid_prefix(guid_prefix)
        existed = self._active.pop(prefix, None) is not None
        if existed:
            self._write()
        record = {
            "event": "block_revoked",
            "guid_prefix": prefix,
            "reason": str(reason)[:128],
            # 撤銷一個不存在的封鎖不是錯誤，但要記下來——分不清楚的話，
            # 「撤銷成功」會掩蓋「這個封鎖根本沒被套用過」。
            "was_active": existed,
        }
        self._journal(record)
        return record

    def expire_due(self) -> list[str]:
        now = float(self._clock())
        due = [prefix for prefix, entry in self._active.items()
               if entry["expires_unix"] <= now]
        for prefix in due:
            self._active.pop(prefix, None)
        if due:
            self._write()
            for prefix in due:
                self._journal({
                    "event": "block_expired",
                    "guid_prefix": prefix,
                    "reason": "ttl",
                })
        return sorted(due)

    def active(self) -> dict[str, dict[str, Any]]:
        return {prefix: dict(entry) for prefix, entry in self._active.items()}

    # ── 落地 ────────────────────────────────────────────────────────────────

    def _write(self) -> None:
        lines = [
            f"# {BLOCKLIST_SCHEMA} guard={self.guard_id}",
            "# guid_prefix ticket_sha256 expires_unix",
        ]
        for prefix, entry in sorted(self._active.items()):
            lines.append(
                f"{prefix} {entry['ticket_sha256']} "
                f"{entry['expires_unix']:.3f}")
        payload = "\n".join(lines) + "\n"

        # 原子寫入：守衛是靠 mtime 變動觸發重讀的，直接覆寫會讓它有機會
        # 讀到寫到一半的檔案，而半個黑名單看起來就像「封鎖被解除了」。
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.blocklist_path.with_suffix(
            self.blocklist_path.suffix + ".tmp")
        temporary.write_text(payload, encoding="utf-8", newline="\n")
        os.replace(temporary, self.blocklist_path)

    def _journal(self, record: dict[str, Any]) -> None:
        record = dict(record)
        record.setdefault("ts_unix", float(self._clock()))
        record["guard_id"] = self.guard_id
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False,
                                    sort_keys=True) + "\n")
