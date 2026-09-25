#!/usr/bin/env python3
"""把最後那個 test 封起來，並讓「只評估一次」變成機制而不是紀律。

## 為什麼

`文件/重訓預先註冊_*.json` 把設定釘死了，但它管不到兩件事：

1. **test 是哪些場次。** 切分是特徵表裡的一個欄位，重抽一次特徵就換一批，
   而沒有任何東西記得原本是哪一批。
2. **它被開過幾次。** 這個專案的 holdout 已經被花掉三次（C2C-054 記過），
   每一次都是有人記得或不記得，沒有東西擋。

這一支把兩者都變成檔案上的事實：封印記下 test 的場次清單雜湊、特徵表雜湊、
以及當時的預先註冊雜湊；開封是**一次性且不可逆**的寫入。

## 封印綁三樣東西，少一樣都能繞過

| 綁什麼 | 不綁的話 |
|---|---|
| test 場次清單的雜湊 | 可以換掉 test 裡的場次而封印照樣成立 |
| 特徵表的雜湊 | 可以重抽特徵、拿舊封印蓋新資料 |
| 預先註冊的雜湊 | 可以在封印之後才決定設定——那正是要防的事 |

## 開封之後

`opened` 一旦為真就寫死。第二次呼叫 `open_once()` 直接拒絕，
而**評估器必須先開封才准讀 test 列**。所以「不小心又跑了一次」會在讀資料
之前就停下來，不是事後才發現。

⚠️ 它擋不了有檔案權限的人刪掉封印。那不是這一層能解的；封印本身要進 git，
**缺席本身就是可偵測的**。

## 用法

    python3 工具腳本/seal_holdout.py seal \\
        --features ~/features_mega/fusion_features_enforce.csv \\
        --registration 文件/重訓預先註冊_2026-09-25.json \\
        --output 文件/封存holdout_enforce_<日期>.json

    python3 工具腳本/seal_holdout.py status --seal <path>
    python3 工具腳本/seal_holdout.py open --seal <path> --reason "final evaluation"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

SCHEMA = "sros2-firewall-sealed-holdout/v1"


class SealError(RuntimeError):
    """封印不成立、已被開過，或與資料不符。刻意不吞。"""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_sessions(sessions: list[str]) -> str:
    """場次清單的雜湊。排序之後再算,所以列的順序不影響身分。"""
    joined = "\n".join(sorted(sessions))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def read_test_sessions(features: Path) -> list[str]:
    """特徵表裡 `split == test` 的場次。不載入 pandas——只讀兩欄。"""
    import csv

    sessions: set[str] = set()
    with features.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SealError("特徵表沒有標題列")
        for column in ("split", "group_id"):
            if column not in reader.fieldnames:
                raise SealError(f"特徵表缺少 {column} 欄")
        for row in reader:
            if (row.get("split") or "").strip() == "test":
                group = (row.get("group_id") or "").strip()
                if group:
                    sessions.add(group)
    if not sessions:
        raise SealError("特徵表裡沒有任何 split=test 的列——沒有東西可以封")
    return sorted(sessions)


def create_seal(features: Path, registration: Path) -> dict:
    if not features.is_file():
        raise SealError(f"特徵表不存在：{features}")
    if not registration.is_file():
        raise SealError(f"預先註冊不存在：{registration}")

    reg = json.loads(registration.read_text(encoding="utf-8"))
    reg_sha = reg.get("registration_sha256")
    if not isinstance(reg_sha, str) or len(reg_sha) != 64:
        raise SealError("預先註冊裡沒有合法的 registration_sha256")

    sessions = read_test_sessions(features)
    return {
        "schema_version": SCHEMA,
        "sealed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "features_path": str(features),
        "features_sha256": _sha256_file(features),
        "registration_path": str(registration),
        "registration_sha256": reg_sha,
        "test_session_count": len(sessions),
        "test_sessions_sha256": _sha256_sessions(sessions),
        "test_sessions": sessions,
        "opened": False,
        "opened_utc": None,
        "opened_reason": None,
        "note": (
            "封印綁 test 場次清單、特徵表與預先註冊三者。開封是一次性的，"
            "而評估器必須先開封才准讀 test 列。"
        ),
    }


def verify_seal(seal: dict, features: Path | None = None) -> dict:
    """封印還成立嗎。給了 features 就一併確認資料沒有被換掉。"""
    if seal.get("schema_version") != SCHEMA:
        raise SealError(f"未知的 schema：{seal.get('schema_version')!r}")

    problems = []
    recorded = seal["test_sessions_sha256"]
    if _sha256_sessions(seal["test_sessions"]) != recorded:
        problems.append("封印裡的場次清單與它自己的雜湊不符")
    if len(seal["test_sessions"]) != seal["test_session_count"]:
        problems.append("場次數與清單長度不符")

    if features is not None:
        if not features.is_file():
            problems.append(f"特徵表不存在：{features}")
        else:
            if _sha256_file(features) != seal["features_sha256"]:
                problems.append("特徵表已經變動——這份封印不適用於這批資料")
            else:
                current = read_test_sessions(features)
                if _sha256_sessions(current) != recorded:
                    problems.append("特徵表裡的 test 場次與封印不同")

    return {
        "valid": not problems,
        "problems": problems,
        "opened": bool(seal.get("opened")),
        "test_session_count": seal["test_session_count"],
    }


def open_once(seal_path: Path, reason: str) -> dict:
    """開封。第二次一律拒絕。"""
    if not reason or not reason.strip():
        raise SealError("開封必須寫理由——沒有理由的開封事後看不出是哪一次")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    check = verify_seal(seal)
    if not check["valid"]:
        raise SealError(f"封印不成立，拒絕開封：{check['problems']}")
    if seal.get("opened"):
        raise SealError(
            f"這個 holdout 已經在 {seal.get('opened_utc')} 開過了"
            f"（理由：{seal.get('opened_reason')!r}）。"
            "第二次評估的數字不可引用——要新的數字就要新的資料。"
        )
    seal["opened"] = True
    seal["opened_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    seal["opened_reason"] = reason.strip()[:256]
    seal_path.write_text(
        json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return seal


def require_unopened(seal_path: Path) -> dict:
    """評估器在讀 test 列**之前**呼叫這個。已開過就拋。"""
    seal = json.loads(Path(seal_path).read_text(encoding="utf-8"))
    if seal.get("opened"):
        raise SealError(
            f"holdout 已於 {seal.get('opened_utc')} 開封，不可再讀 test 列"
        )
    return seal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    make = sub.add_parser("seal", help="產生封印")
    make.add_argument("--features", type=Path, required=True)
    make.add_argument("--registration", type=Path, required=True)
    make.add_argument("--output", type=Path, required=True)

    status = sub.add_parser("status", help="查封印狀態")
    status.add_argument("--seal", type=Path, required=True)
    status.add_argument("--features", type=Path, default=None)

    unseal = sub.add_parser("open", help="開封（一次性）")
    unseal.add_argument("--seal", type=Path, required=True)
    unseal.add_argument("--reason", required=True)

    args = parser.parse_args(argv)

    if args.command == "seal":
        if args.output.exists():
            print(f"⛔ 封印已存在，拒絕覆寫：{args.output}", file=sys.stderr)
            return 2
        seal = create_seal(args.features, args.registration)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"封了 {seal['test_session_count']} 場")
        print(f"  test_sessions_sha256 : {seal['test_sessions_sha256']}")
        print(f"  features_sha256      : {seal['features_sha256']}")
        print(f"  registration_sha256  : {seal['registration_sha256']}")
        print(f"封印：{args.output}")
        return 0

    if args.command == "status":
        seal = json.loads(args.seal.read_text(encoding="utf-8"))
        result = verify_seal(seal, args.features)
        print(f"test 場次   : {result['test_session_count']}")
        print(f"已開封      : {result['opened']}")
        if result["opened"]:
            print(f"  開封時間  : {seal.get('opened_utc')}")
            print(f"  理由      : {seal.get('opened_reason')!r}")
        print(f"封印成立    : {result['valid']}")
        for problem in result["problems"]:
            print(f"  ⚠️ {problem}")
        return 0 if result["valid"] else 1

    seal = open_once(args.seal, args.reason)
    print(f"已開封於 {seal['opened_utc']}：{seal['opened_reason']}")
    print("⚠️ 這個 holdout 現在花掉了。下一個數字需要新的資料。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
