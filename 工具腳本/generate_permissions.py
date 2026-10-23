#!/usr/bin/env python3
"""停用的舊 permissions 產生器。

此檔保留是為了讓舊筆記不會變成失效連結，但不再產生或簽署任何
SROS2 權限。唯一政策來源是：

  展示指令/sros2_policy_least_privilege.xml

修改政策後必須執行：

  bash 展示指令/10_SROS2啟用.sh
  bash 展示指令/sros2_稽核.sh

舊版本內含 wildcard 與過時的 /cmd_vel 發布者，若誤執行會把目前的
單一速度出口及最小權限政策覆蓋掉，因此刻意 fail closed。
"""

from __future__ import annotations


def main() -> int:
    print(
        "拒絕執行：這是已停用的舊 SROS2 權限產生器。\n"
        "請只編輯 展示指令/sros2_policy_least_privilege.xml，然後執行：\n"
        "  bash 展示指令/10_SROS2啟用.sh\n"
        "  bash 展示指令/sros2_稽核.sh"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
