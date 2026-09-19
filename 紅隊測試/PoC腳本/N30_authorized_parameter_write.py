#!/usr/bin/env python3
"""攻擊 N30 — 持合法憑證、且 SROS2 已授權參數寫入的內鬼。

## 與 N14、N29 的差別

| 攻擊 | 憑證 | SROS2 是否放行 | 靠什麼擋 |
|---|---|---|---|
| N14 | 無 | Enforce 下擋在 handshake | SROS2 |
| N29 | 竊取合法節點的憑證 | 放行 | HMAC 金鑰（攻擊者沒有） |
| **N30** | **合法，且被授權呼叫 set_parameters** | **放行** | **rcl 的 read_only 描述子** |

N30 是三者中最深的一層：SROS2 檢查通過、ACL 檢查通過、請求真的抵達節點，
擋住它的是**應用層對安全敏感參數的宣告方式**。

## 為什麼需要這個攻擊

`parameter_unchanged` 這一項的判定要求一筆「參數變更被拒絕」的證據。
在原本的政策下沒有任何身分能呼叫 `set_parameters`，所以 Enforce 下請求
根本到不了節點——那一項因此**空洞地成立**：證明的是 ACL，不是應用層。

改用 Permissive 讓請求抵達也不行：outcome observer 拒絕在 Enforce 以外執行，
而那道拒絕是對的（沒有強制執行時收的證據支撐不了部署宣稱）。

所以改成讓請求**合法**。`/parameter_write_probe` enclave 只被授權一條服務，
連 `get_parameters` 都沒有。它存在的唯一目的就是發起這一次會被拒絕的寫入。

## 預期結果

- SROS2：放行（請求抵達 `dds_security_monitor`）
- rcl：拒絕，`successful=False`、reason 含 `read-only`
- 遙測：`parameter_veto` 事件，`layer=rcl_read_only`
- 參數 digest：前後不變

**任何一次 `successful=True` 都代表修補失效**，那比拿不到證據嚴重得多。

## 安全邊界

同一台主機、loopback、SROS2 Enforce。不使用 sudo、不改防火牆、不連第二台主機。
唯一的動作是對本專案自己的 monitor 送一個必定被拒絕的參數寫入請求。
"""

import os
import signal
import sys
import time

import rclpy
from rcl_interfaces.msg import Parameter, ParameterType, ParameterValue
from rcl_interfaces.srv import SetParameters
from rclpy.node import Node

# enclave 的 profile 節點名。**必須與 enclave 相符**，否則 SROS2 找不到權限，
# 而錯誤訊息會是 "failed to create request DataReader"，完全不提權限——
# 這個陷阱在本專案已經咬過三次（canary、observer、N29）。
NODE_NAME = "parameter_write_probe"
TARGET_SERVICE = "/dds_security_monitor/set_parameters"

_STOP = False


def _handle_stop(_signum, _frame):
    global _STOP
    _STOP = True


class AuthorizedParameterWriter(Node):
    def __init__(self):
        super().__init__(NODE_NAME)
        self._client = self.create_client(SetParameters, TARGET_SERVICE)

    def attempt(self) -> tuple[bool, str]:
        """回傳 (是否成功改到, 拒絕理由)。成功改到就是修補失效。"""
        if not self._client.wait_for_service(timeout_sec=5.0):
            return False, "service-unreachable"

        parameter = Parameter()
        parameter.name = "whitelist"
        parameter.value = ParameterValue()
        parameter.value.type = ParameterType.PARAMETER_STRING_ARRAY
        parameter.value.string_array_value = ["attacker_only_node"]

        request = SetParameters.Request()
        request.parameters = [parameter]
        future = self._client.call_async(request)
        rclpy.spin_until_future_complete(self, future, timeout_sec=8.0)
        if not future.done() or future.result() is None:
            return False, "no-response"
        results = future.result().results
        if not results:
            return False, "empty-results"
        first = results[0]
        return bool(first.successful), str(first.reason)


def main() -> int:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    # duration 走環境變數，不走 argv——argv 要留給 `--ros-args --enclave`，
    # 兩者搶同一個位置會讓 enclave 參數被當成秒數。
    duration = float(os.environ.get("N30_DURATION_SEC", "12"))

    print("=" * 62)
    print(" N30  已授權的參數寫入 → 預期被 rcl 的 read_only 擋下")
    print("=" * 62)
    print(f"  enclave  : /{NODE_NAME}")
    print(f"  target   : {TARGET_SERVICE}")
    print(f"  duration : {duration}s", flush=True)

    rclpy.init(args=sys.argv)
    node = AuthorizedParameterWriter()
    attempts = 0
    refused = 0
    succeeded = 0
    try:
        deadline = time.monotonic() + duration
        while not _STOP and time.monotonic() < deadline:
            try:
                changed, reason = node.attempt()
            except Exception as exc:                    # noqa: BLE001
                # 收到 SIGTERM 時 rclpy 的 signal handler 已經關掉 context，
                # 而 `wait_for_service` 正在進行中就會拋
                # `RCLError: rcl node's context is invalid`。
                #
                # 讓它逃出去會讓退出碼變 1，而 campaign 的 training gate 會把
                # **整批**中止——2026-09-02 的 680 場就是在第 263 場這樣停掉的，
                # 前 15 場同一支都是 rc=0。收尾時的 shutdown 不是攻擊失敗。
                if not rclpy.ok():
                    print(f"  （收到終止訊號，提前結束：{type(exc).__name__}）",
                          flush=True)
                    break
                raise
            attempts += 1
            if changed:
                succeeded += 1
                print(f"  ⛔ 第 {attempts} 次：**改成功了** — 修補失效", flush=True)
            else:
                refused += 1
                print(f"  ✓ 第 {attempts} 次被拒：{reason}", flush=True)
            # 留間隔，避免退化成 parameter flood（那是 N19 的情境）。
            slept = 0.0
            while slept < 2.0 and not _STOP and time.monotonic() < deadline:
                time.sleep(0.1)
                slept += 0.1
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()

    print()
    print(f"  嘗試 {attempts}　被拒 {refused}　**改成功 {succeeded}**")
    if succeeded:
        print("  ⛔ 有成功的寫入——read_only 保護失效", file=sys.stderr)
        return 1
    if not refused:
        print("  ⚠️ 一次都沒被拒絕，也一次都沒成功——請求可能沒有抵達節點。"
              "不可視為防禦成立。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
