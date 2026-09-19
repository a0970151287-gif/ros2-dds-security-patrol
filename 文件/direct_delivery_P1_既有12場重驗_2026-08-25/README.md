# P1 direct-delivery 重驗：第一次 fail-closed 診斷

此資料夾保留第一次遷移的 12 份封存 archive、v2 contract 與單場 report。
單場驗票完成後，aggregate 因 Permissive／Enforce 使用不同 `trial_id`，使原始
`attempt_set_sha256` 不同而拒絕配對。這不是攻防失敗，也不是 12／12 結果；它是
促成 deterministic payload scheme 與 normalized stimulus 驗證的診斷證據。

此資料夾沒有 aggregate，不得作正式統計。後續 canonical 重驗為同層的 `_r3`。
