# P1 direct-delivery 既有 12 場 canonical 重驗

這是 2026-08-25 P1 的 canonical 離線重驗。原始 archive 從
`/home/jesse/canary_evidence` 唯讀複製；舊 contract／report 沒有被修改。

- 6 個重建 pair、12 個 session、120 個 canary。
- 12／12 session 符合修正後的預期語意。
- confusion：TP 30、FN 0、FP 0、TN 90；balanced accuracy 1.0。
- 合法 Enforce publisher 的 30 個 canary 計為應交付的 TN，不再誤算為 FN。
- 無憑證 Enforce publisher 的 30 個 canary 計為未交付的 TP。
- `all_pairings_attested=false`：舊 archive 沒有 pair id，pair map 由舊 runner 的固定
  執行順序重建。
- `publisher_authorization_contexts_all_attested=false`：credential／ACL context 是
  由既有 runner 分支與 archive binding 重建，沒有獨立簽章 attestation。
- `deployment_eligible=false`、`automatic_ip_block_authorized=false`。

因此可稱「修正後驗票器對既有 12 場重算為 12／12」，但不可稱為已取得具獨立
身分／配對 attestation 的部署證據，也不會開啟自動封鎖。
