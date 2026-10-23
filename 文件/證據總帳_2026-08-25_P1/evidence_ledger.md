# Project evidence ledger

- Project: `sros2_room_firewall`
- Revision: `p1-2026-08-25-parallel-gate-and-delivery-semantics`
- Generated (UTC): `2026-08-25T04:05:34.585297+00:00`
- Claims: verified 3, provisional 2, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| Parallel binary-normality-known-attack OOD runtime contract | verified | Every admitted row is scored by the binary, family, leaf, normality and known-attack OOD heads; a binary miss can be recovered only when both reference detectors reject it, while the known-attack OOD head alone cannot turn normal traffic into an attack. | 3 | — |
| Session-grouped leave-one-family-out P1 evaluation | provisional | The P1 evaluator removes every session containing one attack family before fit and threshold selection, excludes official novelty sessions and all test rows, and evaluates IsolationForest and Mahalanobis in both security modes. | 5 | Macro family-LOO unknown recall is only 0.1049 to 0.2182 across the four mode-scorer combinations.; Worst-family unknown recall is only 0.0000 to 0.0229, far below the 0.70 requirement.; Worst known-attack false-unknown rate reaches 0.2500 to 0.2519 under Mahalanobis.; Binary-miss recovery is effectively zero in eleven of twelve folds, showing that current features and reference scores remain non-separable. |
| Credential-ACL-aware direct-delivery verifier v2 | verified | Expected delivery is derived from security mode, credential state, ACL permission, bound enclave and bound topic; authorized Enforce traffic is expected to deliver, while uncredentialed, invalid-credential and ACL-denied Enforce traffic is expected not to deliver. | 4 | — |
| Existing 12-session direct-delivery reanalysis | provisional | Under the corrected v2 semantics, the copied legacy archives produce six reconstructed pairs, twelve passing sessions and message-level TP=30, FN=0, FP=0, TN=90. | 3 | The legacy archives do not contain a shared pair identifier; all_pairings_attested is false.; Credential and ACL context was reconstructed from the runner branch and archive binding; publisher_authorization_contexts_all_attested is false. |
| P1 reproducibility audit | verified | The P1 audit verifies 12 of 12 environment, dependency, critical-file and full-suite checks; 633 tests passed and the three FrozenEstimator calibration warnings were removed without changing the weighted calibration protocol. | 2 | — |
| Room-level autonomous IP-blocking deployment | blocked | The P1 checkpoint is not qualified for autonomous room-level IP blocking or Raspberry Pi gateway deployment. | 1 | Family-LOO unknown recall and known-attack rejection constraints are not satisfied.; No independent sealed final holdout authorizes the candidate.; No trusted participant-to-source-IP attribution has been demonstrated.; Only five of nine local live outcomes have complete evidence.; No isolated two-host, real nftables forward-path, restart-recovery or Raspberry Pi 5 acceptance exists. |

## Claim details

### Evidence for `parallel_gate_runtime_contract`

- `firewall_lab/hierarchical_model.py` — 31102 bytes, SHA-256 `53b94dac023d680747b508b831f7a1366cb4d35e69052c6c0a5ffa391116481e` (Inference v3 parallel gate with a complete boolean truth table)
- `tests/test_hierarchical_model.py` — 24606 bytes, SHA-256 `e9c56e73e7e69c9fca50ae0cf61ce006bb5950b1ef1db6cfcaf3c8be0370b455` (Runtime, truth-table, policy, stream and observe-only tests)
- `文件/可重現性稽核_2026-08-25_P1_verified.json` — 19680 bytes, SHA-256 `86c72aa2f344cd5b99626235878e055eab40c37a49ed51a26b2ce156203e6e46` (P1 audit with 12 of 12 checks and 633 tests verified)

### Limitations for `parallel_gate_runtime_contract`

- A verified decision contract does not establish useful unknown-attack recall.
- Every inference remains action=alert, adapter=none and executable=false.

### Evidence for `parallel_gate_family_loo`

- `工具腳本/evaluate_parallel_gate_loo.py` — 17725 bytes, SHA-256 `883b7f113c42c82a9ab7ec60169a5d64913075845d84da08b022c624f4955f3f` (Session-grouped family-LOO evaluator)
- `文件/P1_AI平行閘門_LOO_2026-08-25/permissive_isolation_forest.json` — 5306 bytes, SHA-256 `f3b69e64a47d78527d4537169ef38e49afee6590bce4cc73ecaa2f7a9efe8b15` (Permissive IsolationForest family-LOO result)
- `文件/P1_AI平行閘門_LOO_2026-08-25/permissive_mahalanobis.json` — 5238 bytes, SHA-256 `b7c136d80a3e6574cdf8b19779a047e2ce8418e1414407809c144ed72153fcae` (Permissive Mahalanobis family-LOO result)
- `文件/P1_AI平行閘門_LOO_2026-08-25/enforce_isolation_forest.json` — 5433 bytes, SHA-256 `fba558e2ee0e04db57b83eb819642d22b88b365dd31d9ac2745c8943def48ca3` (Enforce IsolationForest family-LOO result)
- `文件/P1_AI平行閘門_LOO_2026-08-25/enforce_mahalanobis.json` — 5456 bytes, SHA-256 `487ef2e307df5f8cd285705f7113bab523aad7d99dc29ad4c0ece6bf6b82cf56` (Enforce Mahalanobis family-LOO result)

### Limitations for `parallel_gate_family_loo`

- Historical validation data is reused for development and is not an independent final estimate.
- The reports authorize neither deployment nor any response adapter.

### Evidence for `direct_delivery_v2_contract`

- `firewall_lab/sros2_delivery_evidence.py` — 41637 bytes, SHA-256 `0779085c63489aea1c132041d1c53145b9879b6ed51fd739eee5a25f5d86850c` (Fail-closed v2 contract, report and aggregate verifier)
- `tests/test_sros2_delivery_evidence.py` — 23587 bytes, SHA-256 `263ea8d1951303ffe1fefd5b74f41e03bfe2f5c79cd15efa1c53e44e61104c64` (Authorization matrix, integrity, pairing and aggregate tests)
- `tests/test_delivery_canary.py` — 8848 bytes, SHA-256 `3f408c7a9e5da3b0557282e613e08f179f1e692407f5bb8cd811b59bcc20fdfc` (Independent canary-writer to verifier compatibility tests)
- `工具腳本/run_delivery_canary.sh` — 5557 bytes, SHA-256 `ecde29090aaa68dca6405782bb49b1d8eb5d2fbaa4f72a5f944092d86fe64836` (No-overwrite future runner with shared P/E trial identities)

### Limitations for `direct_delivery_v2_contract`

- The verifier is offline and does not itself attest the launch environment or publisher credential.
- Direct delivery provides no trusted DDS identity-to-source-IP attribution.

### Evidence for `legacy_direct_delivery_reanalysis`

- `firewall_lab/direct_delivery_pair_map_20260818.json` — 674 bytes, SHA-256 `82b74c1adee3fab502762d2391aa47828eb26cef058e23e338bbd103995bf13a` (Explicit reconstruction map for legacy per-session trial identifiers)
- `工具腳本/verify_canary_archives.py` — 8887 bytes, SHA-256 `4025d2c6f1718db5319c6cbb2d1d20bec99d59136e8fb61e9fb9b270e223fa52` (Read-only source migration and fail-closed v2 verifier)
- `文件/direct_delivery_P1_既有12場重驗_2026-08-25_r3/aggregate_v2.json` — 6080 bytes, SHA-256 `395bb372bce5f918d05869fa3b1da844c2632ae38d50eca35054a14fee2cd01a` (Canonical r3 aggregate for 120 canaries)

### Limitations for `legacy_direct_delivery_reanalysis`

- The result is same-host application delivery evidence, not cross-host firewall evidence.
- Twelve of twelve is a corrected verifier result and not a deployment qualification.

### Evidence for `p1_reproducibility`

- `文件/可重現性稽核_2026-08-25_P1_verified.json` — 19680 bytes, SHA-256 `86c72aa2f344cd5b99626235878e055eab40c37a49ed51a26b2ce156203e6e46` (Verified audit with locked dependencies and the full 633-test run)
- `firewall_lab/hierarchical_training.py` — 58795 bytes, SHA-256 `89e5e2879d8020b9026bd66eab0308f8e6c560af7a5a9b9594ab7f88f3a44ccb` (Explicit calibrator-only sample-weight semantics)

### Limitations for `p1_reproducibility`

- The remaining 265 warnings are NumPy 2.5 deprecations emitted while loading existing joblib artifacts.
- File hashes and offline tests are not live ROS, cross-host, kernel nftables or Raspberry Pi evidence.

### Evidence for `room_firewall_deployment`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (Shipping policy with executable_classes still empty)

### Limitations for `room_firewall_deployment`

- All current P1 artifacts authorize observation and offline verification only.
- No live network, ROS, attack or firewall action was performed during P1.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
