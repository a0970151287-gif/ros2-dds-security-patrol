# Project evidence ledger

- Project: `sros2_room_firewall`
- Revision: `p0-2026-08-25-experimental-ood-checkpoint`
- Generated (UTC): `2026-08-25T03:36:31.086882+00:00`
- Claims: verified 5, provisional 4, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| Formal campaign manifest | verified | The sealed campaign manifest records 1,100 completed sessions, split evenly between Permissive and Enforce, across nine scenario identifiers. | 1 | — |
| Dataset integrity exclusion | verified | The candidate set excludes the one known post-manifest mutation from training, calibration, selection, and evaluation while preserving the raw session for audit. | 1 | — |
| Hierarchical causal-temporal candidate contract | verified | The repository contains a fail-closed hierarchical candidate with causal temporal features, source-availability masks, signed policy binding, explicit opt-in OOD scorer selection, and dedicated regression tests. | 4 | — |
| Experimental Mahalanobis OOD candidate | provisional | An opt-in Mahalanobis known-attack OOD scorer and grouped evaluation tools exist, while the default scorer remains unchanged and the candidate is explicitly non-deployable. | 3 | Whole-model recall on the virgin command_injection and identity_abuse holdout is only 0.0410.; The declared 0.05 known-attack rejection budget transfers as 0.2652 under Mahalanobis.; The hard binary gate prevents 73.8 percent of the virgin-holdout rows from reaching the OOD head. |
| Leakage-resistant development evaluation | verified | The frozen development evaluator compares tasks, feature views, and model families with session-disjoint selection, calibration, bootstrap intervals, latency, and test-access safeguards. | 3 | — |
| Two-ended SROS2 delivery verifier contract | provisional | The verifier binds attempt, receipt, heartbeat, policy, topic, enclave, and time window, but its expected-delivery rule is not yet credential-and-ACL aware. | 2 | The current expected-delivery rule treats every Enforce trial as blocked and therefore misclassifies authorized Enforce controls.; The existing 12 live archives have not been recomputed into a trustworthy aggregate under corrected semantics. |
| P0 reproducibility audit and evidence tooling | verified | The P0 audit verified 12 of 12 environment, dependency, file-integrity, and full-suite checks; the full suite completed with 615 passing tests. | 5 | — |
| Live SROS2 direct-delivery outcome | provisional | Twelve same-host 2-by-2 live archives show the expected raw delivery pattern, but no corrected formal aggregate is accepted for P0. | 0 | Authorized Enforce controls are misclassified by the current expected-delivery rule.; The live archives are not sealed inside this repository as a current evidence bundle. |
| Nine local block-zero-release-recovery outcomes | provisional | Five of nine local outcomes have complete per-session live evidence; no nine-of-nine aggregate is available. | 1 | Replay and parameter cases are blocked upstream and do not exercise the currently named inner-layer outcome.; Velocity recovery and graph-failure recovery lack stable same-session three-stage evidence. |
| Room-level autonomous IP-blocking deployment | blocked | The P0 checkpoint is not qualified for autonomous room-level IP blocking or Raspberry Pi gateway deployment. | 2 | No new pre-registered final holdout authorizes the candidate.; No trusted ROS or DDS identity-to-source-IP attribution has been demonstrated.; The nine local live outcomes and corrected two-ended delivery aggregate remain incomplete.; No isolated two-physical-host acceptance has been completed.; No real nftables forward-path timeout, expiry, restart recovery, and rollback acceptance has been completed.; No Raspberry Pi 5 latency, memory, temperature, packet-drop, and 60-minute soak acceptance has been completed. |

## Claim details

### Evidence for `formal_campaign_manifest`

- `firewall_lab/campaign_1100.json` — 402585 bytes, SHA-256 `2ff3f597a1ef7074213fdf4e1fe213c4f65ff4829e9b0529115dfc764de4b7db` (Pinned campaign manifest with 1,100 complete entries)

### Limitations for `formal_campaign_manifest`

- The 300 corrective reruns replace defective feature sources and do not increase the declared campaign to 1,400 sessions.
- Manifest completeness does not prove cross-host, Raspberry Pi, kernel-firewall, or enterprise-field behavior.

### Evidence for `dataset_integrity_exclusion`

- `firewall_lab/dataset_exclusions.v1.json` — 1185 bytes, SHA-256 `9dffa6a361fff27e1cd9353a2249ebc0fa5b0f1f1e436eb3eea0a54e376aa35e` (Fail-closed external exclusion with pinned observed digests)

### Limitations for `dataset_integrity_exclusion`

- The raw session is not repaired or relabelled.
- The exclusion policy does not establish that the remaining 1,099 sessions represent enterprise traffic.

### Evidence for `hierarchical_candidate_contract`

- `firewall_lab/hierarchical_model.py` — 29024 bytes, SHA-256 `1415e87e1ac182b8be9d22f1808a3569b0c0064ac90b85562fa705e6caa7203d` (Runtime hierarchical model contract)
- `firewall_lab/hierarchical_training.py` — 58056 bytes, SHA-256 `b34b71725d0e2dd9ed08f754e71ea1e953bb56305b9fcd9fdf6d63e9d56acc20` (Session-disjoint candidate training pipeline with default scorer unchanged)
- `tests/test_hierarchical_model.py` — 20884 bytes, SHA-256 `061620e3208472bb3151f075d18df62694592a81be2d7b122ae3f1b3efa72ffb` (Split-integrity and fail-closed runtime tests)
- `文件/可重現性稽核_2026-08-25_P0_verified.json` — 19128 bytes, SHA-256 `8a6040d869482f7c06fd308e4109127e32cdef6eae83200a1ae9678666cd972b` (P0 audit with 12 of 12 checks and 615 tests verified)

### Limitations for `hierarchical_candidate_contract`

- The candidate remains observe-only and is not deployment eligible.
- A verified implementation contract does not verify model accuracy, source-IP attribution, or autonomous response safety.

### Evidence for `experimental_ood_candidate`

- `firewall_lab/ood_scorers.py` — 4662 bytes, SHA-256 `5f60d508eee96634bf3acf22a7af5cd26c44dcff2e14db88f99065811b42e85e` (Opt-in Mahalanobis novelty detector)
- `tests/test_ood_scorers.py` — 3785 bytes, SHA-256 `35273fa743eb26f46fb0d98548e5ce7fd1d89ac67c4860b3b413a902607fc573` (Nine scorer behavior and default-preservation tests)
- `文件/未知攻擊偵測改善_2026-08-25.md` — 11609 bytes, SHA-256 `4e47226b1fa07cb4abd9b4b3dcfd3aa7eb9ae6e09fb547d44b88820c2804dab1` (Measured benefits, virgin-holdout failure, and known-attack rejection cost)

### Limitations for `experimental_ood_candidate`

- The 0.8850 result uses a holdout for the second time and is not a fresh final estimate.
- The scorer is research evidence only and cannot authorize quarantine or an IP block.

### Evidence for `development_evaluation_contract`

- `firewall_lab/development_evaluation.py` — 50139 bytes, SHA-256 `2f89b781a3c5f7833ef920d2c606c8f6e5162f64e8344d2e626e8975b20585fe` (Frozen development evaluation implementation)
- `tests/test_development_evaluation.py` — 10201 bytes, SHA-256 `5ccf978ade6e550e5c130edcc4be367db964151beabe4a47928a71769a52c94e` (Evaluation split and test-access safeguards)
- `文件/可重現性稽核_2026-08-25_P0_verified.json` — 19128 bytes, SHA-256 `8a6040d869482f7c06fd308e4109127e32cdef6eae83200a1ae9678666cd972b` (P0 full-suite execution record)

### Limitations for `development_evaluation_contract`

- Development evaluation does not replace a new pre-registered final holdout.
- No development metric authorizes a response adapter or network block.

### Evidence for `direct_delivery_verifier_contract`

- `firewall_lab/sros2_delivery_evidence.py` — 35014 bytes, SHA-256 `2235745f394bc314f58764fcc477295842b7e83e480becae8f8962fc549833ee` (Bounded two-ended evidence verifier)
- `tests/test_sros2_delivery_evidence.py` — 18811 bytes, SHA-256 `48ebfa4b1ab6e5d70ccd27d38cdc00c6d20bd05c9af5b8c882373bdbb8c98eb5` (Current integrity and state-machine tests)

### Limitations for `direct_delivery_verifier_contract`

- The verifier deliberately supplies no trusted source-IP attribution.
- Passing unit tests verifies current code behavior, not that its authorization semantics are complete.

### Evidence for `reproducibility_and_ledger_tooling`

- `工具腳本/verify_reproducibility.py` — 15968 bytes, SHA-256 `fa6a7135bc5f0ea08343626548051c66b37d74b0bf32f07a72e09a0034b3a99e` (Passive audit with atomic no-overwrite publication)
- `tests/test_verify_reproducibility.py` — 3524 bytes, SHA-256 `459ab2d7199bf34ea5dbf96ff6547b2cd18df85ff289f083f471e9e41b5d39e3` (Audit atomicity and overwrite-refusal tests)
- `firewall_lab/project_evidence.py` — 21143 bytes, SHA-256 `02b311e739944843b773ae508b7d02a2b9d7a365c4edded2630cda8c012d9499` (Fail-closed exact-size and SHA-256 ledger generator)
- `tests/test_project_evidence.py` — 9996 bytes, SHA-256 `a41e65826bee9a7f8f009a34f4b977b7373696cec09aa849b53fc2d56b18c2fc` (Traversal, tamper, overclaim, and atomicity tests)
- `文件/可重現性稽核_2026-08-25_P0_verified.json` — 19128 bytes, SHA-256 `8a6040d869482f7c06fd308e4109127e32cdef6eae83200a1ae9678666cd972b` (Verified P0 audit payload)

### Limitations for `reproducibility_and_ledger_tooling`

- The test run emitted 268 warnings: three calibration sample-weight warnings and 265 NumPy deprecation warnings.
- File hashes are integrity observations, not signatures or trusted remote attestation.

### Limitations for `live_sros2_delivery_outcome`

- Same-host delivery behavior is not cross-host firewall evidence.
- Raw delivery counts do not provide trusted participant-to-source-IP attribution.

### Evidence for `nine_local_live_outcomes`

- `文件/九項本機防禦結果_2026-08-19.md` — 11762 bytes, SHA-256 `79dec3d0e3216690271bb0ef0234742c4af19e338beda42b47b5d051f34f0869` (Measured five-of-nine outcomes and blockers)

### Limitations for `nine_local_live_outcomes`

- Offline unit tests and synthetic fixtures do not count as the missing live outcomes.
- The fail-closed assembler correctly refuses to emit a nine-of-nine certificate.

### Evidence for `room_firewall_deployment`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (Shipping action policy with no executable classes)
- `firewall_lab/live_multimodal_contract.json` — 4576 bytes, SHA-256 `cdc63fd63dd4128d523ceb6f4abc6d7339a101217794123422e981a1b62fc1a2` (Blocked live multimodal contract and source gaps)

### Limitations for `room_firewall_deployment`

- The current artifacts authorize observation and offline verification only.
- The shipping policy has executable_classes set to an empty list.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
