# Project evidence ledger

- Project: `sros2_room_firewall`
- Revision: `working-tree-2026-08-17-offline-evidence-r1`
- Generated (UTC): `2026-08-17T09:01:13.854543+00:00`
- Claims: verified 6, provisional 2, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| Formal campaign manifest | verified | The sealed campaign manifest records 1,100 completed sessions, split evenly between Permissive and Enforce, across nine scenario identifiers. | 1 | — |
| Dataset integrity exclusion | verified | The release records and pins the one known post-manifest mutation and excludes the entire affected session from training, calibration, selection, and evaluation. | 1 | — |
| Hierarchical causal-temporal candidate | verified | The repository contains a fail-closed hierarchical candidate implementation and training pipeline with causal temporal features, source-availability masks, signed policy binding, and dedicated regression tests included in the full suite. | 4 | — |
| Leakage-resistant development evaluation | verified | A frozen development-evaluation program compares tasks, feature views, and model families using session-disjoint selection, calibration, thresholding, bootstrap intervals, latency, and calibration metrics; its tests are included in the full suite. | 3 | — |
| Two-ended SROS2 delivery verifier | verified | The offline verifier binds attempted and protected-received archives to one bounded session and recomputes delivery outcomes without treating vendor logs as ground truth; its tests are included in the full suite. | 3 | — |
| Reproducibility audit and evidence ledger | verified | The passive audit verified 12 of 12 environment, dependency, file-integrity, and full-suite checks; the recorded full suite completed with return code zero and 583 passing tests. | 5 | — |
| Live SROS2 direct-delivery outcome | provisional | The evidence contract and verifier are ready, but no newly sealed attempted-versus-protected-received live archive has been accepted for this release. | 0 | Requires an explicitly authorized live window and one bounded capture from both application endpoints.; Requires the real policy, enclave, identity, topic, and collector health records to be sealed before verification. |
| Nine local block-zero-release-recovery outcomes | provisional | The nine-case acceptance procedure is designed, but a complete 9 of 9 live evidence archive has not been sealed and independently recomputed for this release. | 0 | Requires supervised live ROS execution with the shared telemetry collector kept healthy for the full sequence.; Requires raw evidence for normal flow, deny, forged and replay drop, oversized drop, unchanged parameter, guard zero, authenticated release, and recovered motion. |
| Room-level autonomous IP-blocking deployment | blocked | The current release is not qualified for autonomous room-level IP blocking or Raspberry Pi gateway deployment. | 0 | No independent sealed final holdout decision has authorized the candidate.; No trusted ROS or DDS identity-to-source-IP attribution has been demonstrated.; The nine local live outcomes and two-ended live SROS2 outcomes remain incomplete.; No isolated two-physical-host cross-host acceptance has been completed.; No real nftables forward-path timeout, expiry, restart recovery, and rollback acceptance has been completed.; No Raspberry Pi 5 latency, memory, temperature, packet-drop, and 60-minute soak acceptance has been completed. |

## Claim details

### Evidence for `formal_campaign_manifest`

- `firewall_lab/campaign_1100.json` — 402585 bytes, SHA-256 `2ff3f597a1ef7074213fdf4e1fe213c4f65ff4829e9b0529115dfc764de4b7db` (Pinned campaign manifest with 1,100 complete entries)

### Limitations for `formal_campaign_manifest`

- Manifest completeness does not by itself prove cross-host, Raspberry Pi, or kernel-firewall behavior.
- One post-manifest artifact integrity anomaly is handled by a separate exclusion policy.

### Evidence for `dataset_integrity_exclusion`

- `firewall_lab/dataset_exclusions.v1.json` — 1185 bytes, SHA-256 `9dffa6a361fff27e1cd9353a2249ebc0fa5b0f1f1e436eb3eea0a54e376aa35e` (Externally recorded fail-closed exclusion with pinned manifest and observed digests)

### Limitations for `dataset_integrity_exclusion`

- The raw session is preserved for audit and is not repaired or relabelled.
- The exclusion policy does not establish that the remaining data represent enterprise field traffic.

### Evidence for `hierarchical_candidate_contract`

- `firewall_lab/hierarchical_model.py` — 28011 bytes, SHA-256 `75ff196c659db43081f7c3cc8726add2dbaa53a88ba2bf3532628d2610bf8e08` (Runtime hierarchical model contract)
- `firewall_lab/hierarchical_training.py` — 56647 bytes, SHA-256 `3b5af37ce941e23f002f2c8c36c9abe9fdb2db8e6daa8e0203f25bb028210b4c` (Session-disjoint candidate training pipeline)
- `tests/test_hierarchical_model.py` — 20884 bytes, SHA-256 `061620e3208472bb3151f075d18df62694592a81be2d7b122ae3f1b3efa72ffb` (Dedicated fail-closed and split-integrity regression tests)
- `文件/可重現性稽核_2026-08-17.json` — 19106 bytes, SHA-256 `2203951f1c552ab36981b5b0a30dde7def1fe85326c6b9fcfc83de44c87b1c38` (Full offline suite execution record)

### Limitations for `hierarchical_candidate_contract`

- The candidate remains observe-only and is not deployment eligible.
- Validation metrics are not an independent final test and do not prove safe autonomous blocking.

### Evidence for `development_evaluation_contract`

- `firewall_lab/development_evaluation.py` — 50139 bytes, SHA-256 `2f89b781a3c5f7833ef920d2c606c8f6e5162f64e8344d2e626e8975b20585fe` (Frozen development evaluation implementation)
- `tests/test_development_evaluation.py` — 10201 bytes, SHA-256 `5ccf978ade6e550e5c130edcc4be367db964151beabe4a47928a71769a52c94e` (Evaluation split and test-access safeguards)
- `文件/可重現性稽核_2026-08-17.json` — 19106 bytes, SHA-256 `2203951f1c552ab36981b5b0a30dde7def1fe85326c6b9fcfc83de44c87b1c38` (Full offline suite execution record)

### Limitations for `development_evaluation_contract`

- These are development-validation procedures and not a sealed independent final evaluation.
- No result from this claim authorizes a response adapter or network block.

### Evidence for `direct_delivery_verifier_contract`

- `firewall_lab/sros2_delivery_evidence.py` — 35014 bytes, SHA-256 `2235745f394bc314f58764fcc477295842b7e83e480becae8f8962fc549833ee` (Bounded two-ended direct-delivery verifier and aggregator)
- `tests/test_sros2_delivery_evidence.py` — 18811 bytes, SHA-256 `48ebfa4b1ab6e5d70ccd27d38cdc00c6d20bd05c9af5b8c882373bdbb8c98eb5` (Verifier integrity, identity, timing, and fail-closed tests)
- `文件/可重現性稽核_2026-08-17.json` — 19106 bytes, SHA-256 `2203951f1c552ab36981b5b0a30dde7def1fe85326c6b9fcfc83de44c87b1c38` (Full offline suite execution record)

### Limitations for `direct_delivery_verifier_contract`

- This verifies the verifier implementation, not a live SROS2 allow or deny outcome.
- The verifier deliberately supplies no trusted source-IP attribution.

### Evidence for `reproducibility_and_ledger_tooling`

- `工具腳本/verify_reproducibility.py` — 15968 bytes, SHA-256 `fa6a7135bc5f0ea08343626548051c66b37d74b0bf32f07a72e09a0034b3a99e` (Passive audit with atomic no-overwrite JSON publication)
- `tests/test_verify_reproducibility.py` — 3524 bytes, SHA-256 `459ab2d7199bf34ea5dbf96ff6547b2cd18df85ff289f083f471e9e41b5d39e3` (Atomic publication and overwrite-refusal tests)
- `firewall_lab/project_evidence.py` — 21144 bytes, SHA-256 `af0eecece92a12587c32f867f7d4406a889f4e92c0fbd5743481151de9f38df5` (Fail-closed exact-size and SHA-256 project claim ledger)
- `tests/test_project_evidence.py` — 9996 bytes, SHA-256 `a41e65826bee9a7f8f009a34f4b977b7373696cec09aa849b53fc2d56b18c2fc` (Evidence traversal, tamper, overclaim, and atomicity tests)
- `文件/可重現性稽核_2026-08-17.json` — 19106 bytes, SHA-256 `2203951f1c552ab36981b5b0a30dde7def1fe85326c6b9fcfc83de44c87b1c38` (Signed-by-hash audit payload with exact test stdout and stderr digests)

### Limitations for `reproducibility_and_ledger_tooling`

- The test run emitted 268 documented warnings: three calibration sample-weight warnings and 265 NumPy deprecation warnings.
- File hashes are integrity observations, not cryptographic signatures or trusted remote attestation.

### Limitations for `live_sros2_delivery_outcome`

- Historical logs and vendor security messages cannot substitute for two-ended delivery evidence.

### Limitations for `nine_local_live_outcomes`

- Offline unit tests and synthetic sessions do not count as the nine live outcomes.

### Limitations for `room_firewall_deployment`

- The current artifacts authorize observation and offline verification only.
- A local Administrator or root process remains outside the demonstrated protection boundary.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization. 
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
