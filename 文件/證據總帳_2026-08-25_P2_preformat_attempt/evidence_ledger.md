# Project evidence ledger

- Project: `sros2_room_firewall`
- Revision: `p2-2026-08-25-identity-attribution-session-conformal`
- Generated (UTC): `2026-08-25T05:41:04.140237+00:00`
- Claims: verified 3, provisional 1, blocked 2
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| Fail-closed RTPS and DDS identity evidence contract | verified | P2 defines strict SPDP locator, SEDP endpoint and authenticated-identity records bound to one session, capture, decoder, policy, collector, interface, IPv4 source and ordered timeline; ambiguous, incomplete, reordered or mixed-lineage records are rejected. | 3 | — |
| Current campaign identity-attribution observability | provisional | The passive P2 inventory found 1101 session directories, including 1100 sessions with PCAP and Zeek conn.log, but zero sessions with decoded RTPS identity, independent identity attestation, DDS security audit, or the required Zeek identity fields. | 1 | No current session has rtps_identity.jsonl, identity_attestation.json or dds_security_audit.jsonl.; Zeek five-tuples do not expose GUID, entity, topic or authenticated identity subject.; Same-host WSL mirrored addressing cannot establish a unique external attacker source. |
| Session-max split conformal development contract | verified | P2 implements conservative split-conformal p-values from one maximum nonconformity score per calibration session, enforces finite-sample alpha resolution, and rejects calibration-to-holdout group overlap using hashed group identities. | 3 | — |
| Current conformal calibration readiness | blocked | Neither security mode has enough registered calibration sessions to resolve normality alpha 0.02 and known-attack alpha 0.05; even the non-independent calibration-plus-threshold development pools remain short of normality resolution. | 2 | Permissive registered calibration needs 27 additional normal and 4 additional known-attack sessions.; Enforce registered calibration needs 24 additional normal and 1 additional known-attack session.; The expanded development pool still needs 8 Permissive and 5 Enforce normal sessions and shares data with threshold selection.; No independent sealed final confirmation partition exists. |
| P2 reproducibility audit | verified | The canonical Ubuntu-24.04 P2 r3 audit verifies all 20 environment, dependency, critical-file and full-suite checks; 665 tests pass under the locked dependency set without starting ROS or generating network traffic. | 2 | — |
| Room-level autonomous IP-blocking deployment | blocked | The P2 checkpoint is not qualified for autonomous room-level IP blocking, isolated cross-host acceptance or Raspberry Pi gateway deployment. | 2 | Trusted participant-to-source-IP attribution is absent in all current sessions.; Conformal calibration does not meet finite-sample resolution and has no independent final confirmation.; P1 family-LOO unknown recall remains below acceptance.; Only five of nine local live outcomes have complete evidence.; No isolated two-host, real nftables forward-path, restart-recovery or Raspberry Pi 5 acceptance exists. |

## Claim details

### Evidence for `rtps_identity_evidence_contract`

- `firewall_lab/identity_attribution.py` — 19165 bytes, SHA-256 `418be48135361e457052758f0fa19896be4370e2e25981b1776e5a506e8950f6` (Strict observation schema, sealed JSONL reader, feature builder and passive readiness audit)
- `firewall_lab/identity_attribution_contract.v1.json` — 1960 bytes, SHA-256 `c8d9d730981d038da6a0a6064f053dbca8bd5ffe25aaca812277407bf5ec739b` (Versioned identity-attribution evidence and acceptance contract)
- `tests/test_identity_attribution.py` — 7088 bytes, SHA-256 `e9abe6e08c5e31b26d48236c9961547276b8fb0c64d75fe5b52018b0546ed779` (Schema, lineage, feature and readiness fail-closed tests)

### Limitations for `rtps_identity_evidence_contract`

- A verified parser and contract do not verify any participant-to-source-IP binding.
- All generated identity feature rows remain development-only and cannot authorize a response.

### Evidence for `current_identity_observability`

- `文件/P2_身份歸因資料稽核_2026-08-25.json` — 1954 bytes, SHA-256 `59ecb929d5545337fcb34934614eb5a922e2384712916b0778eb882d2bd91a42` (Passive manifest and Zeek-header inventory of the current dataset)

### Limitations for `current_identity_observability`

- The inventory does not decode historical PCAP payloads.
- Source attribution requires a trusted independent collector and attestation in a future isolated run.

### Evidence for `session_max_conformal_contract`

- `firewall_lab/session_conformal.py` — 8296 bytes, SHA-256 `a452a45b1a5b9d9c106f575ddc5f0e38293cb70878eb404e2a1bc9bb61d9b6ad` (Session-max calibrator, conservative p-values, resolution and grouped metrics)
- `tests/test_session_conformal.py` — 3840 bytes, SHA-256 `45eeea90ebf7b393adc0a92573b1406821b56750d584ab3820c918fecb642f32` (Finite-sample, tie, grouping, overlap and non-deployment tests)
- `tests/test_conformal_readiness.py` — 3921 bytes, SHA-256 `254ff3e758ae6207125939fb18ab1c5f7d07ace3c1ff3d3a364f9b8d63081ccf` (Readiness protocol, split-disjointness and no-overwrite tests)

### Limitations for `session_max_conformal_contract`

- The implementation is not fitted into a deployable release.
- Passing method tests does not establish useful unknown-attack recall or bounded live false positives.

### Evidence for `conformal_calibration_readiness`

- `文件/P2_Conformal準備度_2026-08-25/permissive.json` — 2523 bytes, SHA-256 `f73be00bcc667ae1bbb6fee69f410a88245d5bfdd1abcdb03f4e0aa0dbf64ee1` (Permissive registered and expanded development calibration counts)
- `文件/P2_Conformal準備度_2026-08-25/enforce.json` — 2527 bytes, SHA-256 `39a44ccb8ed21048ff852de92aa02de7029a242736558dc580ede10ab4300d31` (Enforce registered and expanded development calibration counts)

### Limitations for `conformal_calibration_readiness`

- Minimum p-value resolution is necessary but not sufficient for model acceptance.
- Historical validation is development evidence and cannot be relabeled as an independent final test.

### Evidence for `p2_reproducibility`

- `文件/可重現性稽核_2026-08-25_P2_verified_r3.json` — 22311 bytes, SHA-256 `725c3cf6cc4186dbe6eef5d3d3245b8d1fb48d3aec9cf9d8327beb2c27b08dee` (Canonical P2 audit with 20 of 20 checks and the 665-test run)
- `文件/P2_身份歸因與SessionConformal_2026-08-25.md` — 6134 bytes, SHA-256 `a7d6117cfe82c826fc2dbacf543746bb3b05567181c79810304bce7d247ecdad` (P2 method, evidence, blockers and progress report)

### Limitations for `p2_reproducibility`

- The 265 warnings are NumPy deprecations emitted while loading existing joblib artifacts.
- Offline tests and file hashes are not live ROS, cross-host, kernel nftables or Raspberry Pi evidence.

### Evidence for `room_firewall_deployment`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (Shipping policy with executable_classes still empty)
- `文件/P2_身份歸因資料稽核_2026-08-25.json` — 1954 bytes, SHA-256 `59ecb929d5545337fcb34934614eb5a922e2384712916b0778eb882d2bd91a42` (Identity source attribution and readiness flags remain false)

### Limitations for `room_firewall_deployment`

- All P2 artifacts authorize observation and offline verification only.
- No live network, ROS, attack or firewall action was performed during P2.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
