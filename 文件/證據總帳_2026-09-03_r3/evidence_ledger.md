# Project evidence ledger

- Project: `sros2_intelligent_firewall`
- Revision: `r3-2026-09-03-refresh640-independent-test`
- Generated (UTC): `2026-09-03T14:02:27.049002+00:00`
- Claims: verified 2, provisional 5, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| Credentialed-insider scenarios are wired fail-closed and Enforce-only | verified | Two insider runners receive the SROS2 keystore but never the HMAC secret or the telemetry socket, so the threat model (SROS2 admits, the application layer blocks) is structural rather than asserted. They are refused outside Enforce because under Permissive SROS2 admits everyone and stolen credentials grant nothing. | 3 | — |
| Attack-surface expansion is gated on exclusive evidence, not on the attack running | verified | Before a candidate attack class is promoted into the shipping catalog it must leave at least one telemetry signal that normal traffic never produces. Signals are encoded as event type, per-field tokens and same-event field pairs; a candidate that only triggers the generic reaction of the defence is refused. | 4 | — |
| Under Enforce no attack class leaves an exclusive application-layer signal | provisional | Measured over 12 sessions per class per mode: each of the eight attack classes has 3 to 17 exclusive signals under Permissive and zero under Enforce, while normal traffic produces 50 to 52 signal kinds in both modes. This is a structural explanation for the identification gap, not a model-capacity limit. | 2 | — |
| First genuinely independent final test: Permissive 0.8502 over 15 classes | provisional | 640 fresh sessions with no overlap with the existing 1,100 were collected, split anew, and the test partition opened exactly once. Permissive reaches balanced accuracy 0.8502 and macro F1 0.8528 over 15 classes, clearing the 0.80 gate. Enforce reaches 0.2819 over 17 classes. | 1 | — |
| Open-set protocol run correctly end to end for the first time | provisional | Fresh data, scorer selected on validation family-LOO only, holdout spent once. Enforce reaches open-set recall 0.8475 with 0.0103 normal false-unknown, clearing 0.70. Permissive reaches 0.5479 and does not clear it. | 3 | — |
| The identity channel is refused as a model feature because it manufactures a blind spot | provisional | On the full 340-session 17-class table the identity channel changes unseen-outsider gate recall by at most 0.013 in either direction, with 0.0000 normal false-positive in both arms, while costing 0.2125 recall against unseen credentialed insiders. The model learns that a zero identity signal implies normal, and a successful insider is exactly zero. | 5 | — |
| Cross-host identity-to-IP attribution with a fourth link-layer rule | provisional | 79 of 80 unattended rounds over eight hours produced attestation against 79 distinct attacker GUIDs with zero false attribution of the defender own address. A fourth admission rule compares observed source MAC against the ARP resolution of the defender, closing a hole where a source-address forgery would have caused an innocent host to be declared blockable. | 5 | — |
| Room-level autonomous IP blocking | blocked | The authoriser, ticket verification, backend and revocation chain passes 7 of 7 on a real ROS runtime, but no class is authorised to execute, no rule points at the DDS guard, and the nftables backend has never actually run. | 1 | executable_classes is the empty list in the shipping policy; zero classes are authorised.; The kernel nftables backend has never been exercised; that needs root and an explicit authorisation.; Source attribution is absent in 0 of 1,101 historical sessions; the cross-host channel is not yet integrated. |

## Claim details

### Evidence for `credentialed_insider_threat_model`

- `firewall_lab/runners.py` — 15914 bytes, SHA-256 `c8e7de1bc16adbb2a70d0bd8a635617ac58c045e0fc1dea57e56fb9aa698a1bb` (CREDENTIALED_RUNNERS allowlist, insider_environment, per-runner session_environment dispatch)
- `firewall_lab/scenarios.json` — 9592 bytes, SHA-256 `701ba0ae9767d7f0bf0ad3c7004649f0ef1318ec80e937b299e9e57c6be7e818` (Insider scenario definitions in the shipping catalog)
- `tests/test_insider_runners.py` — 12307 bytes, SHA-256 `b9be49f531a7afcfec02eedffe4e6a5a2a03e09d303558c02cd13e9e19d1664e` (Secrets-stripped, keystore-only-for-registered-runners and Enforce-only regressions)

### Limitations for `credentialed_insider_threat_model`

- Two attack types over 40 Enforce sessions. The direction is measured; the magnitude is not a population estimate.

### Evidence for `evidence_exclusivity_gate`

- `工具腳本/check_evidence_exclusivity.py` — 13206 bytes, SHA-256 `c1f1a40c74865cde7de8e883927a035406adc1ae72765b0e77e6d8f6a3d6a881` (Gate implementation including the 2026-09-02 field-pair encoding)
- `firewall_lab/catalog.py` — 7209 bytes, SHA-256 `59059292a24303aefac97ec88510ebfb1d750fe1c40e79d00622d09e07134903` (ARCHIVED_COMPLETED_CATALOGS and the promotion path)
- `firewall_lab/session_reader.py` — 7630 bytes, SHA-256 `65033b1ed3629ba2d1236c91a0c2caf940dbe24a370b0928299d7ab5d05b7c85` (Shared session reader whose signal encoding is pinned equal to the gate)
- `tests/test_session_reader.py` — 7062 bytes, SHA-256 `3996ed578bb51ca4088502de3d2b4c2e5ea564e79cbc322b528626984b502332` (13 tests, one asserting the two encodings agree bit for bit)

### Limitations for `evidence_exclusivity_gate`

- Shipping coverage is 17 of 23 policy classes. At least four of the remaining six are structurally unobtainable at this observation layer.

### Evidence for `enforce_has_no_exclusive_signals`

- `文件/Enforce下沒有任何排他訊號_2026-09-02.md` — 5023 bytes, SHA-256 `d34ed48437d70fa1b8431233513dea4928f8ed199de6d80b5b72df838a0172cc` (Full per-class measurement and the 28 of 28 unseparable-pair result)
- `工具腳本/measure_class_separability.py` — 7141 bytes, SHA-256 `739f8e28321f4036e8b8c46f40a430e535c03a3a0c883387265592882d457e59` (Reproduction tool; --dataset is repeatable and any override must be stated explicitly)

### Limitations for `enforce_has_no_exclusive_signals`

- The session corpus lives outside the repository, so this ledger pins the analysis and its tool but not the raw evidence.
- 12 sessions per class. Signal kinds converge well before that, but the count is not a confidence interval.

### Evidence for `independent_final_test_permissive`

- `文件/全量重收結果與第一次獨立test_2026-09-03.md` — 5595 bytes, SHA-256 `b7e7b4cd0716e7aeeffecc3818f17cc3a4526ff3d6da2f50cf304acfc337ebdc` (Collection, data-quality checks, final test and the like-for-like nine-class comparison)

### Limitations for `independent_final_test_permissive`

- Model and feature artifacts live outside the repository; only the analysis is pinned here.
- The new and old Enforce numbers are not the same condition: 20 sessions per class versus roughly 61. This must not be reported as a regression.
- The test partition is now spent. A further independent number requires another collection.

### Evidence for `openset_protocol_first_clean_run`

- `文件/未知攻擊_全新holdout首次評估_2026-09-03.md` — 4415 bytes, SHA-256 `85f500fd07aa442276cb9840b675b37f573946013118fca054d30f28cf9664bf` (Protocol, selection table, holdout result and the three disclosed limits)
- `firewall_lab/stream_replay.py` — 6664 bytes, SHA-256 `f70676a81f5078114f40f95ef68929c3feda640a8c86ed99cb2f8c227b7e9dc6` (Stream-history guard; contiguity gaps reset rather than error, completeness supplied by the caller)
- `tests/test_stream_replay.py` — 6013 bytes, SHA-256 `ad8c30f647b404974804c803c99d02fd1f58350a5c3b10fd8d29e046c821bbf0` (Regressions including one reproducing the original filter-before-feed defect)

### Limitations for `openset_protocol_first_clean_run`

- The scorer used is Mahalanobis, not the shipping default. The shipping default cannot be back-evaluated because the holdout is spent.
- Permissive does not clear the gate and there is no known remedy at this observation layer.
- worst_family_unknown_recall is 0.0000 in all four LOO configurations: a good macro does not mean every family is covered.

### Evidence for `identity_feature_rejected`

- `文件/身份特徵是盲點製造機_2026-09-03.md` — 5079 bytes, SHA-256 `4b371a381299b682d778739a069bd306710aa3eea5846793311a2a3f23b95ca8` (Six leave-out configurations, the mechanism, and the retraction of the 2026-09-01 recommendation)
- `文件/身份通道對持證內鬼無效_2026-09-01.md` — 7159 bytes, SHA-256 `85ec3f3235c06971d28b470d53e89bbdce984be84325986cec1003ae22f827f2` (80-session insider control with positive and negative controls)
- `文件/身份通道只在Enforce有意義_2026-09-03.md` — 4090 bytes, SHA-256 `90b476b92fff4a6b7a3edc24f316bffdf4006d7268dd03b2f006bb23ff2954cc` (Permissive per-class deny medians showing no discriminative power)
- `工具腳本/measure_unseen_gate_recall.py` — 6962 bytes, SHA-256 `e20565189e96ad10ae367084e3839179b6b8fd6ad0b0de3345dee2854c910649` (Reproduction tool)
- `工具腳本/measure_insider_channel_silence.py` — 11258 bytes, SHA-256 `44bf23a0e0c6cac8944e8c9775d67cc78ae032ee255f5da965886090882efa53` (Insider-silence measurement with its three hard preconditions)

### Limitations for `identity_feature_rejected`

- Validation partition only; the test partition was not touched for this measurement.
- Two insider attack types over 40 sessions. The sign is credible, the magnitude is not.
- The cause of the disappearing benefit is not isolated: the full table differs in both class count and session count.

### Evidence for `cross_host_identity_attribution`

- `文件/跨主機批次結果_79場_2026-08-30.md` — 9693 bytes, SHA-256 `0e21766867b77e3d3d6548cb1e23e5283163d2bde789842b01cbd3540ea2bd44` (Batch result, negative control and soak)
- `文件/來源位址偽造加固_2026-08-31.md` — 8009 bytes, SHA-256 `da8fc13c88da25cb86e4bbbc874bf53bfb0c189775bf9a9d2f4a9250faa96e8e` (Fourth rule, three-level verdict and the 80 of 80 re-verification with zero retraction)
- `工具腳本/check_link_layer_binding.py` — 11270 bytes, SHA-256 `e68f6a3d153791da50992290febdaee8ec7017ef2397068a0829076611a27c50` (Passive link-layer binding check)
- `工具腳本/crosscheck_identity_attribution.py` — 15706 bytes, SHA-256 `35791acb01d24a1b05be4cbf75fdd26e1f1ec17b30ff1b430244408fd9420a41` (Four-rule admission cross-check, report schema v2)
- `tests/test_identity_crosscheck.py` — 26037 bytes, SHA-256 `70c3fc409354e69f481922bea22bb527e33f2cede616622afe6f3c7bc7c7c308` (Fail-closed regressions for all four rules)

### Limitations for `cross_host_identity_attribution`

- One attack type. 79 rounds is repetition, not attack-surface coverage.
- Same-subnet Wi-Fi with multicast measured unreachable; unicast initial peer throughout.
- No positive control: it is shown that a hostile remote is blocked, not that a legitimate remote is spared.
- Not integrated into the feature set. authorizes_action remains false.

### Evidence for `autonomous_ip_block`

- `firewall_lab/live_telemetry_collector.py` — 37073 bytes, SHA-256 `f0c5ea8de50eda8e4122ac78463cadb2e8ceae1206bde9683b26d0354fcb9ffd` (Collector schema, including the optional-detail asymmetry that keeps historical sessions readable)

### Limitations for `autonomous_ip_block`

- This claim is recorded as blocked so the ledger cannot be read as deployment readiness.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
