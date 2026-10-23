# Project evidence ledger

- Project: `sros2_intelligent_firewall`
- Revision: `r5-2026-09-24-kernel-nft-and-pi-gateway`
- Generated (UTC): `2026-09-24T16:53:51.198068+00:00`
- Claims: verified 4, provisional 3, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| nftables backend accepted against a real kernel, nine of nine | verified | The response backend was exercised against a real Linux kernel nftables table on a Raspberry Pi 5 and passed all nine required live checks with production_ready=True. The run found five defects that offline tests could not reach, three of which would have made the production backend throw on every call: the rule-expression contract was written in nft input syntax rather than the shape the kernel renders, the timeout set was read as milliseconds while the kernel reports seconds, and reconcile() compared expiry instants at nanosecond exactness that the adapter's granularity can never satisfy. A fourth defect was mine: the anti-lockout guard read SSH_CONNECTION, which sudo strips, so it was a silent no-op; it now reads the kernel socket table. | 11 | — |
| The defence stack runs on the Pi under Enforce | provisional | Eight defence nodes each started under SROS2 Enforce on the Pi with zero SECURITY Error lines, four ran concurrently, and a signed security alert crossed from the monitor process to the velocity guard, which locked zero velocity. The HMAC key was generated on the Pi rather than copied from the laptop, and the keystore and its fourteen enclaves were produced there. A transient ros2cli node was refused by SROS2, which is the defence working. | 1 | — |
| The campaign's row ceiling is arithmetic, not overhead | verified | A read-only decomposition of session wall clock disproved the earlier claim that sixty percent of it was schedulable overhead. Session duration tracks capture volume (inside ~ 85.7s + 0.376 s/MB), and the row ceiling follows from the window length rather than from scheduling: about 450 rows per hour at eight-second windows, so a hundred thousand rows is roughly 9.6 days of continuous running. The pace circuit breaker was rewritten to compare a residual against that volume model, because an absolute threshold fires on any batch of heavy scenarios. | 7 | — |
| Two campaign-collapse defects: a clock origin and a gate's blast radius | verified | Adaptive attack sessions were being SIGKILLed and losing their whole decision trace. The budget was measured from the point the module began running, while the factory measured from Popen, and 4.85 seconds of interpreter boot sat between them; the factory now hands the driver an absolute CLOCK_MONOTONIC deadline. Separately, one session failing the training gate raised and aborted a batch of forty, so a single ineligible session cost thirty-nine good ones; the gate now records status=ineligible and continues, fail-closed on a rate rather than on the first occurrence. The gate itself was not relaxed -- ineligible sessions still carry training_eligible: false. | 8 | — |
| worst_family is not a resolution artifact, and the scorer choice reverses on new data | provisional | The family-LOO worst-family unknown recall of 0.0000 survives a 5.7x increase in resolution, so it is not a small-sample artifact; macro barely moved (0.5592 -> 0.5541), which also says the older validation subset was representative. The two modes fail differently: under Permissive the OOD head rejects nothing while the binary gate scores the held family at 1.0000, and under Enforce the head rejects 98.5% while the gate vetoes 88%. Switching Permissive to max_softmax moves worst-family from 0.0000 to 0.9216 with a lower normal false-unknown rate, and on C2C-028's own adversarial worst-case protocol max_softmax now wins Permissive 0.9212 to Mahalanobis 0.4514 -- the reverse of what that protocol concluded on the older data. | 12 | — |
| Cross-host DDS identity bound to a source IP, with a link-layer check | provisional | Across an unattended eight-hour batch, 79 of 80 rounds produced a verified identity-to-IP attribution for a wrong-CA participant, with 79 distinct GUIDs and zero rounds misjudging the defender's own address as blockable. A fourth decision condition added afterwards -- link-layer binding, which rejects source-address spoofing -- was applied retroactively to that batch with zero retractions, and was later exercised against real spoofed traffic. | 6 | — |
| Nothing in this revision opened an executable path | verified | Across this revision's live work -- a real-kernel nftables acceptance, a Pi running the defence stack under Enforce, and a running campaign -- no shipping default was relaxed. action_policy.json authorises zero classes, LIVE_NFT_ACTIVATION_ALLOWED is False, and the decision layer forces every executable verdict back to alert while deployment_eligible is false. | 3 | — |
| Room-level autonomous IP blocking | blocked | The system does not autonomously block a source IP. Three of the four components now have live evidence -- attribution, a signed revocable ticket chain, and a real-kernel nftables backend -- but they have never run as one chain, and the model side cannot reach the backend by design. | 1 | No end-to-end run exists: attack, attribution, block, revoke has never executed as a single chain. Doing so needs both machines, and the laptop is occupied by the campaign.; executable_classes is empty and no policy rule points at dds_guard, so no model verdict can reach a backend.; Source attribution holds for 0 of the 1,101 existing dataset sessions; the cross-host evidence is a separate, purpose-built batch.; The identification model reaches 0.2819 balanced accuracy under Enforce on the last independent test, far below the 0.80 deployment gate. |

## Claim details

### Evidence for `nft_kernel_live_acceptance`

- `工具腳本/run_nft_live_acceptance.py` — 30896 bytes, SHA-256 `a278b4d9a9f40628b405d8e289ee556447eff6cce058ea7ce2fa850e37ffa515` (Bounded acceptance-only executor; issues its own ticket, never a model decision)
- `firewall_lab/nft_backend_service.py` — 46154 bytes, SHA-256 `951ccfeaff539701f6aea222763c42a26158a597df5141cf9780c4a59e0c5bfc` (Kernel-rendered rule contract, seconds-based timeout parsing, NFT_JSON_SCHEMA_VERSION fail-closed)
- `firewall_lab/response_backend.py` — 47053 bytes, SHA-256 `2cb6931a09ff5e0708fbf8885485e56319ce159672517a40e31d29f590817cbb` (TimeoutSetAdapter.expiry_matches; reconcile compares at the adapter's own granularity)
- `tests/test_nft_kernel_rule_contract.py` — 8044 bytes, SHA-256 `2ad4779af79a60c8ae41e1a4650cef1fa9cceb618d3482104c3f2976d9342cd2` (Rule expression must match what the kernel renders, not what nft accepts as input)
- `tests/test_nft_kernel_timeout_units.py` — 8884 bytes, SHA-256 `1f64026d86be14a163c89f7910358fd452003bd30e2e9f7d2eb9000549bc6b74` (Timeout units pinned to seconds with a schema-version fail-closed)
- `tests/test_nft_live_acceptance_executor.py` — 16934 bytes, SHA-256 `d1019e40c0920ab7e74ecdb3ed304ddba3e443d8f0f52afca6376e8e669f0d63` (Executor bounds: phrase gate, anti-lockout from the socket table, refuse-to-overwrite)
- `tests/test_nft_live_acceptance_rehearsal.py` — 7257 bytes, SHA-256 `2489863a2cd64486d178c9fc340e027ec7e2399b2fdbe34383105b5f46c2fdb8` (Offline rehearsal of ticket issuance, so the live run is not the first execution)
- `tests/test_reconcile_expiry_granularity.py` — 7259 bytes, SHA-256 `8bd4f6a80d798dfd30cab31b8fb79481e647b3e877e6481247ab2229d2b616c5` (Exact-by-default expiry comparison with an explicit adapter override)
- `文件/nft驗收_真核心九項通過_2026-09-24.md` — 5548 bytes, SHA-256 `380d1ed21543f7dd8d7e6b09a45346c7d2ea2daef2e93198129d13c700a9ba82` (Run narrative, the five defects, and what the nine checks do and do not prove)
- `文件/nft驗收_2026-09-24/nft-live-acceptance.json` — 2147 bytes, SHA-256 `2de64dcb13adb4ed2cc5e7b045bbaeaeefc1f8f73527acc4bdced4dea66a6fbe` (The acceptance report itself: nine checks, production_ready=True)
- `文件/nft驗收_2026-09-24/nft-live-acceptance.json.provenance.json` — 468 bytes, SHA-256 `26d7550b2d8eec77be8cfc7cc6b9e78248a14d8c1b4f70f0b5f0e26d5fe9ee89` (Provenance record for the acceptance report)

### Limitations for `nft_kernel_live_acceptance`

- The ticket was signed by the acceptance executor, not produced by a model decision. LIVE_NFT_ACTIVATION_ALLOWED stays False and executable_classes stays empty, so nothing in the shipping path can reach this backend.
- One host, one run, no soak. The nft table was torn down and the default route restored; the checks prove the mechanism, not sustained operation.

### Evidence for `pi_ros_gateway_enforce`

- `文件/Pi當ROS閘道_2026-09-24.md` — 4021 bytes, SHA-256 `e0f13bf091bbb2b696c391d0ef71868ca2062935ef7b38d49885759bc01b35ce` (Per-check results, the two environment findings, and what may not be claimed)

### Limitations for `pi_ros_gateway_enforce`

- The Pi-side artifacts (keystore, logs, build tree) are not in this repo, so this ledger pins the analysis and not the raw evidence.
- The detection that fired was caused by my own start order and a leftover ros2 daemon. Detection, signing, delivery and locking all really executed, so it is a mechanism verification -- it is not a real attack being caught.
- All six IDS detectors scored zero because there is no Gazebo on the Pi (odom_hist=0, scan_hist=0). The IDS starts and polls but sees nothing.
- Each node ran for twelve seconds. This is not a soak.
- The two machines run different ROS versions: Pi has sros2 0.13.6 and Fast DDS 2.14.6, the laptop has 0.13.5 and 2.14.5.

### Evidence for `campaign_throughput_is_arithmetic`

- `工具腳本/measure_campaign_throughput.py` — 15400 bytes, SHA-256 `e3174d15dad3440fbddd26172ff7544c0e5e091561f939c015e099748135c7c0` (Read-only decomposition: gap classification, telemetry and pcap spans, arithmetic ceiling)
- `工具腳本/recent_session_pace.py` — 6309 bytes, SHA-256 `ed77e05c2698ee50b649d55235fcc8db41c8a2127630484035ac9ad7355fa208` (Volume-aware pace guard; exit 0 ok / 4 slow / 2 unreadable)
- `工具腳本/run_mega_campaign.sh` — 14487 bytes, SHA-256 `72bbba80dcf843895db99352eeecc3aefff88a10d8859597e90cdbb58f0e7e67` (Supervisor wiring, MAX_SLOW_BATCHES, and the residual threshold)
- `tests/test_campaign_throughput.py` — 15671 bytes, SHA-256 `02aac1a63649b2231c1ca932bf7550212a8b2d83eb63e2834008b594220358da` (Decomposition regressions including the absolute stall threshold)
- `tests/test_session_pace_guard.py` — 11323 bytes, SHA-256 `6e59b74adf2bea351f3f12c7557c7f8a0d50ff6816a4ce71fb80178f77fd621a` (Guard regressions; six of them are volume-aware after the fixtures gained capture sizes)
- `tests/test_pace_threshold_units.py` — 3829 bytes, SHA-256 `7c81665a9ded081a42cd284b0164747db5f0079b08551e0f65a6769b7a91d6fe` (The supervisor's threshold must equal the tool's default and be read as a residual)
- `文件/大型campaign產能_上限是算術不是開銷_2026-09-24.md` — 9073 bytes, SHA-256 `ae6657d53cf6220e22706a562fd87ad9fa436d25f82c0570cf50a381aecc2bbc` (The measurement, the disproved hypothesis, and the corrected ceiling)

### Limitations for `campaign_throughput_is_arithmetic`

- The volume model was fitted on 503 sessions from one machine under one configuration. The slope is a local regression, not a portable constant.
- The running supervisor still carries the stale 200s threshold; bash reads a script as it executes it, so the corrected value only takes effect on the next restart.

### Evidence for `attacker_clock_origin_and_gate_blast_radius`

- `firewall_lab/orchestrator.py` — 41926 bytes, SHA-256 `e80bce8a021da994ee9e4442556dfcec20eb01e43a1873f050af5d350a2706d1` (ATTACK_DEADLINE_ENV computed next to Popen so both sides read the same clock)
- `firewall_lab/campaign.py` — 43888 bytes, SHA-256 `0a1dc7d06aeaaaa4909555ba30f9bd704390a3c0f5352ff04f2642e5ecd78f26` (status=ineligible, rate-based abort, repair --reset-ineligible)
- `紅隊測試/PoC腳本/N37_adaptive_attacker.py` — 20691 bytes, SHA-256 `bcff720bb83e4e2dbc0e4969c04f9034070edb024e1291fcbef3d352258a7b9d` (Evidence printed before teardown, bounded close on a daemon thread, hard-deadline watchdog)
- `tests/test_attack_deadline_handoff.py` — 6593 bytes, SHA-256 `28326bff0baae3fdfcccc7f9aab8b47ba56ecf22d03e4bd4380fcb1ab99a01fc` (The deadline must cross the process boundary and be read, not recomputed)
- `tests/test_adaptive_attacker_watchdog.py` — 12139 bytes, SHA-256 `e0539d0817c45204a193a92027a59bc629e884dd3ae634b39ba06a7dfa3e8f3b` (Watchdog fires inside the factory window; signal delivery limits are asserted)
- `tests/test_adaptive_attacker_budget.py` — 7930 bytes, SHA-256 `e958da9c9625012f75cb7d17f9e9a806dc5bde58aac98f3531695c95db57b8cf` (Budget starts at process start, and the burst exit reserve covers child reaping)
- `tests/test_campaign_gate_blast_radius.py` — 8234 bytes, SHA-256 `4319726b8e049679a7983e76b8c9ae36aee5ef5ee05a517d4f33d3aa5672d8dc` (One ineligible session must not cost the batch, and the rate guard must still bite)
- `文件/campaign產能塌陷_訓練閘的爆炸半徑_2026-09-24.md` — 7874 bytes, SHA-256 `154e658a0f2229b65220266c59c86e630141927ca68f496a89ac11359973bc9a` (Both defects, the three wrong hypotheses discarded on the way, and the corrections)

### Limitations for `attacker_clock_origin_and_gate_blast_radius`

- Three of the four rounds chasing the SIGKILLs were on the wrong side of the line. Two claims made during them were later corrected in CLAUDE.md (C2C-072 and C2C-073); those corrections are part of this record.
- Sessions already written to disk under the old judgement are not recomputed. Their manifests record the judgement in force at the time.

### Evidence for `unknown_attack_resolution_and_scorer`

- `工具腳本/evaluate_unknown_at_full_resolution.py` — 22345 bytes, SHA-256 `8a4146544e2c74642346f9ef787d1d7f41f821e615340aff075d6eab712617a1` (Full-resolution LOO with a bit-for-bit equivalence guard against the existing artifacts)
- `工具腳本/measure_novelty_separability.py` — 7864 bytes, SHA-256 `09e1b854eece415a57b9781cf2468d26e3c27208815923c0b751b9551390bea7` (Per-feature Mann-Whitney AUC of the held family against known attacks; no model fitting)
- `工具腳本/compare_ood_worst_case.py` — 9958 bytes, SHA-256 `6640fcf977d2aa50908ef71c7f55a1fcf7abf4eb6c92beebbab11bd87cc898b4` (C2C-028's adversarial protocol reproduced: each candidate's worst two classes become a holdout)
- `文件/未知攻擊_解析度與評分器_2026-09-24.md` — 9018 bytes, SHA-256 `e5e0a2cf7c1893b13d58bdcc87cfb6b5390dfa420174620fe1ee7ecc8fdc93e4` (The four rounds, the half-wrong prediction, and what may not be claimed)
- `文件/未知攻擊_2026-09-24/unknown_fullres_permissive_maha.json` — 8514 bytes, SHA-256 `8389c3468ad93339d8b8ddbf238cfe8424972f2cab679d25f9854132017ca256` (Permissive / Mahalanobis at both resolutions with the gate path decomposition)
- `文件/未知攻擊_2026-09-24/unknown_fullres_permissive_msp.json` — 8870 bytes, SHA-256 `defddc99622475ed91ffeeee953b2634f09a5c88cfff122ba33209ce9f40d2b6` (Permissive / max_softmax)
- `文件/未知攻擊_2026-09-24/unknown_fullres_permissive_if.json` — 8139 bytes, SHA-256 `aca815e8219beb7b08e75c854267f31ece64f32195955fad0c8a533555c0e4ce` (Permissive / isolation_forest -- the half that disproved my density prediction)
- `文件/未知攻擊_2026-09-24/unknown_fullres_enforce_maha.json` — 8473 bytes, SHA-256 `9f481f593eaaeeafe2064fee507fdac595288523482f41a1e306a47c420e7324` (Enforce / Mahalanobis)
- `文件/未知攻擊_2026-09-24/unknown_fullres_enforce_msp.json` — 8752 bytes, SHA-256 `e22369f213b34bc1aa8f8e9a30e1b2ed2329521a620abd88fbe22df5223f0040` (Enforce / max_softmax)
- `文件/未知攻擊_2026-09-24/novelty_sep_permissive.json` — 10582 bytes, SHA-256 `56c2e4c0850fde4f793934ac3105cec2ff75ef5734888d0cd415e7bd96aee672` (Per-feature separability ceiling per held family)
- `文件/未知攻擊_2026-09-24/ood_worstcase_permissive.json` — 3005 bytes, SHA-256 `04d8bcf448b6340bc364e9585412d8c38ea766f5cc7e982cf46d14def885caa4` (Adversarial worst case, Permissive)
- `文件/未知攻擊_2026-09-24/ood_worstcase_enforce.json` — 3198 bytes, SHA-256 `df944905b71a3aef3dc1c55baed0941119bab268097aa6f710508c2d4ba71560` (Adversarial worst case, Enforce -- contradicts the gate metrics, so no conclusion)

### Limitations for `unknown_attack_resolution_and_scorer`

- Everything here is family-LOO over train and validation. No test row was read and the official novelty holdout was excluded, so none of it is a held-out number and no percentage moves.
- The shipping scorer is still isolation_forest. Permissive = max_softmax is frozen as a pre-registered setting for the next holdout, not a change.
- A combined density-plus-confidence score is registered as a prior hypothesis and explicitly not claimed: the idea came from looking at the comparison table, which is the reason C2C-028 rejected the same idea.
- Enforce is undecided. Its two measurements contradict each other and the real constraint there is the gate vetoing 88% of the head's rejections.
- The explanation for the reversal -- that C2C-028 ran on data whose network features were corrupted (Zeek without -C, conn_count inflated 7.96x) -- was not tested.

### Evidence for `cross_host_identity_attribution`

- `工具腳本/crosscheck_identity_attribution.py` — 15706 bytes, SHA-256 `35791acb01d24a1b05be4cbf75fdd26e1f1ec17b30ff1b430244408fd9420a41` (Four-condition blockability decision; absence of evidence never justifies a block)
- `工具腳本/check_link_layer_binding.py` — 11270 bytes, SHA-256 `e68f6a3d153791da50992290febdaee8ec7017ef2397068a0829076611a27c50` (Passive three-way verdict from Ethernet headers: consistent / spoofing_evidence / unverifiable)
- `tests/test_identity_crosscheck.py` — 26037 bytes, SHA-256 `70c3fc409354e69f481922bea22bb527e33f2cede616622afe6f3c7bc7c7c308` (Regressions for all four conditions, including the fail-closed without link-layer evidence)
- `文件/跨主機批次結果_79場_2026-08-30.md` — 9693 bytes, SHA-256 `0e21766867b77e3d3d6548cb1e23e5283163d2bde789842b01cbd3540ea2bd44` (The batch, the negative control, and the soak)
- `文件/來源位址偽造加固_2026-08-31.md` — 8009 bytes, SHA-256 `da8fc13c88da25cb86e4bbbc874bf53bfb0c189775bf9a9d2f4a9250faa96e8e` (The fourth condition and the retroactive recheck)
- `文件/N31偽造來源_live結果_2026-09-01.md` — 6336 bytes, SHA-256 `8683c390c1780f800897e052222d324ec724944cd67eb375e068e57aa4e5b0c9` (Live spoofing test; the weak form and why I stopped there)

### Limitations for `cross_host_identity_attribution`

- One attack type, same-segment Wi-Fi with multicast unreachable, no positive control, and authorizes_action stays false.
- The identity signal is still not integrated into the feature table, and the 2026-09-04 audit argues it should not be: it is a defence-reaction feature and credentialed insiders sit exactly where it reads zero.
- The spoofing test reached the weak form (unverifiable) rather than positive spoofing evidence, because the defender sent no packets to the forged address.

### Evidence for `shipping_defaults_unchanged`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (executable_classes is an empty list against 23 rules)
- `firewall_lab/decision.py` — 14552 bytes, SHA-256 `e5aa89ef9372e52bd16b29b387e1899bd101f9a3c41e281af50aa50e8da850e4` (Absent or empty allowlist means nothing executes; unknown-anomaly response needs two independent gates)
- `firewall_lab/scenarios.json` — 11964 bytes, SHA-256 `d481ef27943c340098fc06e2c13e07453779f86bdb7da549d9438cfccc702a48` (Shipping catalog, 19 scenarios, unchanged during this revision)

### Limitations for `shipping_defaults_unchanged`

- This claim is about configuration, not about whether the system would behave safely if those defaults were opened. The acceptance run signed its own ticket precisely because no model decision can reach the backend.

### Evidence for `autonomous_ip_block`

- `文件/nft驗收_真核心九項通過_2026-09-24.md` — 5548 bytes, SHA-256 `380d1ed21543f7dd8d7e6b09a45346c7d2ea2daef2e93198129d13c700a9ba82` (The backend component, accepted in isolation with production_ready=True)

### Limitations for `autonomous_ip_block`

- Recorded as blocked rather than omitted, so the ledger cannot be read as deployment-ready by leaving the hardest claim out.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
