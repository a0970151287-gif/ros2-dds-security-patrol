# Project evidence ledger

- Project: `sros2-smart-firewall`
- Revision: `r9-2026-10-19-thirteen-rounds-of-pre-registration`
- Generated (UTC): `2026-10-18T21:32:17.035722+00:00`
- Claims: verified 10, provisional 0, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| The two classes named as having no exclusive evidence channel sit on opposite channels | verified | A three-arm ablation on the Permissive session-level matrix shows that `identity_abuse` loses 0.354 balanced accuracy when the network columns are zeroed and only 0.021 when the telemetry columns are, while `command_injection` is the exact mirror (network-zeroed 0.4896 -> 0.5625, telemetry-zeroed -> 0.0208). The 2026-08-21 prediction that these two would move together therefore failed not only numerically but in its premise. The gate that produced that statement reads telemetry only, and the network channel was itself broken on that date. | 4 | — |
| In Enforce the whole telemetry layer is worth 0.0009, and one attack class is indistinguishable from benign traffic | verified | Three predictions were written before the measurement. The two security modes are mirrors: Permissive loses 0.299 to telemetry-zeroing and 0.072 to network-zeroing, Enforce loses 0.001 and 0.302. The eighteen-column telemetry layer is therefore worth 0.0009 under Enforce, which deepens the earlier finding that eight classes had no exclusive signal: the problem is not those eight classes but the whole channel. Scanning all 138 non-constant aggregate columns, `hmac_forgery` reaches a maximum separability against `normal` of 0.0507 out of a theoretical 0.5, against 0.5000 for `service_dos` and 0.4994 for `confused_deputy`. The defence still stopped it: eleven forgeries rejected, zero accepted, the next genuine message delivered. | 7 | — |
| The core argument now has a quantitative form, a scope boundary, and three pre-registered attempts | verified | Three measures of per-class separability were each pre-registered in its own commit before being computed, and each was correlated against the sealed-holdout per-class recall. X_old (maximum separability against `normal`) gives Spearman +0.3344 for Permissive, not significant, and +0.6334 for Enforce at p<.01. X_new (minimum separability against the nearest attack neighbour) gives +0.4001 and +0.5968. Their minimum gives +0.7139 at p<.01 for Enforce, the highest in this project, and a control shows the entire +0.1171 gain comes from one class changing places. The third variant, a directional read-out, was falsified: Permissive flips sign to -0.4137. The boundary is explicit: the relationship holds only where the binary task has not saturated. | 12 | — |
| The single-batch ceiling is not a Permissive-only property, and one of my own statistics was wrong | verified | Restricting the large dataset to a single three-hour window reproduces the small dataset's class geometry in Enforce as well: ratio 1.9983 against 1.9234, a relative difference of 3.9%. After controlling for class count the collapse factor is 3.7552 for Enforce against 3.6622 for Permissive, a 2.5% difference, so the batch effect is the same size in both modes. The same round corrected an earlier statement of mine: the figure that the forest beats nearest-neighbour by only 0.045 compared an unbalanced 1-NN score with a balanced forest score. The correct value is +0.1292, so choosing a learner is worth 0.02 while having one is worth 0.13 to 0.16. | 4 | — |
| Under Enforce the adaptive attacker could not adapt, and that is the defence working | verified | Answering a labelling question with existing data required checking the instrument, and the check found something larger. Excluding sessions already recorded as blind, all 9,196 Enforce bursts show zero velocity signal and zero alerts, 1,359 of 1,359 Enforce sessions carry no signal on either channel for their whole duration, and 100.0% of decisions are the single branch 'not noticed, so escalate'. The mechanism is that the observer runs without a keystore, so under Enforce its subscription is created but no protected publisher pairs with it. This extends the earlier count of 113 blind sessions to 1,829, and the new group is recorded by the program as having a healthy observer. The labelling question itself was answered by the pre-registered rule: do not change the label. | 6 | — |
| Binary detection has a one-time holdout number, obtained by folding a published product | verified | The sealed-holdout confusion matrices were already on disk as full 18x18 and 20x20 tables whose row sums equal the per-class holdout session counts. Coarsening them to binary required no model to be rerun and no row of test to be read again. Permissive is 242 of 242 correct, with 197 true positives, zero false negatives, zero false positives and 45 true negatives. Enforce is 227/20/4/41, giving recall 0.9190, false alarm 0.0889 and balanced accuracy 0.9151. Both carry independent_final_test true. This is also the first time the project's central asymmetry has been measured on one one-time dataset: binary 1.0000 and 0.9151 against identification 0.4655 and 0.4228. That number had been computable for six weeks and nobody had folded it. | 5 | — |
| A pre-registered negative result: the simplest de-confounding recovered nothing | verified | Subtracting each session's own batch benign median, with leave-one-out so a session never enters its own baseline, costs 0.0057 in Permissive and 0.0163 in Enforce; adding a scale step costs a further 0.0045 and 0.0715. The registered criterion asked for at least +0.05 and treated at most +0.01 as falsification, so both steps fail. Two of my own registered leakage checks turned out to have no discriminating power, for independent reasons, and one of them printed a passing tick in the mode where it was weakest. What is falsified is that specific de-confounding, not the broader claim that the information is recoverable. | 5 | — |
| A pre-registered control caught my own reading of the long-scale drift | verified | An earlier judgement that Enforce carries a long-timescale component beyond the batch effect was made without controlling for capture volume, and the per-epoch pcap medians differ by a factor of 36.19. After stratifying, both components survive: Spearman against volume gap is +0.6252 against +0.4205 for time gap, the two explanatory variables correlate at +0.4482 so they cannot be separated statistically, and within the most volume-matched layer the epoch effect is still 1.667, with 20 of 20 classes above 1.3. The structure is sharper than the magnitude: one epoch boundary shows no displacement and the next shows a large one, so it is not every configuration change. | 6 | — |
| All four documentation items cover the current state again, after a row that quietly decayed for ten rounds | verified | The documentation row is scored on whether four items cover the current state. Between 2026-10-16 and 2026-10-18 only one of the four did, and that was recorded as a drop from 100% to 95% caused by my own maintenance defect: every round wrote 'no percentage moves' while checking only the rows it had measured. This round completes the remaining items. Each supplement opens by listing what the previous one now gets wrong, and none overwrites its predecessor, which the pinned byte counts of the 2026-08-21 and 2026-10-16 decks demonstrate. | 6 | — |
| Thirteen rounds of analysis opened no executable path | verified | Across C2C-120 to C2C-132 the shipping configuration did not change by one bit. `executable_classes` is an empty list, so zero classes are authorised to act; `LIVE_NFT_ACTIVATION_ALLOWED` is False; both models carry deployment_eligible false; and the decision layer forces any executable verdict back to alert while deployment_eligible is false. Every round in this window was offline analysis of already published products with holdout_reads of zero. | 4 | — |
| Room-level autonomous IP blocking is still not authorised | blocked | The attribution-to-block chain has run end to end twice, the second time with the approval phrase typed by the human, and revocation has been exercised against a real kernel. What remains is not whether the mechanism works but who may trigger it. | 3 | No model verdict participates: the block target came from attribution evidence and the permission came from a human-typed phrase.; `executable_classes` is deliberately an empty list.; No soak and no positive control: a legitimate remote participant should be judged authorised and be unblockable, which conflicts with the current threat model boundary and is a design question for Jesse. |

## Claim details

### Evidence for `channel_scope_of_the_core_finding`

- `文件/identity_abuse是網路通道_我的粒度假設錯了_2026-10-16.md` — 10307 bytes, SHA-256 `f888b016179616605ae3ad33c5b26b51141a1c0c4f3545adc5ad803bcc47253c` (Write-up, including the correction of my own granularity hypothesis)
- `文件/通道消融_identity_abuse_permissive_2026-10-16.json` — 6720 bytes, SHA-256 `081d032d6a658052443b6be12940762b598c9222affdd5f4e48fab52c1872d00` (Three-arm ablation; test_rows_used 0)
- `文件/通道消融_逐特徵群_permissive_2026-10-16.json` — 5656 bytes, SHA-256 `bd01849d738f5ae27480140ad7af1feec759b58a57b49387e3b788611ebf15ef` (Per-feature-group ablation ruling out the encryption proxy)
- `文件/逐類分離度_permissive_2026-10-16.json` — 19847 bytes, SHA-256 `7040c0d744ea142d578c55d7fef04c1b7c65ae80d11fba2be79df5d30641dff3` (Per-class separability ranking: the two named columns rank 59-60/176 and 92/176)

### Limitations for `channel_scope_of_the_core_finding`

- Cross-validation over train+validation only; this is not a held-out test number and no acceptance percentage moves because of it.
- Permissive only. The Enforce channel ablation is a separate claim.
- Zeroing drops columns out of the live matrix, so the aggregate width differs per arm; for a tree model a constant column is equivalent to absence, and the per-arm widths are recorded in the artifact.

### Evidence for `enforce_identification_is_a_network_task`

- `文件/預測_Enforce通道消融_2026-10-16.md` — 2059 bytes, SHA-256 `b59fd7fb384cda4286336eef599d92dead3ca2c7300d24da513fb317b333ab88` (Pre-registration, written before the measurement)
- `文件/Enforce是網路任務而hmac_forgery分不開正常_2026-10-16.md` — 11691 bytes, SHA-256 `c874f16b1449abe649767f55e52f01a4f2a1872875231b1af79b04359bbf0427` (Write-up)
- `文件/通道消融_enforce_2026-10-16.json` — 7104 bytes, SHA-256 `88bd57d3444770d8f6285bfc1f45f430492b84e97e9da3dd27f0e167a34f2624` (Three-arm ablation, Enforce)
- `文件/逐類分離度_enforce_2026-10-16.json` — 35282 bytes, SHA-256 `2c7d429ee77b6cb017a75e7cb79a5381001efac3d90a65d080ea1aa60386b93d` (Per-class separability, Enforce)
- `文件/排他性_一對一_enforce_2026-10-16.json` — 3053 bytes, SHA-256 `5b4254879e71f509a983c60bde119610e338a540a4b7ba1a30203295d30575ae` (One-against-one check that refuted my first guess about hmac_forgery)
- `文件/分不開normal_enforce_2026-10-16.json` — 7227 bytes, SHA-256 `262b68fd9bf0b4fb83b2e19b68a46d575fa9981c58a53f6229091b3a0ceeaca8` (Maximum separability against `normal` across all 138 live columns)
- `文件/通道逐類實際值_enforce_2026-10-16.json` — 9433 bytes, SHA-256 `9432106dc045c98dcad7effd859aa60415895b8ab6d4f17e77b8e4660db59c5b` (Per-class channel values; added after a load-bearing number was printed to the terminal only)

### Limitations for `enforce_identification_is_a_network_task`

- Cross-validation over train+validation only; no acceptance percentage moves.
- The indistinguishability of `hmac_forgery` is scoped to these 37 features. HMAC rejection events exist in the raw telemetry layer; using them would mean treating a defence reaction as a feature, which carries a recorded blind-spot cost.
- Why `confused_deputy` produces node churn and `hmac_forgery` does not was not traced to the runner layer.

### Evidence for `exclusivity_has_a_quantified_form_and_a_boundary`

- `文件/預測_排他性是否逐類預測recall_2026-10-16.md` — 3671 bytes, SHA-256 `18fb851793cac26ad1fb4c7058159f500acdd790c6e0334d89af44adcd965dce` (Pre-registration 1)
- `文件/預測_排他性的正確量法_兩兩最小分離度_2026-10-17.md` — 5139 bytes, SHA-256 `4697f81201b0629c14c84dce3ae94cf9f7c41fa2718c73a7157d89f882441f70` (Pre-registration 2 (commit 887811b))
- `文件/預測_排他性的方向性量法_2026-10-17.md` — 8372 bytes, SHA-256 `e8d6f5664e2aa4c73d41ed8e314214273c4451894b96600f30ee0d2274dd6e49` (Pre-registration 3 (commit dd5888b))
- `文件/排他性只在Enforce預測recall_而我的量法在Permissive飽和_2026-10-16.md` — 7312 bytes, SHA-256 `a763596ecb3272ab8a75dd3b91e47d83d9f08910fdb2cfa1123b6ccc812ffee8` (Write-up 1)
- `文件/排他性的正確量法_兩個量法互補而min在Permissive退化_2026-10-17.md` — 16050 bytes, SHA-256 `dbf7bccc11d81dd17fd5ccc1f579aefd8d4dd95427a8dd672ea327991558a4ac` (Write-up 2)
- `文件/方向性量法否證了我的主要假設_而平手確實塌掉_2026-10-17.md` — 9188 bytes, SHA-256 `c58af6b3e880c5da0465db3109904ab696a066d97fd254e50c8a87680b121586` (Write-up 3)
- `文件/排他性是否預測recall_2026-10-16.json` — 7817 bytes, SHA-256 `be484a1a65ac84e53bb71b0d45b1e21bb3c03b5a063d0f6d2be96225d4e0dad8` (X_old results)
- `文件/對normal飽和度_2026-10-16.json` — 8419 bytes, SHA-256 `51c84c48b2b69445827d120cabc3f2d8a953ddc2122dc98184c78b21d99f531f` (Saturation diagnosis: 16/17 Permissive classes at exactly 0.5000)
- `文件/排他性對照_場次數競爭解釋_2026-10-16.json` — 1136 bytes, SHA-256 `bbb62030988387828b2788e6fdc65f86801c90e08946b884d3efb7d3984cc567` (Control against the session-count explanation)
- `文件/排他性相關係數_拿掉單點後_2026-10-16.json` — 655 bytes, SHA-256 `4c1cde5f08538dd14ea65a0d213f7d5c7ed09b0bcdc861957210aad3ca1b96f1` (Control: removing the class I suspected carried it)
- `文件/排他性_兩兩最小分離度_2026-10-17.json` — 57928 bytes, SHA-256 `5121a56242c1c34e937aa633a4f7e391e8e669eed3295ee42a1a611b9338b76d` (X_new results, with the full-precision columns for bit-exact recomputation)
- `文件/排他性_方向性量法_2026-10-17.json` — 27372 bytes, SHA-256 `0c63f49938791f3b35de8dad65205bd2cc3f496c6c8743eefe93d78ca2477f1f` (X_dir results, with *_before_correction kept)

### Limitations for `exclusivity_has_a_quantified_form_and_a_boundary`

- holdout_reads: 0 — X uses train+validation only and Y cites an already published product, so no acceptance percentage moves.
- Y has a granularity of 1/11 to 1/12; X is a univariate upper bound.
- The +0.7139 contains +0.1171 that comes entirely from one class changing places. The direction was pre-registered, the magnitude was not.
- n = 17 to 19, measured once. Two instrument failures were found and corrected during this work: rounding before ranking, which moved rho across a pre-registered significance threshold, and exact float comparison of mathematically identical values, which broke the tie structure.
- Permissive's per-class ceiling still has no usable quantitative form after three attempts; the reason changed each time rather than being resolved.

### Evidence for `single_batch_ceiling_holds_in_enforce`

- `文件/預測_Enforce的批次效應與觀測者通道混淆_2026-10-17.md` — 7877 bytes, SHA-256 `1785d5d5ad30722d0e2a95058d01f4894225dab6a699e329d395b6b66c3062f3` (Pre-registration (commit 154682d), deliberately containing no results)
- `文件/Enforce的批次效應一樣大_而我更正C2C-116的一個統計量_2026-10-17.md` — 14273 bytes, SHA-256 `73b7f00649c9c9972f235cda9b0235a1940490736770fb3b0df9ba87201a2dd9` (Write-up)
- `文件/Enforce批次效應_幾何_2026-10-17.json` — 11240 bytes, SHA-256 `a025727d890281c17566e1eeb4582970c76fb69c5780925f4c7984d643aa085d` (Geometry layer, with the reproduction controls)
- `文件/Enforce批次效應_模型_2026-10-17.json` — 9186 bytes, SHA-256 `398c4dffaaef1dfa7bb2f74d55a07e29c8824375c2be136ccb157c63e0da74ee` (Model layer; the baseline reproduces a published value bit for bit)

### Limitations for `single_batch_ceiling_holds_in_enforce`

- holdout_reads: 0; no acceptance percentage moves.
- The batch is a time-window proxy. Nothing records a stack instance id, and the session-to-stack pairing was not read from the supervisor log.
- Standardisation uses the whole-table mean and standard deviation, which affects the absolute values more than the ratios.

### Evidence for `adaptive_label_never_held_under_enforce`

- `文件/預測_cmd_vel_race的簽章是否在既有資料裡_2026-10-18.md` — 5288 bytes, SHA-256 `a05a7a0ec2f962f2a526da2e7fc29cf547c9e5e893d2e07fd90ecbc49815d671` (Pre-registration (commit d5bbb4d); its section five fixed the decision rule before the answer was known)
- `文件/D1的答案是不該動標籤_而自適應在整個Enforce半邊從來沒成立過_2026-10-18.md` — 10999 bytes, SHA-256 `b43056406f8c386a01c9b1fccaef13bfc71bcd9b60f151e2313ca103294f0992` (Write-up)
- `文件/D1_零速比例逐類別_2026-10-18.json` — 2848 bytes, SHA-256 `28470b4e2d69e69d4ee43b6ffa617d6bad8c6e0077914c15fc5b934251e4cf51` (Per-class zero-velocity fractions; the decisive pre-registered check)
- `文件/D1_觀測者收到幾則cmd_vel_2026-10-18.json` — 88 bytes, SHA-256 `9519eb8559679cd28896ca41178d5f944580e1fa0d32f12645b1cfb2df4528fc` (How many velocity messages the observer actually received)
- `文件/D1_觀測者兩個通道_逐模式_2026-10-18.json` — 559 bytes, SHA-256 `473d17ccff637ac504491b7b37d2fe7c3dd7699ec7643f0cdff6b532ce977378` (Both observer channels, per security mode)
- `文件/D1_升級梯的行為後果_2026-10-18.json` — 769 bytes, SHA-256 `f23b96691a02e849ce746c06f281fd292de013b85e97a6737dbbb4bb07490a0e` (Behavioural consequence of the fixed escalation ladder)

### Limitations for `adaptive_label_never_held_under_enforce`

- holdout_reads: 0 — only attack logs and manifests were read; no feature table, no seal, no model. The attack-surface coverage row stays at 20 of 23.
- The attacks did execute. Only the adaptive half of the label fails.
- The mechanism is consistent with an earlier measurement of unauthenticated participants, but this round did not directly observe a rejected handshake.
- The unexplained 35.1% of Permissive sessions that also received nothing was not investigated; three candidate causes were left untested.
- The check I registered was itself under-specified: it excluded one shape of instrument failure and missed a second of identical shape.

### Evidence for `binary_detection_has_a_one_time_number`

- `文件/二元偵測第一次有一次性的數字_2026-10-16.md` — 5466 bytes, SHA-256 `552ed389e106c3317de398e2107be720f1ae85ae7f8346924444bba63dd467d3` (Write-up, including the five things it does not replace)
- `文件/二元偵測_由封印holdout混淆矩陣導出_2026-10-16.json` — 1626 bytes, SHA-256 `fce491ccf944f527cc620f8a3c674d3eef44711e9e8df0cb78bf4c127a4066a5` (Derivation from the published confusion matrices)
- `文件/重訓_識別_permissive.json` — 23850 bytes, SHA-256 `97475b380c49044293055cd4cdc4c8c1c1dac859c994c1213dafc2a86d989fb2` (Source product: the sealed-holdout confusion matrix, Permissive)
- `文件/重訓_識別_enforce.json` — 28470 bytes, SHA-256 `7ce6676362b6ac712154207766d8a74ffea8de9c5d0a5393b6963ebee16c72f0` (Source product: the sealed-holdout confusion matrix, Enforce)
- `文件/二元那5%算不出來_而模型在磁碟上holdout才是花掉的_2026-10-18.md` — 8983 bytes, SHA-256 `c653953c257fc8623713807cb84502a3f0f00c220123407772490b57419fa247` (A checked, not inferred, account of why the remaining five percent cannot be computed offline)

### Limitations for `binary_detection_has_a_one_time_number`

- It is not a PR-AUC, and that row's definition asks for PR-AUC, so the literal definition is not met; the remaining five percent is exactly that.
- It is not the shipping binary head. It must not be written as 0.9900 rising to 1.0000.
- Only 45 and 41 normal sessions, so the zero false-positive rate has a one-sided 95% upper bound of 6.7% by the rule of three.
- Enforce's 0.0889 is above the 0.05 budget used elsewhere in this project.
- Session level against per-window: different granularity.

### Evidence for `batch_internal_normalisation_bought_nothing`

- `文件/預測_對良性背景不變的特徵_2026-10-17.md` — 8047 bytes, SHA-256 `0319395ad390aa5ffc0614adac21cda14ed178ea092dcdb9afba9dccd91488c2` (Pre-registration (commit ac36dab), deliberately containing no results)
- `文件/批次內正規化買不到東西_而我的洩漏檢查沒有判別力_2026-10-17.md` — 12395 bytes, SHA-256 `29cfc609f37412635a8578a3438a1df9d2648c07e5242a65500c7d2385360aa2` (Write-up)
- `文件/對良性背景不變的特徵_2026-10-17.json` — 15117 bytes, SHA-256 `5fdbd822fa8315480a1046f8445211420ea98231f0474bf5bade2e6b8084360c` (Results, with *_before_correction kept and the two verdicts changed to 'no discriminating power')
- `文件/對良性背景不變的特徵_診斷_2026-10-17.json` — 2246 bytes, SHA-256 `9a659507a2e7519c2c6d5b63bcba0ec92626998459440bd9eea65d0fa3edf5ab` (Diagnosis, including the structural degeneracy of the scale step)
- `文件/批次身份_dataset_mega_2026-10-17.json` — 230284 bytes, SHA-256 `4368b8c4a6ed1546ba5cc8751612763206dab8dfa24157dcb74acc68fc30b327` (Batch identity assignment used as the grouping)

### Limitations for `batch_internal_normalisation_bought_nothing`

- holdout_reads: 0; both tools assert zero test rows and the ablation writes an in-memory copy, so neither feature table changed.
- The magnitude is below the measured noise floor of plus or minus 0.024, so what can be cited is that it did not reach +0.05, not that it harmed the model. Only the Enforce scale step clearly exceeds the floor.
- Scope is this one transform family and this one learner.
- Because the leakage checks had no discriminating power, leave-one-out was argued for rather than verified.
- The candidate mechanism was formed after seeing the result and was deliberately not tested in the same round.

### Evidence for `long_scale_drift_is_two_components`

- `文件/預測_Enforce的長尺度漂移是設定還是時間_2026-10-17.md` — 8156 bytes, SHA-256 `28e51b429b8911b51fed92c8b0d09e5899ae4e73d40d7c7abc9d93b3a4ed04ea` (Pre-registration (commit 808e905), deliberately containing no results)
- `文件/長尺度漂移是兩個成分_而C-3抓到我的era解讀_2026-10-17.md` — 12837 bytes, SHA-256 `1d90fe274d6e49657cd6dda98f2162c7859cbe3db51591c48d3c3e406fefbe0d` (Write-up)
- `文件/Enforce長尺度漂移_設定還是時間_2026-10-17.json` — 10667 bytes, SHA-256 `bda62e8cc097f7ac55c619ae21a0028bc8d5bdf3e2eca05d7e49fced4ab5909a` (Main results; the seven buckets reproduce the earlier figures bit for bit)
- `文件/Enforce長尺度漂移_補C3C4與混淆探針_2026-10-17.json` — 2229 bytes, SHA-256 `222ed48350d3106f36c61abd6a64641465ef00354cbd084af099888ac7f65f0c` (The volume control that caught my reading, plus the per-class version)
- `文件/Enforce長尺度漂移_穩健性_2026-10-17.json` — 2629 bytes, SHA-256 `38d8364100793b6dfbd65f042b25aa4b73375791f3db4ecc807a62977b36955a` (Robustness across three standard-deviation choices)
- `文件/Enforce長尺度漂移_量體控制_2026-10-17.json` — 2591 bytes, SHA-256 `a0acd0e1f02194f6618162a158c04f90c45ba0b30104d9dbb136c329ebc962ad` (Volume-matched strata)

### Limitations for `long_scale_drift_is_two_components`

- holdout_reads: 0; four tools assert zero test rows.
- The epoch is a time-window proxy. Nothing records what the configuration was in a given session.
- Volume and time are themselves correlated, so this is stratification, not statistical control.
- What the epoch effect is was not identified. Volume is now controlled; earlier code and machine state remain collinear with the epoch in this dataset.
- The magnitude varies by a factor of 1.6 across standard-deviation choices, so only the structure is citable.
- The volume control did not run at all on its first attempt: five field names were guessed wrong and the disk fallback I had written did not fire because its condition tested for completely empty rather than nearly empty.

### Evidence for `documentation_covers_current_state_again`

- `文件/專題完整總報告增補2_2026-10-18.md` — 59105 bytes, SHA-256 `62d6b1874d7493c761bc89a8916d50e8bc90b93334c53eb54451ae91581ac933` (Long-form report supplement 2, covering thirteen rounds)
- `文件/答辯腳本增補2_2026-10-19.md` — 32557 bytes, SHA-256 `6be9b76eafddfa839cc0369d2122202f54f7ce945329dc69b5838ce638d5cb3a` (Defence script supplement 2, with ten new follow-up questions)
- `文件/SROS2智慧防火牆_專題成果增補2_自然色系_2026-10-19.pptx` — 69500 bytes, SHA-256 `b17995b1ab16e843a720c5139e8168e202e15bed447310a31bdc02fd1252a269` (Deck supplement 2: 15 pages, five automated checks all clean)
- `文件/SROS2智慧防火牆_專題成果增補_自然色系_2026-10-16.pptx` — 68532 bytes, SHA-256 `6611ac80a0f394ac53cd8f0300efff6cdc8ffa19a624212e31c8bdb8de8ea9be` (The 2026-10-16 supplement, pinned unchanged)
- `文件/SROS2智慧防火牆_專題最終報告_自然色系_2026-08-21.pptx` — 147644 bytes, SHA-256 `5ef98c374e104d0d8224836a608284ca5bb9b87aaa13fb61c6cddd41dd8473d3` (The 2026-08-21 main deck, pinned unchanged)
- `文件/證據總帳_2026-10-16_r8/evidence_ledger.json` — 29414 bytes, SHA-256 `a07fba7914504bf7593cf930b8a8a04a8638a5d3a4c486ddd443169cc49859d4` (The r8 ledger, which this revision does not overwrite)

### Limitations for `documentation_covers_current_state_again`

- The overflow check estimates text extent from character widths. This environment has no renderer, so no page of the new deck has been visually confirmed.
- Neither the report supplement nor the defence script supplement has been independently reviewed, and the defence script has not been tested by being asked.
- 100% here is a statement about now. The row measures whether four items cover the current state, so it will fall again as soon as there are new results.

### Evidence for `shipping_defaults_unchanged`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (executable_classes is an empty list)
- `firewall_lab/decision.py` — 14552 bytes, SHA-256 `e5aa89ef9372e52bd16b29b387e1899bd101f9a3c41e281af50aa50e8da850e4` (Executable verdicts are forced back to alert while deployment_eligible is false)
- `firewall_lab/scenarios.json` — 11964 bytes, SHA-256 `d481ef27943c340098fc06e2c13e07453779f86bdb7da549d9438cfccc702a48` (Attack catalogue unchanged; coverage stays at 20 of 23)
- `文件/封印_openset_enforce.json` — 9660 bytes, SHA-256 `2387a30ad9810daa867201557f1a94d74b27d92808a8efb3bfb7775f792b5314` (The one remaining unopened seal, still unopened)

### Limitations for `shipping_defaults_unchanged`

- This is an assertion about configuration, not a claim that the paths would be safe if opened.
- The four pinned files are a sample of the shipping surface, not the whole of it.

### Evidence for `autonomous_ip_block`

- `文件/跨主機鏈_2026-10-07/chain_block_human.json` — 2909 bytes, SHA-256 `ca6226d29a9fd4b020a9d54961cc1b82cd8c1eb167023dcad87f613ab6eb9f83` (Nine checks passed with a human-typed approval phrase)
- `文件/跨主機鏈_2026-10-07/provenance_human.json` — 2735 bytes, SHA-256 `25bc89d8e88afd9daf9adbc961957af65f43a8185bb6070ce225f07eb1a3c131` (Provenance: the authorization block is word for word identical to the Claude-typed run, which is why provenance cannot live in the artifact)
- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (executable_classes is empty, so no model verdict can reach a backend)

### Limitations for `autonomous_ip_block`

- Checks 7 and 9 use ICMP rather than attack traffic.
- One run is not a soak: one target, one ticket, a 90 second TTL, one dropped packet.
- One attack type, and no positive control.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
