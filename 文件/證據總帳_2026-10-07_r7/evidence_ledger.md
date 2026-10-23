# Project evidence ledger

- Project: `sros2-smart-firewall`
- Revision: `r7-2026-10-07-crosshost-chain-demonstrated`
- Generated (UTC): `2026-10-07T20:21:08.236985+00:00`
- Claims: verified 4, provisional 0, blocked 1
- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.

| Claim | Status | Statement | Evidence | Blockers |
|---|---|---|---:|---|
| The attribution-to-block chain ran end to end for the first time | verified | On 2026-10-07 the chain that r5 and r6 recorded as never having been run was run end to end on three machines: the Raspberry Pi as the room-scale defender (192.168.0.145 on Wi-Fi, with an out-of-band management link on 192.168.137.2), the desktop as the attacker (192.168.0.141, WSL2 mirrored), and the laptop only as the operator. Stages 1-3 produced the attribution: a 240s window on domain 41, an N28 wrong-CA participant exiting rc=124, 419 RTPS packets decoded into 37 observations across 561 Ethernet frames, the observer recording AUTHORIZED 0 and UNAUTHORIZED 1, one GUID seen by both halves, and exactly one blockable address. The link-layer check returned consistent for the first time on real cross-host traffic (source MAC equal to the ARP-resolved MAC, e8:65:38:20:23:2f); C2C-051 added that fourth criterion with synthetic tests only, and the live run in C2C-052 reached just the weak unverifiable form. In the same run the Pi's own address was correctly refused because the observer held no rejection record for its GUID. Stage 4 then passed all nine checks with chain_demonstrated=True and rc=0: the ticket evidence_id equals the attribution report's own SHA-256, the kernel set carried the target, the counter moved 0 to 1 (84 bytes), revocation left active_count=0 with an empty set confirmed by querying the kernel rather than by trusting a return value, and no packets were dropped after revocation. Teardown removed the dedicated ruleset and nft returned to zero tables. | 14 | — |
| A WSL behind NAT cannot be either end of this chain, measured not inferred | verified | The plan had recorded the laptop as a fallback attacker. A two-listener control refuted it: the Pi sent one UDP datagram to the laptop's LAN address while a Windows listener and a WSL listener were both bound to the same port. Windows received it; WSL timed out with zero packets over 50 seconds. Packets reach the laptop, but NAT does not forward them inbound, and the Windows result rules out a firewall. SROS2 authentication needs both directions, so an outbound-only path leaves the handshake incomplete and produces no UNAUTHORIZED event -- and that failure looks exactly like an observer that silently stopped working. The same reasoning applies to any WSL in the default NAT mode. C2C-048 and C2C-049 succeeded because that laptop ran mirrored networking, a fact that had not previously been connected to the topology requirement. netsh portproxy is not a workaround because it forwards TCP only while RTPS is UDP. | 2 | — |
| The revocation API written on 2026-09-25 had never once been executed | verified | The first stage-4 attempt reached check 8 and raised AttributeError: ResponseBackend object has no attribute revoke_source. The Pi was carrying the 2026-09-24 copy of response_backend.py while revoke_source was added on 2026-09-25 as the revocation half of this very chain. The method had therefore never run anywhere, and it had never even been deployed -- independent confirmation of what C2C-078 asserted when it wrote that the chain had never been run. The inventory step that missed it checked that the files existed rather than comparing their digests. Four modules were then synchronised to the repo versions and the rerun passed. The crash itself was clean: the finally block removed the ruleset, nft returned to zero tables and the ping recovered immediately, so a failure at check 8 left no half-applied block. | 5 | — |
| No executable path was opened by this round | verified | The cross-host chain ran as a human-authorised acceptance, not as autonomous blocking. action_policy.json still lists executable_classes as an empty list, decision.py still forces any executable decision back to alert while deployment_eligible is false, LIVE_NFT_ACTIVATION_ALLOWED remains False, and no model decision took part in the run at any point. After teardown the Pi holds no nft tables at all. | 4 | — |
| Room-scale autonomous IP blocking remains blocked, with two of four blockers cleared | blocked | The chain now has live evidence end to end, which clears two of the four blockers r6 recorded. What remains is not about whether the mechanism works but about who is allowed to trigger it: no model decision can reach a backend, and the one run that did happen was authorised by an operator phrase rather than produced by a detection. The ticket is no longer self-labelled -- its evidence_id is the attribution report's own SHA-256 -- but the authority still comes from a person. | 4 | executable_classes is empty by deliberate choice, so no model decision can reach a backend.; The acceptance ticket is bound to real attribution evidence but is still authorised by an operator phrase, not produced by a model decision -- and in this run that phrase was supplied by Claude under explicit authorisation rather than typed by a human. |

## Claim details

### Evidence for `crosshost_chain_demonstrated_end_to_end`

- `文件/跨主機鏈_2026-10-07/chain_block.json` — 2907 bytes, SHA-256 `49443848fb7efcc9241ed2cfbbb2f9e34272df080ec10d092b4814c8465d869c` (The nine-check report: chain_demonstrated=True, all_passed=True, shipping_defaults_unchanged=True)
- `文件/跨主機鏈_2026-10-07/crosscheck.json` — 1643 bytes, SHA-256 `6475d6ff86cbfeb0602e543d87bdfa0246d42168d733aa377b681dd3f3307284` (The attribution it was driven by; its own SHA-256 became the ticket evidence_id)
- `文件/跨主機鏈_2026-10-07/link_layer_binding.json` — 2834 bytes, SHA-256 `737d5880c2ddae49ebde77658d6af136bb420ab8b74767ebc618748dd0c5f013` (The fourth criterion returning consistent on real cross-host traffic for the first time)
- `文件/跨主機鏈_2026-10-07/observer_events.jsonl` — 486 bytes, SHA-256 `2e85f7de8adfb476ea25c8a0a2b212c168a5a40bcdf844b97f6db644b9fead33` (The observer half: AUTHORIZED 0, UNAUTHORIZED 1)
- `文件/跨主機鏈_2026-10-07/rtps_identity_packets.jsonl` — 27101 bytes, SHA-256 `cf410b99dcee0ce34f4588a082a0b749eb43b59bcd730d48e59c14b57ed45cde` (The packet half: 419 RTPS packets decoded into 37 observations)
- `文件/跨主機鏈_2026-10-07/run_block.log` — 2683 bytes, SHA-256 `6a1d9c0e1e3408847d6e5559550b2255b97453065f5a3d7a871425616c033da4` (The captured stdout of the run, including the AttributeError on the first attempt)
- `文件/跨主機鏈_2026-10-07/provenance.json` — 4937 bytes, SHA-256 `326cdf3a73520bc84522a96a47bb17c6cd61d253fae747951f4db5fd89d0ee83` (Topology, stage timings, digests, and the MUST_BE_DISCLOSED block recording that the phrase was typed by Claude)
- `文件/跨主機鏈第一次跑完_2026-10-07.md` — 7973 bytes, SHA-256 `360776ac6b9f55f0c3037363b3500dd1400cc42b016fff9181bb0a33b5e294c1` (The written account, including the five failed attempts and what was measured wrongly)
- `工具腳本/run_attribution_driven_block.py` — 26404 bytes, SHA-256 `637d3d569abde3df5ef1289866af433da42e41b61ff55cbcec9001b2b79b7c3c` (The chain itself; its nine checks and the approval gate that reads stdin)
- `工具腳本/run_crosshost_identity.sh` — 11174 bytes, SHA-256 `1afc86fdd1541289d5cd31f572cf92ffdc1689f48e0003aeb937eaec5c458518` (The defender-side collector that produced the attribution)
- `工具腳本/crosscheck_identity_attribution.py` — 15706 bytes, SHA-256 `35791acb01d24a1b05be4cbf75fdd26e1f1ec17b30ff1b430244408fd9420a41` (The four criteria, including refusal to infer from absence of a rejection record)
- `工具腳本/check_link_layer_binding.py` — 11270 bytes, SHA-256 `e68f6a3d153791da50992290febdaee8ec7017ef2397068a0829076611a27c50` (Source MAC against ARP-resolved MAC, the spoofing guard added in C2C-051)
- `tests/test_attribution_driven_block.py` — 17065 bytes, SHA-256 `a38d345e9fa30f2efd257737372c8cba98986473da4b7f22b0b9ef9076dc41b8` (Offline coverage of the first four checks and the refusal paths)
- `tests/test_response_revocation.py` — 11662 bytes, SHA-256 `5be6c694bfd94a3e7c154dd1a89ca415ccb407ba9838d1c30de1caee66b019a0` (Revocation ordering, fail-closed confirmation, and the audit entry on a no-op revoke)

### Limitations for `crosshost_chain_demonstrated_end_to_end`

- The approval phrase was typed by Claude, not by a human at the keyboard. Jesse authorised stage 4 and then explicitly authorised Claude to supply the phrase, so the authority is real, but it was exercised in conversation rather than on stdin. The report field human_phrase_supplied=true cannot distinguish the two cases; provenance.json carries the disclosure. Claiming a human in the loop requires a rerun with the phrase typed by hand.
- Checks 7 and 9 used ICMP, not attack traffic. The rule is protocol-agnostic on the input hook, so the Pi pinging the desktop made the desktop's echo replies arrive from the target address. That step verifies the kernel drop path; the attack-traffic attribution comes from stages 1-3.
- One run, one target, one ticket, TTL 90s, a single dropped packet. This is not a soak.
- One attack type (N28 wrong-CA). There is no positive control -- a legitimate remote participant that should be judged AUTHORIZED and not blockable -- because that would require a valid enclave on the attacker host, which conflicts with the threat model boundary.
- No model decision took part. The ticket subject came from attribution evidence and its authority from the approval phrase.
- The raw capture (traffic.pcapng, 517008 bytes, sha256 cbd9cd59babac8e1) stays on the Pi; only derived artifacts and its digest are in the repo.

### Evidence for `nat_rules_out_wsl_as_either_end`

- `文件/跨主機鏈_防守端就緒而NAT封死WSL_2026-10-07.md` — 10578 bytes, SHA-256 `42e34d34d58eb6b5e1fdd6e8f0b197cd87bf748ed8606d483f10a3cb21fdc787` (The staging round: Pi build-out, domain 41 discovery, two negative controls, and the NAT measurement)
- `工具腳本/run_crosshost_identity.sh` — 11174 bytes, SHA-256 `1afc86fdd1541289d5cd31f572cf92ffdc1689f48e0003aeb937eaec5c458518` (The defender-side collector that produced the attribution)

### Limitations for `nat_rules_out_wsl_as_either_end`

- The measurement covers WSL2 in its default NAT mode. Mirrored mode was not measured on the laptop; on the desktop it was confirmed only by observing that its WSL holds 192.168.0.141.

### Evidence for `revoke_source_had_never_been_executed`

- `文件/跨主機鏈_2026-10-07/provenance.json` — 4937 bytes, SHA-256 `326cdf3a73520bc84522a96a47bb17c6cd61d253fae747951f4db5fd89d0ee83` (Topology, stage timings, digests, and the MUST_BE_DISCLOSED block recording that the phrase was typed by Claude)
- `文件/跨主機鏈_2026-10-07/run_block.log` — 2683 bytes, SHA-256 `6a1d9c0e1e3408847d6e5559550b2255b97453065f5a3d7a871425616c033da4` (The captured stdout of the run, including the AttributeError on the first attempt)
- `文件/跨主機鏈第一次跑完_2026-10-07.md` — 7973 bytes, SHA-256 `360776ac6b9f55f0c3037363b3500dd1400cc42b016fff9181bb0a33b5e294c1` (The written account, including the five failed attempts and what was measured wrongly)
- `firewall_lab/response_backend.py` — 52343 bytes, SHA-256 `e59e86a30dd02cbfd68fd309718538a6f5a8f3bb7470b0030e376ebf5148483a` (Carries revoke_source, which this run showed had never been executed anywhere)
- `firewall_lab/nft_backend_service.py` — 46154 bytes, SHA-256 `951ccfeaff539701f6aea222763c42a26158a597df5141cf9780c4a59e0c5bfc` (The fixed ruleset: ip saddr @blocked counter drop, protocol-agnostic on the input hook)

### Limitations for `revoke_source_had_never_been_executed`

- The pre-sync digests on the Pi were recorded in the run output rather than in a separate artifact.

### Evidence for `shipping_defaults_unchanged`

- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (executable_classes is still an empty list)
- `firewall_lab/decision.py` — 14552 bytes, SHA-256 `e5aa89ef9372e52bd16b29b387e1899bd101f9a3c41e281af50aa50e8da850e4` (Forces any executable decision back to alert while deployment_eligible is false)
- `firewall_lab/scenarios.json` — 11964 bytes, SHA-256 `d481ef27943c340098fc06e2c13e07453779f86bdb7da549d9438cfccc702a48` (The shipping catalog, unchanged by this round)
- `文件/跨主機鏈_2026-10-07/chain_block.json` — 2907 bytes, SHA-256 `49443848fb7efcc9241ed2cfbbb2f9e34272df080ec10d092b4814c8465d869c` (The nine-check report: chain_demonstrated=True, all_passed=True, shipping_defaults_unchanged=True)

### Limitations for `shipping_defaults_unchanged`

- This is an assertion about configuration, not a claim that opening those paths would be safe.

### Evidence for `autonomous_ip_block`

- `文件/跨主機鏈_2026-10-07/chain_block.json` — 2907 bytes, SHA-256 `49443848fb7efcc9241ed2cfbbb2f9e34272df080ec10d092b4814c8465d869c` (The nine-check report: chain_demonstrated=True, all_passed=True, shipping_defaults_unchanged=True)
- `文件/跨主機鏈_2026-10-07/provenance.json` — 4937 bytes, SHA-256 `326cdf3a73520bc84522a96a47bb17c6cd61d253fae747951f4db5fd89d0ee83` (Topology, stage timings, digests, and the MUST_BE_DISCLOSED block recording that the phrase was typed by Claude)
- `文件/跨主機鏈第一次跑完_2026-10-07.md` — 7973 bytes, SHA-256 `360776ac6b9f55f0c3037363b3500dd1400cc42b016fff9181bb0a33b5e294c1` (The written account, including the five failed attempts and what was measured wrongly)
- `firewall_lab/action_policy.json` — 3144 bytes, SHA-256 `0ed41ad00639e77f45be4df367f3c9efb5fdcf756a10c07820e4e6380d7c2a49` (executable_classes is still an empty list)

### Limitations for `autonomous_ip_block`

- Two blockers from r6 are cleared: the chain has now been run end to end, and revocation has been confirmed against a real kernel rather than only against the in-memory adapter.


## Safety boundary

This is an evidence inventory, not a cryptographic signature or live-test authorization.
A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.
