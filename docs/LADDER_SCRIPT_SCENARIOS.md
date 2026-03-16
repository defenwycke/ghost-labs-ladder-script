# Ladder Script — Advanced Scenario Test Results

End-to-end functional tests exercising Ladder Script's full capabilities across
block type combinations, covenant recursion, multi-rung logic, PQ cryptography,
and state machines.

All tests are implemented in `test/functional/rung_basic.py` and execute against
a live signet node with real transaction creation, signing, broadcast, and
confirmation.

---

## Test Summary

| # | Scenario | Block Types | Result |
|---|----------|-------------|--------|
| 1 | PQ PUBKEY_COMMIT Spend | SIG + SCHEME + PUBKEY_COMMIT | PASS |
| 2 | PQ PUBKEY_COMMIT Mismatch (neg) | SIG + SCHEME + PUBKEY_COMMIT | PASS |
| 3 | Cross-Rung RECURSE_MODIFIED | SIG + RECURSE_MODIFIED + COMPARE (2 rungs) | PASS |
| 4 | Multi-Mutation RECURSE_MODIFIED | RECURSE_MODIFIED + SEQUENCER + COMPARE | PASS |
| 5 | Wrong Multi-Mutation Delta (neg) | RECURSE_MODIFIED + COMPARE | PASS |
| 6 | Triple AND (SIG+HASH+CSV) | SIG + HASH_PREIMAGE + CSV | PASS |
| 7 | OR Hot/Cold Vault | SIG+CSV ∥ SIG (2 rungs) | PASS |
| 8 | RECURSE_SAME + CLTV | RECURSE_SAME + CLTV | PASS |
| 9 | Inverted COMPARE Floor/Ceiling | COMPARE + COMPARE(inverted) | PASS |
| 10 | Countdown Vault | SIG + RECURSE_COUNT (3 hops + release) | PASS |
| 11 | RECURSE_DECAY Multi-Target | RECURSE_DECAY + 2×COMPARE | PASS |
| 12 | HTLC (Both Paths) | SIG+HASH ∥ SIG+CSV (2 rungs) | PASS |
| 13 | Latch + Cross-Rung State Machine | LATCH_SET + RECURSE_MODIFIED + SEQUENCER | PASS |
| 14 | Timed Secret Reveal | HASH_PREIMAGE + RECURSE_UNTIL | PASS |
| 15 | 3-Rung Priority Spend | MULTISIG ∥ SIG+HASH ∥ SIG+CSV | PASS |
| 16 | pqpubkeycommit RPC | RPC helper | PASS |
| 17 | COSIGN PQ Anchor Co-Spend | SIG + COSIGN + RECURSE_SAME + PUBKEY_COMMIT | PASS |
| 18 | COSIGN Negative (No Anchor) | SIG + COSIGN (missing co-input) | PASS |
| 19 | COSIGN 10-Child Batch Spend | 1 PQ anchor + 10 COSIGN children | PASS |

---

## Scenario Details

### Scenario 1: PQ PUBKEY_COMMIT Spend

**Purpose:** Prove that a FALCON512 public key (897 bytes) can be represented
as a 32-byte SHA256 commitment in the UTXO set, with the full key revealed only
at spend time in the witness.

**How it works:**
1. Generate FALCON512 keypair via `generatepqkeypair` RPC
2. Compute commitment: `pqpubkeycommit(pubkey)` → 32-byte hash
3. Create output with conditions: `SIG { SCHEME(FALCON512), PUBKEY_COMMIT(hash) }`
4. Spend: provide full pubkey + PQ signature in witness via `pq_pubkey` parameter
5. Evaluator checks `SHA256(witness_pubkey) == commitment`, then verifies PQ sig

**UTXO savings:** 865 bytes per output (897B pubkey → 32B commitment).

**Test method:** `test_pq_falcon512_pubkey_commit`

---

### Scenario 2: PQ PUBKEY_COMMIT Mismatch (Negative)

**Purpose:** Verify that providing the wrong pubkey for a PUBKEY_COMMIT is
rejected at consensus level — the SHA256 check fires before signature
verification even begins.

**How it works:**
1. Alice creates output with her PUBKEY_COMMIT
2. Eve generates her own FALCON512 keypair and signs correctly with her key
3. Eve's transaction is signed locally (RPC succeeds) but rejected by consensus:
   `SHA256(eve_pubkey) ≠ alice_commit` → UNSATISFIED

**Test method:** `test_negative_pq_pubkey_commit_mismatch`

---

### Scenario 3: Cross-Rung RECURSE_MODIFIED

**Purpose:** Prove the new multi-mutation format allows mutations targeting
any rung, not just rung 0.

**How it works:**
1. Create 2-rung UTXO:
   - Rung 0: `SIG(pubkey)` + `RECURSE_MODIFIED(target=rung1, block0, param1, delta=+500)`
   - Rung 1: `COMPARE(GT, 5000)`
2. Spend: sign with rung 0 key, output has rung 1 threshold changed 5000→5500
3. Rung 0's SIG block and RECURSE_MODIFIED block are unchanged in output
4. Only rung 1's COMPARE threshold mutates

**Why it matters:** Enables separation of control logic (rung 0) from state
(rung 1). The signing key never moves to the same rung as the mutable state.

**Test method:** `test_recurse_modified_cross_rung`

---

### Scenario 4: Multi-Mutation RECURSE_MODIFIED

**Purpose:** Prove two simultaneous mutations in a single spend — a counter
increment AND a threshold increase happening atomically.

**How it works:**
1. Single rung with: `RECURSE_MODIFIED(2 mutations)` + `SEQUENCER(step, 10)` + `COMPARE(GT, threshold)`
2. Mutation 0: block 1 (SEQUENCER), param 0 (current_step), delta +1
3. Mutation 1: block 2 (COMPARE), param 1 (threshold), delta +1000
4. Each hop: step increments AND threshold increases simultaneously
5. Tested for 2 consecutive hops (step 0→1→2, threshold 10000→11000→12000)

**Why it matters:** Complex state machines that previously required multiple
transactions can now transition atomically in a single spend.

**Test method:** `test_recurse_modified_multi_mutation`

---

### Scenario 5: Wrong Multi-Mutation Delta (Negative)

**Purpose:** Verify that applying the wrong delta to a multi-mutation covenant
is rejected. The covenant enforces exact deltas.

**How it works:**
1. Covenant specifies delta +1 for COMPARE threshold
2. Attacker creates output with threshold 100→102 (delta +2 instead of +1)
3. Consensus rejects: `output_val (102) ≠ input_val (100) + delta (1)`

**Test method:** `test_negative_recurse_modified_wrong_delta`

---

### Scenario 6: Triple AND (SIG + HASH_PREIMAGE + CSV)

**Purpose:** Exercise three-way AND logic — all blocks in one rung must be
satisfied simultaneously.

**Scenario: Escrow payment.** Seller can claim funds only after:
1. Providing their signature (identity)
2. Revealing a shipping tracking secret (hash preimage)
3. Waiting 5 blocks after output creation (CSV cooling period)

All three are independent conditions enforced in parallel.

**Test method:** `test_sig_hash_csv_triple_and`

---

### Scenario 7: OR Hot/Cold Vault

**Purpose:** Two-rung OR logic with different security/delay tradeoffs.

**Rung 0 (hot path):** Hot key signature + CSV 10-block delay. For everyday
spending — accessible but time-gated.

**Rung 1 (cold path):** Cold key signature only. Emergency recovery — immediate
access but requires the cold key.

**Test coverage:** Both paths tested end-to-end:
- Cold path: immediate spend confirmed without waiting
- Hot path: spend confirmed after 10-block CSV maturity

**Test method:** `test_or_hot_cold_vault`

---

### Scenario 8: RECURSE_SAME + CLTV

**Purpose:** Perpetual covenant with an absolute timelock gate.

**How it works:**
1. Output has `RECURSE_SAME(depth=20)` + `CLTV(lock_height)`
2. The UTXO can only be spent into identical conditions (perpetual covenant)
3. CLTV ensures nLockTime ≥ lock_height (prevents spending before height N)
4. After the lock height, re-encumbrance continues indefinitely

**Use case:** Time-locked treasury reserves that circulate through a specific
covenant structure but can't be touched until a governance deadline.

**Test method:** `test_recurse_same_with_cltv`

---

### Scenario 9: Inverted COMPARE as Floor/Ceiling

**Purpose:** Demonstrate the `inverted` flag for creative condition design.

**How it works:**
- Block 0: `COMPARE(GTE, 10000)` → floor: amount ≥ 10,000 sats
- Block 1: `COMPARE(GT, 1000000, inverted=true)` → ceiling: ¬(amount > 1M) = amount ≤ 1M

Together: 10,000 ≤ amount ≤ 1,000,000 sats — a range lock built from two
non-range operators via inversion. This is an alternative to `IN_RANGE` that
demonstrates the composability of inverted blocks.

**Test method:** `test_inverted_compare_floor`

---

### Scenario 10: Countdown Vault (RECURSE_COUNT + SIG)

**Purpose:** Multi-step deliberation vault — funds require N signed
transactions across N separate blocks before release.

**How it works:**
1. Create output: `SIG(vault_key)` + `RECURSE_COUNT(3)`
2. Spend 1: sign + decrement → count=2, re-encumbered output
3. Spend 2: sign + decrement → count=1, re-encumbered output
4. Spend 3: sign + decrement → count=0, re-encumbered output
5. Spend 4: count=0, covenant terminates → free spend to any address

**Use case:** Corporate treasury withdrawal requiring 3 deliberation periods.
Board signs off 3 times across 3 blocks before funds move. Prevents impulsive
or coerced single-transaction withdrawals.

**Test method:** `test_countdown_vault`

---

### Scenario 11: RECURSE_DECAY Multi-Target

**Purpose:** Prove the new multi-mutation format works for RECURSE_DECAY too,
with two parameters decaying at different rates.

**How it works:**
1. Two COMPARE(GT) blocks with different thresholds (500K and 1M sats)
2. RECURSE_DECAY with 2 mutations: threshold A decays by 50K, threshold B decays by 100K
3. Each hop relaxes both constraints progressively
4. After enough hops, constraints become very permissive

**Use case:** Adaptive constraint relaxation — a long-running covenant that
gradually lowers its requirements as the contract ages.

**Test method:** `test_recurse_decay_multi_target`

---

### Scenario 12: HTLC (Hash Time-Locked Contract)

**Purpose:** Classic cross-chain atomic swap primitive, fully expressed in
Ladder Script.

**Rung 0 (receiver claims):** Bob provides his signature + the hash preimage.
This is the happy path — Bob knows the secret, claims immediately.

**Rung 1 (sender refund):** Alice provides her signature after a CSV timeout
of 20 blocks. Safety net — if Bob doesn't claim, Alice recovers after timeout.

**Test coverage:** Both paths tested on separate UTXOs:
1. Bob claims via rung 0 (preimage + sig) — confirmed
2. Alice refunds via rung 1 (sig + CSV 20) — confirmed after waiting

**Test method:** `test_htlc_pattern`

---

### Scenario 13: Latch + Cross-Rung State Machine

**Purpose:** Combine PLC latch gating with cross-rung RECURSE_MODIFIED for a
real state machine where the gate and state live on different rungs.

**How it works:**
1. Rung 0: `LATCH_SET(state=0)` + `RECURSE_MODIFIED(target=rung1, delta=+1)`
2. Rung 1: `SEQUENCER(step=0, total=5)`
3. Spend: LATCH_SET gates the transition (only if state=0), then
   RECURSE_MODIFIED increments rung 1's sequencer step 0→1
4. The latch stays at state=0 (it's not the mutation target), so it
   can be triggered again on the next hop

**Why it matters:** Demonstrates that control flow (rung 0) can be cleanly
separated from state storage (rung 1) — a key pattern for complex contracts.

**Test method:** `test_latch_cross_rung_state_machine`

---

### Scenario 14: Timed Secret Reveal

**Purpose:** RECURSE_UNTIL + HASH_PREIMAGE: a "reveal by deadline" pattern.

**How it works:**
1. Output requires `HASH_PREIMAGE(secret)` + `RECURSE_UNTIL(deadline)`
2. Before deadline: spending re-encumbers with identical conditions (forced
   by RECURSE_UNTIL). You can spend, but only back into the same covenant.
3. After deadline: RECURSE_UNTIL terminates, output can go anywhere. But
   HASH_PREIMAGE still requires the correct preimage to be revealed.
4. Net effect: a forced delay before the secret can be used to unlock funds.

**Use case:** Commitment-reveal schemes where the commitment period has a
minimum duration enforced at consensus level.

**Test method:** `test_timed_secret_reveal`

---

### Scenario 15: 3-Rung Priority Spend

**Purpose:** Three alternative spending paths with different trust/delay
tradeoffs, exercising OR logic across 3 rungs.

| Rung | Path | Requirements | Delay |
|------|------|-------------|-------|
| 0 | Emergency | 2-of-2 MULTISIG | Immediate |
| 1 | Normal | SIG + hash preimage | Immediate |
| 2 | Delayed | SIG + CSV 15 blocks | 15 blocks |

**Test:** Emergency path (rung 0) — both keys sign the 2-of-2 multisig,
spend confirmed immediately without touching rungs 1 or 2.

**Why it matters:** Real-world wallets need multiple access tiers. Ladder
Script's OR-across-rungs naturally models this with the first satisfied
rung winning.

**Test method:** `test_three_rung_priority`

---

### Scenario 16: pqpubkeycommit RPC

**Purpose:** Verify the `pqpubkeycommit` convenience RPC correctly computes
SHA256 of PQ public keys.

**Test:** Generate FALCON512 keypair, compute commitment via RPC, verify it
matches Python's `hashlib.sha256(pubkey).hexdigest()`.

**Test method:** `test_pqpubkeycommit_rpc`

---

### Scenario 17: COSIGN PQ Anchor Co-Spend

**Purpose:** Prove the PQ anchor pattern -- a single perpetual FALCON512 UTXO
protects non-PQ children via co-spending, amortizing the PQ signature cost
across unlimited future transactions (theoretical max depth ~4.3 billion spends).

**How it works:**
1. Create PQ anchor: `SIG { SCHEME(FALCON512), PUBKEY_COMMIT(hash) }` + `RECURSE_SAME(depth=1000)`
2. Create child UTXO: `SIG(schnorr_key)` + `COSIGN { HASH256(sha256(anchor_spk)) }`
3. Spend both in a single transaction — anchor provides PQ sig, child provides Schnorr sig
4. COSIGN evaluator checks: does any other input's spent scriptPubKey hash to the HASH256 field?
5. Anchor re-encumbers itself (RECURSE_SAME) — ready for the next co-spend

**Measured tx size:** 1,877 bytes (1 FALCON512 sig + 1 Schnorr sig)

**Test method:** `test_cosign_anchor_spend`

---

### Scenario 18: COSIGN Negative (No Anchor)

**Purpose:** Verify that a COSIGN child cannot be spent without its anchor
present as a co-input. This is the security guarantee — without the PQ
anchor's co-signature, a quantum attacker cannot spend the child.

**How it works:**
1. Create child with COSIGN referencing an anchor's scriptPubKey hash
2. Attempt to spend the child alone (no anchor co-input)
3. COSIGN evaluator scans all other inputs — none match → UNSATISFIED
4. Transaction rejected at consensus

**Test method:** `test_cosign_negative_no_anchor`

---

### Scenario 19: COSIGN 10-Child Batch Spend

**Purpose:** Demonstrate the PQ anchor pattern at scale — 1 anchor protecting
10 children in a single transaction, with concrete byte-level cost comparison
against individual PQ protection.

**How it works:**
1. Create PQ anchor (FALCON512 + PUBKEY_COMMIT + RECURSE_SAME)
2. Create 10 child UTXOs in a single funding tx, each with `SIG(schnorr) + COSIGN(anchor_hash)`
3. Spend all 11 inputs in one transaction: anchor + 10 children
4. Anchor re-encumbers itself; all children's value goes to a single destination

**Measured results:**

| Metric | Value |
|--------|-------|
| COSIGN tx size | 2,996 bytes |
| 10x individual FALCON512 (hypothetical) | 15,820 bytes |
| Savings | 12,824 bytes (5.3x smaller) |
| PQ signatures in tx | 1 (anchor only) |
| Schnorr signatures in tx | 10 (children) |

**Scaling characteristics:**

| Children | COSIGN total | vs Individual PQ | Savings |
|----------|-------------|------------------|---------|
| 1 | ~1,877B | 1,582B | -295B (slight overhead) |
| 10 | 2,996B | 15,820B | 5.3x |
| 50 | ~7,600B | 79,100B | 10.4x |
| 100 | ~13,100B | 158,200B | 12.1x |

**Key properties:**
- The anchor's scriptPubKey hash never changes (RECURSE_SAME), so children
  created at any future time reference the same hash
- One anchor per user, perpetual reuse via re-encumbrance
- Each additional child adds ~112 bytes (input + Schnorr witness + COSIGN block)
- The fixed PQ cost (~1,586 bytes) is amortized across all children in the batch

**Test method:** `test_cosign_10_children`

---

## Unit Test Coverage (rung_tests.cpp)

In addition to the functional tests above, the following unit tests were added
for the core evaluator logic:

| Test | What it verifies |
|------|-----------------|
| `eval_sig_pq_pubkey_commit` | PUBKEY_COMMIT + PUBKEY match → proceeds to PQ verify |
| `eval_sig_pq_pubkey_commit_mismatch` | Wrong PUBKEY for commitment → UNSATISFIED |
| `eval_sig_pubkey_commit_no_pubkey_error` | PUBKEY_COMMIT without PUBKEY → ERROR |
| `eval_sig_pubkey_commit_schnorr` | PUBKEY_COMMIT with Schnorr (non-PQ) → SATISFIED |
| `eval_recurse_modified_legacy_compat` | 4-NUMERIC format (backward compat) → SATISFIED |
| `eval_recurse_modified_cross_rung` | New format targeting rung 1 → SATISFIED |
| `eval_recurse_modified_multi_mutation` | Two mutations + wrong delta negative → correct |
| `eval_recurse_modified_no_context_satisfied` | No context (structural only) → SATISFIED |
| `eval_recurse_decay_legacy_compat` | Legacy decay format → SATISFIED |
| `eval_recurse_decay_multi_mutation` | Two decay targets across rungs → SATISFIED |
| `eval_cosign_matching_input` | Matching spent output hash → SATISFIED |
| `eval_cosign_no_matching_input` | No matching spent output → UNSATISFIED |
| `eval_cosign_no_hash_error` | Missing HASH256 field → ERROR |
| `eval_cosign_no_context_satisfied` | No tx context (structural) → SATISFIED |
| `eval_cosign_skips_self` | Self-match prevention → UNSATISFIED |

**Total rung unit tests: 166 (all passing)**

---

## Spam Resistance Tests

Ladder Script's typed field system makes arbitrary data embedding impractical.
Every byte in a rung transaction must conform to a known data type with strict
size limits and semantic validation. The following tests prove each defense layer.

| # | Attack Vector | Defense | Result |
|---|--------------|---------|--------|
| S1 | Arbitrary PREIMAGE | Hash preimage must match HASH256 in conditions | REJECTED at consensus |
| S2 | Arbitrary PUBKEY bytes | UTXO created but cryptographically unspendable | Funds burned |
| S3 | Garbage NUMERIC operator | RPC accepts (valid 4B field), evaluator rejects semantics at spend | REJECTED at consensus |
| S4 | 5-byte NUMERIC | FieldMaxSize(NUMERIC) = 4 bytes | REJECTED at RPC |
| S5 | Unknown data type | ParseDataType() rejects unknown names | REJECTED at RPC |
| S6 | SIGNATURE in conditions | IsConditionDataType() = false for witness types | REJECTED at RPC |
| S7 | PREIMAGE in conditions | IsConditionDataType() = false for witness types | REJECTED at RPC |
| S8 | PUBKEY > 2048 bytes | FieldMaxSize(PUBKEY) = 2048 | REJECTED at RPC |
| S9 | HASH256 ≠ 32 bytes | Fixed-size field validation | REJECTED at RPC |
| S10 | HASH160 ≠ 20 bytes | Fixed-size field validation | REJECTED at RPC |
| S11 | SCHEME ≠ 1 byte | Fixed-size field validation | REJECTED at RPC |
| S12 | 9 blocks per rung | MAX_BLOCKS_PER_RUNG = 8 (policy) | REJECTED at broadcast |
| S13 | Coil address overflow | Standard scriptPubKey size limit | Structurally bounded |

### Defense-in-Depth Summary

1. **RPC layer**: Unknown types rejected, field sizes validated, witness-only
   types blocked from conditions
2. **Serialization**: Structure limits (rungs, blocks, fields) enforced at
   deserialization
3. **Policy**: Output validation rejects oversized structures before mempool
4. **Consensus**: Semantic validation at spend time — garbage operators,
   wrong preimages, mismatched keys all produce UNSATISFIED/ERROR
5. **Economic**: Even if structurally valid data gets into a UTXO (e.g.,
   arbitrary PUBKEY), the funds are burned — the attacker pays for storage
   they can never recover

### Maximum Data Capacity (theoretical upper bound)

Even in the worst case where an attacker burns funds:
- Max PUBKEY: 2048 bytes per field, but must start with valid prefix (02/03/04)
- Max NUMERIC: 4 bytes per field
- Max fields/block: 16, max blocks/rung: 8, max rungs: 8
- Theoretical max: ~2048 × 16 × 8 × 8 ≈ 2MB per UTXO — but this exceeds
  standard transaction size limits. In practice, the 100KB witness limit and
  standard tx size limit cap actual data at far less, and every byte costs
  real satoshis that are permanently burned.

**Test methods:** `test_spam_*` (8 tests in `rung_basic.py`)

---

## Key Takeaways

1. **PUBKEY_COMMIT** reduces PQ UTXO footprint by 96% (897B → 32B) with zero
   security compromise — the full key is still required for verification.

2. **Multi-mutation RECURSE_MODIFIED** enables atomic state transitions across
   multiple parameters and rungs in a single spend. This is essential for
   complex smart contracts (counters + latches + thresholds).

3. **Cross-rung mutation** cleanly separates control logic from state storage,
   following the PLC (Programmable Logic Controller) design philosophy.

4. **OR-across-rungs** naturally models priority spending paths (emergency >
   normal > delayed) without any special opcodes.

5. **Inverted blocks** compose with any block type to negate conditions,
   enabling ceiling guards and NOT-logic without dedicated opcodes.

6. **Backward compatibility** is preserved: existing 4-NUMERIC RECURSE_MODIFIED
   and RECURSE_DECAY scripts continue to work unchanged.

7. **COSIGN PQ anchor pattern** enables post-quantum protection for unlimited
   UTXOs using a single perpetual FALCON512 anchor (theoretical max depth
   ~4.3 billion spends). The anchor re-encumbers
   itself on every spend (RECURSE_SAME), so children created at any future
   time reference the same anchor hash. At 10 children per batch, witness
   data is 5.3x smaller than individual PQ signatures; at 100 children,
   12.1x smaller. This makes PQ protection practical today without waiting
   for signature aggregation schemes.

---

## Stub Fix Summary

The following evaluator stubs were replaced with proper state-gating logic:

### PLC Blocks — State Gating

| Block | Before | After |
|-------|--------|-------|
| COUNTER_DOWN | SATISFIED if fields present | SATISFIED if count > 0; UNSATISFIED at 0 |
| COUNTER_UP | SATISFIED if fields present | SATISFIED if current < target; UNSATISFIED when done |
| COUNTER_PRESET | SATISFIED if 2 NUMERICs present | SATISFIED if current < preset; UNSATISFIED at/above preset |
| ONE_SHOT | SATISFIED if NUMERIC + HASH present | SATISFIED if state == 0 (can fire); UNSATISFIED if already fired |
| TIMER_CONTINUOUS | SATISFIED if val > 0 | 2-field mode: SATISFIED if accumulated >= target; 1-field backward compat preserved |
| TIMER_OFF_DELAY | SATISFIED if val > 0 | SATISFIED if remaining > 0 (hold-off); UNSATISFIED when expired |

### HYSTERESIS_FEE — Tx Fee Rate Check

Previously validated structure only ("needs mempool access"). Now computes the
spending transaction's actual fee rate from `sum(input_values) - sum(output_values)`
divided by vsize, and checks it falls within the `[low_sat_vb, high_sat_vb]` band.
Falls back to SATISFIED when no tx context (structural-only mode).

### ADAPTOR_SIG — Real Adaptor Signature Support

- **Evaluator:** Added 32-byte x-only point validation for `adaptor_point` (pubkeys[1])
- **RPC (signrungtx):** ADAPTOR_SIG separated from VAULT_LOCK; accepts optional
  `adaptor_secret` parameter for adapted signing
- **New RPCs:** `extractadaptorsecret` (scalar subtraction) and `verifyadaptorpresig`
  (pre-signature verification against adaptor point)
- **New files:** `src/rung/adaptor.cpp` / `adaptor.h` — adaptor sig math

### VerifyDeferredAttestation — Fail Closed

Changed from "return true if non-null hash" to unconditional `return false`.
Deferred attestation is not yet supported; fail closed prevents silent acceptance.
