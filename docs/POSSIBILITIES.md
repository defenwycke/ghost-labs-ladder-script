# Building with Ladder Script: Patterns and Possibilities

Ladder Script's 60 block types across 10 families compose into an enormous design space. Because evaluation follows simple AND/OR logic (all blocks in a rung must pass, first satisfied rung wins), complex spending policies emerge from combining simple primitives. This document explores what can be built.

Each pattern below lists the specific blocks involved, explains why the combination works, and notes practical considerations. Where rung numbers are shown, Rung 0 is tried first and evaluation short-circuits on the first satisfied rung.

---

## 1. Self-Custody Patterns

### 1.1 Time-Locked Savings Vault

**Blocks:** `SIG` + `CLTV` (single rung)

The simplest meaningful Ladder Script UTXO. A single rung requires both a valid signature and an absolute block height lock. The funds physically cannot move until the chain reaches the target height, regardless of what the key holder wants.

```
Rung 0: SIG(owner_key) + CLTV(height=900000)
```

This is not a social contract or a multisig quorum; it is a consensus-enforced "do not touch" mechanism. The owner's key is necessary but not sufficient. Use cases: saving discipline, scheduled payments, time-locked escrow deposits.

**Practical note:** The compound block `CLTV_SIG` (0x0705) encodes this exact pattern in a single block, saving ~8 bytes of wire overhead. For UTXOs that will sit untouched for months, this is negligible. For high-volume protocols creating thousands of timelocked outputs, the compound form adds up.

---

### 1.2 Dead Man's Switch

**Blocks:** `SIG`, `CSV`, `CLTV` (two rungs)

```
Rung 0: SIG(owner) + CSV(144)
Rung 1: SIG(heir) + CLTV(current_height + 52560)
```

The owner can spend at any time with a 1-day relative delay. The heir can only spend after approximately one year (~52,560 blocks). The owner periodically spends the UTXO to themselves, re-creating it with an updated CLTV height on Rung 1. Each refresh pushes the heir's access window another year into the future.

If the owner stops refreshing (because they lost access, became incapacitated, or died), the CLTV clock eventually expires and the heir gains access.

**Why this works:** CSV on Rung 0 provides a small delay that prevents instant drain if the owner's key is compromised (giving time to detect and react). CLTV on Rung 1 is absolute, so it does not reset when the UTXO is spent and re-created, so the owner must explicitly set a new future height each refresh. The heir's key is never exposed on-chain until needed.

**Practical note:** The compound block `TIMELOCKED_SIG` (0x0701) can replace `SIG + CSV` on Rung 0. For the heir's rung, `CLTV_SIG` (0x0705) encodes `SIG + CLTV` in one block.

---

### 1.3 Spending Velocity Limit

**Blocks:** `RATE_LIMIT` + `SIG` + `RECURSE_SAME` (single rung)

```
Rung 0: RATE_LIMIT(max_per_block=100000, cap=500000, refill=6) + SIG(owner) + RECURSE_SAME(depth=1000)
```

Every spend from this UTXO is capped at 100,000 sats. The UTXO must re-encumber itself with identical conditions after each spend (enforced by `RECURSE_SAME`). The result is a "drip wallet" that releases funds gradually.

Even if the owner's key is compromised, the attacker can only extract 100,000 sats per transaction. Combined with the refill interval of 6 blocks (~1 hour), the legitimate owner has time to detect the breach and move remaining funds through a recovery path (add a second rung with `MULTISIG` + `CSV` for emergency sweep).

**Why this works:** `RATE_LIMIT` checks the output amount against the per-block maximum. `RECURSE_SAME` forces the spending transaction to create an output with identical conditions, so the rate limit persists across every spend in the chain. The depth of 1000 allows up to 1000 spends before the covenant expires.

---

### 1.4 Graduated Access

**Blocks:** `RECURSE_COUNT` + `SIG` + `AMOUNT_LOCK` (single rung)

```
Rung 0: RECURSE_COUNT(10) + SIG(owner) + AMOUNT_LOCK(min=50000, max=100000)
```

A 10-step countdown vault. Each spend must withdraw between 50,000 and 100,000 sats, and the output must carry a `RECURSE_COUNT` decremented by 1. After 10 spends, the counter reaches 0, the covenant terminates, and remaining funds are freely spendable.

This is self-enforced dollar-cost averaging. The owner decides *when* to spend (any time), but the protocol constrains *how much* per step. It prevents the behavioral failure mode of lump-sum panic selling.

**Why this works:** `RECURSE_COUNT` enforces that the output's count is exactly `input_count - 1`. `AMOUNT_LOCK` constrains each withdrawal to a band. When the count reaches 0, `RECURSE_COUNT` returns SATISFIED without checking the output, releasing the remaining balance.

---

### 1.5 Fee-Gated Spending

**Blocks:** `HYSTERESIS_FEE` + `SIG` (single rung)

```
Rung 0: HYSTERESIS_FEE(high=20, low=1) + SIG(owner)
```

The UTXO can only move when the spending transaction's fee rate falls between 1 and 20 sat/vB. During fee spikes (common during congestion events), the UTXO is consensus-locked. No signature can override this.

This prevents accidental high-fee spends during mempool congestion, protects against fee-sniping attacks on covenant chains, and is useful for automated systems (DCA bots, scheduled payouts) that should pause rather than overpay.

**Why this works:** `HYSTERESIS_FEE` computes the actual fee rate of the spending transaction (total input value minus total output value, divided by virtual size) and checks it against the band. This is a consensus check, not a policy check. Miners cannot include the transaction if the fee rate is outside the band.

---

## 2. Multi-Party Coordination

### 2.1 Corporate Treasury

**Blocks:** `MULTISIG`, `SIG`, `CSV`, `EPOCH_GATE`, `WEIGHT_LIMIT` (multiple rungs)

```
Rung 0: MULTISIG(2-of-3, [CFO, CEO, Board]) + EPOCH_GATE(2016, 144) + WEIGHT_LIMIT(100000)
Rung 1: SIG(recovery_key) + CSV(1008)
```

Standard operations require 2-of-3 authorisation, but only during the first 144 blocks (~1 day) of each 2016-block difficulty period (~2 weeks). Outside the spending window, even a valid 2-of-3 quorum cannot move funds. The `WEIGHT_LIMIT` prevents bloated transactions that could siphon value to fees.

Rung 1 provides emergency recovery: a single recovery key (stored in a secure vault, hardware security module, or distributed via Shamir's Secret Sharing) can sweep funds after a 1-week delay. The delay gives the board time to detect unauthorised recovery attempts.

**Why this works:** `EPOCH_GATE` creates predictable spending windows that align with organizational governance cycles. `WEIGHT_LIMIT` caps transaction complexity, preventing a compromised signer from constructing a transaction that routes most value to miner fees. The OR logic between rungs means recovery is always available as a fallback.

**Enhancement:** Add `OUTPUT_COUNT(1, 3)` to Rung 0 to restrict standard operations to 1-3 outputs, preventing fan-out attacks where a compromised quorum creates hundreds of small outputs to obfuscate fund movements.

---

### 2.2 Atomic Swap

**Blocks:** `HTLC` (compound block, single rung per side)

```
Alice's UTXO:
  Rung 0: HTLC(sender=Alice, receiver=Bob, hash=H(secret), csv=144)

Bob's UTXO (other chain or other UTXO):
  Rung 0: HTLC(sender=Bob, receiver=Alice, hash=H(secret), csv=288)
```

The `HTLC` compound block (0x0702) handles the entire Hash Time-Locked Contract pattern in a single block: hash preimage verification + CSV timeout + dual-key signature routing. Alice knows the preimage. She claims Bob's UTXO by revealing it. Bob sees the preimage on-chain and uses it to claim Alice's UTXO.

If Alice does not claim within Bob's CSV window, Bob refunds himself. Alice's CSV is shorter than Bob's, ensuring she must act first.

**Why compound blocks matter here:** An HTLC built from separate `HASH_PREIMAGE` + `CSV` + `SIG` blocks requires 3 blocks in a rung, with separate field overhead for each. The `HTLC` compound block saves ~16 bytes per UTXO. In Lightning-style protocols that create thousands of HTLCs, this translates to meaningful bandwidth and storage savings.

**For adaptor-signature-based swaps:** Use `PTLC` (0x0704) instead of `HTLC`. PTLCs use adaptor signatures rather than hash preimages, providing superior privacy (no hash correlation across hops) and compatibility with Schnorr-native protocols.

---

### 2.3 Board Vote

**Blocks:** `COUNTER_PRESET` + `RECURSE_MODIFIED` (voting rung), additional release rung

```
Rung 0: COUNTER_PRESET(current=0, preset=3) + SIG(board_member) + RECURSE_MODIFIED(depth=10, target=current, delta=+1)
Rung 1: SIG(treasurer) + COMPARE(GTE, 300000)
```

Rung 0 is the voting path. Each board member spends the UTXO, which increments the counter by 1 (enforced by `RECURSE_MODIFIED`) and re-encumbers with the same conditions. `COUNTER_PRESET` is SATISFIED while `current < preset`, meaning the voting rung remains usable until 3 votes are collected.

Once `current >= preset` (3 votes reached), `COUNTER_PRESET` returns UNSATISFIED, locking out Rung 0. The system now falls through to Rung 1, where the treasurer can release funds (subject to a minimum amount check via `COMPARE`).

**Why this works:** `COUNTER_PRESET` acts as a gate that closes when the target is reached. `RECURSE_MODIFIED` ensures the counter advances by exactly +1 per spend (no skipping, no double-counting). The combination creates an on-chain quorum accumulator. Each "vote" is a real transaction, providing a permanent audit trail.

**Practical note:** Each vote costs a transaction fee. For small boards (3-7 members), this is negligible. For larger groups, consider `MUSIG_THRESHOLD` for off-chain signature aggregation with on-chain verification as a single Schnorr signature.

---

### 2.4 Escrow with Arbitration

**Blocks:** `MULTISIG`, `SIG`, `CSV`, `CLTV` (three rungs)

```
Rung 0: MULTISIG(2-of-2, [buyer, seller])
Rung 1: SIG(buyer) + CSV(144)
Rung 2: SIG(arbiter) + CLTV(deadline_height)
```

Three resolution paths, one UTXO:

- **Rung 0 (happy path):** Buyer and seller agree. Both sign. Funds move immediately. No arbitrator involved, no delays.
- **Rung 1 (buyer refund):** If the seller disappears, the buyer can reclaim after 144 blocks (~1 day). The delay prevents the buyer from racing the seller.
- **Rung 2 (arbitration):** After a hard deadline, the arbitrator can adjudicate. The arbitrator has no power before the deadline and cannot collude with either party to bypass the happy path.

**Why this works:** Rung evaluation order matters. The 2-of-2 multisig (Rung 0) is tried first and resolves instantly if both parties cooperate. The CSV delay on Rung 1 ensures the buyer cannot unilaterally refund before giving the seller time to fulfil. The CLTV on Rung 2 ensures the arbitrator only acts as a last resort after the deadline passes. Each party has exactly the power they need, no more.

---

### 2.5 Co-Spend Authorisation

**Blocks:** `COSIGN` + `SIG` (single rung)

```
Child UTXO:
  Rung 0: COSIGN(SHA256(guardian_scriptPubKey)) + SIG(spender)

Guardian UTXO:
  Rung 0: SIG(guardian)
```

The child UTXO cannot move unless the guardian UTXO is consumed as another input in the same transaction. `COSIGN` verifies that one of the transaction's other inputs has a spent output whose scriptPubKey hashes to the committed value.

A single guardian UTXO can protect unlimited child UTXOs through `COSIGN` references. When the guardian is spent (co-signing the child's transaction), it can re-encumber itself using `RECURSE_SAME` to remain available for future co-spends.

**Why this works:** `COSIGN` creates a cryptographic dependency between UTXOs without requiring the guardian to sign anything specific to the child. The guardian simply needs to be spent in the same transaction. This is strictly more powerful than multisig: the guardian is a UTXO, not just a key, so it can carry its own spending conditions (timelocks, multisig, rate limits).

**Use case:** Parental controls on a child's wallet. The child has their own key (`SIG`), but every spend requires the parent's guardian UTXO to be co-spent. The parent can add `RATE_LIMIT` to the guardian to impose spending velocity limits across all child UTXOs simultaneously.

---

## 3. Covenant Chains

### 3.1 Perpetual Treasury

**Blocks:** `RECURSE_SAME` + `MULTISIG` (single rung)

```
Rung 0: RECURSE_SAME(depth=1000) + MULTISIG(3-of-5, [key1..key5])
```

Every spend must re-create the UTXO with identical conditions. The 3-of-5 governance structure is permanent; it survives across spends. Funds can be withdrawn (the transaction can have additional outputs beyond the re-encumbered one), but the treasury itself persists.

After 1000 spends, the covenant expires (`depth` reaches 0, `RECURSE_SAME` returns UNSATISFIED), and the remaining funds become freely spendable by the 3-of-5 quorum. Set depth to a large value (e.g., 100,000) for effectively permanent treasuries.

**Why this works:** `RECURSE_SAME` compares the serialised conditions of the input being spent against the serialised conditions of the designated output. They must be byte-identical. The multisig quorum can spend value *from* the treasury but cannot change the rules *of* the treasury.

**Practical note:** The depth counter decrements implicitly. Each spend reduces the effective remaining depth by 1. When building long-lived treasuries, choose a depth that exceeds your expected governance lifetime.

---

### 3.2 State Machine

**Blocks:** `LATCH_SET`, `LATCH_RESET`, `SEQUENCER`, `RECURSE_MODIFIED`, `TIMER_CONTINUOUS`

Build a multi-step approval process as a sequence of UTXO spends:

```
Rung 0: SEQUENCER(current=0, total=4) + LATCH_SET(initiator, state=0) + RECURSE_MODIFIED(depth=20, mutations=[
    (rung=0, block=0, param=0, delta=+1),   // advance sequencer
    (rung=0, block=1, param=1, delta=+1)     // set latch 0→1
])
```

- **Step 0 (Initiation):** Sequencer at step 0. Latch unset (state=0), so `LATCH_SET` is SATISFIED. Spending this step sets the latch and advances to step 1.
- **Step 1 (Review):** `TIMER_CONTINUOUS` accumulates blocks across spends. Each spend increments the timer until the target is reached.
- **Step 2 (Approval):** `COUNTER_PRESET` collects authorisation signatures. Each spend increments the counter.
- **Step 3 (Execution):** All gates passed. Funds released.

Each step is a UTXO spend that advances the sequencer by exactly 1 (enforced by `RECURSE_MODIFIED`). The state machine cannot skip steps, cannot run backwards, and cannot be forked. There is only one UTXO.

**Why this works:** `SEQUENCER` is SATISFIED when `0 <= current < total`, gating which step is active. `RECURSE_MODIFIED` enforces that exactly the specified NUMERIC fields change by exactly the specified deltas. All other fields must remain identical. This creates deterministic, verifiable state transitions.

---

### 3.3 UTXO Tree Distribution

**Blocks:** `RECURSE_SPLIT` + `SIG` (single rung)

```
Rung 0: RECURSE_SPLIT(max_splits=3, min_sats=10000) + SIG(distributor)
```

A single UTXO splits into multiple children. Each child carries the same conditions with `max_splits` decremented by 1. With 3 levels of splitting and binary splits at each level: 1 UTXO becomes 2, then 4, then 8. At depth 0, the children are freely spendable.

Minimum output size (10,000 sats) prevents dust creation. Total output value must not exceed input value (value conservation enforced by `RECURSE_SPLIT`).

**Use cases:**
- **Airdrops:** Create one funded UTXO, split it into N recipient UTXOs in log(N) rounds.
- **Batch payments:** A payroll UTXO splits into employee-specific outputs, each carrying their own spending conditions.
- **Parallel processing:** Distribute a large covenant into smaller independent pieces that can be spent concurrently.

**Why this works:** `RECURSE_SPLIT` verifies every output in the spending transaction: each must carry a `RECURSE_SPLIT` with `max_splits - 1`, each must have at least `min_sats`, and total outputs must not exceed total inputs. The split counter prevents infinite recursion.

---

### 3.4 Decaying Timelock

**Blocks:** `RECURSE_DECAY` + `CSV` + `SIG` (single rung)

```
Rung 0: RECURSE_DECAY(depth=7, target=CSV_numeric, delta=144) + CSV(1008) + SIG(owner)
```

The initial CSV delay is 1008 blocks (~1 week). Each spend, `RECURSE_DECAY` *subtracts* the delta from the targeted NUMERIC field: 1008 becomes 864, then 720, then 576, 432, 288, 144, and finally 0. After 7 spends, the delay has decayed to zero and the UTXO is effectively freely spendable (CSV of 0 is always satisfied).

This creates a graduated release schedule. Early spends require long waits. Later spends are nearly instant. Useful for trust-building in new business relationships: start with heavy constraints, relax them as the relationship proves reliable.

**Why this works:** `RECURSE_DECAY` is identical to `RECURSE_MODIFIED` except all deltas are negated. Where `RECURSE_MODIFIED` adds, `RECURSE_DECAY` subtracts. The output's CSV value must be exactly `input_CSV - delta`. The decreasing delay is consensus-enforced.

---

### 3.5 Value-Preserving Covenant

**Blocks:** `RECURSE_SAME` + `RELATIVE_VALUE` (single rung)

```
Rung 0: RECURSE_SAME(depth=100) + RELATIVE_VALUE(numerator=95, denominator=100) + SIG(operator)
```

Every spend must re-encumber with identical conditions AND the output must be worth at least 95% of the input. This prevents value siphoning from covenant chains: an attacker who compromises the operator's key can extract at most 5% per spend (for fees or partial withdrawals).

Over 100 spends at maximum extraction, the covenant retains `0.95^100 = ~0.6%` of its original value. In practice, most spends extract far less (just transaction fees), so the effective preservation is much higher.

**Why this works:** `RELATIVE_VALUE` computes `output_amount * denominator >= input_amount * numerator` using 128-bit arithmetic to prevent overflow. Combined with `RECURSE_SAME`, the ratio check persists across every spend in the chain. The covenant cannot be modified to weaken the ratio.

---

## 4. Post-Quantum Patterns

### 4.1 PQ Guardian Network

**Blocks:** `SIG(FALCON512)`, `PUBKEY_COMMIT`, `RECURSE_SAME`, `COSIGN`

```
PQ Anchor UTXO:
  Rung 0: SIG(SCHEME=FALCON512, key=pq_key) + PUBKEY_COMMIT(SHA256(pq_key)) + RECURSE_SAME(depth=100000)

Child UTXOs (unlimited):
  Rung 0: SIG(SCHEME=SCHNORR, key=classical_key) + COSIGN(SHA256(anchor_scriptPubKey))
```

The PQ anchor is a single quantum-resistant UTXO that re-creates itself perpetually. All child UTXOs use fast, small Schnorr signatures but require the anchor to be co-spent in the same transaction via `COSIGN`.

The anchor's FALCON-512 signature provides quantum resistance. The children's Schnorr signatures provide speed and compactness. The `COSIGN` link means a quantum attacker would need to break FALCON-512 (believed to be quantum-hard) to spend any child, even though the children themselves use classical cryptography.

**Why this works:** `PUBKEY_COMMIT` stores only a 32-byte hash of the 897-byte FALCON-512 public key in the UTXO set. The full key is revealed only in the witness at spend time. This keeps the UTXO set compact. `RECURSE_SAME` ensures the anchor persists across spends without any modification.

**Scaling:** One anchor can protect an unlimited number of child UTXOs. The anchor is spent and re-created in each transaction that spends a child, but the cost is amortised when batching multiple child spends.

---

### 4.2 Hybrid Signing

**Blocks:** `SIG(SCHNORR)`, `SIG(FALCON512)`, `PUBKEY_COMMIT` (two rungs)

```
Rung 0: SIG(SCHEME=SCHNORR, key=classical_key)
Rung 1: SIG(SCHEME=FALCON512, key=pq_key) + PUBKEY_COMMIT(SHA256(pq_key))
```

In normal operation, the user spends via Rung 0 with a fast, compact 64-byte Schnorr signature. If quantum computers emerge and threaten Schnorr, the user switches to Rung 1 with a FALCON-512 signature. No UTXO migration needed; the PQ path is already baked in.

**Why this matters:** Quantum migration in Bitcoin requires moving funds to new address types. With hybrid signing, the migration path is pre-committed at UTXO creation time. The user does not need to move funds under time pressure during a quantum emergency.

**Practical note:** The Rung 1 witness is large (FALCON-512 signatures are ~666 bytes, keys are ~897 bytes). Under normal conditions, this cost is never incurred because Rung 0 resolves first. The PQ path is insurance, not the default.

---

### 4.3 Key Rotation via PUBKEY_COMMIT

**Blocks:** `SIG`, `PUBKEY_COMMIT`

```
Rung 0: SIG(SCHEME=FALCON512) + PUBKEY_COMMIT(SHA256(current_pq_key))
```

`PUBKEY_COMMIT` stores a 32-byte SHA-256 hash of the public key in the scriptPubKey conditions. The full key (up to 897 bytes for FALCON-512) is provided only in the witness at spend time. The evaluator verifies `SHA256(witness_key) == committed_hash` before checking the signature.

Key rotation works by spending the UTXO and creating a new one with a different `PUBKEY_COMMIT` value. The old key is revealed only in the spending witness. The new key remains hidden behind its commitment until the next spend.

**UTXO set impact:** Every PQ UTXO costs exactly 32 bytes of commitment data in the UTXO set, regardless of the underlying key size. This is the same as a Schnorr-based UTXO. Without `PUBKEY_COMMIT`, a FALCON-512 UTXO would consume 897 bytes, making PQ migration prohibitively expensive for the UTXO set.

---

## 5. Financial Instruments

### 5.1 Dollar-Cost Averaging

**Blocks:** `RECURSE_COUNT` + `AMOUNT_LOCK` + `SIG` + `CSV` (single rung)

```
Rung 0: RECURSE_COUNT(26) + AMOUNT_LOCK(min=50000, max=100000) + SIG(owner) + CSV(4032)
```

Every ~4032 blocks (~2 weeks), the owner withdraws between 50,000 and 100,000 sats. The covenant enforces: you must wait 2 weeks between withdrawals, you must withdraw within the specified band, and you must re-encumber the remainder. After 26 withdrawals (~1 year), the covenant expires and remaining funds are freely spendable.

This is a fully self-custodial, consensus-enforced DCA schedule. No exchange, no third party, no API. The blockchain itself is the execution engine.

**Why this works:** `CSV` enforces the minimum time between spends (relative to the previous UTXO's confirmation). `AMOUNT_LOCK` constrains withdrawal size. `RECURSE_COUNT` limits total withdrawals and terminates the covenant. `SIG` ensures only the owner can execute. All four conditions must be satisfied simultaneously (AND logic within the rung).

---

### 5.2 Options Contract

**Blocks:** `SIG`, `MULTISIG`, `CLTV_TIME`, `AMOUNT_LOCK` (three rungs)

```
Rung 0: SIG(holder) + CLTV_TIME(expiry_timestamp) + AMOUNT_LOCK(min=strike, max=strike)
Rung 1: MULTISIG(2-of-2, [holder, writer])
Rung 2: SIG(writer) + CLTV_TIME(expiry_timestamp + 604800)
```

- **Rung 0 (Exercise):** After expiry, the holder can exercise the option. `AMOUNT_LOCK` constrains the settlement value to the strike price.
- **Rung 1 (Early exercise):** By mutual agreement (2-of-2), holder and writer can settle early at any time.
- **Rung 2 (Reclaim):** If the holder does not exercise within one week after expiry (604,800 seconds), the writer reclaims the collateral.

**Why this works:** The three rungs create three non-overlapping time windows. Before expiry, only Rung 1 (mutual agreement) can satisfy. After expiry, the holder gains unilateral exercise rights via Rung 0. After expiry + 1 week, the writer can reclaim via Rung 2. The option's strike price is enforced by `AMOUNT_LOCK`, not by trust.

---

### 5.3 Revenue Sharing

**Blocks:** `RECURSE_SPLIT` + `RELATIVE_VALUE` (single rung)

```
Rung 0: RECURSE_SPLIT(max_splits=1, min_sats=10000) + RELATIVE_VALUE(numerator=60, denominator=100) + SIG(operator)
```

The parent UTXO splits into children. `RELATIVE_VALUE` ensures each child output is worth at least 60% of the input. Combined with exactly 2 outputs (one for each revenue recipient), this enforces a 60/40 split. For more complex ratios, use multiple outputs with different `RELATIVE_VALUE` constraints.

After 1 level of splitting (`max_splits=1`), the children's `RECURSE_SPLIT` counter reaches 0 and they are freely spendable by their respective recipients.

**Why this works:** `RECURSE_SPLIT` enforces value conservation (total outputs <= total input) and minimum output sizes. `RELATIVE_VALUE` enforces a minimum ratio between input and output. Together, they guarantee fair distribution without a trusted intermediary.

---

### 5.4 Streaming Payments

**Blocks:** `RECURSE_MODIFIED` + `SIG` + `CSV` + `AMOUNT_LOCK` (two rungs)

```
Rung 0: AMOUNT_LOCK(min=1000, max=1000) + SIG(recipient) + CSV(6) + RECURSE_MODIFIED(depth=100, target=amount_in_parent, delta=-1000)
Rung 1: SIG(sender)
```

Every ~6 blocks (~1 hour), the recipient can claim exactly 1,000 sats. `RECURSE_MODIFIED` decreases the tracked amount by 1,000 each spend, creating a diminishing balance. When the balance reaches zero, the stream is complete.

Rung 1 gives the sender an escape hatch: they can terminate the stream at any time by spending with their own key. This provides cancellation without requiring the recipient's cooperation.

**Why this works:** `CSV(6)` enforces a minimum gap between claims, preventing the recipient from draining everything in one block. `AMOUNT_LOCK(1000, 1000)` constrains each claim to exactly 1,000 sats. `RECURSE_MODIFIED` ensures the tracked state decreases by exactly 1,000 per spend. The sender's Rung 1 provides unilateral exit because it is evaluated after Rung 0 fails (when the recipient has not satisfied their conditions).

**Practical note:** This pattern requires one on-chain transaction per payment. For high-frequency streaming, consider Lightning or L2 channels. This on-chain version is best for low-frequency, high-trust-requirement streams (rent, subscriptions, royalties).

---

### 5.5 Escrow with Milestone Release

**Blocks:** `RECURSE_COUNT` + `SIG` + `AMOUNT_LOCK` + `CLTV` (two rungs)

```
Rung 0: RECURSE_COUNT(4) + SIG(arbiter) + AMOUNT_LOCK(min=25000, max=25000)
Rung 1: SIG(contractor) + CLTV(deadline_height)
```

A 4-milestone escrow. The arbiter authorises release of exactly 25,000 sats per milestone (enforced by `AMOUNT_LOCK`). After 4 releases, the `RECURSE_COUNT` reaches 0 and the covenant terminates.

Rung 1 is the contractor's safety net: if the client abandons the project, the contractor can claim all remaining funds after the deadline. This prevents funds from being locked forever in a stale escrow.

**Why this works:** `AMOUNT_LOCK(25000, 25000)` constrains each milestone payment to an exact amount. `RECURSE_COUNT(4)` limits total milestones. The arbiter has authority only within these constraints: they cannot release more than 25,000 per milestone or more than 4 milestones total. The contractor's CLTV fallback is a hard deadline that does not depend on anyone's cooperation.

---

## 6. Protocol Building Blocks

### 6.1 Lightning Channel Anchors

**Blocks:** `ANCHOR_CHANNEL` + `MULTISIG` + `COSIGN`

```
Channel UTXO:
  Rung 0: ANCHOR_CHANNEL(local_key, remote_key, commitment=N) + MULTISIG(2-of-2, [local, remote])
```

`ANCHOR_CHANNEL` (0x0502) records the channel's local key, remote key, and commitment number as parseable, typed metadata. The actual spending authorisation is handled by the `MULTISIG`. The anchor data enables channel state to be read directly from the UTXO set without parsing opaque scripts.

For HTLC outputs within the channel, `COSIGN` links each HTLC UTXO back to the channel anchor, ensuring they can only be spent in the same transaction as the channel state update.

---

### 6.2 Virtual UTXO Trees (VTXOs)

**Blocks:** `ANCHOR_POOL` + `CTV`

```
Pool UTXO:
  Rung 0: ANCHOR_POOL(vtxo_root=merkle_root, participant_count=256) + CTV(exit_template_hash) + MULTISIG(2-of-3, operators)
  Rung 1: CTV(unilateral_exit_template)
```

`ANCHOR_POOL` commits to a Merkle root of virtual UTXOs and a participant count. `CTV` (CheckTemplateVerify) constrains the spending transaction to match a pre-committed template. Participants can unilaterally exit by spending through Rung 1, which enforces a transaction template that includes their specific branch of the VTXO tree.

This is the foundation for Ark-style protocols, joinpools, and shared UTXO constructions. 256 participants share one on-chain UTXO. Cooperative spends (Rung 0) are efficient. Unilateral exits (Rung 1) are always available.

**Why this works:** `CTV` commits to the full transaction structure: version, locktime, input count, output count, and all output scripts and values. The exit template guarantees that a participant can always extract their funds without anyone else's cooperation. `ANCHOR_POOL` makes the commitment data parseable by protocol software.

---

### 6.3 Oracle-Gated Spending

**Blocks:** `ANCHOR_ORACLE` + `TAGGED_HASH` + `SIG`

```
Rung 0: ANCHOR_ORACLE(oracle_key, outcomes=4) + TAGGED_HASH(tag=SHA256("outcome/win"), expected=H) + SIG(winner)
Rung 1: ANCHOR_ORACLE(oracle_key, outcomes=4) + TAGGED_HASH(tag=SHA256("outcome/lose"), expected=H') + SIG(loser)
```

`ANCHOR_ORACLE` records the oracle's public key and the number of possible outcomes. `TAGGED_HASH` verifies that a witness preimage, when hashed with a specific BIP-340 tag, matches an expected digest. The oracle publishes a signed attestation to a specific outcome; the winning party provides this attestation as the preimage.

This is the foundation for Discreet Log Contracts (DLCs), prediction markets, and oracle-dependent financial instruments.

**Why this works:** `TAGGED_HASH` uses domain separation (the tag) to ensure preimages for different outcomes cannot be reused. The oracle commits to outcomes *before* the event. The expected hash values are baked into the UTXO at creation time. After the event, the oracle reveals exactly one attestation, and only the matching rung can be satisfied.

---

### 6.4 Notarized Timestamps

**Blocks:** `ANCHOR_SEAL` + `SIG`

```
Rung 0: ANCHOR_SEAL(asset_id=H(document), state_hash=H(content_v1)) + SIG(notary)
```

`ANCHOR_SEAL` (0x0505) records an asset identifier and a state transition hash as structured, typed metadata. The SIG ensures only the authorised notary can create the seal. Once confirmed, the blockchain provides an immutable timestamp proving that the document existed at a specific block height.

To update the document, spend the UTXO and create a new one with `ANCHOR_SEAL(asset_id=same, state_hash=H(content_v2))`. The chain of spends creates a verifiable document history.

**Why this works:** Anchor blocks are structural metadata: they contain typed fields that are parseable without understanding the full protocol. Any indexer can extract `ANCHOR_SEAL` data from the UTXO set to build a document registry. The `SIG` prevents unauthorised seals.

---

### 6.5 Accumulator Allowlists

**Blocks:** `ACCUMULATOR` + `SIG`

```
Rung 0: ACCUMULATOR(merkle_root=R) + SIG(owner)
```

The spending transaction's witness must include a Merkle proof demonstrating that the destination address is a leaf in a pre-committed tree of allowed addresses. The root `R` commits to the full allowlist; the proof is verified by `ACCUMULATOR` during evaluation.

This enforces on-chain allowlists without storing the full address set in the UTXO. A tree of depth 20 supports ~1 million allowed addresses with only a 32-byte root in the UTXO set. Each spend provides a Merkle proof of ~640 bytes (20 sibling hashes).

To update the allowlist, spend the UTXO and re-create it (using `RECURSE_SAME` minus the old root, or manually) with a new `ACCUMULATOR` root reflecting the updated set.

**Why this works:** `ACCUMULATOR` takes the root hash from conditions and the sibling path + leaf hash from the witness. It recomputes the Merkle root from the leaf up and compares against the committed root. If the proof verifies, the leaf is in the set. The canonical ordering (smaller hash on the left) ensures deterministic verification.

---

## 7. Governance Patterns

### 7.1 DAO Treasury with Spending Windows

**Blocks:** `EPOCH_GATE` + `MULTISIG` + `WEIGHT_LIMIT` + `OUTPUT_COUNT` (single rung)

```
Rung 0: EPOCH_GATE(2016, 144) + MULTISIG(3-of-5, [keys]) + WEIGHT_LIMIT(100000) + OUTPUT_COUNT(1, 3)
```

Four simultaneous constraints, all enforced by consensus:

1. **Temporal:** Spending only during the first 144 blocks (~1 day) of each 2016-block difficulty epoch (~2 weeks).
2. **Authorisation:** 3-of-5 multisig quorum.
3. **Structural:** Transaction weight capped at 100,000 WU, preventing bloated fee-siphon transactions.
4. **Fan control:** 1-3 outputs only, preventing value fragmentation.

No single key compromise can drain funds outside the spending window. Even a compromised 3-of-5 quorum must wait for the next window and is constrained to small, simple transactions.

**Why stacking constraints works:** AND logic within a rung means *every* block must be SATISFIED. An attacker who compromises the keys still cannot spend outside the epoch window. An attacker who somehow bypasses the epoch gate still needs 3-of-5 signatures. The constraints are independent and compose multiplicatively; each one narrows the attack surface.

---

### 7.2 Anti-Siphon Protection

**Blocks:** `RELATIVE_VALUE` + `RECURSE_SAME` + `CSV` (single rung)

```
Rung 0: RELATIVE_VALUE(99, 100) + RECURSE_SAME(depth=10000) + CSV(144) + SIG(operator)
```

Every spend preserves at least 99% of the UTXO's value. At most 1% per spend can leave the covenant (for fees, partial withdrawals, or operational costs). Combined with `CSV(144)`, at most one spend per day is possible.

Maximum extraction rate: 1% per day. After 30 days of sustained extraction, the covenant retains `0.99^30 = ~74%` of its original value. After 100 days, ~36%. This is slow enough to detect and respond to any compromise.

**Why this works:** `RELATIVE_VALUE` uses integer arithmetic (`output * 100 >= input * 99`) to avoid floating-point issues. `RECURSE_SAME` ensures the 99% rule persists across every spend. `CSV` throttles the frequency. Together, they cap both the rate and volume of value extraction.

---

### 7.3 Input/Output Fan Control

**Blocks:** `INPUT_COUNT` + `OUTPUT_COUNT` + `SIG` (single rung)

```
Rung 0: INPUT_COUNT(1, 2) + OUTPUT_COUNT(2, 2) + SIG(owner)
```

The spending transaction must have at most 2 inputs and exactly 2 outputs. This enforces a specific transaction topology:

- **Prevents consolidation attacks:** An attacker cannot combine this UTXO with dozens of others in a single transaction.
- **Enforces change output:** Exactly 2 outputs means one payment + one change (or one re-encumbered covenant + one withdrawal).
- **Limits complexity:** Simple transactions are easier to audit and verify.

**Why this works:** `INPUT_COUNT` and `OUTPUT_COUNT` inspect the spending transaction's structure at consensus time. These are hard constraints, not policy rules. A miner cannot include a transaction that violates them, regardless of fee incentives.

---

### 7.4 Weighted Governance

**Blocks:** `HYSTERESIS_VALUE` + `EPOCH_GATE` + `COUNTER_PRESET`

```
Rung 0: HYSTERESIS_VALUE(high=1000000, low=100000) + EPOCH_GATE(2016, 144) + COUNTER_PRESET(current=0, preset=5) + RECURSE_MODIFIED(depth=10, target=counter_current, delta=+1) + SIG(voter)
```

Governance participation requires a UTXO valued between 100,000 and 1,000,000 sats (enforced by `HYSTERESIS_VALUE`). Voting only happens during spending windows (`EPOCH_GATE`). Each vote increments the counter (`COUNTER_PRESET` + `RECURSE_MODIFIED`). When 5 votes are collected, the counter threshold is met and a different rung becomes active.

This creates sybil-resistant, time-bounded governance. Dust UTXOs cannot vote. Whale UTXOs above the ceiling cannot vote. Voting has a cadence. The result is accumulated on-chain.

---

## 8. Privacy and Efficiency

### 8.1 MLSC (Merkelised Ladder Script Conditions)

Any of the patterns above can be deployed using the `0xC2` MLSC output format. Instead of storing full conditions in the scriptPubKey, only a 32-byte Merkle root is published. At spend time, the witness reveals only the exercised rung plus a Merkle proof.

Consider a vault with 5 spending paths (rungs):

- **Inline format (`0xC1`):** All 5 rungs are visible in the UTXO set. Observers can analyze the vault's full spending policy.
- **MLSC format (`0xC2`):** Only a 32-byte root is stored. When the owner spends via Rung 2, they reveal Rung 2's blocks plus 3 sibling hashes. Rungs 0, 1, 3, and 4 remain hidden behind hash commitments forever (unless the UTXO is spent through those paths).

**UTXO set impact:** Always 34 bytes (1-byte prefix + 1-byte coil metadata + 32-byte root), regardless of how many rungs or blocks the ladder contains. A simple SIG and a complex 16-rung, 128-block governance policy cost the same UTXO set space.

**Privacy benefit:** Unused spending paths are never revealed. An observer cannot tell whether a UTXO has 1 rung or 16 rungs. The MLSC root leaks no structural information about the underlying policy.

---

### 8.2 Compound Block Savings

Replace multi-block patterns with single compound blocks for reduced wire overhead:

| Pattern | Separate Blocks | Compound Block | Savings |
|---------|----------------|----------------|---------|
| SIG + CSV | ~74 bytes | TIMELOCKED_SIG (~66 bytes) | ~8 bytes |
| HASH_PREIMAGE + CSV + SIG | ~118 bytes | HTLC (~102 bytes) | ~16 bytes |
| SIG + CLTV | ~74 bytes | CLTV_SIG (~66 bytes) | ~8 bytes |
| ADAPTOR_SIG + CSV | ~106 bytes | PTLC (~98 bytes) | ~8 bytes |
| MULTISIG + CSV | ~170 bytes (2-of-3) | TIMELOCKED_MULTISIG (~158 bytes) | ~12 bytes |
| HASH_PREIMAGE + SIG | ~106 bytes | HASH_SIG (~98 bytes) | ~8 bytes |

These savings seem small individually. They compound across protocols. A Lightning node managing 10,000 channels with 2 HTLC outputs each saves ~320 KB of witness data. At scale, this reduces bandwidth, storage, and fee costs.

**When to use compound blocks:** Always, for the 6 supported patterns. There is no downside. The evaluation semantics are identical, and the wire encoding is strictly smaller.

---

### 8.3 Diff Witnesses

When a transaction spends multiple UTXOs with similar conditions (common in covenant chains), subsequent inputs can reference a previous input's witness and provide only the fields that differ.

**How it works:** The first input provides a full witness. The second input sets `n_rungs = 0` (the diff sentinel), specifies `input_index` pointing to the first input, and provides field-level patches (rung index, block index, field index, new value). The coil is always provided fresh.

**Savings estimates:**
- **Simple SIG witness:** The diff needs only the new signature (~64 bytes) instead of the full witness (~92 bytes). ~28% savings.
- **3-of-5 MULTISIG:** The diff provides only the 3 new signatures (~192 bytes) instead of the full witness (~480 bytes). ~60% savings.
- **Covenant chain (RECURSE_SAME + PLC blocks):** When 5 inputs share identical conditions with different signatures, inputs 2-5 each save the full conditions overhead. Aggregate savings can exceed 70%.

**When diff witnesses matter:** Batched covenant operations. Consolidation transactions. Any transaction that spends multiple UTXOs locked to the same or similar conditions.

---

## 9. Combining Everything

The real power is composition. Each pattern above is a building block. A single UTXO can combine primitives from every family:

- **Identity** (who can spend): `SIG`, `MULTISIG`, `MUSIG_THRESHOLD`, `ADAPTOR_SIG`, `KEY_REF_SIG`
- **Time** (when they can spend): `CSV`, `CLTV`, `CSV_TIME`, `CLTV_TIME`, `EPOCH_GATE`
- **Knowledge** (what they must prove): `HASH_PREIMAGE`, `HASH160_PREIMAGE`, `TAGGED_HASH`
- **Value** (how much can move): `AMOUNT_LOCK`, `RELATIVE_VALUE`, `HYSTERESIS_VALUE`, `HYSTERESIS_FEE`, `RATE_LIMIT`, `COMPARE`
- **Structure** (what the transaction looks like): `INPUT_COUNT`, `OUTPUT_COUNT`, `WEIGHT_LIMIT`, `CTV`
- **State** (what has happened before): `LATCH_SET`, `LATCH_RESET`, `COUNTER_DOWN`, `COUNTER_UP`, `COUNTER_PRESET`, `SEQUENCER`, `TIMER_CONTINUOUS`, `TIMER_OFF_DELAY`, `ONE_SHOT`
- **Recursion** (what comes next): `RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_UNTIL`, `RECURSE_COUNT`, `RECURSE_SPLIT`, `RECURSE_DECAY`
- **Coordination** (what else must be true): `COSIGN`, `ACCUMULATOR`, `VAULT_LOCK`
- **Metadata** (what protocols can parse): `ANCHOR`, `ANCHOR_CHANNEL`, `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL`, `ANCHOR_ORACLE`
- **Privacy** (what remains hidden): MLSC (`0xC2`), compound blocks, diff witnesses

With AND within rungs and OR across rungs, any boolean combination of these primitives is expressible. Multiple rungs create fallback paths. Block inversion (the `inverted` flag on any block) creates ceiling guards (a block that must *not* be satisfied). Recursion creates persistent state machines. Compound blocks and diff witnesses keep it efficient. MLSC keeps it private.

The result is a composable, typed, deterministic contract system that covers everything from simple wallets to complex multi-party protocols. No virtual machine. No arbitrary computation. No opcode proliferation. Just 60 typed blocks, AND/OR logic, and the expressiveness that emerges from their combination.
