# Building with Ladder Script: Patterns and Possibilities

What can you build when every spending condition is a typed block and any combination is valid?

---

## 1. Self-Custody

### 1.1 Dead Man's Switch

```
Rung 0: SIG(owner) + CSV(144)
Rung 1: SIG(heir) + CLTV(current_height + 52560)
```

The owner spends freely with a 1-day safety delay. If the owner stops transacting for a year, the heir gains access. Each time the owner spends, they re-create the UTXO with a fresh CLTV height, pushing the heir's window forward.

CSV on Rung 0 prevents instant drain if the key is compromised. CLTV on Rung 1 is absolute - the heir's deadline is fixed at creation and only moves when the owner explicitly refreshes it.

### 1.2 Spending Velocity Limit

```
Rung 0: RATE_LIMIT(max=100000, refill=6) + SIG(owner) + RECURSE_SAME(depth=1000)
Rung 1: MULTISIG(2-of-2, [owner, backup]) + CSV(144)
```

Every spend is capped at 100,000 sats. The UTXO re-encumbers itself with identical conditions. Even with a compromised key, the attacker extracts 100k per transaction with a 6-block cooldown. The owner detects the breach and sweeps via Rung 1.

### 1.3 Fee-Gated Wallet

```
Rung 0: HYSTERESIS_FEE(high=20, low=1) + SIG(owner)
```

The UTXO is consensus-locked during fee spikes. Not policy - consensus. Miners cannot include the transaction if the fee rate exceeds 20 sat/vB. Prevents accidental high-fee spends and protects automated systems.

---

## 2. Multi-Party

### 2.1 Corporate Treasury

```
Rung 0: MULTISIG(2-of-3, [CFO, CEO, Board]) + EPOCH_GATE(2016, 144) + WEIGHT_LIMIT(100000) + OUTPUT_COUNT(1, 3)
Rung 1: SIG(recovery) + CSV(1008)
```

Four constraints stack on the normal spending path: 2-of-3 quorum, spending window (first day of each difficulty epoch), transaction weight cap, and output fan limit. Even a compromised quorum can only operate during the window, in small simple transactions.

Rung 1 is the emergency override - a single recovery key with a 1-week delay.

### 2.2 Co-Spend Guardian

```
Child UTXO:
  Rung 0: SIG(spender) + COSIGN(SHA256(guardian_spk))

Guardian UTXO:
  Rung 0: SIG(guardian) + RECURSE_SAME(depth=100000)
```

The child cannot move unless the guardian is spent in the same transaction. The guardian re-encumbers itself with each spend (theoretical max depth ~4.3 billion). One guardian protects unlimited children.

This is more powerful than multisig. The guardian is a UTXO, not just a key - it can carry its own conditions (timelocks, rate limits, fee gates). A parent controlling a child's wallet. An institution supervising an operator's hot wallet.

### 2.3 On-Chain Vote

```
Rung 0: COUNTER_PRESET(current=0, preset=3) + SIG(board_member) + RECURSE_MODIFIED(target=current, delta=+1)
Rung 1: SIG(treasurer) + COMPARE(GTE, 300000)
```

Each board member spends the UTXO to cast a vote, incrementing the counter by exactly 1. After 3 votes, the counter threshold is met, Rung 0 locks out, and the treasurer can release funds via Rung 1. Every vote is a transaction - permanent audit trail.

### 2.4 Escrow with Arbitration

```
Rung 0: MULTISIG(2-of-2, [buyer, seller])
Rung 1: SIG(buyer) + CSV(144)
Rung 2: SIG(arbiter) + CLTV(deadline)
```

Three non-overlapping paths. Happy path: both agree, instant settlement. Buyer refund: 1-day delay. Arbitration: only after the deadline. Each party has exactly the power they need.

---

## 3. Covenants

### 3.1 Perpetual Treasury

```
Rung 0: RECURSE_SAME(depth=100000) + MULTISIG(3-of-5, [keys]) + RELATIVE_VALUE(99, 100)
```

The governance structure survives across spends. The 3-of-5 quorum can withdraw value, but the output must preserve 99% and carry identical conditions. Maximum extraction: 1% per spend. The rules of the treasury are immutable.

### 3.2 State Machine

```
Rung 0: SEQUENCER(step=0, total=4) + LATCH_SET(state=0) + RECURSE_MODIFIED(mutations=[
    (sequencer.step, delta=+1),
    (latch.state, delta=+1)
])
```

Each spend advances the sequencer by exactly 1. The latch gates transitions. Steps cannot be skipped, reversed, or forked. Each UTXO spend is one scan cycle of a PLC program - deterministic, verifiable state transitions stored on-chain.

### 3.3 UTXO Tree Distribution

```
Rung 0: RECURSE_SPLIT(max_splits=3, min_sats=10000) + SIG(distributor)
```

One UTXO splits into children, each carrying the same conditions with `max_splits` decremented. Three levels of binary splits: 1 → 2 → 4 → 8. At depth 0, children are freely spendable. Airdrops, batch payroll, parallel processing - all from a single funded output.

### 3.4 Decaying Timelock

```
Rung 0: RECURSE_DECAY(depth=7, target=CSV, delta=144) + CSV(1008) + SIG(owner)
```

Initial delay: 1008 blocks (~1 week). Each spend subtracts 144: 1008 → 864 → 720 → ... → 0. After 7 spends, the delay is zero. Trust-building in new relationships: start constrained, relax as reliability is proven.

---

## 4. Post-Quantum

### 4.1 PQ Guardian Network

```
PQ Anchor:
  Rung 0: SIG(FALCON512) + RECURSE_SAME(depth=100000)

Children (unlimited):
  Rung 0: SIG(SCHNORR) + COSIGN(SHA256(anchor_spk))
```

One quantum-resistant anchor protects unlimited classical children (theoretical max depth ~4.3 billion spends). The MLSC output stores only a 32-byte Merkle root regardless of the PQ key size (897 bytes for FALCON-512). Pubkeys are folded into the Merkle leaf (merkle_pub_key) and appear only in the prunable witness at spend time.

A quantum attacker must break FALCON-512 to spend any child. The children use fast, compact Schnorr signatures for daily operations.

### 4.2 Hybrid Signing

```
Rung 0: SIG(SCHNORR)
Rung 1: SIG(FALCON512)
```

Normal operation: Rung 0, fast Schnorr. Quantum emergency: switch to Rung 1. The migration path is pre-committed at UTXO creation. No fund movement required under time pressure. The PQ witness is large (~1,600 bytes) but never incurred unless needed.

---

## 5. Financial Instruments

### 5.1 Self-Enforcing DCA

```
Rung 0: RECURSE_COUNT(26) + AMOUNT_LOCK(50000, 100000) + SIG(owner) + CSV(4032)
```

Every ~2 weeks, withdraw 50k-100k sats. 26 withdrawals over a year. The blockchain enforces the schedule - no exchange, no API, no third party. When the counter hits 0, remaining funds are free.

### 5.2 Streaming Payments

```
Rung 0: AMOUNT_LOCK(1000, 1000) + SIG(recipient) + CSV(6) + RECURSE_MODIFIED(target=balance, delta=-1000)
Rung 1: SIG(sender)
```

The recipient claims exactly 1,000 sats per hour (6 blocks). The balance decrements with each claim. The sender can cancel anytime via Rung 1. On-chain streaming for rent, subscriptions, royalties.

### 5.3 Escrow with Milestones

```
Rung 0: RECURSE_COUNT(4) + SIG(arbiter) + AMOUNT_LOCK(25000, 25000)
Rung 1: SIG(contractor) + CLTV(deadline)
```

Four milestone releases of exactly 25,000 sats each. The arbiter cannot release more or fewer. After the deadline, the contractor claims the remainder unilaterally.

---

## 6. Protocol Infrastructure

### 6.1 Virtual UTXO Pools

```
Rung 0: ANCHOR_POOL(vtxo_root, participants=256) + CTV(exit_template) + MULTISIG(2-of-3, operators)
Rung 1: CTV(unilateral_exit)
```

256 participants share one on-chain UTXO. Cooperative operations via Rung 0. Unilateral exit always available via Rung 1 - the CTV template guarantees each participant can extract their branch without cooperation.

### 6.2 Oracle Contracts

```
Rung 0: TAGGED_HASH(tag="outcome/win", expected=H) + SIG(winner)
Rung 1: TAGGED_HASH(tag="outcome/lose", expected=H') + SIG(loser)
```

The oracle publishes one attestation. Only the matching rung can be satisfied. Domain-separated tags prevent cross-outcome preimage reuse. Foundation for DLCs and prediction markets.

### 6.3 Accumulator Allowlists

```
Rung 0: ACCUMULATOR(merkle_root) + SIG(owner)
```

The destination must be in a pre-committed Merkle tree of allowed addresses. A tree of depth 20 supports ~1 million addresses with only a 32-byte root in the UTXO. Each spend proves membership with ~640 bytes of Merkle proof.

---

## 7. Combining Everything

The real power is composition. Each pattern above is a building block. A single UTXO can combine primitives from every family:

- **Identity** (who can spend): `SIG`, `MULTISIG`, `MUSIG_THRESHOLD`, `ADAPTOR_SIG`, `KEY_REF_SIG`
- **Time** (when they can spend): `CSV`, `CLTV`, `CSV_TIME`, `CLTV_TIME`, `EPOCH_GATE`
- **Knowledge** (what they must prove): `TAGGED_HASH`, `HTLC`, `HASH_SIG`
- **Value** (how much can move): `AMOUNT_LOCK`, `RELATIVE_VALUE`, `HYSTERESIS_VALUE`, `HYSTERESIS_FEE`, `RATE_LIMIT`, `COMPARE`
- **Structure** (what the transaction looks like): `INPUT_COUNT`, `OUTPUT_COUNT`, `WEIGHT_LIMIT`, `CTV`
- **State** (what has happened before): `LATCH_SET`, `LATCH_RESET`, `COUNTER_DOWN`, `COUNTER_UP`, `COUNTER_PRESET`, `SEQUENCER`, `TIMER_CONTINUOUS`, `TIMER_OFF_DELAY`, `ONE_SHOT`
- **Recursion** (what comes next): `RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_UNTIL`, `RECURSE_COUNT`, `RECURSE_SPLIT`, `RECURSE_DECAY`
- **Coordination** (what else must be true): `COSIGN`, `ACCUMULATOR`, `VAULT_LOCK`
- **Metadata** (what protocols can parse): `ANCHOR`, `ANCHOR_CHANNEL`, `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL`, `ANCHOR_ORACLE`
- **Legacy** (bridging existing formats): `P2PK_LEGACY`, `P2PKH_LEGACY`, `P2SH_LEGACY`, `P2WPKH_LEGACY`, `P2WSH_LEGACY`, `P2TR_LEGACY`, `P2TR_SCRIPT_LEGACY`
- **Privacy** (what remains hidden): MLSC (`0xC2`), compound blocks, diff witnesses

With AND within rungs and OR across rungs, any boolean combination of these primitives is expressible. Multiple rungs create fallback paths. Selective block inversion (non-key blocks only) creates ceiling guards. Recursion creates persistent state machines. Compound blocks and diff witnesses keep it efficient. MLSC keeps it private.

The result is a composable, typed, deterministic contract system that covers everything from simple wallets to complex multi-party protocols. No virtual machine. No arbitrary computation. No opcode proliferation. Just 59 typed blocks, AND/OR logic, and the expressiveness that emerges from their combination.
