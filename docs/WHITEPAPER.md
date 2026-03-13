# Ladder Script: A Typed, Structured Transaction Format for Bitcoin

**Version 1.0, March 2026**

---

## Abstract

Ladder Script is a typed, structured transaction format for Bitcoin (transaction version 4) that replaces opcode-based scripting with a declarative block model inspired by industrial Programmable Logic Controllers (PLC). Every byte in a Ladder Script witness is typed. Every condition is a named block with validated fields. Evaluation follows deterministic ladder logic: AND within rungs, OR across rungs, first match wins.

The design eliminates the classes of bugs inherent to stack-based scripting (type confusion, push-data ambiguity, implicit coercion) by requiring that all data conform to one of nine declared data types with enforced size constraints. Spending conditions are not computed; they are stated. The result is a transaction format that is auditable by inspection, verifiable in bounded time, and extensible without opcode proliferation.

---

## 1. Introduction and Motivation

### 1.1 The Limitations of Bitcoin Script

Bitcoin Script is a stack-based, Forth-like language designed for simplicity. That simplicity has served Bitcoin well, but it carries structural costs:

- **Untyped data.** Every element on the stack is an opaque byte array. A public key, a hash, a timelock value, and arbitrary graffiti are indistinguishable at the protocol level. Validation logic must infer types from position and context.

- **Opcode proliferation.** Each new capability requires a new opcode, a soft fork, and years of social coordination. Proposals such as OP_CTV, OP_CAT, OP_VAULT, and OP_CHECKCONTRACTVERIFY each add a single primitive that addresses one use case while leaving the underlying structural problems intact.

- **Difficulty of static analysis.** Because Script is imperative and stack-based, determining what a script does requires executing it. Tools that analyze scripts must simulate the stack, handle branching (OP_IF/OP_ELSE), and account for data-dependent control flow.

- **Spam surface.** Any opcode that pushes data to the stack can be used to embed arbitrary content in the blockchain. OP_RETURN provides a designated area, but witness data and non-standard scripts offer unbounded storage with no type enforcement.

### 1.2 The PLC Analogy

Industrial control systems solved a parallel problem decades ago. Early relay logic was wired point-to-point: fragile, difficult to audit, and resistant to modification. The Programmable Logic Controller replaced relay wiring with structured programs organised as **ladder diagrams**: horizontal rungs, each containing a series of conditions (contacts) that must all be satisfied for the output (coil) to energise.

The properties that made ladder logic successful in safety-critical industrial environments are precisely those needed in a transaction authorisation language:

- **Declarative.** Conditions are stated, not computed. A rung says "key A AND timelock B AND hash C," not "push A, check sig, push B, check sequence, push C, hash, equal."
- **Deterministic.** Evaluation is bounded. There are no loops, no recursion in evaluation, no data-dependent branching.
- **Auditable.** The structure of a ladder program is apparent from its representation. No simulation is required to determine what conditions must be met.

Ladder Script brings this philosophy to Bitcoin transactions.

### 1.3 Goals

1. Replace untyped stack operations with typed, validated data fields.
2. Replace opcodes with named function blocks organised in a declarative hierarchy.
3. Provide a single extensible framework that subsumes the functionality of OP_CTV, OP_VAULT, OP_CAT, and other pending proposals as individual block types within a unified system.
4. Enable post-quantum cryptographic signatures without protocol-level changes.
5. Eliminate the ability to embed arbitrary untyped data in transaction witnesses.

---

## 2. Design Philosophy

### 2.1 Typed Fields Over Raw Bytes

Every byte in a Ladder Script witness belongs to one of nine declared data types:

| Data Type | Code | Size (bytes) | Purpose |
|-----------|------|-------------|---------|
| PUBKEY | 0x01 | 1--2048 | Public key (witness only; conditions use PUBKEY_COMMIT) |
| PUBKEY_COMMIT | 0x02 | 32 | SHA-256 commitment to a public key |
| HASH256 | 0x03 | 32 | SHA-256 hash |
| HASH160 | 0x04 | 20 | RIPEMD160(SHA-256) hash |
| PREIMAGE | 0x05 | 1--252 | Hash preimage |
| SIGNATURE | 0x06 | 1--50000 | Signature (Schnorr, ECDSA, or post-quantum) |
| SPEND_INDEX | 0x07 | 4 | Index reference into the transaction |
| NUMERIC | 0x08 | 1--4 | Numeric value (threshold, timelock, amount) |
| SCHEME | 0x09 | 1 | Signature scheme selector |

There is no generic "push data" operation. Data that does not conform to a declared type with valid size constraints is rejected at deserialization. This is enforced by `FieldMinSize()` and `FieldMaxSize()` bounds checking during witness parsing.

### 2.2 Named Blocks Over Opcodes

Where Bitcoin Script uses opcode sequences (OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG), Ladder Script uses named function blocks. A SIG block contains a PUBKEY field and a SIGNATURE field. A CSV block contains a NUMERIC field specifying the relative lock height. The block type determines the evaluation semantics; the fields provide the parameters.

This design decouples the addition of new capabilities from opcode allocation. A new block type requires a new evaluator function but no changes to the serialization format, the type system, or the evaluation framework.

### 2.3 Declarative Over Imperative

A Ladder Script output does not contain instructions. It contains conditions. The distinction is fundamental: instructions describe a procedure to follow; conditions describe a state that must hold. The evaluator does not execute a program. It checks whether the presented witness satisfies the declared conditions.

This makes Ladder Script programs amenable to static analysis. The set of conditions required to spend an output can be enumerated by parsing the conditions structure. No execution or simulation is necessary.

### 2.4 Block Type Families

Block types are organised into ten families, each occupying a dedicated range in the `uint16_t` block type space:

- **Signature** (0x0001--0x00FF): Identity verification — SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG.
- **Timelock** (0x0100--0x01FF): Temporal constraints — CSV, CSV_TIME, CLTV, CLTV_TIME.
- **Hash** (0x0200--0x02FF): Knowledge proofs — HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH.
- **Covenant** (0x0300--0x03FF): Output constraints — CTV, VAULT_LOCK, AMOUNT_LOCK.
- **Recursion** (0x0400--0x04FF): Self-referential covenants — RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY.
- **Anchor** (0x0500--0x05FF): L2 integration and protocol-specific UTXO tagging — ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE.
- **PLC** (0x0600--0x06FF): State machines and flow control — hysteresis, timers, latches, counters, comparators, sequencers, rate limiters, co-spend.
- **Compound** (0x0700--0x07FF): Multi-condition blocks combining signature, timelock, and hash checks in a single block — HTLC, PTLC, TIMELOCKED_SIG, CLTV_SIG, HASH_SIG, TIMELOCKED_MULTISIG.
- **Governance** (0x0800--0x08FF): Transaction-level constraints — epoch gates, weight limits, input/output count bounds, relative value ratios, Merkle accumulator proofs.
- **Legacy** (0x0900--0x09FF): Legacy Bitcoin transaction types wrapped as typed Ladder blocks — P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY.

All block types are activated as a single deployment and are standard upon activation.

### 2.5 Forward Compatibility

Unknown block types return `UNKNOWN_BLOCK_TYPE` during evaluation, which is treated as unsatisfied (not as an error). This means that a transaction containing an unknown block type will fail to spend but will not cause a consensus failure. Nodes running older software can validate the structural integrity of any Ladder Script transaction even if they do not recognise all block types.

---

## 3. Architecture

### 3.1 Transaction Format

Ladder Script transactions use **transaction version 4** (`RUNG_TX_VERSION = 4`). This cleanly separates Ladder Script transactions from legacy (version 1) and SegWit/Taproot (version 2) transactions at the protocol level.

**Output (locking side):** The scriptPubKey of a version 4 output begins with the prefix byte `0xc1`, followed by the serialised `RungConditions` structure. Conditions contain only the "lock" data types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX). Witness-only types (PUBKEY, SIGNATURE, PREIMAGE) are prohibited in conditions — raw public keys are revealed only at spend time in the witness, where they are verified against their PUBKEY_COMMIT.

**Witness (unlocking side):** The witness for a version 4 input contains a serialised `LadderWitness` structure. This provides the "key" data (signatures, preimages) that satisfies the conditions in the spent output.

**Evaluation:** The `VerifyRungTx` entry point deserializes both structures, merges them field-by-field, and invokes `EvalLadder` on the merged result. The merge requires structural correspondence: same number of rungs, same number of blocks per rung, and matching block types.

### 3.2 Wire Format

The witness wire format (serialization encoding version 3) is:

```
[n_rungs: varint]
for each rung:
  [n_blocks: varint]
  for each block:
    [block_type: uint16_t LE]
    [inverted: uint8_t (0x00 or 0x01)]
    [n_fields: varint]
    for each field:
      [data_type: uint8_t]
      [data_len: varint]
      [data: bytes]
[coil_type: uint8_t]
[attestation: uint8_t]
[scheme: uint8_t]
[address_len: varint]
[address: bytes]
[n_coil_conditions: varint]
for each coil condition rung:
  (same block format as input rungs)
```

#### Micro-Header Encoding

Each block begins with a single byte that determines the encoding mode:

| First Byte | Mode | Encoding |
|------------|------|----------|
| `0x00`–`0x7F` | Micro-header | Lookup table maps byte to block type; inverted = false |
| `0x80` | Escape | Followed by `type(uint16_t LE)`; inverted = false |
| `0x81` | Escape + inverted | Followed by `type(uint16_t LE)`; inverted = true |

The micro-header lookup table assigns 1-byte slots to all 60 block types:

| Slot | Block Type | Slot | Block Type | Slot | Block Type |
|------|------------|------|------------|------|------------|
| 0x00 | SIG | 0x12 | RECURSE_DECAY | 0x24 | ONE_SHOT |
| 0x01 | MULTISIG | 0x13 | ANCHOR | 0x25 | RATE_LIMIT |
| 0x02 | ADAPTOR_SIG | 0x14 | ANCHOR_CHANNEL | 0x26 | COSIGN |
| 0x03 | CSV | 0x15 | ANCHOR_POOL | 0x27 | TIMELOCKED_SIG |
| 0x04 | CSV_TIME | 0x16 | ANCHOR_RESERVE | 0x28 | HTLC |
| 0x05 | CLTV | 0x17 | ANCHOR_SEAL | 0x29 | HASH_SIG |
| 0x06 | CLTV_TIME | 0x18 | ANCHOR_ORACLE | 0x2A | PTLC |
| 0x07 | HASH_PREIMAGE | 0x19 | HYSTERESIS_FEE | 0x2B | CLTV_SIG |
| 0x08 | HASH160_PREIMAGE | 0x1A | HYSTERESIS_VALUE | 0x2C | TIMELOCKED_MULTISIG |
| 0x09 | TAGGED_HASH | 0x1B | TIMER_CONTINUOUS | 0x2D | EPOCH_GATE |
| 0x0A | CTV | 0x1C | TIMER_OFF_DELAY | 0x2E | WEIGHT_LIMIT |
| 0x0B | VAULT_LOCK | 0x1D | LATCH_SET | 0x2F | INPUT_COUNT |
| 0x0C | AMOUNT_LOCK | 0x1E | LATCH_RESET | 0x30 | OUTPUT_COUNT |
| 0x0D | RECURSE_SAME | 0x1F | COUNTER_DOWN | 0x31 | RELATIVE_VALUE |
| 0x0E | RECURSE_MODIFIED | 0x20 | COUNTER_PRESET | 0x32 | ACCUMULATOR |
| 0x0F | RECURSE_UNTIL | 0x21 | COUNTER_UP | 0x33 | MUSIG_THRESHOLD |
| 0x10 | RECURSE_COUNT | 0x22 | COMPARE | 0x34 | KEY_REF_SIG |
| 0x11 | RECURSE_SPLIT | 0x23 | SEQUENCER | | |

Slots `0x35`–`0x7F` are reserved for future block types. When a block type has an implicit field layout for the current serialization context, field count and data type bytes are omitted (the layout defines them). Variable-size fields still carry a length prefix. The full per-type field encoding rules and implicit layouts are specified in the BIP (see Section 12, Wire Format).

### 3.3 Compact Rung Encoding

For the most common single-block patterns, the wire format supports a compact encoding signalled by `n_blocks == 0` within a rung. A COMPACT_SIG rung stores only a 32-byte `pubkey_commit` and a 1-byte `scheme` selector, and is expanded into a standard SIG block at deserialisation. This reduces per-rung overhead for the dominant single-signer case without adding new block types or evaluation paths.

### 3.4 Evaluation Model

Evaluation follows a three-level dispatch:

1. **EvalLadder** iterates over rungs in order. The first rung that returns SATISFIED causes the ladder to succeed. If no rung is satisfied, the ladder fails. This is OR logic across rungs.

2. **EvalRung** iterates over blocks within a single rung. All blocks must return SATISFIED for the rung to succeed. If any block returns UNSATISFIED, UNKNOWN_BLOCK_TYPE, or ERROR, the rung fails. This is AND logic within a rung.

3. **EvalBlock** dispatches to the appropriate block-type evaluator (e.g., `EvalSigBlock`, `EvalCSVBlock`, `EvalCTVBlock`). Each evaluator examines the typed fields within the block and returns one of four results: SATISFIED, UNSATISFIED, ERROR, or UNKNOWN_BLOCK_TYPE.

If a block has the `inverted` flag set, the result is flipped: SATISFIED becomes UNSATISFIED and vice versa. ERROR is never inverted. UNKNOWN_BLOCK_TYPE inverted becomes SATISFIED.

### 3.5 Coil Types

Each output carries a `RungCoil` that determines unlock semantics:

| Coil Type | Code | Semantics |
|-----------|------|-----------|
| UNLOCK | 0x01 | Standard spend; the output is consumed |
| UNLOCK_TO | 0x02 | Spend to a specific destination address |
| COVENANT | 0x03 | Constrains the structure of the spending transaction |

### 3.6 Attestation Modes

Each coil specifies an attestation mode that determines how signatures are provided:

| Mode | Code | Behaviour |
|------|------|----------|
| INLINE | 0x01 | Signatures are provided inline in the witness fields |
| AGGREGATE | 0x02 | A single block-level aggregate signature covers multiple spends |
| DEFERRED | 0x03 | Template hash attestation (fail-closed; not yet active — verification always returns false) |

The AGGREGATE mode uses an `AggregateProof` structure containing pubkey commitments and a single aggregate signature. The DEFERRED mode always returns false (any output using DEFERRED attestation is unspendable), following the fail-closed principle for features not yet activated.

---

## 4. Block Type System

Ladder Script defines 60 block types across ten families. Each family occupies a dedicated range in the uint16_t block type space.

### 4.1 Signature Family (0x0001--0x00FF)

Identity verification blocks.

**SIG (0x0001):** Single signature verification. Conditions: PUBKEY_COMMIT (32-byte SHA-256 commitment), optional SCHEME. Witness: PUBKEY, SIGNATURE. Routes to Schnorr (64--65 byte sig), ECDSA (8--72 byte sig), or post-quantum verification based on the SCHEME field or signature size.

**MULTISIG (0x0002):** M-of-N threshold signature. Fields: NUMERIC (threshold M), N PUBKEY fields, M SIGNATURE fields. All M signatures must verify against distinct pubkeys from the set.

**ADAPTOR_SIG (0x0003):** Adaptor signature verification for atomic swaps and payment channels. Enables secret extraction from the difference between a pre-signature and the adapted on-chain signature.

**MUSIG_THRESHOLD (0x0004):** Aggregate threshold signature. The conditions commit a PUBKEY_COMMIT for the aggregate key and NUMERIC fields for M and N. The witness provides the aggregate public key and a single Schnorr signature. The threshold signing ceremony occurs off-chain.

**KEY_REF_SIG (0x0005):** Signature using a key commitment resolved from a relay block. Enables multiple rungs to share a single PUBKEY_COMMIT defined in a relay, avoiding duplication.

### 4.2 Timelock Family (0x0100--0x01FF)

Temporal constraint blocks.

**CSV (0x0101):** Relative timelock by block height. Enforces BIP-68 sequence-based relative lock.

**CSV_TIME (0x0102):** Relative timelock by median-time-past. Same semantics as CSV but measured in seconds.

**CLTV (0x0103):** Absolute timelock by block height. Enforces nLockTime-based absolute lock.

**CLTV_TIME (0x0104):** Absolute timelock by median-time-past.

### 4.3 Hash Family (0x0200--0x02FF)

Knowledge proof blocks.

**HASH_PREIMAGE (0x0201):** SHA-256 hash preimage reveal. The conditions contain a HASH256 field; the witness provides a PREIMAGE field whose SHA-256 hash must match.

**HASH160_PREIMAGE (0x0202):** HASH160 preimage reveal. Same pattern using RIPEMD160(SHA-256).

**TAGGED_HASH (0x0203):** BIP-340 tagged hash verification. Verifies that a preimage produces a specific tagged hash value, enabling domain-separated hash commitments.

### 4.4 Covenant Family (0x0300--0x03FF)

Output constraint blocks.

**CTV (0x0301):** CheckTemplateVerify covenant. The conditions contain a HASH256 field representing the BIP-119 template hash. The spending transaction must produce a matching template hash at the given input index.

**VAULT_LOCK (0x0302):** Vault timelock covenant. Combines a signature requirement with a timelock, enforcing a mandatory delay before vault funds can be moved.

**AMOUNT_LOCK (0x0303):** Output amount range check. Contains NUMERIC fields for minimum and maximum amounts, enforcing that the output being created falls within the specified range.

### 4.5 Recursion Family (0x0400--0x04FF)

Self-referential condition blocks. These enable outputs that constrain their own spending to recreate equivalent or modified conditions in the spending transaction's outputs.

**RECURSE_SAME (0x0401):** Perpetual covenant. The spending transaction must include an output whose rung conditions are structurally identical to the spent output's conditions. This creates outputs that can be spent but never freed from their conditions.

**RECURSE_MODIFIED (0x0402):** State mutation covenant. Like RECURSE_SAME but permits a single specified field to differ between the input conditions and the output conditions. This enables state machines where one parameter changes per transaction.

**RECURSE_UNTIL (0x0403):** Temporal termination. The recursive constraint holds until a specified block height, after which the output can be spent freely.

**RECURSE_COUNT (0x0404):** Countdown termination. Contains a NUMERIC counter that must be decremented in each recursive spend. When the counter reaches zero, the recursion terminates and the output can be spent without recreating the conditions.

**RECURSE_SPLIT (0x0405):** UTXO tree splitting. The spending transaction must create multiple outputs, each carrying a portion of the original conditions. This enables fan-out patterns such as binary tree distributions.

**RECURSE_DECAY (0x0406):** Progressive constraint relaxation. Parameters decay (decrease) with each recursive spend, gradually loosening the conditions until they become trivially satisfiable.

### 4.6 PLC Family (0x0600--0x06FF)

State machine blocks inspired directly by PLC programming elements. These blocks encode stateful logic using the UTXO chain as the state carrier.

**HYSTERESIS_FEE (0x0601) / HYSTERESIS_VALUE (0x0602):** Hysteresis bands for fee rates and output values. Prevents oscillation by requiring the triggering value to exceed an upper threshold to activate and fall below a lower threshold to deactivate.

**TIMER_CONTINUOUS (0x0611):** Requires N consecutive blocks between the input and output, implementing a continuous-run timer.

**TIMER_OFF_DELAY (0x0612):** Hold-after-trigger timer. Once activated, the condition remains satisfied for a specified number of blocks after the trigger ceases.

**LATCH_SET (0x0621) / LATCH_RESET (0x0622):** Binary state latches. LATCH_SET activates a state flag; LATCH_RESET deactivates it. State is carried in the recursive UTXO chain.

**COUNTER_DOWN (0x0631) / COUNTER_PRESET (0x0632) / COUNTER_UP (0x0633):** Event counters. COUNTER_DOWN decrements on each spend. COUNTER_UP increments. COUNTER_PRESET acts as an approval accumulator with a target value.

**COMPARE (0x0641):** Threshold comparator. Evaluates an amount against high and low thresholds, producing a boolean result.

**SEQUENCER (0x0651):** Step sequencer. Enforces that spends follow a predetermined sequence of states, advancing one step per transaction.

**ONE_SHOT (0x0661):** Single-activation window. The condition can be satisfied exactly once within a specified block range.

**RATE_LIMIT (0x0671):** Spend rate limiter. Enforces a minimum interval between spends of the UTXO chain.

**COSIGN (0x0681):** Co-spend constraint. Requires that another input in the same transaction has a matching conditions hash, enabling multi-UTXO coordination without pre-signed transactions.

### 4.7 Anchor Family (0x0500--0x05FF)

Typed metadata blocks for layer-2 protocols and external systems.

**ANCHOR (0x0501):** Generic typed metadata anchor.

**ANCHOR_CHANNEL (0x0502):** Lightning channel state anchor.

**ANCHOR_POOL (0x0503):** Mining pool coordination anchor.

**ANCHOR_RESERVE (0x0504):** Guardian set reserve anchor.

**ANCHOR_SEAL (0x0505):** Data seal anchor for timestamping and notarisation.

**ANCHOR_ORACLE (0x0506):** Oracle data feed anchor.

Anchor blocks always evaluate to SATISFIED. They serve as typed, validated metadata carriers that are committed to in the conditions hash and therefore in the sighash. This ensures that anchor data is authenticated by the transaction's signatures without requiring additional verification logic.

### 4.8 Compound Family (0x0700--0x07FF)

Multi-condition blocks that combine signature, timelock, and hash checks into a single block with a single header. Compound blocks eliminate per-block headers and field counts for the merged conditions.

**TIMELOCKED_SIG (0x0701):** Signature plus relative timelock in a single block. Replaces SIG + CSV.

**HTLC (0x0702):** Hash time-locked contract. Combines HASH_PREIMAGE + CSV + SIG for atomic swaps.

**HASH_SIG (0x0703):** Hash preimage reveal with signature. Combines HASH_PREIMAGE + SIG.

**PTLC (0x0704):** Point time-locked contract. Combines ADAPTOR_SIG + CSV for payment channels.

**CLTV_SIG (0x0705):** Signature plus absolute timelock. Replaces SIG + CLTV.

**TIMELOCKED_MULTISIG (0x0706):** M-of-N multisig plus relative timelock. Replaces MULTISIG + CSV.

### 4.9 Governance Family (0x0800--0x08FF)

Transaction-level constraint blocks that enforce structural properties of the spending transaction.

**EPOCH_GATE (0x0801):** Spending window gate. Restricts transactions to periodic windows defined by block height modular arithmetic.

**WEIGHT_LIMIT (0x0802):** Maximum transaction weight in weight units.

**INPUT_COUNT (0x0803):** Minimum and maximum number of inputs.

**OUTPUT_COUNT (0x0804):** Minimum and maximum number of outputs.

**RELATIVE_VALUE (0x0805):** Anti-siphon protection. Output value must be at least a specified ratio of the input value.

**ACCUMULATOR (0x0806):** Merkle set membership proof. Verifies that a value is in a pre-committed allowlist via a Merkle proof.

### 4.10 Legacy Family (0x0900--0x09FF)

Legacy Bitcoin transaction types wrapped as typed Ladder Script blocks. Each block preserves the original spending semantics while eliminating arbitrary data surfaces.

**P2PK_LEGACY (0x0901):** P2PK wrapped. Conditions: PUBKEY_COMMIT + SCHEME. Witness: PUBKEY + SIGNATURE. The PUBKEY_COMMIT commits to the full public key; SCHEME selects the signature algorithm.

**P2PKH_LEGACY (0x0902):** P2PKH wrapped. Conditions: HASH160. Witness: PUBKEY + SIGNATURE. The witness PUBKEY must hash to the committed HASH160 value, and the SIGNATURE must verify against that key.

**P2SH_LEGACY (0x0903):** P2SH wrapped. Conditions: HASH160. Witness: PREIMAGE + inner witness. The PREIMAGE must hash to HASH160 and must deserialize as valid Ladder Script conditions. Inner witness satisfies those conditions. Recursion depth limited to 2.

**P2WPKH_LEGACY (0x0904):** P2WPKH wrapped. Conditions: HASH160. Witness: PUBKEY + SIGNATURE. Delegates to P2PKH_LEGACY evaluation: HASH160 contains the 20-byte witness program.

**P2WSH_LEGACY (0x0905):** P2WSH wrapped. Conditions: HASH256. Witness: PREIMAGE + inner witness. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2.

**P2TR_LEGACY (0x0906):** P2TR key-path wrapped. Conditions: PUBKEY_COMMIT + SCHEME. Witness: PUBKEY + SIGNATURE. PUBKEY_COMMIT commits to the Taproot internal key. Verification uses Schnorr (BIP-340) by default.

**P2TR_SCRIPT_LEGACY (0x0907):** P2TR script-path wrapped. Conditions: HASH256 + PUBKEY_COMMIT. Witness: PREIMAGE + inner witness. HASH256 is the tapleaf hash; PUBKEY_COMMIT commits to the internal key. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2.

For P2SH_LEGACY, P2WSH_LEGACY, and P2TR_SCRIPT_LEGACY, the PREIMAGE field in the witness must deserialize as a valid `RungConditions` structure. Arbitrary byte sequences are rejected at deserialization. The recursion depth is limited to 2, preventing unbounded nesting while allowing one level of script wrapping.

---

## 5. Post-Quantum Cryptography

### 5.1 Scheme-Based Routing

Ladder Script's SCHEME data type (code `0x09`, 1 byte) enables transparent routing to post-quantum signature verification without any changes to the block type system. A SIG block containing a SCHEME field set to FALCON512 (`0x10`), FALCON1024 (`0x11`), DILITHIUM3 (`0x12`), or SPHINCS_SHA (`0x13`) is automatically routed to the post-quantum verifier. When the SCHEME field is omitted, the scheme is inferred from the signature size (64--65 bytes → Schnorr, 8--72 bytes → ECDSA).

Supported schemes:

| Scheme | Code | Signature Size | Public Key Size |
|--------|------|---------------|-----------------|
| Schnorr (BIP-340) | 0x01 | 64--65 B | 32 B |
| ECDSA | 0x02 | 8--72 B | 33 B |
| FALCON-512 | 0x10 | ~666 B | 897 B |
| FALCON-1024 | 0x11 | ~1,280 B | 1,793 B |
| Dilithium3 | 0x12 | 3,293 B | 1,952 B |
| SPHINCS_SHA | 0x13 | ~7,856 B | 32 B |

The PUBKEY data type supports sizes up to 2,048 bytes, and the SIGNATURE data type supports sizes up to 50,000 bytes, accommodating all supported post-quantum signature schemes.

### 5.2 PUBKEY_COMMIT: Compact UTXO Commitments

Post-quantum public keys are large. A FALCON-512 public key is 897 bytes, which would significantly increase UTXO set size if stored in full. Ladder Script addresses this with the PUBKEY_COMMIT data type: a 32-byte SHA-256 commitment to the full public key.

The conditions (stored in the UTXO set) contain only the 32-byte PUBKEY_COMMIT. The full public key is revealed in the witness at spend time, where it is verified against the commitment before being used for signature verification. This reduces UTXO overhead from 897 bytes to 32 bytes per post-quantum output, a 96% reduction.

### 5.3 The COSIGN Guardian Pattern

The COSIGN block type (0x0681) enables a practical post-quantum migration pattern. A single UTXO locked to a post-quantum key can serve as a guardian for an unlimited number of classical (Schnorr/ECDSA) UTXOs by requiring co-spending:

1. Each protected UTXO includes a COSIGN block referencing the PQ guardian's conditions hash.
2. To spend any protected UTXO, the PQ guardian must be included as another input in the same transaction.
3. The PQ guardian uses RECURSE_SAME to perpetuate itself across spends.

This pattern provides post-quantum security to the entire set of protected UTXOs using a single post-quantum key, avoiding the need to migrate every UTXO individually.

---

## 6. Covenant Programming

The recursion family enables a class of programs that were previously impossible or required complex opcode compositions.

### 6.1 Perpetual Covenants (RECURSE_SAME)

A RECURSE_SAME block constrains the spending transaction to include an output with structurally identical conditions. This creates an output that can be spent (its value transferred) but whose conditions persist indefinitely. Applications include perpetual treasuries, governance tokens, and protocol-enforced reserve requirements.

### 6.2 State Mutations (RECURSE_MODIFIED)

RECURSE_MODIFIED permits exactly one field to change between the input conditions and the required output conditions. The evaluator compares all condition-type fields between input and output, verifying that at most one field differs. This enables state machines: a counter, a timestamp, a threshold. Any single parameter can advance per transaction while all other conditions remain fixed.

### 6.3 Countdown Termination (RECURSE_COUNT)

RECURSE_COUNT requires a NUMERIC counter field that decrements with each recursive spend. When the counter reaches zero, the recursion terminates. This is useful for vesting schedules (N spends to unlock), graduated access, and bounded commitment chains.

### 6.4 UTXO Tree Splitting (RECURSE_SPLIT)

RECURSE_SPLIT requires the spending transaction to create multiple outputs, each inheriting conditions from the parent. This enables binary tree distributions where a single UTXO can be progressively divided into 2, 4, 8, ... outputs while maintaining conditions on each branch.

### 6.5 Progressive Relaxation (RECURSE_DECAY)

RECURSE_DECAY specifies that one or more parameters must decrease with each recursive spend. A timelock might shorten, a threshold might lower, or a required amount might decrease. Eventually the conditions become trivially satisfiable, releasing the UTXO from its constraints.

---

## 7. Spam Resistance

Ladder Script's type system provides structural spam resistance that does not depend on policy rules or social conventions.

### 7.1 Mandatory Typing

Every byte in a Ladder Script witness must belong to a typed field with validated size constraints. There is no equivalent of OP_PUSHDATA that accepts arbitrary content. The deserialization function (`DeserializeLadderWitness`) rejects any witness containing unknown data types or fields that violate size bounds.

### 7.2 Witness-Only Types

The SIGNATURE and PREIMAGE data types are prohibited in conditions (the locking side stored in the UTXO set). The function `IsConditionDataType()` enforces this distinction. This prevents using condition scripts as arbitrary data storage, since the only types allowed in conditions carry semantic meaning (keys, hashes, numeric parameters).

### 7.3 Structural Limits

Policy enforcement (`IsStandardRungTx`) imposes the following limits:

| Parameter | Limit |
|-----------|-------|
| Rungs per input | 16 |
| Blocks per rung | 8 |
| Fields per block | 16 |
| Total witness size | 10,000 bytes |

These limits are sufficient for any practical spending condition while preventing pathological witness sizes.

### 7.4 Economic Disincentive

Because every field must conform to a data type that has semantic meaning in the evaluation model, embedding arbitrary data requires encoding it as valid-looking typed fields (e.g., as PUBKEY or HASH256 data). Such fields, if used in conditions, create cryptographically unspendable outputs; the "data" would need to be a valid public key or hash with a known preimage. Funds locked to such outputs are permanently burned. This creates a direct economic cost for data embedding that scales with the amount of data stored.

### 7.5 Legacy Wrapping

Legacy Bitcoin transaction types (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR) retain writable surfaces for arbitrary data embedding. By wrapping these as typed Ladder Script blocks in the Legacy family (0x0900--0x09FF), all fields become typed and validated. P2SH/P2WSH/P2TR_SCRIPT inner scripts must be valid Ladder Script conditions — arbitrary byte sequences are rejected at deserialization. This closes the inscription vector while preserving legacy spending semantics.

---

## 8. Comparison with Existing Proposals

### 8.1 vs OP_CTV (BIP-119)

OP_CTV adds a single opcode for template-based covenants. Ladder Script includes CTV functionality as one block type (0x0301) among 53. The CTV block evaluator computes the identical BIP-119 template hash and verifies it against the committed value. Ladder Script subsumes OP_CTV while providing the additional infrastructure (typed fields, named blocks, structured extensibility) that OP_CTV does not address.

### 8.2 vs OP_CAT

OP_CAT proposes byte concatenation to enable computed scripts. Ladder Script eliminates the need for concatenation entirely: the type system handles composition through structured fields rather than byte manipulation. Where OP_CAT would concatenate bytes to build a hash preimage, Ladder Script declares a HASH_PREIMAGE block with typed fields. Where OP_CAT would build covenant scripts through concatenation, Ladder Script declares RECURSE_MODIFIED blocks with typed mutation parameters.

### 8.3 vs Simplicity

Simplicity and Ladder Script share the goal of replacing Bitcoin Script with a more structured, verifiable alternative. They differ in approach: Simplicity uses combinators and a type-theoretic foundation suitable for formal verification; Ladder Script uses named blocks and a PLC-inspired evaluation model optimised for auditability and industrial deployment patterns. Simplicity is a general-purpose combinator language; Ladder Script is a domain-specific block library with fixed evaluation semantics.

### 8.4 vs Bitcoin Script

| Property | Bitcoin Script | Ladder Script |
|----------|---------------|---------------|
| Data typing | Untyped byte arrays | 9 declared types with size bounds |
| Control flow | Imperative (IF/ELSE/ENDIF) | Declarative (AND within rung, OR across rungs) |
| Extensibility | New opcodes (soft fork) | New block types (same wire format) |
| Static analysis | Requires execution simulation | Conditions enumerable by parsing |
| PQ readiness | Would require new opcodes | SCHEME field routes to PQ verifier |
| Spam resistance | Policy-dependent | Structural (type-enforced) |

---

## 9. Security Analysis

### 9.1 Threat Model

Ladder Script defends against the following attack classes:

- **Type confusion attacks.** Script's untyped stack allows a 32-byte value to be interpreted as a public key, hash, or arbitrary data depending on context. Ladder Script eliminates this by requiring every field to declare its type, with size constraints enforced at deserialization.
- **Data smuggling / spam embedding.** Attackers embed arbitrary data in Script witnesses via OP_PUSHDATA. Ladder Script's mandatory typing means every witness byte must conform to a known data type with semantic meaning; embedding arbitrary data requires creating cryptographically unspendable outputs (economic cost). Additionally, PUBKEY_COMMIT values in compact SIG conditions are always computed by the node from validated public keys — raw user-supplied commitments are rejected, preventing data smuggling via the commitment field.
- **Witness bloat / DoS.** Pathologically large witnesses can slow validation. Bounded limits (MAX_RUNGS=16, MAX_BLOCKS_PER_RUNG=8, MAX_FIELDS_PER_BLOCK=16, MAX_LADDER_WITNESS_SIZE=10,000 bytes) cap worst-case evaluation at 2,048 field checks.
- **Signature replay across outputs.** Including the conditions hash in the sighash binds each signature to the specific locking conditions it satisfies, preventing replay even when the same key locks multiple outputs.
- **Quantum key extraction.** The PUBKEY_COMMIT mechanism stores only a 32-byte hash of the public key in conditions. The full key is revealed only in the witness at spend time, limiting the window for quantum adversaries.
- **Recursive covenant non-termination.** Every RECURSE_* block type has a provably reachable terminal state (see Section 9.5).
- **Inversion-masked errors.** The inversion flag never inverts ERROR results, preventing attackers from using inverted blocks to suppress consensus failures.
- **Forward-compatibility exploitation.** Unknown block types are policy-non-standard (not relayed or mined), preventing exploitation before soft fork activation.

### 9.2 Deterministic Evaluation

Ladder Script evaluation contains no loops, no recursion in the evaluator (recursion blocks constrain outputs, they do not cause recursive evaluation), and no data-dependent branching in the evaluation path. The evaluation of a ladder witness visits each rung at most once and each block at most once. Worst-case evaluation time is O(R x B x F) where R is the number of rungs, B is the number of blocks per rung, and F is the maximum fields per block. With the policy limits (16 x 8 x 16), this is bounded at 2,048 field evaluations.

### 9.3 Fail-Closed Defaults

Three mechanisms ensure that ambiguity defaults to rejection:

1. **Unknown block types** return UNKNOWN_BLOCK_TYPE, which is treated as UNSATISFIED by the rung evaluator. An output containing an unknown block type cannot be spent by a node that does not implement it.

2. **Deferred attestation** (`VerifyDeferredAttestation`) always returns false. This mode is defined for forward compatibility but is not activated.

3. **Empty ladders** (no rungs) return false from `EvalLadder`. There is no default-allow path.

### 9.4 Sighash Integrity

The Ladder Script sighash (`SignatureHashLadder`) uses a BIP-340 tagged hash with the tag "LadderSighash". It commits to:

- Transaction version and locktime
- Prevouts hash, amounts hash, and sequences hash (unless ANYONECANPAY)
- Outputs hash (unless SIGHASH_NONE)
- Input-specific data (prevout or index)
- **Conditions hash**: the SHA-256 hash of the serialised rung conditions from the spent output

The inclusion of the conditions hash in the sighash means that a signature is bound to the specific conditions it satisfies. A valid signature for one set of conditions cannot be replayed against a different set, even if the pubkey and amounts are identical.

### 9.5 Inversion Safety

The `ApplyInversion` function preserves ERROR status: inverting an ERROR still returns ERROR. This prevents an attacker from using the inversion flag to bypass error detection. The `UNKNOWN_BLOCK_TYPE` result, when inverted, becomes SATISFIED. This is intentional: it enables conditions to express "NOT (some future condition)" patterns while maintaining forward compatibility. The rationale is that "the absence of an unknown condition" is a reasonable thing to assert, and conditions containing unknown block types are policy-non-standard (not relayed or mined by default), preventing exploitation before the block type is activated via soft fork.

### 9.6 Merge Validation

The `MergeConditionsAndWitness` function performs strict structural validation before evaluation. The witness must have the exact same number of rungs, the same number of blocks per rung, and matching block types in each position. A witness that attempts to present a different structure than the conditions is rejected before any evaluation occurs. The `inverted` flag is always taken from the conditions side, preventing the witness from overriding inversion semantics.

---

## 10. Worked Example

The following illustrates a complete Ladder Script output and witness for a simple SIG + CSV condition ("sign with key K after 10 blocks").

**Conditions (scriptPubKey):**

```
c1                          — 0xC1 prefix (Ladder Script inline conditions)
01                          — n_rungs = 1
02                          — n_blocks = 2 (SIG + CSV)
00                          — micro-header slot 0x00 = SIG
  <32 bytes pubkey_commit>  — PUBKEY_COMMIT (SHA-256 of compressed pubkey)
  01                        — SCHEME = SCHNORR (0x01)
03                          — micro-header slot 0x03 = CSV
  0a                        — NUMERIC varint = 10 (blocks)
01                          — coil_type = UNLOCK (0x01)
01                          — attestation = INLINE (0x01)
01                          — scheme = SCHNORR (0x01)
00                          — address_len = 0 (no destination constraint)
00                          — n_coil_conditions = 0
00                          — n_relays = 0
```

Total conditions size: 1 (prefix) + 1 + 1 + 1 + 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = **45 bytes**.

**Witness (spending input):**

```
01                          — n_rungs = 1
02                          — n_blocks = 2 (SIG + CSV)
00                          — micro-header slot 0x00 = SIG (witness context)
  40                        — length prefix = 64
  <64 bytes signature>      — Schnorr signature
03                          — micro-header slot 0x03 = CSV (witness context)
                            — (no witness fields for CSV — implicit empty layout)
01                          — coil_type = UNLOCK
01                          — attestation = INLINE
01                          — scheme = SCHNORR
00                          — address_len = 0
00                          — n_coil_conditions = 0
00                          — n_relays = 0
```

Total witness size: 1 + 1 + 1 + 1 + 64 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = **75 bytes** (18.75 vbytes at segwit discount).

**Evaluation:** The evaluator deserializes both structures, merges them, and evaluates rung 0: the SIG block verifies the signature against the committed pubkey using the Ladder sighash, and the CSV block checks BIP-68 sequence enforcement for 10 blocks. Both must pass (AND logic) for the spend to succeed.

---

## 11. Conclusion

Ladder Script replaces Bitcoin's untyped, imperative scripting model with a typed, declarative block system that draws on decades of industrial control system design. By requiring every byte to be typed, every condition to be named, and every evaluation to be deterministic, Ladder Script eliminates the classes of ambiguity and complexity that have constrained Bitcoin's programmability.

The 60 block types across ten families (signature, timelock, hash, covenant, recursion, anchor, PLC, compound, governance, and legacy) provide a comprehensive vocabulary for transaction authorisation. Post-quantum cryptography is supported natively through the SCHEME routing mechanism and PUBKEY_COMMIT compact representations. Spam resistance is structural rather than policy-dependent.

All block types activate simultaneously as a single deployment. Forward compatibility ensures that transactions using future block types are structurally valid even to nodes that do not yet implement those types.

The design is implemented in Bitcoin Ghost's fork of Bitcoin Core, with 185 unit tests and 19 functional test scenarios validating the complete evaluation pipeline.

---

## References

1. Bitcoin Script reference, Bitcoin Wiki. https://en.bitcoin.it/wiki/Script
2. IEC 61131-3:2013, "Programmable controllers — Part 3: Programming languages," International Electrotechnical Commission. Defines Ladder Diagram (LD) and other PLC programming languages.
3. BIP-65: OP_CHECKLOCKTIMEVERIFY (Peter Todd). Absolute timelock enforcement.
4. BIP-68: Relative lock-time using consensus-enforced sequence numbers (Mark Friedenbach, BtcDrak, Nicolas Dorier, kinoshitajona).
5. BIP-112: CHECKSEQUENCEVERIFY (BtcDrak, Mark Friedenbach, Eric Lombrozo). Relative timelock enforcement.
6. BIP-119: CHECKTEMPLATEVERIFY (Jeremy Rubin). Template-based covenant mechanism.
7. BIP-141: Segregated Witness (Eric Lombrozo, Johnson Lau, Pieter Wuille). Witness data separation and versioned script.
8. BIP-340: Schnorr Signatures for secp256k1 (Pieter Wuille, Jonas Nick, Tim Ruffing).
9. BIP-341: Taproot: SegWit version 1 spending rules (Pieter Wuille, Jonas Nick, Anthony Towns).
10. BIP-350: Bech32m format for v1+ witness addresses (Pieter Wuille).
11. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA, formerly Dilithium). National Institute of Standards and Technology, 2024. Specifies Dilithium3 with 1,952-byte public keys and 3,293-byte signatures.
12. NIST FIPS 206: Stateless Hash-Based Digital Signature Standard (SLH-DSA, formerly SPHINCS+). National Institute of Standards and Technology, 2024. SPHINCS+-SHA2-256f: 32-byte public keys, ~7,856-byte signatures.
13. FALCON: Fast-Fourier Lattice-based Compact Signatures over NTRU. NIST PQC Round 3 finalist. FALCON-512: 897-byte public keys, ~666-byte signatures. FALCON-1024: 1,793-byte public keys, ~1,280-byte signatures. (Pending FIPS standardization as of 2025.)
14. Open Quantum Safe (OQS) project: liboqs C library. https://openquantumsafe.org/
