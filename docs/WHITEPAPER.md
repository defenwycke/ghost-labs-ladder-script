# Ladder Script: A Typed, Structured Transaction Format for Bitcoin

**Version 1.0 -- March 2026**

---

## Abstract

Ladder Script is a typed, structured transaction format for Bitcoin (transaction version 4) that replaces opcode-based scripting with a declarative block model inspired by industrial Programmable Logic Controllers (PLC). Every byte in a Ladder Script witness is typed. Every condition is a named block with validated fields. Evaluation follows deterministic ladder logic: AND within rungs, OR across rungs, first match wins.

The design eliminates the classes of bugs inherent to stack-based scripting -- type confusion, push-data ambiguity, implicit coercion -- by requiring that all data conform to one of nine declared data types with enforced size constraints. Spending conditions are not computed; they are stated. The result is a transaction format that is auditable by inspection, verifiable in bounded time, and extensible without opcode proliferation.

---

## 1. Introduction and Motivation

### 1.1 The Limitations of Bitcoin Script

Bitcoin Script is a stack-based, Forth-like language designed for simplicity. That simplicity has served Bitcoin well, but it carries structural costs:

- **Untyped data.** Every element on the stack is an opaque byte array. A public key, a hash, a timelock value, and arbitrary graffiti are indistinguishable at the protocol level. Validation logic must infer types from position and context.

- **Opcode proliferation.** Each new capability requires a new opcode, a soft fork, and years of social coordination. Proposals such as OP_CTV, OP_CAT, OP_VAULT, and OP_CHECKCONTRACTVERIFY each add a single primitive that addresses one use case while leaving the underlying structural problems intact.

- **Difficulty of static analysis.** Because Script is imperative and stack-based, determining what a script does requires executing it. Tools that analyze scripts must simulate the stack, handle branching (OP_IF/OP_ELSE), and account for data-dependent control flow.

- **Spam surface.** Any opcode that pushes data to the stack can be used to embed arbitrary content in the blockchain. OP_RETURN provides a designated area, but witness data and non-standard scripts offer unbounded storage with no type enforcement.

### 1.2 The PLC Analogy

Industrial control systems solved a parallel problem decades ago. Early relay logic was wired point-to-point -- fragile, difficult to audit, and resistant to modification. The Programmable Logic Controller replaced relay wiring with structured programs organized as **ladder diagrams**: horizontal rungs, each containing a series of conditions (contacts) that must all be satisfied for the output (coil) to energize.

The properties that made ladder logic successful in safety-critical industrial environments are precisely those needed in a transaction authorization language:

- **Declarative.** Conditions are stated, not computed. A rung says "key A AND timelock B AND hash C," not "push A, check sig, push B, check sequence, push C, hash, equal."
- **Deterministic.** Evaluation is bounded. There are no loops, no recursion in evaluation, no data-dependent branching.
- **Auditable.** The structure of a ladder program is apparent from its representation. No simulation is required to determine what conditions must be met.

Ladder Script brings this philosophy to Bitcoin transactions.

### 1.3 Goals

1. Replace untyped stack operations with typed, validated data fields.
2. Replace opcodes with named function blocks organized in a declarative hierarchy.
3. Provide a single extensible framework that subsumes the functionality of OP_CTV, OP_VAULT, OP_CAT, and other pending proposals as individual block types within a unified system.
4. Enable post-quantum cryptographic signatures without protocol-level changes.
5. Eliminate the ability to embed arbitrary untyped data in transaction witnesses.

---

## 2. Design Philosophy

### 2.1 Typed Fields Over Raw Bytes

Every byte in a Ladder Script witness belongs to one of nine declared data types:

| Data Type | Code | Size (bytes) | Purpose |
|-----------|------|-------------|---------|
| PUBKEY | 0x01 | 1--2048 | Public key (compressed, x-only, or post-quantum). Witness only. |
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

### 2.4 Family Classification

Block types are organized into nine families based on their type code range. All 48 block types are consensus-valid and mempool-standard from activation. Family classification functions (`IsBaseBlockType`, `IsCovenantBlockType`, `IsStatefulBlockType`) exist for potential future policy differentiation, but currently all families are treated equally by the relay and mining policy.

### 2.5 Forward Compatibility

Unknown block types return `UNKNOWN_BLOCK_TYPE` during evaluation, which is treated as unsatisfied (not as an error). This means that a transaction containing a block type not yet recognized by the local node will fail to spend but will not cause a consensus failure. Nodes running older software can validate the structural integrity of any Ladder Script transaction even if they do not recognize all block types.

---

## 3. Architecture

### 3.1 Transaction Format

Ladder Script transactions use **transaction version 4** (`RUNG_TX_VERSION = 4`). This cleanly separates Ladder Script transactions from legacy (version 1) and SegWit/Taproot (version 2) transactions at the protocol level.

**Output (locking side):** The scriptPubKey of a version 4 output begins with the prefix byte `0xc1`, followed by the serialized `RungConditions` structure. Conditions contain only the "lock" data types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX). Witness-only types (PUBKEY, SIGNATURE, PREIMAGE) are prohibited in conditions. Blocks that reference public keys use PUBKEY_COMMIT (a 32-byte SHA-256 hash) in conditions; the raw PUBKEY is provided in the witness at spend time.

**Witness (unlocking side):** The witness for a version 4 input contains a serialized `LadderWitness` structure. This provides the "key" data (signatures, preimages) that satisfies the conditions in the spent output.

**Evaluation:** The `VerifyRungTx` entry point deserializes both structures, merges them field-by-field, and invokes `EvalLadder` on the merged result. The merge requires structural correspondence: same number of rungs, same number of blocks per rung, and matching block types.

### 3.2 Wire Format

The witness wire format (v2) is:

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

### 3.3 Evaluation Model

Evaluation follows a three-level dispatch:

1. **EvalLadder** iterates over rungs in order. The first rung that returns SATISFIED causes the ladder to succeed. If no rung is satisfied, the ladder fails. This is OR logic across rungs.

2. **EvalRung** iterates over blocks within a single rung. All blocks must return SATISFIED for the rung to succeed. If any block returns UNSATISFIED, UNKNOWN_BLOCK_TYPE, or ERROR, the rung fails. This is AND logic within a rung.

3. **EvalBlock** dispatches to the appropriate block-type evaluator (e.g., `EvalSigBlock`, `EvalCSVBlock`, `EvalCTVBlock`). Each evaluator examines the typed fields within the block and returns one of four results: SATISFIED, UNSATISFIED, ERROR, or UNKNOWN_BLOCK_TYPE.

If a block has the `inverted` flag set, the result is flipped: SATISFIED becomes UNSATISFIED and vice versa. ERROR is never inverted. UNKNOWN_BLOCK_TYPE inverted becomes SATISFIED.

### 3.4 Coil Types

Each output carries a `RungCoil` that determines unlock semantics:

| Coil Type | Code | Semantics |
|-----------|------|-----------|
| UNLOCK | 0x01 | Standard spend -- the output is consumed |
| UNLOCK_TO | 0x02 | Spend to a specific destination address |
| COVENANT | 0x03 | Constrains the structure of the spending transaction |

### 3.5 Attestation Modes

Each coil specifies an attestation mode that determines how signatures are provided:

| Mode | Code | Behavior |
|------|------|----------|
| INLINE | 0x01 | Signatures are provided inline in the witness fields |
| AGGREGATE | 0x02 | A single block-level aggregate signature covers multiple spends |
| DEFERRED | 0x03 | Template hash attestation (fail-closed; not yet active) |

The AGGREGATE mode uses an `AggregateProof` structure containing pubkey commitments and a single aggregate signature. The DEFERRED mode always returns false, following the fail-closed principle for features not yet activated.

---

## 4. Block Type System

Ladder Script defines 48 block types across nine families. Each family occupies a dedicated range in the uint16_t block type space.

### 4.1 Signature Family (0x0001--0x00FF)

Identity verification blocks.

**SIG (0x0001):** Single signature verification. Fields: PUBKEY (or PUBKEY_COMMIT + PUBKEY), SIGNATURE, optional SCHEME. Routes to Schnorr (64--65 byte sig), ECDSA (8--72 byte sig), or post-quantum verification based on the SCHEME field or signature size.

**MULTISIG (0x0002):** M-of-N threshold signature. Fields: NUMERIC (threshold M), N PUBKEY fields, M SIGNATURE fields. All M signatures must verify against distinct pubkeys from the set.

**ADAPTOR_SIG (0x0003):** Adaptor signature verification for atomic swaps and payment channels. Enables secret extraction from the difference between a pre-signature and the adapted on-chain signature.

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

**COSIGN (0x0681):** Co-spend contact. Requires that another input in the same transaction has a matching conditions hash, enabling multi-UTXO coordination without pre-signed transactions.

### 4.7 Anchor Family (0x0500--0x05FF)

Typed metadata blocks for layer-2 protocols and external systems.

**ANCHOR (0x0501):** Generic typed metadata anchor.

**ANCHOR_CHANNEL (0x0502):** Lightning channel state anchor.

**ANCHOR_POOL (0x0503):** Mining pool coordination anchor.

**ANCHOR_RESERVE (0x0504):** Guardian set reserve anchor.

**ANCHOR_SEAL (0x0505):** Data seal anchor for timestamping and notarization.

**ANCHOR_ORACLE (0x0506):** Oracle data feed anchor.

Anchor blocks always evaluate to SATISFIED. They serve as typed, validated metadata carriers that are committed to in the conditions hash and therefore in the sighash. This ensures that anchor data is authenticated by the transaction's signatures without requiring additional verification logic.

---

## 5. Post-Quantum Cryptography

### 5.1 Scheme-Based Routing

Ladder Script's SCHEME data type enables transparent routing to post-quantum signature verification without any changes to the block type system. A SIG block containing a SCHEME field set to FALCON512 (0x10), FALCON1024 (0x11), DILITHIUM3 (0x12), or SPHINCS_SHA (0x13) is automatically routed to the post-quantum verifier.

Supported schemes:

| Scheme | Code | Signature Size | Public Key Size |
|--------|------|---------------|-----------------|
| Schnorr (BIP-340) | 0x01 | 64--65 B | 32 B |
| ECDSA | 0x02 | 8--72 B | 33 B |
| FALCON-512 | 0x10 | ~666 B | 897 B |
| FALCON-1024 | 0x11 | ~1,280 B | 1,793 B |
| Dilithium3 | 0x12 | 3,293 B | 1,952 B |
| SPHINCS+-SHA2-256f | 0x13 | 49,216 B | 32 B |

The PUBKEY data type supports sizes up to 2,048 bytes, and the SIGNATURE data type supports sizes up to 50,000 bytes, accommodating even the largest post-quantum signature schemes.

### 5.2 PUBKEY_COMMIT: Compact UTXO Commitments

All public keys -- classical and post-quantum -- are referenced in conditions via the PUBKEY_COMMIT data type: a 32-byte SHA-256 commitment to the full public key. Raw PUBKEY is witness-only.

The conditions (stored in the UTXO set) contain only the 32-byte PUBKEY_COMMIT. The full public key is revealed in the witness at spend time, where it is verified against the commitment before being used for signature verification. This eliminates user-chosen bytes from conditions (anti-spam) and is especially beneficial for PQ keys, reducing UTXO overhead from 897 bytes to 32 bytes per post-quantum output -- a 96% reduction. The `createrungtx` RPC auto-hashes any provided pubkey hex into PUBKEY_COMMIT when building conditions.

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

RECURSE_MODIFIED permits exactly one field to change between the input conditions and the required output conditions. The evaluator compares all condition-type fields between input and output, verifying that at most one field differs. This enables state machines: a counter, a timestamp, a threshold -- any single parameter can advance per transaction while all other conditions remain fixed.

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

The PUBKEY, SIGNATURE, and PREIMAGE data types are prohibited in conditions (the locking side stored in the UTXO set). The function `IsConditionDataType()` enforces this distinction -- `IsConditionDataType(PUBKEY)` returns false. Blocks that need keys use PUBKEY_COMMIT (the SHA-256 hash of the key) in conditions. This ensures that conditions contain zero user-chosen bytes: every field is either a fixed-size hash digest or a small bounded numeric. Witness data is prunable and cryptographically bound to conditions.

### 7.3 Structural Limits

Policy enforcement (`IsStandardRungTx`) imposes the following limits:

| Parameter | Limit |
|-----------|-------|
| Rungs per input | 16 |
| Blocks per rung | 8 |
| Fields per block | 16 |
| Total witness size | 100,000 bytes |

These limits are sufficient for any practical spending condition while preventing pathological witness sizes.

### 7.4 Economic Disincentive

Conditions contain zero user-chosen bytes. Every condition field is either a fixed-size hash digest (PUBKEY_COMMIT, HASH256, HASH160 -- outputs of SHA-256 or RIPEMD160, computationally impossible to choose freely) or a small bounded integer (NUMERIC, SCHEME, SPEND_INDEX). Raw public keys are witness-only and cryptographically bound to their PUBKEY_COMMIT in conditions. Witness preimage blocks are limited to 2 per witness (MAX_PREIMAGE_BLOCKS_PER_WITNESS). The total embeddable data is limited to a few bits of grindable entropy in signature nonces -- an irreducible minimum, not a data channel.

---

## 8. Comparison with Existing Proposals

### 8.1 vs OP_CTV (BIP-119)

OP_CTV adds a single opcode for template-based covenants. Ladder Script includes CTV functionality as one block type (0x0301) among 48. The CTV block evaluator computes the identical BIP-119 template hash and verifies it against the committed value. Ladder Script subsumes OP_CTV while providing the additional infrastructure (typed fields, named blocks, standardness tiers) that OP_CTV does not address.

### 8.2 vs OP_CAT

OP_CAT proposes byte concatenation to enable computed scripts. Ladder Script eliminates the need for concatenation entirely: the type system handles composition through structured fields rather than byte manipulation. Where OP_CAT would concatenate bytes to build a hash preimage, Ladder Script declares a HASH_PREIMAGE block with typed fields. Where OP_CAT would build covenant scripts through concatenation, Ladder Script declares RECURSE_MODIFIED blocks with typed mutation parameters.

### 8.3 vs Simplicity

Simplicity and Ladder Script share the goal of replacing Bitcoin Script with a more structured, verifiable alternative. They differ in approach: Simplicity uses combinators and a type-theoretic foundation suitable for formal verification; Ladder Script uses named blocks and a PLC-inspired evaluation model optimized for auditability and industrial deployment patterns. Simplicity is a general-purpose combinator language; Ladder Script is a domain-specific block library with fixed evaluation semantics.

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

### 9.1 Deterministic Evaluation

Ladder Script evaluation contains no loops, no recursion in the evaluator (recursion blocks constrain outputs, they do not cause recursive evaluation), and no data-dependent branching in the evaluation path. The evaluation of a ladder witness visits each rung at most once and each block at most once. Worst-case evaluation time is O(R x B x F) where R is the number of rungs, B is the number of blocks per rung, and F is the maximum fields per block. With the policy limits (16 x 8 x 16), this is bounded at 2,048 field evaluations.

### 9.2 Fail-Closed Defaults

Three mechanisms ensure that ambiguity defaults to rejection:

1. **Unknown block types** return UNKNOWN_BLOCK_TYPE, which is treated as UNSATISFIED by the rung evaluator. An output containing an unrecognized block type cannot be spent by a node that does not implement it.

2. **Deferred attestation** (`VerifyDeferredAttestation`) always returns false. This mode is defined for forward compatibility but is not activated.

3. **Empty ladders** (no rungs) return false from `EvalLadder`. There is no default-allow path.

### 9.3 Sighash Integrity

The Ladder Script sighash (`SignatureHashLadder`) uses a BIP-340 tagged hash with the tag "LadderSighash". It commits to:

- Transaction version and locktime
- Prevouts hash, amounts hash, and sequences hash (unless ANYONECANPAY)
- Outputs hash (unless SIGHASH_NONE)
- Input-specific data (prevout or index)
- **Conditions hash**: the SHA-256 hash of the serialized rung conditions from the spent output

The inclusion of the conditions hash in the sighash means that a signature is bound to the specific conditions it satisfies. A valid signature for one set of conditions cannot be replayed against a different set, even if the pubkey and amounts are identical.

### 9.4 Inversion Safety

The `ApplyInversion` function preserves ERROR status: inverting an ERROR still returns ERROR. This prevents an attacker from using the inversion flag to bypass error detection. The `UNKNOWN_BLOCK_TYPE` result, when inverted, becomes SATISFIED -- this is intentional, as it allows conditions to express "NOT (some future condition)" patterns while maintaining forward compatibility.

### 9.5 Merge Validation

The `MergeConditionsAndWitness` function performs strict structural validation before evaluation. The witness must have the exact same number of rungs, the same number of blocks per rung, and matching block types in each position. A witness that attempts to present a different structure than the conditions is rejected before any evaluation occurs. The `inverted` flag is always taken from the conditions side, preventing the witness from overriding inversion semantics.

---

## 10. Conclusion

Ladder Script replaces Bitcoin's untyped, imperative scripting model with a typed, declarative block system that draws on decades of industrial control system design. By requiring every byte to be typed, every condition to be named, and every evaluation to be deterministic, Ladder Script eliminates the classes of ambiguity and complexity that have constrained Bitcoin's programmability.

The 48 block types across nine families — signature, timelock, hash, covenant, recursion, anchor, PLC, compound, and governance — provide a comprehensive vocabulary for transaction authorization. Post-quantum cryptography is supported natively through the SCHEME routing mechanism and PUBKEY_COMMIT compact representations. Spam resistance is structural rather than policy-dependent.

All block types activate together in a single soft fork. Forward compatibility ensures that transactions using future block types are structurally valid even to nodes that do not yet implement those types.

The design is implemented in Bitcoin Ghost's fork of Bitcoin Core, with 185 unit tests and 19 functional test scenarios validating the complete evaluation pipeline.

---

## References

1. Bitcoin Script reference, Bitcoin Wiki.
2. IEC 61131-3: Programmable Controllers -- Programming Languages (Ladder Diagram).
3. BIP-119: CHECKTEMPLATEVERIFY (Jeremy Rubin).
4. BIP-340: Schnorr Signatures for secp256k1.
5. BIP-341: Taproot: SegWit version 1 spending rules.
6. BIP-68: Relative lock-time using consensus-enforced sequence numbers.
7. NIST Post-Quantum Cryptography Standardization (FALCON, Dilithium, SPHINCS+).
