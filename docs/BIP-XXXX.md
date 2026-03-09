```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script — Typed Structured Transaction Conditions
Author: Bitcoin Ghost
Status: Draft
Type: Standards Track
Created: 2026-03-06
```

## Abstract

Ladder Script introduces transaction version 4 (`RUNG_TX`) with typed, structured spending conditions that replace opcode-based Script for participating outputs. Conditions are organised as named function blocks within rungs, evaluated with AND-within-rung, OR-across-rungs, first-match semantics. Every byte in a Ladder Script witness belongs to a declared data type; no arbitrary data pushes are possible. The system covers signatures, timelocks, hashes, covenants, anchors, recursion, and programmable logic controllers, all activated as a single deployment.

## Motivation

Bitcoin Script was designed as a minimal stack-based language for expressing spending conditions. Over two decades of use, several limitations have become apparent:

**Opcode ambiguity.** Script opcodes operate on untyped stack elements. A 32-byte push could be a public key, a hash, a preimage, or arbitrary data. This ambiguity complicates static analysis, makes policy enforcement unreliable, and creates opportunities for data smuggling through witness fields.

**Compositional complexity.** Expressing compound conditions (e.g., "2-of-3 multisig AND CSV timelock, OR single-sig after CLTV") requires careful stack manipulation that is error-prone and difficult to audit. The resulting scripts are opaque to non-expert reviewers.

**Limited introspection.** Bitcoin Script cannot inspect the transaction that spends it beyond basic signature verification and timelock checks. Covenants, recursive conditions, and stateful logic require proposals (CTV, APO, VAULT) that each add individual opcodes without a unifying framework.

**Forward compatibility.** Adding new spending condition types to Script requires new opcodes, each consuming from a finite opcode space and requiring individual soft fork activation. There is no mechanism for structured extensibility.

**Post-quantum readiness.** Post-quantum signature schemes produce signatures and public keys significantly larger than ECDSA or Schnorr. Script's 520-byte push limit and 10,000-byte script limit are insufficient for FALCON-1024 (1,793-byte keys) or Dilithium3 (3,293-byte signatures).

Ladder Script addresses these limitations by replacing opcode sequences with a typed, structured format where every field has a declared type with enforced size constraints, conditions compose through explicit AND/OR rung logic, and new block types can be added to numbered families without consuming opcode space.

## Specification

### Transaction Format

A Ladder Script transaction is identified by `nVersion = 4` (constant `CTransaction::RUNG_TX_VERSION`). When a node encounters a version 4 transaction spending an output whose `scriptPubKey` begins with `0xc1` or `0xc2`, it invokes the ladder evaluator instead of the Script interpreter.

**Output formats:**

Two output formats are supported:

1. **Inline conditions (`0xC1`)** — full conditions embedded in the output:
   ```
   0xc1 || SerializedRungConditions
   ```

2. **MLSC — Merkelized Ladder Script Conditions (`0xC2`)** — only a 32-byte Merkle root:
   ```
   0xc2 || conditions_root    (1 + 32 = 33 bytes)
   ```

MLSC outputs store no condition data in the UTXO set. All conditions are revealed at spend time in the witness. This eliminates data embedding (fake conditions are never published since unspendable outputs are never spent), reduces UTXO set to 40 bytes per entry regardless of script complexity, and provides MAST privacy (unused spending paths are never revealed).

The Merkle tree uses BIP-341-style tagged hashes for domain separation: leaf nodes are computed as `TaggedHash("LadderLeaf", SerializeRung(rung))` and interior nodes as `TaggedHash("LadderInternal", min(A,B) || max(A,B))`. See MERKLE-UTXO-SPEC.md for the complete specification.

The prefix bytes `0xc1` and `0xc2` were chosen after rigorous collision analysis (see Security Considerations). They do not collide with any existing standard scriptPubKey first byte (P2PKH `0x76`, P2SH `0xa9`, witness v0 `0x00`, witness v1 `0x51`, OP_RETURN `0x6a`), any witness version opcode (`0x00`-`0x60`), or any data push prefix (`0x01`-`0x4e`). While `0xc1` is the opcode for `OP_CHECKLOCKTIMEVERIFY` (BIP-65) and `0xc2` for `OP_CHECKSEQUENCEVERIFY` (BIP-112), neither appears as the first byte of a standard scriptPubKey. Condition data types (PUBKEY, PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX) are enforced; witness-only types SIGNATURE and PREIMAGE are forbidden in conditions.

**Input (unlocking side):**

The first element of the segregated witness stack for each v4 input is a serialised `LadderWitness`. For `0xC1` outputs, this contains the same rung/block layout as the conditions plus SIGNATURE and PREIMAGE fields. For `0xC2` (MLSC) outputs, the witness additionally contains the revealed rung conditions, Merkle proof hashes, and coil data.

**Evaluation entry point:**

The function `VerifyRungTx` is called for each input of a v4 transaction. For `0xC1` inputs, it deserializes conditions from the spent output's `scriptPubKey` and the witness from the spending input. For `0xC2` inputs, it deserializes the revealed conditions and Merkle proof from the witness, verifies the proof against the UTXO root, then evaluates the ladder. All 52 block evaluators are identical for both output formats.

### Wire Format (v3)

All multi-byte integers are encoded as Bitcoin compact-size varints unless otherwise noted. Single-byte enumerations are encoded as `uint8_t`. Serialization is context-aware: the same block type may use different implicit field layouts depending on whether it appears in CONDITIONS (locking) or WITNESS (spending) context.

#### Ladder Structure

```
LADDER WITNESS / RUNG CONDITIONS:

[n_rungs: varint]                         — number of rungs (0 = template mode, 1..MAX_RUNGS = normal)
  for each rung:
    [n_blocks: varint]                    — number of blocks in this rung (1..MAX_BLOCKS_PER_RUNG)
      for each block:
        <block encoding>                  — micro-header or escape (see below)
[coil_type: uint8_t]                      — RungCoilType enum
[attestation: uint8_t]                    — RungAttestationMode enum
[scheme: uint8_t]                         — RungScheme enum
[address_len: varint]                     — length of destination address (0 = none)
[address: bytes]                          — raw scriptPubKey bytes
[n_coil_conditions: varint]               — number of coil condition rungs (0 = none)
  for each coil condition rung:
    [n_blocks: varint]
      for each block:
        <block encoding>                  — same encoding as input blocks
[n_relays: varint]                        — number of relay definitions (0 = none)
  for each relay:
    [n_requirements: varint]              — number of required input indices
      for each requirement:
        [input_index: uint16_t LE]        — required co-spend input index
    [n_blocks: varint]
      for each block:
        <block encoding>                  — relay condition blocks
```

#### Block Encoding: Micro-Headers

Each block begins with a single byte that determines the encoding mode:

| First Byte | Mode | Encoding |
|------------|------|----------|
| `0x00`–`0x7F` | Micro-header | Lookup table maps byte to block type; inverted = false |
| `0x80` | Escape | Followed by `type(uint16_t LE)`; inverted = false |
| `0x81` | Escape + inverted | Followed by `type(uint16_t LE)`; inverted = true |

The micro-header lookup table maps 128 slot indices to block type values. All 52 current block types have assigned slots:

| Slot | Block Type | Slot | Block Type | Slot | Block Type |
|------|------------|------|------------|------|------------|
| 0x00 | SIG | 0x12 | ANCHOR_RESERVE | 0x24 | COUNTER_PRESET |
| 0x01 | MULTISIG | 0x13 | ANCHOR_SEAL | 0x25 | COUNTER_UP |
| 0x02 | ADAPTOR_SIG | 0x14 | ANCHOR_ORACLE | 0x26 | COMPARE |
| 0x03 | CSV | 0x15 | RECURSE_SAME | 0x27 | SEQUENCER |
| 0x04 | CSV_TIME | 0x16 | RECURSE_MODIFIED | 0x28 | ONE_SHOT |
| 0x05 | CLTV | 0x17 | RECURSE_UNTIL | 0x29 | RATE_LIMIT |
| 0x06 | CLTV_TIME | 0x18 | RECURSE_COUNT | 0x2A | COSIGN |
| 0x07 | HASH_PREIMAGE | 0x19 | RECURSE_SPLIT | 0x2B | EPOCH_GATE |
| 0x08 | HASH160_PREIMAGE | 0x1A | RECURSE_DECAY | 0x2C | HASH_SIG |
| 0x09 | TAGGED_HASH | 0x1B | HYSTERESIS_FEE | 0x2D | PTLC |
| 0x0A | CTV | 0x1C | HYSTERESIS_VALUE | 0x2E | CLTV_SIG |
| 0x0B | VAULT_LOCK | 0x1D | TIMER_CONTINUOUS | 0x2F | TIMELOCKED_MULTISIG |
| 0x0C | AMOUNT_LOCK | 0x1E | TIMER_OFF_DELAY | 0x30 | WEIGHT_LIMIT |
| 0x0D | ANCHOR | 0x1F | LATCH_SET | 0x31 | INPUT_COUNT |
| 0x0E | ANCHOR_CHANNEL | 0x20 | LATCH_RESET | 0x32 | OUTPUT_COUNT |
| 0x0F | ANCHOR_POOL | 0x21 | COUNTER_DOWN | 0x33 | RELATIVE_VALUE |
| 0x10 | ACCUMULATOR | 0x22 | HTLC | | |
| 0x11 | MUSIG_THRESHOLD | 0x23 | TIMELOCKED_SIG | | |

Slots `0x34`–`0x7F` are reserved for future block types. Unknown micro-header slots are rejected during deserialization.

A micro-header is used when all three conditions are met:
1. The block type has an assigned micro-header slot.
2. The block is not inverted (`inverted = false`).
3. The block's fields match the implicit field layout for the current context (or no implicit layout exists for the type).

When condition 3 is not met (unusual field composition), the escape byte is used even if the block type has a micro-header slot.

#### Field Encoding

Fields within a block are encoded in one of two modes:

**Explicit fields** (used with escape headers, or micro-headers without implicit layout):
```
[n_fields: varint]
  for each field:
    [data_type: uint8_t]
    <field data>                          — encoding depends on type (see below)
```

**Implicit fields** (used with micro-headers when implicit layout matches):
```
— n_fields is omitted (count known from layout)
— data_type bytes are omitted (types known from layout)
  for each field:
    <field data>                          — encoding depends on type (see below)
```

**Per-type field data encoding:**

| Data Type | Encoding |
|-----------|----------|
| NUMERIC | `CompactSize(value)` — the numeric value itself, not a length prefix. Values 0–252 use 1 byte; 253–65535 use 3 bytes; 65536–2³²−1 use 5 bytes. After deserialization, always stored as 4-byte LE internally. |
| Fixed-size (PUBKEY_COMMIT, HASH256, HASH160, SPEND_INDEX, SCHEME) | Implicit: raw data only (size known from layout). Explicit: `CompactSize(len) + data`. |
| Variable-size (PUBKEY, SIGNATURE, PREIMAGE) | `CompactSize(len) + data` (always length-prefixed). |

#### Implicit Field Layouts

For block types with a micro-header, the implicit field layout defines the expected field types and whether their sizes are fixed. This enables skipping field count, type bytes, and length prefixes for fixed-size fields.

**Example layouts (CONDITIONS context):**

| Block Type | Implicit Fields |
|------------|----------------|
| SIG | PUBKEY_COMMIT(fixed 32) + SCHEME(fixed 1) |
| CSV | NUMERIC(varint) |
| CLTV | NUMERIC(varint) |
| HTLC (HASH_PREIMAGE) | PUBKEY_COMMIT(fixed 32) + PUBKEY_COMMIT(fixed 32) + HASH256(fixed 32) + NUMERIC(varint) |
| CTV | HASH256(fixed 32) |
| COSIGN | HASH256(fixed 32) |

**Example layouts (WITNESS context):**

| Block Type | Implicit Fields |
|------------|----------------|
| SIG | SIGNATURE(variable) |
| CSV | *(empty — no witness fields)* |
| HASH_PREIMAGE | SIGNATURE(variable) + PREIMAGE(variable) |

Block types with variable field counts (e.g., MULTISIG with N pubkeys) have no implicit layout. They use micro-headers for the 3-byte header saving but encode fields explicitly.

#### Template Inheritance

When `n_rungs = 0` in a conditions script, the output uses **template inheritance**: conditions are copied from another input's conditions with optional field-level diffs.

```
TEMPLATE REFERENCE (n_rungs = 0):

[n_rungs: varint = 0]                    — signals template mode
[input_index: varint]                    — which input's conditions to inherit
[n_diffs: varint]                        — number of field-level patches
  for each diff:
    [rung_index: varint]                 — target rung
    [block_index: varint]               — target block within rung
    [field_index: varint]               — target field within block
    [data_type: uint8_t]                — replacement field type
    <field data>                        — encoded per type (NUMERIC = varint, others = length-prefixed)
```

Template resolution rules:
- The referenced input must have non-template conditions (no chaining).
- Each diff's `data_type` must match the original field's type (type-safe patching).
- Only condition data types are permitted in diffs (SIGNATURE and PREIMAGE are rejected).
- Resolution copies the source conditions and applies diffs in order.
- The sighash always commits to the **resolved** conditions, not the compact template reference.

#### Diff Witness (Witness Inheritance)

When `n_rungs = 0` in a ladder witness (the input's witness stack element), the witness inherits rungs and relays from another input's witness, with optional field-level diffs and a mandatory fresh coil. This is the witness-side counterpart to template inheritance.

```
DIFF WITNESS (n_rungs = 0 in witness):

[n_rungs: varint = 0]                    — signals diff witness mode
[input_index: varint]                    — source input to inherit from
[n_diffs: varint]                        — number of field-level diffs
  for each diff:
    [rung_index: varint]                 — target rung
    [block_index: varint]               — target block within rung
    [field_index: varint]               — target field within block
    [data_type: uint8_t]                — replacement field type
    <field data>                        — encoded per type
[coil]                                   — fresh coil (never inherited)
                                         — no relays section (inherited from source)
```

Diff witness resolution rules:
- `input_index` must be strictly less than the current input index (forward-only, prevents cycles).
- The source witness must not itself be a diff witness (no chaining).
- Only witness-side data types are permitted in diffs: PUBKEY, SIGNATURE, PREIMAGE, SCHEME.
- Each diff's type must match the source field's type (type-safe replacement).
- The coil is always provided fresh by the spender. Relays are inherited from the source.
- Resolution copies source rungs/relays, applies diffs, then proceeds through normal evaluation.
- The sighash is per-input (includes input index), so SIGNATURE fields almost always require a diff.

#### Wire Size Comparison (per block, v2 → v3)

| Scenario | V2 | V3 | Saved |
|----------|---:|---:|------:|
| SIG conditions | 41 B | 34 B | 17% |
| SIG witness | 70 B | 66 B | 6% |
| CSV conditions | 7 B | 2 B | 71% |
| HTLC conditions | 109 B | 98 B | 10% |
| HTLC witness | 104 B | 99 B | 5% |
| Template ref (vs repeated SIG conds) | 41 B | ~3 B | 93% |
| Diff witness (vs repeated SIG witness) | 107 B | ~77 B | 28% |

Conditions savings are amplified 4× by segwit weight accounting.

Deserialization performs full type and size validation. Any malformed data causes immediate rejection. Trailing bytes after the relay section cause rejection.

### Data Types

Every field in a Ladder Script witness or conditions structure has one of the following types. The type constrains the allowed data size, preventing abuse of witness space.

| Code | Name | Min Size | Max Size | Context | Description |
|------|------|----------|----------|---------|-------------|
| `0x01` | PUBKEY | 1 | 2,048 | Both | Public key (compressed 33B, x-only 32B, or post-quantum up to 1,793B) |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Both | SHA-256 commitment to a public key (for commit-reveal PQ migration) |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 hash digest |
| `0x04` | HASH160 | 20 | 20 | Both | RIPEMD160(SHA256()) hash digest |
| `0x05` | PREIMAGE | 1 | 252 | Witness only | Hash preimage (forbidden in conditions) |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness only | Signature (Schnorr 64-65B, ECDSA 8-72B, PQ up to ~3,300B) |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Index reference (uint32 LE) for aggregate attestation |
| `0x08` | NUMERIC | 1 | 4 | Both | Unsigned 32-bit integer. Encoded on wire as CompactSize(value); stored internally as 4-byte LE. |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector byte |

The SIGNATURE maximum of 50,000 bytes accommodates all post-quantum signature schemes including SPHINCS_SHA (~7,856 bytes) and Dilithium3 (3,293 bytes) with headroom. The PUBKEY maximum of 2,048 bytes accommodates FALCON-1024 public keys (1,793 bytes).

Data type validity is checked by `IsKnownDataType()`. Unknown data type codes cause deserialization failure.

### Block Types

Block types are organised into numbered families. Each block type evaluates a single spending condition. The block type is encoded as a `uint16_t` (little-endian) on the wire.

#### Signature, Timelock, and Hash (0x0001-0x02FF)

These block types cover the fundamental spending conditions equivalent to existing Script capabilities.

**Signature Family (0x0001-0x00FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0001` | SIG | PUBKEY + SIGNATURE | Single signature verification. Supports Schnorr (BIP-340), ECDSA, and post-quantum schemes via SCHEME field. If a PUBKEY_COMMIT field is present, the PUBKEY must hash to it (commit-reveal). |
| `0x0002` | MULTISIG | NUMERIC(threshold) + N*(PUBKEY + SIGNATURE) | M-of-N threshold signature. First NUMERIC field is the threshold M. Exactly M valid signatures required from the N provided public keys. |
| `0x0003` | ADAPTOR_SIG | PUBKEY(signer) + PUBKEY(adaptor point) + SIGNATURE | Adaptor signature verification. The second PUBKEY is the adaptor point T. Verification checks that the signature is valid under the combined challenge H(R+T \|\| P \|\| m). Enables atomic swaps and payment channel protocols. |
| `0x0004` | MUSIG_THRESHOLD | PUBKEY_COMMIT + NUMERIC(M) + NUMERIC(N) + PUBKEY + SIGNATURE | MuSig2/FROST aggregate threshold signature. On-chain: single aggregate key + single Schnorr signature (~131B total, constant regardless of M/N). M and N are policy/display only. Schnorr-only (no PQ path). |

**Timelock Family (0x0100-0x01FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0101` | CSV | NUMERIC(blocks) | Relative timelock in blocks (BIP-68 sequence enforcement). |
| `0x0102` | CSV_TIME | NUMERIC(seconds) | Relative timelock in seconds (BIP-68 time-based). |
| `0x0103` | CLTV | NUMERIC(height) | Absolute timelock by block height (nLockTime enforcement). |
| `0x0104` | CLTV_TIME | NUMERIC(timestamp) | Absolute timelock by median-time-past. |

**Hash Family (0x0200-0x02FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0201` | HASH_PREIMAGE | HASH256 + PREIMAGE | SHA-256 preimage reveal. SATISFIED when SHA256(preimage) equals the committed hash. |
| `0x0202` | HASH160_PREIMAGE | HASH160 + PREIMAGE | HASH160 preimage reveal. SATISFIED when RIPEMD160(SHA256(preimage)) equals the committed hash. |
| `0x0203` | TAGGED_HASH | HASH256(tag) + HASH256(expected) + PREIMAGE | BIP-340 tagged hash verification. SATISFIED when TaggedHash(tag, preimage) equals the expected hash. |

#### Covenant and Anchor (0x0300-0x05FF)

These block types constrain the spending transaction's outputs or anchor the UTXO to a protocol role.

**Covenant Family (0x0300-0x03FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0301` | CTV | HASH256(template) | OP_CHECKTEMPLATEVERIFY covenant (BIP-119). SATISFIED when the spending transaction matches the committed template hash. The template hash is computed identically to BIP-119. |
| `0x0302` | VAULT_LOCK | PUBKEY + SIGNATURE + NUMERIC(delay) | Vault timelock covenant. Requires a valid signature plus an enforced delay period before the vault can be swept. |
| `0x0303` | AMOUNT_LOCK | NUMERIC(min) + NUMERIC(max) | Output amount range check. SATISFIED when the corresponding output amount is within [min, max] satoshis inclusive. |

**Anchor Family (0x0500-0x05FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0501` | ANCHOR | HASH256(protocol_id) | Generic anchor. Tags a UTXO as belonging to a protocol identified by the hash. Requires at least one field. |
| `0x0502` | ANCHOR_CHANNEL | PUBKEY + NUMERIC(commitment) | Lightning channel anchor. Binds a UTXO to a channel identified by the public key. Commitment value must be non-zero if present. |
| `0x0503` | ANCHOR_POOL | HASH256(pool_id) + NUMERIC(participant_count) | Pool anchor. Requires a pool identifier hash and a non-zero participant count. |
| `0x0504` | ANCHOR_RESERVE | NUMERIC(threshold_n) + NUMERIC(group_m) + HASH256(group_id) | Reserve anchor with N-of-M guardian set. Requires N <= M and a group identifier hash. |
| `0x0505` | ANCHOR_SEAL | HASH256(seal_hash) | Seal anchor. Permanently binds a UTXO to a data commitment. |
| `0x0506` | ANCHOR_ORACLE | PUBKEY(oracle) + NUMERIC(quorum) | Oracle anchor. Requires an oracle public key and a non-zero quorum count. |

#### Recursion and Programmable Logic Controllers (0x0400-0x06FF)

These block types enable stateful, self-referencing, and rate-governed spending conditions.

**Recursion Family (0x0400-0x04FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0401` | RECURSE_SAME | (none beyond structure) | Recursive re-encumbrance. SATISFIED only when at least one output carries the identical rung conditions as the input being spent. |
| `0x0402` | RECURSE_MODIFIED | NUMERIC(rung_index) + NUMERIC(block_index) + NUMERIC(field_index) + NUMERIC/HASH256(new_value) | Recursive re-encumbrance with a single field mutation. The spending output must carry conditions identical to the input except for the specified field. Supports cross-rung mutation and multi-field mutation via multiple field groups. |
| `0x0403` | RECURSE_UNTIL | NUMERIC(target_height) | Recursive until block height. SATISFIED (allowing termination) when the current block height >= target. Below the target height, the output must re-encumber with identical conditions. |
| `0x0404` | RECURSE_COUNT | NUMERIC(current) + NUMERIC(step) | Recursive countdown. Current value must decrease by step in the re-encumbered output. SATISFIED (allowing termination) when current reaches zero. |
| `0x0405` | RECURSE_SPLIT | NUMERIC(min_sats) | Recursive output splitting. SATISFIED when the output amount is at least min_sats, enabling controlled subdivision. |
| `0x0406` | RECURSE_DECAY | NUMERIC(rung) + NUMERIC(block) + NUMERIC(field) + NUMERIC(delta) | Recursive parameter decay. Like RECURSE_MODIFIED but the target field must decrease by exactly delta per spend. Supports multi-field decay via multiple field groups. |

**PLC Family (0x0600-0x06FF):**

The Programmable Logic Controller family brings industrial automation concepts to transaction conditions, enabling stateful, rate-governed, and sequenced spending logic.

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0601` | HYSTERESIS_FEE | NUMERIC(low) + NUMERIC(high) | Fee hysteresis band. SATISFIED when the transaction fee rate falls within the [low, high] range. Low must not exceed high. When transaction context is available, validates against actual fee rate. |
| `0x0602` | HYSTERESIS_VALUE | NUMERIC(low) + NUMERIC(high) | Value hysteresis band. SATISFIED when the output amount falls within the [low, high] range. Low must not exceed high. |
| `0x0611` | TIMER_CONTINUOUS | NUMERIC(duration) [+ NUMERIC(elapsed)] | Continuous timer. Requires a specified number of consecutive blocks. With two NUMERIC fields, SATISFIED when elapsed >= duration. Duration must be non-zero. |
| `0x0612` | TIMER_OFF_DELAY | NUMERIC(delay) + NUMERIC(remaining) | Off-delay timer. Hold after trigger expires. SATISFIED when remaining reaches zero. Both delay and remaining must be non-zero. |
| `0x0621` | LATCH_SET | PUBKEY + [NUMERIC(state)] | Latch set (state activation). SATISFIED when the latch state is unset (0) or absent, allowing transition to set. UNSATISFIED if state is already non-zero. |
| `0x0622` | LATCH_RESET | PUBKEY + NUMERIC(delay) + [NUMERIC(state)] | Latch reset (state deactivation). SATISFIED when the latch state is set (non-zero), allowing transition to unset after delay. UNSATISFIED if state is zero. |
| `0x0631` | COUNTER_DOWN | PUBKEY + NUMERIC(current) + NUMERIC(step) | Down counter. SATISFIED when current count is positive. Decrements by step per spend. |
| `0x0632` | COUNTER_PRESET | NUMERIC(preset) + NUMERIC(current) | Preset counter (approval accumulator). SATISFIED when current >= preset (threshold reached). |
| `0x0633` | COUNTER_UP | PUBKEY + NUMERIC(current) + NUMERIC(target) | Up counter. SATISFIED when current >= target. Requires two NUMERIC fields. |
| `0x0641` | COMPARE | NUMERIC(operator) + NUMERIC(operand) [+ NUMERIC(upper)] | Comparator. Operator encoding: 0=EQ, 1=NEQ, 2=LT, 3=GT, 4=LTE, 5=GTE, 6=IN_RANGE. IN_RANGE requires a third NUMERIC (upper bound). Compares against the output amount from evaluation context. |
| `0x0651` | SEQUENCER | NUMERIC(current_step) + NUMERIC(total_steps) | Step sequencer. SATISFIED when current_step < total_steps. Total must be non-zero. |
| `0x0661` | ONE_SHOT | HASH256(id) + NUMERIC(window) [+ NUMERIC(state)] | One-shot activation window. SATISFIED when state is zero (not yet fired) or absent. Once fired, permanently unsatisfied. |
| `0x0671` | RATE_LIMIT | NUMERIC(max_per_window) + NUMERIC(window_blocks) + NUMERIC(current_count) | Rate limiter. SATISFIED when current_count < max_per_window. |
| `0x0681` | COSIGN | HASH256(conditions_hash) | Co-spend contact. SATISFIED when another input in the same transaction has rung conditions whose serialised hash matches conditions_hash. The evaluator skips the current input index when scanning. |

### Coil Types

The coil determines the output semantics of a ladder-locked UTXO. It is serialised after the rung data.

| Code | Name | Description |
|------|------|-------------|
| `0x01` | UNLOCK | Standard unlock. The UTXO can be spent to any destination. |
| `0x02` | UNLOCK_TO | Unlock to a specific destination. The coil's `address` field contains the required destination `scriptPubKey`. The recipient must also satisfy any coil conditions. |
| `0x03` | COVENANT | Covenant. Constrains the structure of the spending transaction via coil conditions. |

### Attestation Modes

The attestation mode determines how signatures are provided for spends within a block.

| Code | Name | Description |
|------|------|-------------|
| `0x01` | INLINE | Signatures are provided inline in the witness, one per SIG/MULTISIG block. This is the default mode. |
| `0x02` | AGGREGATE | Block-level signature aggregation. A single aggregate signature covers all AGGREGATE-mode spends in one block. Each spend is identified by a SPEND_INDEX and a PUBKEY_COMMIT. All spends in an aggregate proof must use the same signature scheme. |
| `0x03` | DEFERRED | Deferred attestation via template hash. Currently specified but not activated (verification always returns false, failing closed). Reserved for future cross-chain and batch verification protocols. |

### Signature Schemes

The scheme selector determines which signature algorithm is used for verification.

| Code | Name | Key Size | Sig Size | Description |
|------|------|----------|----------|-------------|
| `0x01` | SCHNORR | 32 B | 64-65 B | BIP-340 Schnorr signatures (default). |
| `0x02` | ECDSA | 33 B | 8-72 B | ECDSA for legacy compatibility. |
| `0x10` | FALCON512 | 897 B | ~666 B | FALCON-512 post-quantum lattice signatures. |
| `0x11` | FALCON1024 | 1,793 B | ~1,280 B | FALCON-1024 post-quantum lattice signatures. |
| `0x12` | DILITHIUM3 | 1,952 B | 3,293 B | Dilithium3 (ML-DSA) post-quantum lattice signatures. |

Post-quantum schemes (codes >= `0x10`) require liboqs support compiled into the node. Verification against a PQ scheme without liboqs support returns false.

The PUBKEY_COMMIT mechanism enables commit-reveal PQ migration: a conditions output commits to the SHA-256 hash of a PQ public key (32 bytes), while the witness reveals the full public key for verification. This prevents quantum adversaries from extracting keys from the conditions script before the spend occurs.

### Evaluation Rules

Ladder evaluation follows a strict three-level logic:

**Level 1, Ladder (OR):** Rungs are evaluated in order. The first rung that returns SATISFIED terminates evaluation with success. If all rungs return UNSATISFIED, the ladder fails. If any rung returns ERROR, the entire transaction is invalid (consensus failure).

**Level 2, Rung (AND):** All blocks within a rung must return SATISFIED for the rung to be SATISFIED. Evaluation short-circuits on the first UNSATISFIED or ERROR result.

**Level 3, Block Inversion:** Each block has an `inverted` flag. When set:
- SATISFIED becomes UNSATISFIED
- UNSATISFIED becomes SATISFIED
- ERROR remains ERROR (never inverted)
- UNKNOWN_BLOCK_TYPE becomes ERROR (unconditionally unusable)

**Unknown block types:** An unrecognized `block_type` value returns UNKNOWN_BLOCK_TYPE. When not inverted, it propagates as a non-SATISFIED result, causing the rung to fail and evaluation to fall through to subsequent rungs. When inverted, it becomes ERROR (consensus failure). This prevents an attacker from using an inverted unknown block type to bypass spending conditions. New block types are deployed via soft fork activation — all block types activate simultaneously.

### Sighash

Ladder Script uses a tagged hash `TaggedHash("LadderSighash")` for signature computation. The algorithm is derived from BIP-341 sighash but simplified (no annex, no tapscript extensions, no code separator).

**Sighash computation commits to:**

```
epoch              = 0x00 (uint8)
hash_type          = uint8 (SIGHASH_DEFAULT=0, ALL=1, NONE=2, SINGLE=3, ANYONECANPAY=0x80)
tx_version         = int32
tx_locktime        = uint32

— Unless ANYONECANPAY:
prevouts_hash      = SHA256(all input prevouts)
amounts_hash       = SHA256(all spent output amounts)
sequences_hash     = SHA256(all input sequences)

— If SIGHASH_ALL (or DEFAULT):
outputs_hash       = SHA256(all outputs)

spend_type         = 0x00 (uint8, always 0 for ladder)

— Input-specific:
  If ANYONECANPAY: prevout + spent_output + sequence
  Else: input_index (uint32)

— If SIGHASH_SINGLE:
output_hash        = SHA256(output at input_index)

conditions_hash    = SHA256(serialized rung conditions from spent output)
```

The `conditions_hash` commitment binds the signature to the specific locking conditions, preventing signature replay across different ladder-locked outputs even if they use the same key.

Valid `hash_type` values: `0x00` (DEFAULT/ALL), `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE), `0x81` (ALL|ANYONECANPAY), `0x82` (NONE|ANYONECANPAY), `0x83` (SINGLE|ANYONECANPAY). All other values are rejected.

### Policy Limits

The following limits are enforced at the policy (mempool) layer. Consensus enforcement uses the same limits unless noted.

| Limit | Value | Rationale |
|-------|-------|-----------|
| MAX_RUNGS | 16 | Maximum rungs per ladder witness. Prevents combinatorial explosion in evaluation. |
| MAX_BLOCKS_PER_RUNG | 8 | Maximum blocks per rung. Limits AND-condition depth. |
| MAX_FIELDS_PER_BLOCK | 16 | Maximum typed fields per block. Sufficient for 16-of-16 multisig. |
| MAX_LADDER_WITNESS_SIZE | 10,000 bytes | Maximum total serialised witness size. Accommodates Dilithium3 signatures (3,293 bytes) with headroom for multi-block rungs. |

Policy additionally restricts:
- All block types are standard upon activation.
- All data types must be known (`IsKnownDataType` returns true).
- All field sizes must conform to type constraints (`FieldMinSize` through `FieldMaxSize`).
- Conditions scripts must not contain SIGNATURE or PREIMAGE fields.

### Address Format

Ladder Script outputs use the `rung1` human-readable prefix with Bech32m encoding (BIP-350). The address encodes the raw conditions bytes (the `scriptPubKey` payload after the `0xc1` prefix).

**Encoding:** Convert conditions bytes to 5-bit groups using Bech32 base conversion, then encode with `bech32::Encode(bech32::Encoding::BECH32M, "rung", data)`.

**Decoding:** Detect the `rung1` prefix, decode with Bech32m, convert from 5-bit groups to 8-bit bytes. The result is a `LadderDestination` in the `CTxDestination` variant type.

**Character limit:** 500 characters (`CharLimit::RUNG_ADDRESS`), accommodating variable-length conditions from simple single-block to complex multi-rung PQ conditions.

**Script detection:** The `Solver` identifies rung conditions by the `0xc1` prefix, returning `TxoutType::RUNG_CONDITIONS`.

### RPC Interface

The following RPCs are provided for wallet and application integration:

- `encodeladderaddress` — Encode serialised rung conditions as a `rung1`-prefixed Bech32m address.
- `decodeladderaddress` — Decode a `rung1`-prefixed Bech32m address back to raw conditions hex.
- `createrung` — Create a rung conditions structure from a JSON description of blocks and fields.
- `decoderung` — Decode a hex-encoded rung conditions structure to human-readable JSON.
- `validateladder` — Validate a raw v4 RUNG_TX transaction's ladder witnesses against its spent outputs.
- `createrungtx` — Create an unsigned v4 RUNG_TX transaction with rung condition outputs.
- `signrungtx` — Sign a v4 RUNG_TX transaction's inputs given private keys and spent output information.
- `computectvhash` — Compute the BIP-119 CTV template hash for a v4 RUNG_TX transaction at a given input index.
- `pqkeygen` — Generate a post-quantum keypair for a specified scheme.
- `pqpubkeycommit` — Compute the SHA-256 PUBKEY_COMMIT for a given public key.
- `extractadaptorsecret` — Extract the adaptor secret from a pre-signature and adapted signature pair.

## Rationale

**Typed fields over opcodes.** By requiring every byte of witness data to belong to a declared type with enforced size constraints, Ladder Script eliminates the data smuggling vector inherent in arbitrary `OP_PUSH` operations. Static analysis tools can parse any ladder witness without executing it.

**Rung/block composition.** The AND-within-rung, OR-across-rungs model maps directly to how spending conditions are naturally expressed: "condition A AND condition B, OR alternatively condition C." This is more readable than equivalent stack manipulation in Script.

**Block type families.** Organizing block types into numbered ranges (0x0001-0x00FF for signatures, 0x0100-0x01FF for timelocks, etc.) allows new conditions to be added within families without exhausting a flat namespace. The `uint16_t` encoding provides 65,536 possible types.

**Inversion.** The `inverted` flag on blocks provides NOT logic without a separate opcode. Combined with AND/OR rung semantics, this yields full boolean expressiveness. The rule that ERROR is never inverted prevents masking of consensus failures.

**Strict unknown type handling.** Unknown block types return UNSATISFIED (rung fails, falls through to next rung) when not inverted, and ERROR when inverted. This prevents the inverted-unknown footgun where an attacker could bypass conditions using unknown block types in negated position. New block types activate simultaneously via soft fork — there is no need for forward-compatible unknown type evaluation.

**Post-quantum signature support.** The PUBKEY maximum of 2,048 bytes and SIGNATURE maximum of 50,000 bytes were chosen to accommodate all NIST post-quantum finalist schemes including SPHINCS_SHA. The PUBKEY_COMMIT mechanism enables a commit-reveal migration path: users can lock funds to a 32-byte hash of their PQ public key today, revealing the full key only at spend time.

**Coil separation.** Separating input conditions (rungs) from output semantics (coil) provides a clean interface between "who can spend" and "where it can go." This makes covenant logic (UNLOCK_TO, COVENANT coil types) orthogonal to signature and timelock logic.

**PLC block types.** The Programmable Logic Controller family (hysteresis, timers, latches, counters, comparators, sequencers) is borrowed from industrial automation where these primitives have decades of proven reliability. They enable stateful transaction logic (e.g., rate-limited withdrawals, multi-step approval processes, time-delayed state machines) without requiring a general-purpose virtual machine.

**Conditions hash in sighash.** Including the SHA-256 hash of the serialised locking conditions in the sighash computation prevents signature reuse across different ladder outputs that happen to use the same key. This is analogous to BIP-341's tapleaf hash commitment.

**Policy vs. consensus limits.** MAX_RUNGS, MAX_BLOCKS_PER_RUNG, and MAX_FIELDS_PER_BLOCK are enforced at both policy and consensus layers. The MAX_LADDER_WITNESS_SIZE limit at 10,000 bytes accommodates post-quantum signatures (Dilithium3 at 3,293 bytes) with headroom for multi-block rungs while preventing witness bloat attacks.

## Backward Compatibility

**Non-upgraded nodes.** Transaction version 4 is currently non-standard in Bitcoin Core. No existing software creates v4 transactions. Non-upgraded nodes treat v4 transactions as anyone-can-spend, which is the standard soft fork upgrade path established by BIP-141 (Segregated Witness) and BIP-341 (Taproot).

**Existing transactions.** Ladder Script does not modify the validation rules for transaction versions 1 or 2. All existing UTXOs, scripts, and spending paths remain valid and unchanged.

**Wallet compatibility.** Wallets that do not implement Ladder Script can still:
- Receive funds to ladder-locked outputs (they appear as non-standard scriptPubKey types).
- Track ladder-locked UTXOs in their UTXO set.
- Construct transactions that spend non-ladder inputs alongside ladder inputs (mixed-version inputs are valid).

Wallets cannot spend ladder-locked outputs without implementing the ladder evaluator and sighash computation.

**Unified deployment.** All block types activate simultaneously as a single deployment. Upon activation, all block types (signature, timelock, hash, covenant, anchor, recursion, and PLC) are standard and enforced.

## Reference Implementation

The reference implementation is located in the `src/rung/` directory:

| File | Purpose |
|------|---------|
| `types.h` / `types.cpp` | Core type definitions: `RungBlockType`, `RungDataType`, `RungCoilType`, `RungAttestationMode`, `RungScheme`, and all struct definitions. |
| `conditions.h` / `conditions.cpp` | Conditions (locking side): `RungConditions`, serialization to/from `CScript` with `0xc1` prefix, condition data type validation, template inheritance resolution. |
| `serialize.h` / `serialize.cpp` | Wire format v3 serialization/deserialization with micro-headers, implicit fields, varint NUMERIC, and context-aware encoding. Policy limit constants. |
| `evaluator.h` / `evaluator.cpp` | Block evaluators for all 52 block types. Rung AND logic, ladder OR logic, inversion. `VerifyRungTx` entry point. `LadderSignatureChecker` for Schnorr/PQ signature verification. |
| `sighash.h` / `sighash.cpp` | `SignatureHashLadder` tagged hash computation. |
| `policy.h` / `policy.cpp` | Mempool policy enforcement: `IsStandardRungTx`, `IsStandardRungOutput`. |
| `aggregate.h` / `aggregate.cpp` | Block-level signature aggregation and deferred attestation. |
| `adaptor.h` / `adaptor.cpp` | Adaptor signature creation, verification, and secret extraction. |
| `pq_verify.h` / `pq_verify.cpp` | Post-quantum signature verification via liboqs (FALCON-512/1024, Dilithium3). |
| `rpc.cpp` | RPC commands: `createrung`, `decoderung`, `validateladder`, `createrungtx`, `signrungtx`, `computectvhash`, `pqkeygen`, `pqpubkeycommit`, `extractadaptorsecret`. |

## Test Vectors

The implementation includes comprehensive test coverage across two layers:

**Unit tests** (`src/test/rung_tests.cpp`): 268 test cases covering:
- Field validation for all 9 data types with boundary conditions
- Serialization round-trips for all 52 block types
- Deserialization rejection of malformed inputs (empty, truncated, trailing bytes, oversized, unknown types)
- Block evaluation for all block types
- Inversion logic including ERROR non-inversion
- Rung AND logic and ladder OR logic
- Policy enforcement (standard/non-standard classification)
- Conditions serialization and witness-only field rejection
- Sighash determinism, hash type variants, and invalid hash type rejection
- Witness-conditions merge validation
- Anchor structural validation for all 6 anchor subtypes
- PLC structural validation for all 15 PLC block types
- Post-quantum key generation, signing, and commit-reveal verification
- Adaptor signature creation and verification
- COSIGN cross-input matching
- RECURSE_MODIFIED cross-rung and multi-field mutation
- RECURSE_DECAY multi-field parameter decay
- Counter, latch, and one-shot state gating
- Varint NUMERIC encoding edge cases (0, 1, 252, 253, 65535, max uint32)
- Micro-header roundtrips for all known block types
- Implicit field encoding in CONDITIONS and WITNESS contexts
- Template inheritance serialization, resolution, and diff application
- Cross-phase integration (multi-block, multi-rung optimised roundtrips)

**Functional tests** (`test/functional/rung_basic.py`): 115 end-to-end test scenarios covering:
- RPC interface for rung creation, decoding, and validation
- Full transaction lifecycle (create, sign, broadcast, confirm, spend) for all block types
- Negative tests (wrong signature, wrong preimage, timelock too early, wrong template, wrong key)
- Multi-input/multi-output transactions
- Inversion (inverted CSV, inverted hash preimage, inverted compare)
- Compound conditions (SIG+CSV+HASH triple AND, hot/cold vault OR patterns)
- Recursive chains (RECURSE_SAME, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_MODIFIED, RECURSE_SPLIT, RECURSE_DECAY)
- PLC patterns (hysteresis, rate limit, sequencer, latch state machines, counter state gating, one-shot)
- COSIGN anchor spend and 10-child fan-out
- Post-quantum FALCON-512 signature verification and PUBKEY_COMMIT
- Anti-spam validation (arbitrary preimage rejection, unknown data types, oversized fields, structure limits)
- Deeply nested covenant chains

Additional functional tests:
- `test/functional/rung_p2p.py`: P2P relay of v4 transactions between nodes.
- `test/functional/rung_pq_block.py`: Post-quantum block-level tests.

**Fuzz testing** (`src/test/fuzz/rung_deserialize.cpp`): Continuous fuzz testing of the deserialization path.

## Security Considerations

### COSIGN Mempool Griefing

The COSIGN block type (0x0681) creates a transaction-level dependency: a child UTXO can only be spent in a transaction that also spends a specific anchor UTXO (identified by the SHA-256 hash of its scriptPubKey). An attacker who observes a pending child spend could attempt to independently spend the anchor, orphaning the child transaction.

This is a mempool-level nuisance, not a consensus vulnerability. No funds can be stolen. The attack is bounded by the anchor's own spending conditions:

- **Signature protection.** Production anchors should include a SIG block, preventing unauthorised spending entirely.
- **RECURSE_SAME re-encumbrance.** Anchors using RECURSE_SAME require the spending transaction to create a new output with identical conditions. The attacker creates a new anchor at their own expense; the defender uses the new anchor in their next transaction.
- **Fee asymmetry.** The attacker pays fees per griefing attempt. The defender's cost is updating a single outpoint reference.

This is analogous to the anchor output griefing vector in Lightning Network commitment transactions (BOLT-3).

### Recursive Covenant Termination

Every RECURSE_* block type has a provably reachable terminal state:

| Block Type | Termination | Proof |
|------------|-------------|-------|
| RECURSE_SAME | `max_depth == 0` → UNSATISFIED | Finite unsigned integer, checked before evaluation |
| RECURSE_MODIFIED | `max_depth == 0` → UNSATISFIED | Same as RECURSE_SAME |
| RECURSE_UNTIL | `block_height >= target` → SATISFIED | Block height is monotonically increasing |
| RECURSE_COUNT | `count == 0` → SATISFIED | Decremented by 1 per spend, unsigned integer |
| RECURSE_SPLIT | `max_splits == 0` → UNSATISFIED | Decremented by 1 per split level |
| RECURSE_DECAY | `max_depth == 0` → UNSATISFIED | Same as RECURSE_MODIFIED |

The maximum chain length is bounded by the initial value of the termination parameter (`uint32_t`, max ~4 billion). This is infeasible to execute and each intermediate transaction pays fees, making long chains economically prohibitive.

When multiple RECURSE_* blocks appear in the same rung (AND), the shortest termination parameter dominates. Alternative rungs (OR) may provide early exit paths.

### Post-Quantum Library Dependency

Post-quantum signature verification uses the Open Quantum Safe project's liboqs library. The dependency is structured to minimise consensus risk:

- **Optional.** Nodes compile and run without liboqs (`HAVE_LIBOQS` flag). Without it, all PQ verification returns false (fail-closed).
- **Verification-only.** liboqs is used exclusively for `OQS_SIG_verify`, not for key generation or signing in consensus paths.
- **Deterministic.** FALCON and Dilithium verification is a mathematical equation: given identical inputs, any correct implementation produces the same result. A consensus split would require a liboqs bug that causes different results on different nodes — the same risk class as libsecp256k1 for ECDSA/Schnorr.
- **Pinned version.** The build system pins a specific liboqs release. Nodes running the same software version use the same library version.
- **Algorithm stability.** FALCON and Dilithium are NIST-standardised (FIPS 204, FIPS 206). The verification equations are fixed by the standard.

If liboqs proves insufficient for consensus use, the PQ verification functions can be replaced with in-tree implementations without changing the wire format or evaluation semantics.

### 0xc1 Prefix Collision Analysis

The `0xc1` byte identifies Ladder Script conditions as the first byte of scriptPubKey. Collision analysis:

- **Standard output types.** P2PKH starts with `0x76` (OP_DUP), P2SH with `0xa9` (OP_HASH160), witness v0 with `0x00` (OP_0), witness v1 with `0x51` (OP_1), OP_RETURN with `0x6a`. None use `0xc1`.
- **Witness version range.** BIP-141 witness versions use `OP_0` (`0x00`) through `OP_16` (`0x60`). `0xc1` is outside this range.
- **Data push range.** Script data push opcodes occupy `0x01`-`0x4e`. `0xc1` is outside this range.
- **Opcode identity.** `0xc1` is `OP_NOP2` / `OP_CHECKLOCKTIMEVERIFY` (BIP-65). CLTV is used *within* scripts but never as the first byte of a scriptPubKey. No wallet generates scriptPubKeys beginning with `0xc1`.
- **Soft fork compatibility.** Non-upgraded nodes encountering a `0xc1` scriptPubKey treat it as a non-standard output type, which is the correct behaviour for soft fork deployment.

## Copyright

This document is placed in the public domain.
