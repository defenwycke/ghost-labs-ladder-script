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

The prefix bytes `0xc1` and `0xc2` were chosen after rigorous collision analysis (see Security Considerations). They do not collide with any existing standard scriptPubKey first byte (P2PKH `0x76`, P2SH `0xa9`, witness v0 `0x00`, witness v1 `0x51`, OP_RETURN `0x6a`), any witness version opcode (`0x00`-`0x60`), or any data push prefix (`0x01`-`0x4e`). While `0xc1` is the opcode for `OP_CHECKLOCKTIMEVERIFY` (BIP-65) and `0xc2` for `OP_CHECKSEQUENCEVERIFY` (BIP-112), neither appears as the first byte of a standard scriptPubKey. Condition data types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX) are enforced; witness-only types PUBKEY, SIGNATURE, and PREIMAGE are forbidden in conditions — raw public keys are revealed only at spend time in the witness.

**Input (unlocking side):**

The first element of the segregated witness stack for each v4 input is a serialised `LadderWitness`. For `0xC1` outputs, this contains the same rung/block layout as the conditions plus SIGNATURE and PREIMAGE fields. For `0xC2` (MLSC) outputs, the witness additionally contains the revealed rung conditions, Merkle proof hashes, and coil data.

**Evaluation entry point:**

The function `VerifyRungTx` is called for each input of a v4 transaction. For `0xC1` inputs, it deserializes conditions from the spent output's `scriptPubKey` and the witness from the spending input. For `0xC2` inputs, it deserializes the revealed conditions and Merkle proof from the witness, verifies the proof against the UTXO root, then evaluates the ladder. All 60 block evaluators are identical for both output formats.

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

The micro-header lookup table maps 128 slot indices to block type values. All 60 current block types have assigned slots:

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
| 0x11 | RECURSE_SPLIT | 0x23 | SEQUENCER | 0x35 | P2PK_LEGACY |
| | | | | 0x36 | P2PKH_LEGACY |
| | | | | 0x37 | P2SH_LEGACY |
| | | | | 0x38 | P2WPKH_LEGACY |
| | | | | 0x39 | P2WSH_LEGACY |
| | | | | 0x3A | P2TR_LEGACY |
| | | | | 0x3B | P2TR_SCRIPT_LEGACY |

Slots `0x3C`–`0x7F` are reserved for future block types. Unknown micro-header slots are rejected during deserialization.

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

#### Compact Rung Encoding

When `n_blocks = 0` within a rung, the rung uses a compact encoding instead of the standard block-level format. The only currently defined compact form is **COMPACT_SIG**:

```
COMPACT_SIG (n_blocks = 0 in a rung):

[n_blocks: varint = 0]                  — sentinel for compact mode
[pubkey_commit: 32 bytes]               — SHA-256 commitment to signing public key
[scheme: uint8_t]                       — signature scheme selector
```

At deserialisation the compact rung is expanded into a standard rung containing a single SIG block with PUBKEY_COMMIT and SCHEME fields. Evaluation proceeds on the expanded form; compact encoding is a wire-level optimisation only. The `n_blocks == 0` sentinel is reserved for future compact forms.

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
| `0x01` | PUBKEY | 1 | 2,048 | Witness only | Public key (compressed 33B, x-only 32B, or post-quantum up to 1,793B). Forbidden in conditions; use PUBKEY_COMMIT instead. |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Both | SHA-256 commitment to a public key (for commit-reveal PQ migration) |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 hash digest |
| `0x04` | HASH160 | 20 | 20 | Both | RIPEMD160(SHA256()) hash digest |
| `0x05` | PREIMAGE | 1 | 252 | Witness only | Hash preimage (forbidden in conditions) |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness only | Signature (Schnorr 64-65B, ECDSA 8-72B, PQ up to ~3,300B) |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Index reference (uint32 LE) for aggregate attestation |
| `0x08` | NUMERIC | 1 | 4 | Both | Unsigned 32-bit integer. Encoded on wire as CompactSize(value); stored internally as 4-byte LE. |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector byte |
| `0x0A` | SCRIPT_BODY | 1 | 10,000 | Witness | Serialized inner conditions (P2SH/P2WSH/P2TR_SCRIPT inner scripts exceeding PREIMAGE's 252-byte limit) |

The SIGNATURE maximum of 50,000 bytes accommodates all post-quantum signature schemes including SPHINCS_SHA (~7,856 bytes) and Dilithium3 (3,293 bytes) with headroom. The PUBKEY maximum of 2,048 bytes accommodates FALCON-1024 public keys (1,793 bytes). The SCRIPT_BODY type extends PREIMAGE for complex inner conditions in legacy wrapping blocks: multi-rung scripts serialized as Ladder Script conditions that exceed 252 bytes.

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
| `0x0005` | KEY_REF_SIG | Conditions: NUMERIC(relay_index) + NUMERIC(block_index). Witness: PUBKEY + SIGNATURE | Resolve PUBKEY_COMMIT + SCHEME from relay[relay_index].blocks[block_index]. Verify witness PUBKEY matches commitment (SHA256). Verify SIGNATURE against resolved scheme. |

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
| `0x0641` | COMPARE | NUMERIC(operator) + NUMERIC(operand) [+ NUMERIC(upper)] | Comparator. Operator encoding: 1=EQ, 2=NEQ, 3=LT, 4=GT, 5=LTE, 6=GTE, 7=IN_RANGE. IN_RANGE requires a third NUMERIC (upper bound). Compares against the input amount from evaluation context. |
| `0x0651` | SEQUENCER | NUMERIC(current_step) + NUMERIC(total_steps) | Step sequencer. SATISFIED when current_step < total_steps. Total must be non-zero. |
| `0x0661` | ONE_SHOT | HASH256(id) + NUMERIC(window) [+ NUMERIC(state)] | One-shot activation window. SATISFIED when state is zero (not yet fired) or absent. Once fired, permanently unsatisfied. |
| `0x0671` | RATE_LIMIT | NUMERIC(max_per_window) + NUMERIC(window_blocks) + NUMERIC(current_count) | Rate limiter. SATISFIED when current_count < max_per_window. |
| `0x0681` | COSIGN | HASH256(conditions_hash) | Co-spend constraint. SATISFIED when another input in the same transaction has rung conditions whose serialised hash matches conditions_hash. The evaluator skips the current input index when scanning. |

**Compound Family (0x0700–0x07FF):**

The Compound family combines multiple conditions into single blocks for wire efficiency. Each block replaces a multi-block rung pattern with a single typed block that performs the same validation with fewer bytes on the wire.

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0701` | TIMELOCKED_SIG | PUBKEY_COMMIT + SCHEME + NUMERIC(sequence). Witness: PUBKEY + SIGNATURE | Signature with CSV relative timelock in one block. Equivalent to a SIG block AND a CSV block in the same rung, but encoded as a single block. The NUMERIC field is interpreted as a BIP-68 relative lock-time value. |
| `0x0702` | HTLC | PUBKEY_COMMIT + SCHEME + HASH256(payment_hash) + NUMERIC(timeout). Witness: PUBKEY + SIGNATURE + PREIMAGE | Hash Time-Locked Contract. SATISFIED when the PREIMAGE hashes to payment_hash AND the signature verifies AND the timelock has not expired. Used for atomic swaps and payment channels. |
| `0x0703` | HASH_SIG | PUBKEY_COMMIT + SCHEME + HASH256(hash). Witness: PUBKEY + SIGNATURE + PREIMAGE | Hash preimage combined with signature. SATISFIED when the PREIMAGE hashes to hash AND the signature verifies. |
| `0x0704` | PTLC | PUBKEY_COMMIT + SCHEME + NUMERIC(sequence). Witness: PUBKEY + SIGNATURE | Point Time-Locked Contract. Adaptor signature with CSV relative timelock for point-locked payments. The signature must be a valid adaptor signature that commits to an agreed point. |
| `0x0705` | CLTV_SIG | PUBKEY_COMMIT + SCHEME + NUMERIC(locktime). Witness: PUBKEY + SIGNATURE | Signature with CLTV absolute timelock in one block. The NUMERIC field is the absolute block height or time after which the signature can be used. |
| `0x0706` | TIMELOCKED_MULTISIG | PUBKEY_COMMIT + NUMERIC(M) + NUMERIC(N) + SCHEME + NUMERIC(sequence). Witness: PUBKEY + SIGNATURE (×M) | Multisig with CSV relative timelock. M-of-N multisig that additionally requires a BIP-68 relative lock-time to be satisfied. |

**Governance Family (0x0800–0x08FF):**

The Governance family provides transaction-level constraints that restrict how a UTXO can be spent based on properties of the spending transaction itself. These blocks operate on transaction metadata rather than cryptographic proofs.

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0801` | EPOCH_GATE | NUMERIC(epoch_length) + NUMERIC(offset) + NUMERIC(window) | Spending windows within block epochs. Divides the blockchain into epochs of epoch_length blocks. SATISFIED only during blocks [offset, offset+window) within each epoch. Enables scheduled spending windows (e.g., "spendable only during blocks 0-100 of each 1000-block epoch"). |
| `0x0802` | WEIGHT_LIMIT | NUMERIC(max_weight) | Maximum transaction weight. SATISFIED when the spending transaction's weight is at most max_weight weight units. Prevents bloated spending transactions. |
| `0x0803` | INPUT_COUNT | NUMERIC(min_inputs) + NUMERIC(max_inputs) | Input count bounds. SATISFIED when the spending transaction has between min_inputs and max_inputs inputs (inclusive). Constrains transaction structure. |
| `0x0804` | OUTPUT_COUNT | NUMERIC(min_outputs) + NUMERIC(max_outputs) | Output count bounds. SATISFIED when the spending transaction has between min_outputs and max_outputs outputs (inclusive). Constrains transaction structure. |
| `0x0805` | RELATIVE_VALUE | NUMERIC(numerator) + NUMERIC(denominator) | Output-to-input value ratio. SATISFIED when the ratio of the output value to the input value is at least numerator/denominator. Ensures a minimum proportion of value is preserved (e.g., 95/100 requires at least 95% of input value forwarded). |
| `0x0806` | ACCUMULATOR | HASH256(merkle_root) + HASH256(leaf). Witness: PREIMAGE (Merkle proof) | Merkle set membership proof. SATISFIED when the witness Merkle proof demonstrates that leaf is a member of the set committed to by merkle_root. Enables whitelist/blacklist patterns and large-set membership checks without enumerating all elements on-chain. |

**Legacy Family (0x0900-0x09FF):**

The Legacy family wraps traditional Bitcoin transaction types as typed Ladder Script blocks. Each block preserves the original spending semantics while eliminating arbitrary data surfaces.

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0901` | P2PK_LEGACY | Conditions: PUBKEY_COMMIT + SCHEME. Witness: PUBKEY + SIGNATURE | P2PK wrapped as a typed block. The PUBKEY_COMMIT commits to the full public key; SCHEME selects the signature algorithm. Verification is identical to SIG but restricted to P2PK semantics. |
| `0x0902` | P2PKH_LEGACY | Conditions: HASH160. Witness: PUBKEY + SIGNATURE | P2PKH wrapped. The HASH160 field contains the public key hash. The witness PUBKEY must hash to the committed HASH160 value, and the SIGNATURE must verify against that key. |
| `0x0903` | P2SH_LEGACY | Conditions: HASH160. Witness: PREIMAGE + inner witness | P2SH wrapped. The HASH160 field is the script hash. The PREIMAGE must hash to HASH160 and must deserialize as valid Ladder Script conditions. Inner witness satisfies those conditions. Recursion depth limited to 2. |
| `0x0904` | P2WPKH_LEGACY | Conditions: HASH160. Witness: PUBKEY + SIGNATURE | P2WPKH wrapped. Delegates to P2PKH_LEGACY evaluation: HASH160 contains the 20-byte witness program, witness provides the public key and signature. |
| `0x0905` | P2WSH_LEGACY | Conditions: HASH256. Witness: PREIMAGE + inner witness | P2WSH wrapped. The HASH256 field is the witness script hash. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2. |
| `0x0906` | P2TR_LEGACY | Conditions: PUBKEY_COMMIT + SCHEME. Witness: PUBKEY + SIGNATURE | P2TR key-path wrapped. PUBKEY_COMMIT commits to the Taproot internal key. Verification uses Schnorr (BIP-340) by default. |
| `0x0907` | P2TR_SCRIPT_LEGACY | Conditions: HASH256 + PUBKEY_COMMIT. Witness: PREIMAGE + inner witness | P2TR script-path wrapped. HASH256 is the tapleaf hash; PUBKEY_COMMIT commits to the internal key. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2. |

**Inner-conditions semantics (P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY):** The PREIMAGE field in the witness must deserialize as a valid `RungConditions` structure. Arbitrary byte sequences that do not parse as valid Ladder Script conditions are rejected at deserialization. The recursion depth is limited to 2 (an inner script may not itself contain a P2SH/P2WSH/P2TR_SCRIPT_LEGACY block with another inner script). This prevents unbounded nesting while allowing one level of script wrapping.

#### Legacy Migration Model

The Legacy family supports a three-phase migration path from traditional Bitcoin transaction types to fully typed Ladder Script:

1. **Coexistence.** Both legacy Bitcoin transaction types (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and Ladder Script version 4 transactions are valid on-chain. No existing transaction type is deprecated. Wallets choose which format to use.

2. **Legacy-in-Blocks.** Legacy transaction types are wrapped as typed Ladder Script blocks in the Legacy family. The spending semantics are identical — a P2PKH_LEGACY block evaluates the same way as a P2PKH script — but all fields are typed and validated. No arbitrary data surfaces exist in the wrapped form.

3. **Sunset.** Raw legacy transaction formats are deprecated for new output creation. Only block-wrapped versions in the Legacy family are accepted. Existing legacy UTXOs remain spendable under their original rules indefinitely.

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
| `0x13` | SPHINCS_SHA | 32 B | ~7,856 B | SPHINCS+-SHA256 post-quantum hash-based signatures. Stateless — no key reuse tracking required. |

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
- UNKNOWN_BLOCK_TYPE becomes SATISFIED (forward-compatible)

**Unknown block types:** An unrecognized `block_type` value returns UNKNOWN_BLOCK_TYPE. When not inverted, it propagates as a non-SATISFIED result, causing the rung to fail and evaluation to fall through to subsequent rungs. When inverted, it becomes SATISFIED — the absence of an unknown condition passes, enabling forward-compatible "NOT (some future condition)" patterns. Conditions with unknown block types are policy-non-standard and will not be relayed or mined by default. New block types are deployed via soft fork activation — all block types activate simultaneously.

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
| MAX_LADDER_WITNESS_SIZE | 100,000 bytes | Maximum total serialised witness size. Accommodates post-quantum signatures (SPHINCS_SHA at ~7,856 bytes, Dilithium3 at 3,293 bytes) with headroom for multi-block rungs. |
| MAX_PREIMAGE_BLOCKS_PER_WITNESS | 2 | Maximum HASH_PREIMAGE / HASH160_PREIMAGE blocks per witness. Limits user-chosen data to ~504 bytes, preventing data embedding. |
| MAX_RELAYS | 8 | Maximum relay definitions per ladder witness. |
| MAX_REQUIRES | 8 | Maximum relay requirements (co-spend input indices) per rung or relay. |
| MAX_RELAY_DEPTH | 4 | Maximum transitive relay chain depth. Prevents unbounded recursive relay evaluation. |

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

**Forward-compatible unknown type handling.** Unknown block types return UNSATISFIED (rung fails, falls through to next rung) when not inverted, and SATISFIED when inverted. This enables "NOT (some future condition)" patterns while maintaining forward compatibility. Conditions with unknown block types are policy-non-standard and will not be relayed or mined by default, preventing exploitation before the block type is activated via soft fork.

**Post-quantum signature support.** The PUBKEY maximum of 2,048 bytes and SIGNATURE maximum of 50,000 bytes were chosen to accommodate all NIST post-quantum finalist schemes including SPHINCS_SHA. The PUBKEY_COMMIT mechanism enables a commit-reveal migration path: users can lock funds to a 32-byte hash of their PQ public key today, revealing the full key only at spend time.

**Coil separation.** Separating input conditions (rungs) from output semantics (coil) provides a clean interface between "who can spend" and "where it can go." This makes covenant logic (UNLOCK_TO, COVENANT coil types) orthogonal to signature and timelock logic.

**PLC block types.** The Programmable Logic Controller family (hysteresis, timers, latches, counters, comparators, sequencers) is borrowed from industrial automation where these primitives have decades of proven reliability. They enable stateful transaction logic (e.g., rate-limited withdrawals, multi-step approval processes, time-delayed state machines) without requiring a general-purpose virtual machine.

**Conditions hash in sighash.** Including the SHA-256 hash of the serialised locking conditions in the sighash computation prevents signature reuse across different ladder outputs that happen to use the same key. This is analogous to BIP-341's tapleaf hash commitment.

**Policy vs. consensus limits.** MAX_RUNGS, MAX_BLOCKS_PER_RUNG, and MAX_FIELDS_PER_BLOCK are enforced at both policy and consensus layers. The MAX_LADDER_WITNESS_SIZE limit at 100,000 bytes accommodates post-quantum signatures (SPHINCS_SHA at ~7,856 bytes, Dilithium3 at 3,293 bytes) with headroom for multi-block rungs while preventing witness bloat attacks.

## Implications for External Protocol Layers

Ladder Script's typed field system and native programmability have significant implications for the ecosystem of external protocols and meta-protocols that have emerged to work around Bitcoin Script's limitations.

### Data Embedding Protocols

Protocols that exploit Script's arbitrary data push capability to embed non-financial data in the UTXO set or witness — including Inscriptions (Ordinals), BRC-20 tokens, and similar constructions — are structurally incompatible with Ladder Script. In a RUNG_TX, every byte of witness data belongs to a declared data type with enforced size constraints. There are no arbitrary `OP_PUSH` operations, no `OP_FALSE OP_IF` envelopes, and no unused script branches where data can be smuggled. The Legacy block family (0x0900–0x0907) extends this protection to wrapped legacy transaction types, closing the taproot script-path vector that Inscriptions currently exploit.

### Programmability Layers

Several projects have built programmability layers on top of Bitcoin because Script cannot express the conditions they need:

- **BitVM** uses fraud proofs and challenge-response protocols to simulate arbitrary computation, requiring complex off-chain coordination because Script lacks native state and introspection.
- **Citrea** and similar rollup/sidechain constructions move execution off-chain and post commitments to Bitcoin, partly because expressing complex spending conditions in Script is infeasible.
- **Ark** introduces virtual UTXOs and a coordinator model to improve payment throughput, working around Script's limited composability.
- **OP_NET** and similar meta-protocol token layers encode state transitions in witness data because Script cannot enforce token semantics natively.

Ladder Script addresses the underlying limitations that motivated these constructions. Covenants, recursive state machines, programmable logic controllers, governance constraints, and stateful conditions are all expressed natively as typed blocks within the consensus layer. This does not necessarily eliminate the need for every external protocol — some serve purposes beyond programmability (e.g., privacy, throughput scaling) — but it does mean that applications which were forced off-chain solely due to Script's expressiveness limitations can now be built directly on layer 1.

The practical consequence is that users, wallets, and applications gain access to these capabilities without trusting external coordinators, virtual machines, or meta-protocol indexers. The security model is Bitcoin's own: conditions are verified by every full node as part of consensus, not by an external system that may have different trust assumptions.

## Examples

The following examples demonstrate common spending patterns expressed as Ladder Script conditions. Each example shows the rung/block structure, the RPC JSON for `createrungtx`, and the resulting conditions layout.

### Example 1: Single Signature (Compact Encoding)

The simplest possible RUNG_TX: a single SIG rung with one output.

**Rung structure:**
```
Rung 0 (SPEND):
  └─ SIG { pubkey_commit: <32-byte SHA256 of pubkey>, scheme: SCHNORR }
```

**RPC JSON:**
```json
{
  "inputs": [{ "txid": "abc123...", "vout": 0 }],
  "outputs": [
    {
      "address": "tb1q...",
      "amount": 0.00010000,
      "conditions": [{
        "blocks": [{ "type": "SIG", "pubkey": "02abc123..." }]
      }]
    }
  ]
}
```

The node auto-converts the 33-byte `pubkey` to a 32-byte `PUBKEY_COMMIT` (SHA-256 hash) in the on-chain conditions. The full pubkey is only revealed in the witness at spend time. With a single SIG block, the serializer uses compact encoding — the micro-header encodes the block type directly, and the implicit field layout for SIG (`PUBKEY_COMMIT(32) + SCHEME(1)`) avoids explicit field headers.

### Example 2: 2-of-3 Multisig Vault with Time-Locked Recovery

A vault with daily multisig spending and an emergency cold-key sweep after one year.

**Rung structure:**
```
Rung 0 (SPEND):
  ├─ MULTISIG { threshold: 2, pubkeys: [pk1, pk2, pk3] }
  └─ AMOUNT_LOCK { min: 546, max: 5000000 }

Rung 1 (SWEEP):
  ├─ CSV { blocks: 52560 }
  └─ SIG { pubkey: pk_cold }
```

**Evaluation:** Rung 0 requires 2-of-3 signatures AND the output amount to be between 546 and 5,000,000 sats (AND logic within rung). If Rung 0 fails, Rung 1 is tried: it requires the UTXO to be at least ~1 year old (52,560 blocks) AND a cold key signature (OR logic across rungs).

**RPC JSON:**
```json
{
  "inputs": [{ "txid": "def456...", "vout": 0 }],
  "outputs": [
    {
      "address": "tb1q...",
      "amount": 0.00050000,
      "conditions": [
        {
          "label": "SPEND",
          "blocks": [
            { "type": "MULTISIG", "threshold": 2, "pubkeys": ["02aaa...", "02bbb...", "02ccc..."] },
            { "type": "AMOUNT_LOCK", "min": 546, "max": 5000000 }
          ]
        },
        {
          "label": "SWEEP",
          "blocks": [
            { "type": "CSV", "blocks": 52560 },
            { "type": "SIG", "pubkey": "02ddd..." }
          ]
        }
      ]
    }
  ]
}
```

### Example 3: Atomic Swap (HTLC)

Cross-chain atomic swap using hash time-locked contracts. Alice claims with the hash preimage; Bob refunds after timeout.

**Rung structure:**
```
Rung 0 (CLAIM):
  ├─ HASH256_PREIMAGE { hash: <32-byte SHA-256 of preimage> }
  └─ SIG { pubkey: pk_alice }

Rung 1 (REFUND):
  └─ TIMELOCKED_SIG { pubkey: pk_bob, blocks: 144 }
```

**Evaluation:** Alice spends via Rung 0 by providing the preimage (which Bob can then extract from the published transaction to claim the other chain) plus her signature. If Alice never claims, Bob uses Rung 1 after 144 blocks.

### Example 4: DCA Covenant Chain

Dollar-cost averaging vault that enforces periodic fixed-amount withdrawals using RECURSE_SAME re-encumbrance.

**Rung structure:**
```
Rung 0 (DCA):
  ├─ SIG { pubkey: pk_owner }
  ├─ AMOUNT_LOCK { min: 100000, max: 100000 }
  └─ coil: RECURSE_SAME
```

**Evaluation:** Each spend is limited to exactly 100,000 sats by AMOUNT_LOCK. The RECURSE_SAME coil forces the change output to carry identical conditions, creating a chain of fixed-size withdrawals. The covenant terminates when the UTXO balance falls below the minimum amount.

### Example 5: Governance-Gated Treasury

Treasury with spending windows, I/O limits, weight cap, and anti-siphon ratio enforcement.

**Rung structure:**
```
Rung 0 (GOVERNED):
  ├─ SIG { pubkey: pk_treasurer }
  ├─ EPOCH_GATE { epoch_size: 2016, window_size: 144 }
  ├─ INPUT_COUNT { min: 1, max: 3 }
  ├─ OUTPUT_COUNT { min: 1, max: 2 }
  ├─ WEIGHT_LIMIT { max_weight: 400000 }
  └─ RELATIVE_VALUE { numerator: 9, denominator: 10 }

Rung 1 (OVERRIDE):
  └─ MULTISIG { threshold: 3, pubkeys: [pk1, pk2, pk3, pk4] }
```

**Evaluation:** The treasurer can spend only during a 144-block window per 2016-block epoch, with at most 3 inputs and 2 outputs, under the standard weight limit, and must return at least 90% of the input value as change (anti-siphon). The 3-of-4 board override bypasses all governance constraints.

### Example 6: Post-Quantum Vault with Classical Hot Path

Hybrid vault: Schnorr for daily use, FALCON-512 for long-term cold storage.

**Rung structure:**
```
Rung 0 (HOT):
  ├─ SIG { pubkey_commit: <sha256(schnorr_pk)>, scheme: SCHNORR }
  └─ AMOUNT_LOCK { min: 546, max: 1000000 }

Rung 1 (PQ_COLD):
  ├─ CSV { blocks: 4320 }
  └─ SIG { pubkey_commit: <sha256(falcon_pk)>, scheme: FALCON512 }
```

**Evaluation:** Daily spending uses Schnorr with an amount cap. After ~30 days (4,320 blocks), the FALCON-512 cold key can sweep everything. The PUBKEY_COMMIT mechanism means the 897-byte FALCON-512 public key is only revealed at spend time — the on-chain conditions store only a 32-byte hash.

### Example 7: Legacy P2PKH Wrapped as Ladder Block

Legacy Bitcoin P2PKH semantics wrapped in typed fields, closing arbitrary-data surfaces.

**Rung structure:**
```
Rung 0 (SPEND):
  └─ P2PKH_LEGACY { hash160: <20-byte HASH160 of pubkey> }

Rung 1 (RECOVER):
  ├─ CSV { blocks: 52560 }
  └─ SIG { pubkey: pk_recovery }
```

**Evaluation:** Rung 0 uses P2PKH_LEGACY — the spender provides a pubkey whose HASH160 matches the committed hash, plus a signature. Identical to Bitcoin P2PKH semantics, but expressed as typed fields with no room for data embedding. Rung 1 adds a native Ladder Script recovery path that was not possible in legacy P2PKH.

## Backward Compatibility

**Non-upgraded nodes.** Transaction version 4 is currently non-standard in Bitcoin Core. No existing software creates v4 transactions. Non-upgraded nodes treat v4 transactions as anyone-can-spend, which is the standard soft fork upgrade path established by BIP-141 (Segregated Witness) and BIP-341 (Taproot).

**Existing transactions.** Ladder Script does not modify the validation rules for transaction versions 1 or 2. All existing UTXOs, scripts, and spending paths remain valid and unchanged.

**Wallet compatibility.** Wallets that do not implement Ladder Script can still:
- Receive funds to ladder-locked outputs (they appear as non-standard scriptPubKey types).
- Track ladder-locked UTXOs in their UTXO set.
- Construct transactions that spend non-ladder inputs alongside ladder inputs (mixed-version inputs are valid).

Wallets cannot spend ladder-locked outputs without implementing the ladder evaluator and sighash computation.

**Coexistence.** Version 4 transactions coexist with all existing transaction versions. No existing transaction type is deprecated or modified by this proposal. Should Ladder Script achieve broad adoption, a future BIP may propose deprecating the creation of new legacy output types to consolidate the benefits of typed, structured conditions across the network.

## Deployment

Activation uses BIP-9 version bits signaling with Speedy Trial parameters, following the precedent established by BIP-341 (Taproot):

| Parameter | Value |
|-----------|-------|
| Consensus name | `ladder` |
| Bit | (to be assigned) |
| Start time | (to be determined) |
| Timeout | Start time + 7,776,000 seconds (90 days) |
| Threshold | 90% (1,815 of 2,016 blocks per retarget period) |
| Minimum activation height | (to be determined — set to allow sufficient ecosystem preparation) |

All 60 block types activate simultaneously as a single deployment. Upon activation, all block types across all ten families are consensus-enforced and policy-standard. Partial activation of individual block types is not supported; the evaluation engine, wire format, and sighash computation form an interdependent whole.

Nodes that have not upgraded treat version 4 transactions as anyone-can-spend, consistent with the soft fork upgrade path established by BIP-141 and BIP-341.

## Reference Implementation

The reference implementation is located in the `src/rung/` directory. A step-by-step review guide (`docs/REVIEW_GUIDE.md`) provides a recommended reading order — start with `types.h` for the type system, then pick any single block evaluator to understand the pattern before reviewing the full set.

| File | Purpose |
|------|---------|
| `types.h` / `types.cpp` | Core type definitions: `RungBlockType`, `RungDataType`, `RungCoilType`, `RungAttestationMode`, `RungScheme`, and all struct definitions. |
| `conditions.h` / `conditions.cpp` | Conditions (locking side): `RungConditions`, serialization to/from `CScript` with `0xc1` prefix, condition data type validation, template inheritance resolution. |
| `serialize.h` / `serialize.cpp` | Wire format v3 serialization/deserialization with micro-headers, implicit fields, varint NUMERIC, and context-aware encoding. Policy limit constants. |
| `evaluator.h` / `evaluator.cpp` | Block evaluators for all 60 block types. Rung AND logic, ladder OR logic, inversion. `VerifyRungTx` entry point. `LadderSignatureChecker` for Schnorr/PQ signature verification. |
| `sighash.h` / `sighash.cpp` | `SignatureHashLadder` tagged hash computation. |
| `policy.h` / `policy.cpp` | Mempool policy enforcement: `IsStandardRungTx`, `IsStandardRungOutput`. |
| `aggregate.h` / `aggregate.cpp` | Block-level signature aggregation and deferred attestation. |
| `adaptor.h` / `adaptor.cpp` | Adaptor signature creation, verification, and secret extraction. |
| `pq_verify.h` / `pq_verify.cpp` | Post-quantum signature verification via liboqs (FALCON-512/1024, Dilithium3). |
| `rpc.cpp` | RPC commands: `createrung`, `decoderung`, `validateladder`, `createrungtx`, `signrungtx`, `computectvhash`, `pqkeygen`, `pqpubkeycommit`, `extractadaptorsecret`. |

### Implementation Footprint

Despite activating 60 block types across 10 families, Ladder Script's consensus footprint is smaller and more contained than previous soft forks:

| Metric | SegWit (BIP 141/143/144) | Taproot (BIP 340/341/342) | Ladder Script |
|--------|--------------------------|---------------------------|---------------|
| **Consensus files changed** | 80 | 44 | 19 |
| **Lines added** | +5,305 | +2,985 | +9,846 |
| **Lines removed** | -571 | -121 | 0 |
| **Files outside new code** | ~60 | ~30 | ~5 |
| **Test lines** | (included above) | (included above) | +20,521 |
| **Core PRs** | PR #8149 | PR #19953 + secp256k1 #558 | Single patch |

**Key difference: containment.** SegWit modified 80 existing files across `src/script/`, `src/consensus/`, `src/primitives/`, `src/wallet/`, `src/net_processing.cpp`, and the serialization layer. Taproot modified 44 files across similar directories plus a prerequisite Schnorr module in libsecp256k1 (+2,445 lines across 20 files).

Ladder Script adds 19 new files in a single directory (`src/rung/`) and touches approximately 5 existing files for integration (transaction validation dispatch, RPC registration, build system). Removing `src/rung/` restores Bitcoin Core to its unmodified state. No existing consensus logic, serialization code, or wallet code is altered.

The line count is higher because Ladder Script replaces the entire Script evaluation model rather than extending it. But the review surface is modular: each block type is a self-contained evaluator function (~20-80 lines) with its own field layout and test cases. A reviewer can audit one block type without understanding the others.

## Test Vectors

The implementation includes comprehensive test coverage across two layers:

**Unit tests** (`src/test/rung_tests.cpp`): 430 test cases covering:
- Field validation for all 10 data types with boundary conditions
- Serialization round-trips for all 60 block types
- Deserialization rejection of malformed inputs (empty, truncated, trailing bytes, oversized, unknown types)
- Block evaluation for all 60 block types
- Inversion logic including ERROR non-inversion
- Rung AND logic and ladder OR logic
- Policy enforcement (standard/non-standard classification)
- Conditions serialization and witness-only field rejection
- Sighash determinism, hash type variants, and invalid hash type rejection
- Witness-conditions merge validation
- Anchor structural validation for all 6 anchor subtypes
- PLC structural validation for all 14 PLC block types
- Post-quantum key generation, signing, and commit-reveal verification
- Adaptor signature creation and verification
- COSIGN cross-input matching
- RECURSE_MODIFIED cross-rung and multi-field mutation
- RECURSE_DECAY multi-field parameter decay
- Counter, latch, and one-shot state gating
- Varint NUMERIC encoding edge cases (0, 1, 252, 253, 65535, max uint32)
- Micro-header roundtrips for all known block types
- Legacy block types: serialization round-trips, evaluator pass/fail, wrong hash/key, missing fields, inner condition deserialization, recursion depth limits, ECDSA fallback, dispatch routing
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

### Commitment Integrity

PUBKEY_COMMIT values are always computed by the node from validated public keys supplied in the `pubkey` field. User-supplied raw 32-byte commitments are rejected. This prevents inscription-style data embedding in the UTXO set via the commitment field, since every stored commitment is provably derived from a real public key.

**Hash preimage commitments** follow the same model. For HASH_PREIMAGE, HASH160_PREIMAGE, HTLC, and HASH_SIG blocks, the node computes the hash commitment from a user-supplied preimage:

- **HASH_PREIMAGE / HASH_SIG / HTLC:** User provides `PREIMAGE` → node computes `HASH256 = SHA256(preimage)` and stores the hash in conditions.
- **HASH160_PREIMAGE:** User provides `PREIMAGE` → node computes `HASH160 = RIMEMD160(SHA256(preimage))` and stores the hash in conditions.
- **P2SH_LEGACY:** User provides `SCRIPT_BODY` or `PREIMAGE` → node computes `HASH160 = RIPEMD160(SHA256(data))` and stores the hash in conditions.
- **P2WSH_LEGACY / P2TR_SCRIPT_LEGACY:** User provides `SCRIPT_BODY` or `PREIMAGE` (serialized inner conditions) → node computes `HASH256 = SHA256(data)` and stores the hash in conditions. `SCRIPT_BODY` supports inner conditions up to 10,000 bytes, removing the 252-byte `PREIMAGE` limitation.

**Legacy block key commitments** extend the PUBKEY auto-conversion:

- **P2PKH_LEGACY / P2WPKH_LEGACY:** User provides `PUBKEY` → node computes `HASH160 = RIPEMD160(SHA256(pubkey))` and stores the hash in conditions. Raw HASH160 input is rejected.
- **P2PK_LEGACY / P2TR_LEGACY:** User provides `PUBKEY` → node computes `PUBKEY_COMMIT = SHA256(pubkey)` (standard auto-conversion).
- **P2TR_SCRIPT_LEGACY:** Internal key follows standard `PUBKEY → PUBKEY_COMMIT` conversion; script tree root follows `PREIMAGE → HASH256` conversion.

The combined effect is that **no condition field across all 60 block types accepts arbitrary user-chosen bytes**. Every commitment stored in the UTXO set is a deterministic hash function of validated input data. The node rejects raw hash/commitment values for block types that support auto-conversion, forcing all data through the node-computed path.

**Normative rule:** In `RUNG_TX`, all hash commitments stored in the UTXO set are computed exclusively by the node from validated preimages. No hash field accepts user-supplied values directly. Arbitrary data embedding is structurally impossible regardless of transaction construction method. This property is enforced at the consensus layer — not by mempool policy — and cannot be bypassed by miners or custom transaction construction software.

### Post-Quantum Library Dependency

Post-quantum signature verification uses the Open Quantum Safe project's liboqs library. The dependency is structured to minimise consensus risk:

- **Optional.** Nodes compile and run without liboqs (`HAVE_LIBOQS` flag). Without it, all PQ verification returns false (fail-closed).
- **Verification-only.** liboqs is used exclusively for `OQS_SIG_verify`, not for key generation or signing in consensus paths.
- **Deterministic.** FALCON and Dilithium verification is a mathematical equation: given identical inputs, any correct implementation produces the same result. A consensus split would require a liboqs bug that causes different results on different nodes — the same risk class as libsecp256k1 for ECDSA/Schnorr.
- **Pinned version.** The build system pins a specific liboqs release. Nodes running the same software version use the same library version.
- **Algorithm stability.** FALCON and Dilithium are NIST-standardised (FIPS 204, FIPS 206). The verification equations are fixed by the standard.

If liboqs proves insufficient for consensus use, the PQ verification functions can be replaced with in-tree implementations without changing the wire format or evaluation semantics.

**Scheme swappability.** The PQ architecture is designed for algorithm agility. Adding or replacing a signature scheme requires only:

1. A new `RungScheme` enum value (single byte in the SCHEME field)
2. A verification function in `pq_verify.cpp`
3. Key generation support in the `pqkeygen` RPC

No changes to the wire format, serialization, evaluation framework, sighash computation, or any existing block type. The SIG block's SCHEME field routes to the appropriate verifier at evaluation time. If NIST revises or deprecates a standard (e.g., replaces FALCON with a variant), a new scheme can be added in a soft fork while existing schemes continue to function. Users with funds locked under the old scheme can still spend them; new UTXOs can use the updated scheme.

This means the quantum migration path is not a one-time event but a continuous capability. A user can lock funds to FALCON-512 today, and if a stronger scheme is standardised later, spend via the FALCON path and re-lock to the new scheme — all within the existing block type system.

### Post-Quantum Multi-Scheme Composition

Ladder Script's rung/block structure enables security constructions not possible in any other Bitcoin transaction format. Because blocks compose with AND logic within a rung and OR logic across rungs, multiple post-quantum schemes can be combined in a single output.

**AND composition — defence in depth:**

```
Rung 0:  SIG(SCHNORR) + SIG(FALCON-512)
```

Both signatures must be satisfied. A quantum computer breaking secp256k1 Schnorr cannot spend the output — it must also break FALCON. If a flaw is found in FALCON, the Schnorr signature still protects the funds. Neither cryptographic assumption failing alone is fatal.

**Cross-family scheme diversity:**

```
Rung 0:  SIG(FALCON-512) + SIG(DILITHIUM3)
```

FALCON is based on NTRU lattices. Dilithium is based on module lattices (Module-LWE). These are distinct mathematical structures. A cryptanalytic advance against one lattice family does not automatically break the other. This is the post-quantum equivalent of not trusting a single mathematical assumption.

**OR fallback across rungs — scheme migration:**

```
Rung 0:  SIG(FALCON-512)        ← primary spend path
Rung 1:  SIG(FALCON-1024)       ← fallback if 512 is weakened
Rung 2:  SIG(SPHINCS_SHA)       ← hash-based, independent assumption
```

OR across rungs means if FALCON-512 is compromised, the owner spends via a higher-security path. SPHINCS+ is particularly significant: its security reduces to SHA-256 collision resistance rather than any lattice assumption. If every lattice-based scheme is simultaneously broken, SPHINCS+ still stands. If SHA-256 breaks, Bitcoin's proof-of-work and transaction integrity are already compromised — the signature scheme is the least of the network's problems.

Only one rung's witness is revealed at spend time — the UTXO is 33 bytes (MLSC) or 42 bytes (inline) regardless of how many fallback paths exist.

**Threshold PQ multisig — institutional custody:**

```
Rung 0:  MULTISIG(2-of-3, FALCON-512 keys)
```

Three independently generated FALCON-512 keypairs, 2 required to spend. Protects against single-key compromise, supply chain attacks on key generation hardware, and loss/destruction of any one key. This is the institutional custody model for the post-quantum era — the same m-of-n structure used today with Schnorr, applied to PQ schemes.

**Mixed-family threshold — maximum adversarial cost:**

```
Rung 0:  MULTISIG(2-of-3: schnorr_key, falcon_key, dilithium_key)
```

An attacker must simultaneously break two of three distinct cryptographic problems across different mathematical families. This is the most robust single-output construction possible with current cryptography.

**COSIGN — efficient PQ coverage for existing wallets:**

```
Anchor UTXO:   SIG(FALCON-512) + RECURSE_SAME(max_depth=1000)
Child UTXOs:   COSIGN(anchor_hash)
```

A single FALCON-512 anchor UTXO provides quantum protection for unlimited classical child outputs. Each child spends only when the anchor is co-spent (and recreated via RECURSE_SAME). The PQ witness cost is paid once per transaction, not once per output. This is the practical migration path for wallets with many existing classical UTXOs.

**Why this matters for BIP evaluation:** BIP-360 (P2QRH) proposes hybrid classical+PQ for single outputs but defers multi-scheme composition to future proposals. Ladder Script solves scheme composition, threshold PQ multisig, cross-family diversity, and scheme migration fallbacks within the existing block type system — no additional proposals required.

### Condition Opacity

MLSC outputs (`0xC2`) store only a 32-byte Merkle root in the UTXO set. This root is computed as `TaggedHash("LadderInternal", ...)` over the condition tree and is computationally indistinguishable from random data.

**No information is leaked about:**

- The number of rungs (spending paths)
- Whether classical or post-quantum signatures are used
- Which specific PQ schemes are present
- Threshold parameters (m-of-n structure)
- Whether timelocks, covenants, or hash conditions exist
- Whether a COSIGN anchor is required
- The total complexity of the spending conditions

**Comparison to existing output formats:**

| Format | What an adversary sees | Quantum target? |
|--------|----------------------|-----------------|
| P2PKH | `OP_DUP OP_HASH160 <20B hash> ...` | HASH160 of pubkey — no target until spend |
| P2WPKH | `OP_0 <20B hash>` | Same as P2PKH |
| P2TR | `OP_1 <32B x-only pubkey>` | **Yes — x-only pubkey is a Shor's algorithm target** |
| P2QRH (BIP-360) | `OP_2 <32B hash>` | Hash of PQ key — reveals a PQ key exists |
| MLSC | `0xC2 <32B Merkle root>` | **Nothing — root is indistinguishable from random** |

P2TR exposes the tweaked output key directly. A quantum adversary scanning the UTXO set can identify every P2TR output and target them with Shor's algorithm. P2QRH commits to a hash of the post-quantum key, which reveals that a PQ scheme is in use and which scheme from the commitment structure.

MLSC reveals nothing. A quantum adversary scanning the UTXO set sees a field of identical 32-byte blobs. There is no signal to distinguish a 1-satoshi dust output from a high-value vault with 3-of-5 hybrid PQ multisig across three lattice families with SPHINCS+ fallback.

**Interaction with multi-scheme composition:** The opacity property compounds with the multi-scheme constructions described above. An adversary not only cannot break the schemes — they cannot determine which schemes to attack. The five-layer security model:

1. **Opacity** — the adversary cannot see the conditions (Merkle root hides everything)
2. **Path ambiguity** — the adversary cannot determine which rung is the primary spend path
3. **Scheme ambiguity** — the adversary cannot determine which signature schemes are used
4. **Compositional security** — even if the schemes are guessed, multiple independent breaks are required
5. **Hash-based fallback** — SPHINCS+ reduces to SHA-256, which is unbreakable by any known quantum algorithm (Grover's algorithm provides only quadratic speedup, mitigated by SHA-256's 128-bit post-quantum security level)

**Temporal property:** Condition opacity holds for all unspent outputs. At spend time, only the *satisfied rung* is revealed in the witness — unsatisfied rungs remain hidden behind the Merkle proof. An adversary observing a spend learns the structure of the used path but gains no information about alternative paths that were not exercised.

**Caveat — condition reuse:** If identical conditions are used across multiple outputs (same Merkle root), spending one output reveals the structure for all outputs sharing that root. Implementations SHOULD generate unique condition trees per output where possible, or use output-specific nonces in timelock or hash conditions to ensure distinct Merkle roots even when the logical spending policy is identical.

### 0xc1 Prefix Collision Analysis

The `0xc1` byte identifies Ladder Script conditions as the first byte of scriptPubKey. Collision analysis:

- **Standard output types.** P2PKH starts with `0x76` (OP_DUP), P2SH with `0xa9` (OP_HASH160), witness v0 with `0x00` (OP_0), witness v1 with `0x51` (OP_1), OP_RETURN with `0x6a`. None use `0xc1`.
- **Witness version range.** BIP-141 witness versions use `OP_0` (`0x00`) through `OP_16` (`0x60`). `0xc1` is outside this range.
- **Data push range.** Script data push opcodes occupy `0x01`-`0x4e`. `0xc1` is outside this range.
- **Opcode identity.** `0xc1` is `OP_NOP2` / `OP_CHECKLOCKTIMEVERIFY` (BIP-65). CLTV is used *within* scripts but never as the first byte of a scriptPubKey. No wallet generates scriptPubKeys beginning with `0xc1`.
- **Soft fork compatibility.** Non-upgraded nodes encountering a `0xc1` scriptPubKey treat it as a non-standard output type, which is the correct behaviour for soft fork deployment.

## Copyright

This document is placed in the public domain.
