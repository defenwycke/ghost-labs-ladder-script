# Ladder Script: Technical Specification

**Version:** 3 (wire format v3)
**Transaction version:** 4 (`RUNG_TX_VERSION`)
**Status:** Implemented; all block types consensus-standard

---

## 1. Overview

Ladder Script is a structured, typed transaction verification system for Bitcoin Ghost. It replaces Bitcoin Script's stack-based opcode model with a declarative model of typed function blocks organised into rungs.

A version 4 transaction (`RUNG_TX`) uses Ladder Script for both locking (output conditions) and unlocking (input witness). The system provides:

- **Typed data fields:** every byte in a Ladder Script witness belongs to a declared data type with enforced size constraints. No arbitrary data pushes are possible.
- **Function blocks:** each block evaluates a single spending condition (signature check, timelock, hash preimage, covenant, etc.).
- **AND/OR composition:** blocks within a rung are combined with AND logic; rungs within a ladder are combined with OR logic (first satisfied rung wins).
- **Inversion:** any block can be inverted, flipping SATISFIED to UNSATISFIED and vice versa.
- **Coil metadata:** per-output semantics (unlock, unlock-to-destination, covenant) with attestation mode and signature scheme selection.
- **Post-quantum readiness:** native support for FALCON-512, FALCON-1024, and Dilithium3 via liboqs.

---

## 2. Data Model

### 2.1 LadderWitness

The top-level witness structure for one input.

```
struct LadderWitness {
    rungs:  Vec<Rung>     // Input condition rungs (OR logic — first satisfied wins)
    coil:   RungCoil      // Output coil (per-output metadata)
}
```

### 2.2 Rung

A single rung in a ladder. All blocks within a rung must be satisfied (AND logic).

```
struct Rung {
    blocks:   Vec<RungBlock>    // Function blocks (AND logic)
    rung_id:  uint8_t           // Rung identifier within the ladder
}
```

### 2.3 RungBlock

A function block within a rung. Contains typed fields that the evaluator checks.

```
struct RungBlock {
    type:      RungBlockType (uint16_t)    // Block type enum
    fields:    Vec<RungField>              // Typed parameter fields
    inverted:  bool                        // If true, result is inverted
}
```

### 2.4 RungField

A single typed field within a block. The type constrains the allowed data size.

```
struct RungField {
    type:  RungDataType (uint8_t)    // Data type enum
    data:  Vec<uint8_t>              // Variable-length bytes
}
```

### 2.5 RungCoil

Coil metadata attached to each output, determining unlock semantics.

```
struct RungCoil {
    coil_type:    RungCoilType (uint8_t)            // UNLOCK, UNLOCK_TO, COVENANT
    attestation:  RungAttestationMode (uint8_t)     // INLINE, AGGREGATE, DEFERRED
    scheme:       RungScheme (uint8_t)              // Signature scheme
    address:      Vec<uint8_t>                      // Destination (raw scriptPubKey bytes)
    conditions:   Vec<Rung>                         // Coil condition rungs
}
```

---

## 3. Wire Format (v3)

All multi-byte integers are little-endian. Variable-length counts use Bitcoin's `CompactSize` (varint) encoding. The wire format is context-aware: `SerializationContext::CONDITIONS` (for scriptPubKey) and `SerializationContext::WITNESS` (for spending witness) use different implicit field layouts for the same block type.

### 3.1 Ladder Structure

```
[n_rungs: varint]                          // Number of rungs (>= 1, <= 16; 0 = template mode)
  FOR EACH rung:
    [n_blocks: varint]                     // Number of blocks (>= 1, <= 8)
    FOR EACH block:
      (see Block Encoding below)

[coil_type: uint8_t]                       // RungCoilType
[attestation: uint8_t]                     // RungAttestationMode
[scheme: uint8_t]                          // RungScheme
[address_len: varint]                      // Length of destination address (0 = none)
[address: bytes]                           // Raw scriptPubKey bytes

[n_coil_conditions: varint]                // Number of coil condition rungs (0 = none)
  FOR EACH coil condition rung:
    [n_blocks: varint]
    FOR EACH block:
      (same block encoding)
```

Trailing bytes after the complete structure are rejected. The maximum total serialised size is 10,000 bytes (`MAX_LADDER_WITNESS_SIZE`).

### 3.2 Block Encoding: Micro-Headers

Each block begins with a single header byte:

| Byte Value | Meaning |
|------------|---------|
| `0x00`--`0x7F` | Micro-header: index into 128-slot lookup table (block type, inverted=false) |
| `0x80` | Escape to full header: followed by `[block_type: uint16_t LE]` + `[n_fields: varint]` (inverted=false) |
| `0x81` | Escape to full header with inverted=true: followed by `[block_type: uint16_t LE]` + `[n_fields: varint]` |

All 52 current block types fit in micro-header slots 0x00--0x33. Inverted blocks that have a micro-header slot use `0x81` escape + type instead of slot + inversion byte.

When a block uses a micro-header AND has an implicit field table for the current serialization context, field count and per-field type bytes are omitted entirely (see Section 3.4).

### 3.3 Field Encoding

Each field is encoded differently depending on whether the block uses implicit or explicit fields.

**Explicit fields** (when no implicit table matches, or escape header):

```
[data_type: uint8_t]                       // RungDataType enum value
[data_len: varint]                         // Length of data payload (or value for NUMERIC)
[data: bytes]                              // Raw data payload
```

**Implicit fields** (when micro-header + implicit table matches):

```
[data_len: varint]                         // Length of data payload (or value for NUMERIC)
[data: bytes]                              // Raw data payload
```

Per-type field data encoding:

| Data Type | Encoding |
|-----------|----------|
| NUMERIC (0x08) | `CompactSize(value)`, varint encodes the value directly, not a length prefix. Deserialized to 4-byte LE in memory. |
| PUBKEY_COMMIT (0x02) | `CompactSize(32)` + 32 bytes |
| HASH256 (0x03) | `CompactSize(32)` + 32 bytes |
| HASH160 (0x04) | `CompactSize(20)` + 20 bytes |
| SCHEME (0x09) | `CompactSize(1)` + 1 byte |
| PUBKEY (0x01) | `CompactSize(len)` + len bytes (1--2048) |
| SIGNATURE (0x06) | `CompactSize(len)` + len bytes (1--50000) |
| PREIMAGE (0x05) | `CompactSize(len)` + len bytes (1--252) |
| SPEND_INDEX (0x07) | `CompactSize(4)` + 4 bytes |

### 3.4 Implicit Field Layouts

For common block types, the field count and per-field type bytes are implicit. The serializer checks `MatchesImplicitLayout()`; if the block's fields match the expected layout for the current context, implicit encoding is used.

Example layouts:

```
SIG CONDITIONS:      [PUBKEY_COMMIT(32), SCHEME(1)]
SIG WITNESS:         [PUBKEY(var), SIGNATURE(var)]
HTLC CONDITIONS:     [PUBKEY_COMMIT(32), PUBKEY_COMMIT(32), HASH256(32), NUMERIC(varint)]
HTLC WITNESS:        [PUBKEY(var), SIGNATURE(var), PREIMAGE(var), NUMERIC(varint)]
CLTV_SIG CONDITIONS: [PUBKEY_COMMIT(32), SCHEME(1), NUMERIC(varint)]
CLTV_SIG WITNESS:    [PUBKEY(var), SIGNATURE(var), NUMERIC(varint)]
```

Blocks with variable field counts (e.g. MULTISIG with N pubkeys) use escape headers with explicit field encoding.

### 3.5 Template Inheritance

When `n_rungs = 0` in a conditions output, the output inherits conditions from another input via template reference:

```
[n_rungs: varint = 0]                      // Signals template mode
[input_index: varint]                      // Which input's conditions to inherit
[n_diffs: varint]                          // Number of field-level diffs
FOR EACH diff:
  [rung_index: varint]
  [block_index: varint]
  [field_index: varint]
  [data_type: uint8_t]                     // Replacement field type
  [field_data]                             // Replacement field data (type-dependent encoding)
```

Template resolution rules:
- Source must not itself be a template reference (no chaining)
- Diff type must match the field being replaced
- Resolution produces fully expanded conditions for sighash computation

### 3.6 Diff Witness (Witness Inheritance)

When `n_rungs = 0` in a ladder witness (input witness stack element), the witness inherits its rungs and relays from another input's witness with optional field-level diffs. This is the witness-side counterpart to template inheritance (§3.5).

#### Wire Format

```
DIFF WITNESS (n_rungs = 0 in witness):

[n_rungs: varint = 0]                      // Signals diff witness mode
[input_index: varint]                      // Source input to inherit from
[n_diffs: varint]                          // Number of field-level diffs
FOR EACH diff:
  [rung_index: varint]
  [block_index: varint]
  [field_index: varint]
  [data_type: uint8_t]                     // Replacement field type byte
  [field_data]                             // Type-dependent encoding (same as standard fields)
[coil]                                      // Fresh coil (always provided, never inherited)
                                            // No relays section (inherited from source)
```

#### Resolution Rules

- **Forward-only**: `input_index` must be strictly less than the current input index (`input_index < nIn`). This prevents cycles and ensures deterministic evaluation order.
- **No chaining**: The source input's witness must not itself be a diff witness. Only one level of indirection is permitted.
- **Coil never inherited**: The spending input always provides its own fresh coil. Inheriting destination addresses from another input would be a security footgun.
- **Relays inherited**: Relays are copied wholesale from the source witness. The diff witness wire format omits the relay section entirely.
- **Allowed diff field types**: Only witness-side data types are permitted in diffs: PUBKEY (`0x01`), SIGNATURE (`0x06`), PREIMAGE (`0x05`), and SCHEME (`0x09`). Condition-only types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SPEND_INDEX) are rejected during deserialization.
- **Type matching at resolution**: Each diff's `data_type` must match the type of the field it replaces in the source witness. Mismatches are rejected.

#### Resolution Process

1. Deserialize the source input's witness from `tx.vin[input_index].scriptWitness.stack[0]`.
2. Verify the source is not itself a diff witness (no chaining).
3. Copy the source's rungs and relays into the current witness.
4. Apply each diff: replace `rungs[rung_index].blocks[block_index].fields[field_index]` with the diff's new field.
5. Clear the witness reference. The witness is now fully resolved and proceeds through normal evaluation.

The sighash is computed against the current input's conditions (not the source's). Each input gets its own sighash even when inheriting witness structure, because the sighash includes the input index. This means SIGNATURE fields almost always require a diff — the same key produces different signatures for different inputs.

#### Wire Size Savings

For a two-input transaction spending identical SIG conditions with the same key:

| Component | Full Witness | Diff Witness | Saved |
|-----------|:-----------:|:------------:|:-----:|
| Block header | 1 B | — | 1 B |
| Field count | 0 B | — | 0 B |
| PUBKEY | 34 B | — | 34 B |
| SIGNATURE | 65 B | 65 B | 0 B |
| Diff overhead | — | 4 B | −4 B |
| Coil | 7 B | 7 B | 0 B |
| **Total** | **107 B** | **77 B** | **28%** |

Savings increase with more complex witness structures (MULTISIG, HTLC, compound blocks) where more fields can be inherited without diffs.

---

## 4. Output Format (scriptPubKey)

Two output formats are supported:

### 4.1 Inline Conditions (`0xC1`)

```
[0xc1] [serialized RungConditions]
```

The prefix byte `0xc1` (`RUNG_CONDITIONS_PREFIX`) identifies the script as inline Ladder Script conditions. The serialised conditions use the same wire format as a `LadderWitness` (Section 3), but **only condition data types are permitted**. The witness-only types SIGNATURE (`0x06`) and PREIMAGE (`0x05`) must not appear in conditions.

Deserialization strips the `0xc1` prefix and decodes the remainder as a `LadderWitness`, then validates that no witness-only fields are present.

### 4.2 Merkelized Ladder Script Conditions — MLSC (`0xC2`)

```
[0xc2] [conditions_root: 32 bytes]
```

The prefix byte `0xc2` (`RUNG_MLSC_PREFIX`) identifies the output as an MLSC commitment. The `conditions_root` is a 32-byte Merkle root computed over all rung leaves, relay leaves, and the coil leaf. **No condition data is stored in the UTXO set** — only the root.

At spend time, the witness reveals the exercised rung, coil, any referenced relays, and a Merkle proof (sibling hashes). The verifier reconstructs the root from the revealed data and proof, then checks it against the UTXO root.

**Merkle tree construction uses BIP-341-style tagged hashes:**
- Leaf: `TaggedHash("LadderLeaf", SerializeRung(rung))` (or coil/relay)
- Interior: `TaggedHash("LadderInternal", min(A,B) || max(A,B))`
- Empty padding: `TaggedHash("LadderLeaf", "")`
- `TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)`

The tagged hash domain separation prevents second preimage attacks between leaf and interior nodes (same pattern as BIP-341 TapLeaf/TapBranch).

**Output size: 42 bytes** (8 value + 1 scriptPubKey length + 1 prefix + 32 root), fixed regardless of script complexity. **UTXO entry: 40 bytes** (value + root).

See `MERKLE-UTXO-SPEC.md` for the complete MLSC specification including witness format, verification algorithm, data embedding analysis, and worked examples.

---

## 5. Data Types

Every field in a Ladder Script witness or condition must be one of the following typed values. Size constraints are enforced at deserialization time.

| Code | Name | Min Size | Max Size | Condition | Witness | Purpose |
|------|------|----------|----------|-----------|---------|---------|
| `0x01` | PUBKEY | 1 | 2048 | Yes | Yes | Public key (32-byte x-only, 33-byte compressed, or PQ) |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Yes | No | SHA256 commitment to a public key |
| `0x03` | HASH256 | 32 | 32 | Yes | Yes | SHA-256 hash digest |
| `0x04` | HASH160 | 20 | 20 | Yes | Yes | RIPEMD160(SHA256()) hash digest |
| `0x05` | PREIMAGE | 1 | 252 | No | Yes | Hash preimage (witness-only) |
| `0x06` | SIGNATURE | 1 | 5,000 | No | Yes | Signature bytes (witness-only) |
| `0x07` | SPEND_INDEX | 4 | 4 | Yes | Yes | Spend index reference (uint32 LE) |
| `0x08` | NUMERIC | 1 | 4 | Yes | Yes | Numeric value. Wire: varint `CompactSize(value)`. Memory: 4-byte unsigned LE. |
| `0x09` | SCHEME | 1 | 1 | Yes | Yes | Signature scheme selector byte |

**Validation rules:**

- PUBKEY fields of exactly 33 bytes must begin with `0x02` or `0x03` (compressed SEC1 format). Other sizes (32 for x-only, or PQ key sizes) skip this prefix check.
- SCHEME fields must contain a known scheme value (see Section 11).
- Size violations are rejected at deserialization time with a descriptive error.

---

## 6. Block Types

Block types are encoded as `uint16_t` little-endian. They are organised into ranges by family.

### 6.1 Signature Family (0x0001--0x00FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0001` | SIG | PUBKEY, SIGNATURE | PUBKEY_COMMIT, SCHEME |
| `0x0002` | MULTISIG | NUMERIC (threshold M), N x PUBKEY, M x SIGNATURE | SCHEME |
| `0x0003` | ADAPTOR_SIG | 2 x PUBKEY (signing_key, adaptor_point), SIGNATURE | — |
| `0x0004` | MUSIG_THRESHOLD | PUBKEY_COMMIT (aggregate key hash), 2 x NUMERIC (M, N), PUBKEY, SIGNATURE | — |

### 6.2 Timelock Family (0x0100--0x01FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0101` | CSV | NUMERIC (sequence value) | — |
| `0x0102` | CSV_TIME | NUMERIC (sequence value) | — |
| `0x0103` | CLTV | NUMERIC (locktime value) | — |
| `0x0104` | CLTV_TIME | NUMERIC (locktime value) | — |

### 6.3 Hash Family (0x0200--0x02FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0201` | HASH_PREIMAGE | HASH256, PREIMAGE | — |
| `0x0202` | HASH160_PREIMAGE | HASH160, PREIMAGE | — |
| `0x0203` | TAGGED_HASH | 2 x HASH256 (tag_hash, expected_hash), PREIMAGE | — |

### 6.4 Covenant Family (0x0300--0x03FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0301` | CTV | HASH256 (template hash) | — |
| `0x0302` | VAULT_LOCK | 2 x PUBKEY (recovery_key, hot_key), SIGNATURE, NUMERIC (hot_delay) | — |
| `0x0303` | AMOUNT_LOCK | 2 x NUMERIC (min_sats, max_sats) | — |

### 6.5 Anchor/L2 Family (0x0500--0x05FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0501` | ANCHOR | >= 1 typed field (any) | — |
| `0x0502` | ANCHOR_CHANNEL | 2 x PUBKEY (local_key, remote_key) | NUMERIC (commitment_number) |
| `0x0503` | ANCHOR_POOL | HASH256 (vtxo_tree_root) | NUMERIC (participant_count) |
| `0x0504` | ANCHOR_RESERVE | 2 x NUMERIC (threshold_n, threshold_m), HASH256 (guardian_set_hash) | — |
| `0x0505` | ANCHOR_SEAL | 2 x HASH256 (asset_id, state_transition) | — |
| `0x0506` | ANCHOR_ORACLE | PUBKEY (oracle_key) | NUMERIC (outcome_count) |

### 6.6 Recursion Family (0x0400--0x04FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0401` | RECURSE_SAME | NUMERIC (max_depth) | — |
| `0x0402` | RECURSE_MODIFIED | >= 4 x NUMERIC (see Section 7 for format) | — |
| `0x0403` | RECURSE_UNTIL | NUMERIC (until_height) | — |
| `0x0404` | RECURSE_COUNT | NUMERIC (count) | — |
| `0x0405` | RECURSE_SPLIT | 2 x NUMERIC (max_splits, min_split_sats) | — |
| `0x0406` | RECURSE_DECAY | >= 4 x NUMERIC (same format as RECURSE_MODIFIED) | — |

### 6.7 PLC Family (0x0600--0x06FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0601` | HYSTERESIS_FEE | 2 x NUMERIC (high_sat_vb, low_sat_vb) | — |
| `0x0602` | HYSTERESIS_VALUE | 2 x NUMERIC (high_sats, low_sats) | — |
| `0x0611` | TIMER_CONTINUOUS | 2 x NUMERIC (accumulated, target) | — |
| `0x0612` | TIMER_OFF_DELAY | NUMERIC (remaining) | — |
| `0x0621` | LATCH_SET | PUBKEY (setter_key), NUMERIC (state) | — |
| `0x0622` | LATCH_RESET | PUBKEY (resetter_key), 2 x NUMERIC (state, delay_blocks) | — |
| `0x0631` | COUNTER_DOWN | PUBKEY (event_signer), NUMERIC (count) | — |
| `0x0632` | COUNTER_PRESET | 2 x NUMERIC (current, preset) | — |
| `0x0633` | COUNTER_UP | PUBKEY (event_signer), 2 x NUMERIC (current, target) | — |
| `0x0641` | COMPARE | 2-3 x NUMERIC (operator, value_b [, value_c]) | — |
| `0x0651` | SEQUENCER | 2 x NUMERIC (current_step, total_steps) | — |
| `0x0661` | ONE_SHOT | NUMERIC (state), HASH256 (commitment) | — |
| `0x0671` | RATE_LIMIT | 3 x NUMERIC (max_per_block, accumulation_cap, refill_blocks) | — |
| `0x0681` | COSIGN | HASH256 (conditions_hash) | — |

### 6.8 Compound Family (0x0700--0x07FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0701` | TIMELOCKED_SIG | PUBKEY, SIGNATURE, NUMERIC (CSV delay) | PUBKEY_COMMIT, SCHEME |
| `0x0702` | HTLC | 2 x PUBKEY, HASH256 (hash_lock), NUMERIC (CSV delay), SIGNATURE, PREIMAGE | PUBKEY_COMMIT |
| `0x0703` | HASH_SIG | PUBKEY, HASH256 (hash_lock), SIGNATURE, PREIMAGE | PUBKEY_COMMIT, SCHEME |
| `0x0704` | PTLC | 2 x PUBKEY (signing_key, adaptor_point), SIGNATURE, NUMERIC (CSV delay) | PUBKEY_COMMIT |
| `0x0705` | CLTV_SIG | PUBKEY, SIGNATURE, NUMERIC (CLTV height) | PUBKEY_COMMIT, SCHEME |
| `0x0706` | TIMELOCKED_MULTISIG | NUMERIC (threshold M), N x PUBKEY, M x SIGNATURE, NUMERIC (CSV delay) | SCHEME |

### 6.9 Governance Family (0x0800--0x08FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0801` | EPOCH_GATE | 2 x NUMERIC (epoch_size, window_size) | — |
| `0x0802` | WEIGHT_LIMIT | NUMERIC (max_weight) | — |
| `0x0803` | INPUT_COUNT | 2 x NUMERIC (min_inputs, max_inputs) | — |
| `0x0804` | OUTPUT_COUNT | 2 x NUMERIC (min_outputs, max_outputs) | — |
| `0x0805` | RELATIVE_VALUE | 2 x NUMERIC (numerator, denominator) | — |
| `0x0806` | ACCUMULATOR | >= 3 x HASH256 (root, proof siblings, leaf) | — |

---

## 7. Evaluation Semantics

### 7.1 General Rules

- **Rung evaluation (AND):** All blocks in a rung must return SATISFIED. If any block returns UNSATISFIED, ERROR, or UNKNOWN_BLOCK_TYPE, the rung fails.
- **Ladder evaluation (OR):** The first rung that returns SATISFIED wins. If no rung is satisfied, the ladder fails.
- **Inversion:** Applied after block evaluation via `ApplyInversion()`. See Section 13.
- **Merge:** At verification time, conditions (from the spent output) and witness (from the spending input) are merged. Condition fields are placed first in each block, followed by witness fields. The inverted flag is taken from conditions.

### 7.2 SIG (0x0001)

**Required fields:** PUBKEY, SIGNATURE
**Optional fields:** PUBKEY_COMMIT, SCHEME

**Evaluation:**

1. If PUBKEY_COMMIT is present without PUBKEY, return ERROR.
2. If both PUBKEY_COMMIT and PUBKEY are present, compute `SHA256(PUBKEY.data)` and compare to `PUBKEY_COMMIT.data`. If mismatch, return UNSATISFIED.
3. If PUBKEY or SIGNATURE is missing, return ERROR.
4. If SCHEME field is present and its value is a PQ scheme (`>= 0x10`), route to PQ signature verification (Section 7.2.1).
5. If SIGNATURE is 64 or 65 bytes, treat as Schnorr:
   - If PUBKEY is 33 bytes (compressed), strip the prefix byte to get the 32-byte x-only key.
   - Verify via `CheckSchnorrSignature()` using `SigVersion::LADDER`.
6. If SIGNATURE is 8--72 bytes, treat as ECDSA:
   - Verify via `CheckECDSASignature()`.
7. Otherwise, return ERROR.

**7.2.1 PQ Signature Verification:**

1. Cast the checker to `LadderSignatureChecker`.
2. Compute the ladder sighash via `ComputeSighash(SIGHASH_DEFAULT, hash_out)`.
3. Call `VerifyPQSignature(scheme, sig, sighash, pubkey)` via liboqs.
4. Return SATISFIED if verification succeeds, UNSATISFIED otherwise.

### 7.3 MULTISIG (0x0002)

**Required fields:** NUMERIC (threshold M), N x PUBKEY, M x SIGNATURE
**Optional fields:** SCHEME

**Evaluation:**

1. Read threshold M from the first NUMERIC field. If M <= 0, return ERROR.
2. Collect all PUBKEY fields (N total) and all SIGNATURE fields.
3. If N == 0 or M > N, return ERROR. If fewer than M signatures provided, return UNSATISFIED.
4. If SCHEME is a PQ scheme, compute sighash once and verify each signature against pubkeys using `VerifyPQSignature()`.
5. Otherwise, for each signature, try each unused pubkey:
   - 64--65 byte signatures: Schnorr verification.
   - 8--72 byte signatures: ECDSA verification.
6. Track distinct pubkey matches. Return SATISFIED if valid_count >= M.

### 7.4 ADAPTOR_SIG (0x0003)

**Condition fields:** 2 x PUBKEY_COMMIT (signing_key at index 0, adaptor_point at index 1)
**Witness fields:** PUBKEY (signing_key), SIGNATURE (adapted)

**Evaluation:**

1. Resolve PUBKEY_COMMITs: the witness PUBKEY must match the signing_key commitment. The adaptor_point is committed in conditions but not revealed in the witness (the adaptor secret is applied off-chain).
2. If no resolved PUBKEY or no SIGNATURE, return ERROR.
3. The adapted signature (64--65 bytes) is verified against the signing_key using `CheckSchnorrSignature()`.
4. Return SATISFIED on successful verification, UNSATISFIED otherwise.

### 7.5 MUSIG_THRESHOLD (0x0004)

**Condition fields:** PUBKEY_COMMIT (aggregate key hash), 2 x NUMERIC (threshold M, group size N)
**Witness fields:** PUBKEY (aggregate key), SIGNATURE (aggregate Schnorr signature)

**Evaluation:**

1. Read PUBKEY_COMMIT. If missing or not 32 bytes, return ERROR.
2. Read NUMERIC fields for M and N. These are policy/display only and not enforced during evaluation (the aggregate key already encodes the threshold).
3. Resolve PUBKEY from witness. Verify `SHA256(PUBKEY) == PUBKEY_COMMIT`. If mismatch, return UNSATISFIED.
4. Verify the aggregate SIGNATURE against the aggregate PUBKEY using `CheckSchnorrSignature()`. Schnorr-only; no PQ path.
5. Return SATISFIED on successful verification, UNSATISFIED otherwise.

Note: The threshold signing ceremony (MuSig2 or FROST) occurs entirely off-chain. On-chain, the spend is indistinguishable from a single-sig SIG block (~131 bytes total regardless of M or N).

### 7.6 CSV (0x0101)

**Required fields:** NUMERIC (sequence value)

**Evaluation:**

1. Read the sequence value. If negative, return ERROR.
2. If the disable flag (`SEQUENCE_LOCKTIME_DISABLE_FLAG`) is set, return SATISFIED unconditionally.
3. Call `CheckSequence(nSequence)`. Return SATISFIED if it passes, UNSATISFIED otherwise.

**Context:** Uses `BaseSignatureChecker::CheckSequence()`, which compares against the input's `nSequence` field per BIP-68 block-height-based relative timelocks.

### 7.7 CSV_TIME (0x0102)

Identical logic to CSV. The distinction is semantic: the NUMERIC value should encode a time-based relative lock (BIP-68 with the type flag set). `CheckSequence()` handles both interpretations.

### 7.8 CLTV (0x0103)

**Required fields:** NUMERIC (locktime value)

**Evaluation:**

1. Read the locktime value. If negative, return ERROR.
2. Call `CheckLockTime(nLockTime)`. Return SATISFIED if it passes, UNSATISFIED otherwise.

**Context:** Uses `BaseSignatureChecker::CheckLockTime()`, which compares against `tx.nLockTime` per BIP-65 absolute block-height timelocks.

### 7.9 CLTV_TIME (0x0104)

Identical logic to CLTV. The distinction is semantic: the NUMERIC value should encode a median-time-past threshold.

### 7.10 HASH_PREIMAGE (0x0201)

**Required fields:** HASH256, PREIMAGE

**Evaluation:**

1. If PREIMAGE is missing, return ERROR.
2. If HASH256 is missing, return ERROR.
3. Compute `SHA256(PREIMAGE.data)` and compare to `HASH256.data`.
4. Return SATISFIED on match, UNSATISFIED otherwise.

### 7.11 HASH160_PREIMAGE (0x0202)

**Required fields:** HASH160, PREIMAGE

**Evaluation:**

1. If PREIMAGE is missing, return ERROR.
2. If HASH160 is missing, return ERROR.
3. Compute `RIPEMD160(SHA256(PREIMAGE.data))` and compare to `HASH160.data`.
4. Return SATISFIED on match, UNSATISFIED otherwise.

### 7.12 TAGGED_HASH (0x0203)

**Required fields:** 2 x HASH256 (tag_hash at index 0, expected_hash at index 1), PREIMAGE

**Evaluation:**

1. If fewer than 2 HASH256 fields or no PREIMAGE, return ERROR.
2. Both HASH256 fields must be exactly 32 bytes.
3. Compute `SHA256(tag_hash || tag_hash || PREIMAGE.data)`. Note: the tag_hash field IS `SHA256(tag)` already, so this produces the BIP-340 tagged hash.
4. Compare the result to expected_hash. Return SATISFIED on match.

### 7.13 CTV (0x0301)

**Required fields:** HASH256 (template hash)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.input_index`

**Evaluation:**

1. If HASH256 is missing or not 32 bytes, return ERROR.
2. If no transaction context, return UNSATISFIED.
3. Compute the BIP-119 template hash:
   ```
   SHA256(
     version (4 bytes LE) ||
     locktime (4 bytes LE) ||
     scriptsigs_hash (SHA256 of all scriptSigs concatenated) ||
     num_inputs (4 bytes LE) ||
     sequences_hash (SHA256 of all sequences, each 4 bytes LE) ||
     num_outputs (4 bytes LE) ||
     outputs_hash (SHA256 of all outputs: amount 8B LE || spk_len 8B LE || scriptPubKey) ||
     input_index (4 bytes LE)
   )
   ```
4. Compare computed hash to the template hash. Return SATISFIED on match.

### 7.14 VAULT_LOCK (0x0302)

**Condition fields:** 2 x PUBKEY_COMMIT (recovery_key at index 0, hot_key at index 1), NUMERIC (hot_delay)
**Witness fields:** PUBKEY (the key being used), SIGNATURE

**Evaluation (two-path):**

1. If fewer than 2 PUBKEY_COMMITs, no witness PUBKEY, no SIGNATURE, or no NUMERIC, return ERROR.
2. Read the hot_delay value. If negative, return ERROR.
3. Compute `SHA256(witness_PUBKEY)` and match against PUBKEY_COMMITs to determine which key is being used. If no match, return ERROR.
4. Verify the signature against the witness PUBKEY (Schnorr). If invalid, return UNSATISFIED.
5. **Recovery path:** If the matched PUBKEY_COMMIT is at index 0 (recovery_key), return SATISFIED immediately (cold sweep, no delay).
6. **Hot path:** If the matched PUBKEY_COMMIT is at index 1 (hot_key), call `CheckSequence(hot_delay)`. If the delay is met, return SATISFIED. If not, return UNSATISFIED.

### 7.15 AMOUNT_LOCK (0x0303)

**Required fields:** 2 x NUMERIC (min_sats at index 0, max_sats at index 1)
**Context requirements:** `RungEvalContext.output_amount`

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. Read min_sats and max_sats. If either is negative, return ERROR.
3. If `min_sats <= output_amount <= max_sats`, return SATISFIED.
4. Otherwise, return UNSATISFIED.

### 7.16 ANCHOR (0x0501)

**Required fields:** At least one typed field of any type.

**Evaluation:**

1. If the block has no fields, return ERROR.
2. Return SATISFIED. (Generic anchor; structural validation only.)

### 7.17 ANCHOR_CHANNEL (0x0502)

**Required fields:** 2 x PUBKEY (local_key, remote_key)
**Optional fields:** NUMERIC (commitment_number)

**Evaluation:**

1. If fewer than 2 PUBKEYs, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.18 ANCHOR_POOL (0x0503)

**Required fields:** HASH256 (vtxo_tree_root)
**Optional fields:** NUMERIC (participant_count)

**Evaluation:**

1. If no HASH256, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.19 ANCHOR_RESERVE (0x0504)

**Required fields:** 2 x NUMERIC (threshold_n, threshold_m), HASH256 (guardian_set_hash)

**Evaluation:**

1. If fewer than 2 NUMERICs or no HASH256, return ERROR.
2. Read threshold_n and threshold_m. If either is negative or threshold_n > threshold_m, return UNSATISFIED.
3. Return SATISFIED.

### 7.20 ANCHOR_SEAL (0x0505)

**Required fields:** 2 x HASH256 (asset_id, state_transition)

**Evaluation:**

1. If fewer than 2 HASH256 fields, return ERROR.
2. Return SATISFIED.

### 7.21 ANCHOR_ORACLE (0x0506)

**Required fields:** PUBKEY (oracle_key)
**Optional fields:** NUMERIC (outcome_count)

**Evaluation:**

1. If no PUBKEY, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.22 RECURSE_SAME (0x0401)

**Required fields:** NUMERIC (max_depth)
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

1. If no NUMERIC, return ERROR.
2. Read max_depth. If max_depth <= 0, return UNSATISFIED.
3. If input_conditions and spending_output are both available:
   - Deserialize the spending output's scriptPubKey as `RungConditions`.
   - If deserialization fails, return UNSATISFIED.
   - Compare output conditions to input conditions. If not identical, return UNSATISFIED.
4. Return SATISFIED.

### 7.23 RECURSE_MODIFIED (0x0402)

**Required fields:** >= 4 x NUMERIC
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Mutation format:**

*Legacy (4 or 5 NUMERICs):*
```
numerics[0] = max_depth
numerics[1] = block_idx     (target block index, rung implicitly 0)
numerics[2] = param_idx     (target condition-field index within the block)
numerics[3] = delta          (additive delta to apply)
```

*Multi-mutation (6+ NUMERICs):*
```
numerics[0] = max_depth
numerics[1] = num_mutations
FOR EACH mutation (4 NUMERICs per mutation starting at index 2):
  rung_idx, block_idx, param_idx, delta
```

**Evaluation:**

1. Parse mutation specifications. If parsing fails, return ERROR.
2. If max_depth <= 0, return UNSATISFIED.
3. Verify the spending output's conditions match the input conditions except at mutated targets, where `output_value == input_value + delta`. Only NUMERIC fields may be mutated.
4. Non-mutated fields must be identical.

### 7.24 RECURSE_UNTIL (0x0403)

**Required fields:** NUMERIC (until_height)
**Context requirements:** `RungEvalContext.block_height`, `RungEvalContext.tx`, `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

1. Read until_height. If negative, return ERROR.
2. Compute the effective height as `max(block_height, tx.nLockTime)` (only if nLockTime < `LOCKTIME_THRESHOLD`, i.e., it represents a block height).
3. If effective_height >= until_height, return SATISFIED (covenant terminates).
4. Otherwise (before termination): verify the spending output carries identical conditions to the input. Return UNSATISFIED if conditions do not match.

### 7.25 RECURSE_COUNT (0x0404)

**Required fields:** NUMERIC (count)
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

1. Read count. If negative, return ERROR.
2. If count == 0, return SATISFIED (countdown complete, covenant terminates).
3. If count > 0: verify the spending output contains a RECURSE_COUNT block with count == (input count - 1).
4. Return UNSATISFIED if the decremented count is not found.

### 7.26 RECURSE_SPLIT (0x0405)

**Required fields:** 2 x NUMERIC (max_splits, min_split_sats)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.input_conditions`, `RungEvalContext.input_amount`

**Evaluation:**

1. Read max_splits and min_split_sats. If max_splits <= 0 or min_split_sats < 0, return UNSATISFIED.
2. For each output in the transaction:
   - Verify `output.nValue >= min_split_sats`.
   - Deserialize the output conditions and verify any RECURSE_SPLIT block has `max_splits - 1`.
3. Verify value conservation: `sum(output values) <= input_amount`.
4. If output_amount > 0 but < min_split_sats (no full context), return UNSATISFIED.

### 7.27 RECURSE_DECAY (0x0406)

**Required fields:** >= 4 x NUMERIC (same format as RECURSE_MODIFIED)
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

Uses the same mutation parsing and verification as RECURSE_MODIFIED, but **negates all deltas**. This means the output value is `input_value - delta`, implementing a decaying parameter.

### 7.28 HYSTERESIS_FEE (0x0601)

**Required fields:** 2 x NUMERIC (high_sat_vb at index 0, low_sat_vb at index 1)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.spent_outputs`

**Evaluation:**

1. Read high and low bounds. If either is negative or low > high, return UNSATISFIED.
2. If no transaction context, return SATISFIED (structural-only mode).
3. Compute fee: `sum(spent output values) - sum(tx output values)`. If fee < 0, return UNSATISFIED.
4. Compute fee_rate: `fee / GetVirtualTransactionSize(tx)`. If vsize <= 0, return ERROR.
5. If `low <= fee_rate <= high`, return SATISFIED.

### 7.29 HYSTERESIS_VALUE (0x0602)

**Required fields:** 2 x NUMERIC (high_sats at index 0, low_sats at index 1)
**Context requirements:** `RungEvalContext.input_amount`

**Evaluation:**

1. Read high and low bounds. If either is negative or low > high, return UNSATISFIED.
2. If `low <= input_amount <= high`, return SATISFIED.

### 7.30 TIMER_CONTINUOUS (0x0611)

**Required fields:** 2 x NUMERIC (accumulated at index 0, target at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs: single-field backward compatibility (treat as target, satisfied if > 0).
2. If either value is negative, return ERROR.
3. If `accumulated >= target`, return SATISFIED (timer elapsed).
4. Otherwise, return UNSATISFIED. (Pair with RECURSE_MODIFIED to increment accumulated each covenant spend.)

### 7.31 TIMER_OFF_DELAY (0x0612)

**Required fields:** NUMERIC (remaining)

**Evaluation:**

1. Read remaining. If negative, return ERROR.
2. If `remaining > 0`, return SATISFIED (still in hold-off period).
3. If `remaining == 0`, return UNSATISFIED (delay expired).
4. Pair with RECURSE_MODIFIED to decrement remaining each covenant spend.

### 7.32 LATCH_SET (0x0621)

**Required fields:** PUBKEY (setter_key)
**Optional fields:** NUMERIC (state)

**Evaluation:**

1. If no PUBKEY, return ERROR.
2. If no NUMERIC (backward compat), return SATISFIED.
3. If `state == 0` (unset), return SATISFIED (the latch can be set).
4. If `state != 0` (already set), return UNSATISFIED.
5. Pair with RECURSE_MODIFIED to enforce state transition 0 -> 1 in the output.

### 7.33 LATCH_RESET (0x0622)

**Required fields:** PUBKEY (resetter_key), 2 x NUMERIC (state, delay_blocks)

**Evaluation:**

1. If no PUBKEY, return ERROR. If fewer than 2 NUMERICs, return ERROR.
2. Read state and delay. If delay < 0, return ERROR.
3. If `state >= 1` (set), return SATISFIED (the latch can be reset).
4. If `state == 0` (already unset), return UNSATISFIED.
5. Pair with RECURSE_MODIFIED to enforce state transition 1 -> 0 in the output.

### 7.34 COUNTER_DOWN (0x0631)

**Required fields:** PUBKEY (event_signer), NUMERIC (count)

**Evaluation:**

1. If no PUBKEY, return ERROR. If no NUMERIC, return ERROR.
2. Read count. If negative, return ERROR.
3. If `count > 0`, return SATISFIED (can still decrement).
4. If `count == 0`, return UNSATISFIED (countdown done).
5. Pair with RECURSE_MODIFIED to decrement each spend.

### 7.35 COUNTER_PRESET (0x0632)

**Required fields:** 2 x NUMERIC (current at index 0, preset at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. If either is negative, return ERROR.
3. If `current < preset`, return SATISFIED (still accumulating).
4. If `current >= preset`, return UNSATISFIED (threshold reached).

### 7.36 COUNTER_UP (0x0633)

**Required fields:** PUBKEY (event_signer), 2 x NUMERIC (current at index 0, target at index 1)

**Evaluation:**

1. If no PUBKEY, return ERROR. If fewer than 2 NUMERICs, return ERROR.
2. If either is negative, return ERROR.
3. If `current < target`, return SATISFIED (still counting).
4. If `current >= target`, return UNSATISFIED (target reached).

### 7.37 COMPARE (0x0641)

**Required fields:** 2 x NUMERIC (operator at index 0, value_b at index 1)
**Optional fields:** 3rd NUMERIC (value_c for IN_RANGE)
**Context requirements:** `RungEvalContext.input_amount`

**Operators:**

| Code | Operator | Condition |
|------|----------|-----------|
| `0x01` | EQ | `input_amount == value_b` |
| `0x02` | NEQ | `input_amount != value_b` |
| `0x03` | GT | `input_amount > value_b` |
| `0x04` | LT | `input_amount < value_b` |
| `0x05` | GTE | `input_amount >= value_b` |
| `0x06` | LTE | `input_amount <= value_b` |
| `0x07` | IN_RANGE | `value_b <= input_amount <= value_c` (requires 3rd NUMERIC) |

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR. If value_b < 0, return ERROR.
2. Apply the operator. For IN_RANGE, require a third NUMERIC and check range bounds.
3. Unknown operator codes return ERROR.

### 7.38 SEQUENCER (0x0651)

**Required fields:** 2 x NUMERIC (current_step at index 0, total_steps at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. Read current and total. If current < 0, total <= 0, or current >= total, return UNSATISFIED.
3. If `0 <= current < total`, return SATISFIED.

### 7.39 ONE_SHOT (0x0661)

**Required fields:** NUMERIC (state), HASH256 (commitment)

**Evaluation:**

1. If no NUMERIC, return ERROR. If no HASH256, return ERROR.
2. If `state == 0`, return SATISFIED (can fire).
3. If `state != 0`, return UNSATISFIED (already fired).

### 7.40 RATE_LIMIT (0x0671)

**Required fields:** 3 x NUMERIC (max_per_block, accumulation_cap, refill_blocks)
**Context requirements:** `RungEvalContext.output_amount`

**Evaluation:**

1. If fewer than 3 NUMERICs, return ERROR.
2. Read max_per_block. If negative, return ERROR.
3. If `output_amount > max_per_block`, return UNSATISFIED.
4. Return SATISFIED. (Full accumulation tracking requires UTXO chain state beyond single-transaction evaluation.)

### 7.41 COSIGN (0x0681)

**Required fields:** HASH256 (conditions_hash, the SHA256 of the required co-spent scriptPubKey)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.spent_outputs`, `RungEvalContext.input_index`

**Evaluation:**

1. If no HASH256 or its size is not 32 bytes, return ERROR.
2. If no transaction context or spent outputs, return SATISFIED (structural-only mode).
3. For each other input (excluding self):
   - Compute `SHA256(spent_outputs[i].scriptPubKey)`.
   - If it matches the conditions_hash, return SATISFIED.
4. If no match found, return UNSATISFIED.

### 7.42 TIMELOCKED_SIG (0x0701)

**Required fields:** PUBKEY, SIGNATURE, NUMERIC (CSV delay)
**Optional fields:** PUBKEY_COMMIT, SCHEME

**Evaluation:**

1. Resolve PUBKEY_COMMIT if present (SHA256(PUBKEY) must match).
2. Verify signature (PQ if SCHEME indicates, otherwise Schnorr/ECDSA by size).
3. If CSV disable flag is set, return SATISFIED.
4. Verify `CheckSequence(csv_delay)`. If failed, return UNSATISFIED.
5. Return SATISFIED.

### 7.43 HTLC (0x0702)

**Required fields:** 2 x PUBKEY, HASH256 (hash_lock), NUMERIC (CSV delay), SIGNATURE, PREIMAGE
**Optional fields:** PUBKEY_COMMIT

**Evaluation:**

1. Verify `SHA256(PREIMAGE) == HASH256`. If mismatch, return UNSATISFIED.
2. Verify CSV timelock via `CheckSequence()`. If not met, return UNSATISFIED.
3. Resolve PUBKEY_COMMIT, verify signature against matched pubkey.
4. If signature invalid, return UNSATISFIED.
5. Return SATISFIED.

### 7.44 HASH_SIG (0x0703)

**Required fields:** PUBKEY, HASH256, SIGNATURE, PREIMAGE
**Optional fields:** PUBKEY_COMMIT, SCHEME

**Evaluation:**

1. Verify `SHA256(PREIMAGE) == HASH256`. If mismatch, return UNSATISFIED.
2. Resolve PUBKEY_COMMIT, verify signature (PQ if SCHEME indicates).
3. If signature invalid, return UNSATISFIED.
4. Return SATISFIED.

### 7.45 PTLC (0x0704)

**Required fields:** 2 x PUBKEY (signing_key, adaptor_point), SIGNATURE, NUMERIC (CSV delay)
**Optional fields:** PUBKEY_COMMIT

**Evaluation:**

1. Resolve signing key from PUBKEY_COMMIT.
2. Verify adapted Schnorr signature against signing key (adaptor point committed but not needed on-chain).
3. If signature invalid, return UNSATISFIED.
4. Verify CSV timelock. If not met, return UNSATISFIED.
5. Return SATISFIED.

Note: Schnorr only. No ECDSA or PQ support.

### 7.46 CLTV_SIG (0x0705)

**Required fields:** PUBKEY, SIGNATURE, NUMERIC (CLTV height)
**Optional fields:** PUBKEY_COMMIT, SCHEME

**Evaluation:**

1. Resolve PUBKEY_COMMIT, verify signature (PQ if SCHEME indicates).
2. If signature invalid, return UNSATISFIED.
3. Verify `CheckLockTime(cltv_height)`. If not met, return UNSATISFIED.
4. Return SATISFIED.

### 7.47 TIMELOCKED_MULTISIG (0x0706)

**Required fields:** NUMERIC (threshold M), N x PUBKEY, M x SIGNATURE, NUMERIC (CSV delay)
**Optional fields:** SCHEME

**Evaluation:**

1. Read threshold M from first NUMERIC.
2. Resolve PUBKEY_COMMITs (need >= M matching PUBKEYs).
3. Verify M-of-N signatures (each sig must match a distinct pubkey). PQ if SCHEME indicates.
4. If fewer than M valid sigs, return UNSATISFIED.
5. Verify CSV timelock. If not met, return UNSATISFIED.
6. Return SATISFIED.

### 7.48 EPOCH_GATE (0x0801)

**Required fields:** 2 x NUMERIC (epoch_size, window_size)
**Context requirements:** `ctx.block_height`

**Evaluation:**

1. If epoch_size <= 0, window_size <= 0, or window_size > epoch_size, return ERROR.
2. Compute `position = block_height % epoch_size`.
3. If `position < window_size`, return SATISFIED.
4. Return UNSATISFIED.

### 7.49 WEIGHT_LIMIT (0x0802)

**Required fields:** NUMERIC (max_weight)
**Context requirements:** `ctx.tx`

**Evaluation:**

1. If no tx context, return SATISFIED.
2. If `GetTransactionWeight(tx) <= max_weight`, return SATISFIED.
3. Return UNSATISFIED.

### 7.50 INPUT_COUNT (0x0803)

**Required fields:** 2 x NUMERIC (min_inputs, max_inputs)
**Context requirements:** `ctx.tx`

**Evaluation:**

1. If min_inputs > max_inputs, return ERROR.
2. If no tx context, return SATISFIED.
3. If `tx.vin.size()` within [min, max], return SATISFIED.
4. Return UNSATISFIED.

### 7.51 OUTPUT_COUNT (0x0804)

**Required fields:** 2 x NUMERIC (min_outputs, max_outputs)
**Context requirements:** `ctx.tx`

**Evaluation:**

1. If min_outputs > max_outputs, return ERROR.
2. If no tx context, return SATISFIED.
3. If `tx.vout.size()` within [min, max], return SATISFIED.
4. Return UNSATISFIED.

### 7.52 RELATIVE_VALUE (0x0805)

**Required fields:** 2 x NUMERIC (numerator, denominator)
**Context requirements:** `ctx.input_amount`, `ctx.output_amount`

**Evaluation:**

1. If denominator == 0, return ERROR.
2. Compute `output_amount * denominator >= input_amount * numerator` (128-bit safe).
3. If true, return SATISFIED.
4. Return UNSATISFIED.

### 7.53 ACCUMULATOR (0x0806)

**Required fields:** >= 3 x HASH256 (root at index 0, proof siblings, leaf at last index)

**Evaluation:**

1. If fewer than 3 HASH256 fields, return ERROR.
2. Set `current = leaf` (last hash).
3. For each sibling (hashes[1..N-1]):
   - If `current < sibling`, compute `SHA256(current || sibling)`.
   - Else, compute `SHA256(sibling || current)`.
4. If `current == root`, return SATISFIED.
5. Return UNSATISFIED.

---

## 8. Sighash

### 8.1 LadderSighash

The signature hash for v4 RUNG_TX inputs uses the tagged hash `TaggedHash("LadderSighash")`.

The tagged hash is computed as `SHA256(SHA256("LadderSighash") || SHA256("LadderSighash") || data)`.

### 8.2 Commitment List

The sighash commits to the following data in order:

| Field | Encoding | Condition |
|-------|----------|-----------|
| epoch | uint8_t (always 0) | Always |
| hash_type | uint8_t | Always |
| tx.version | int32_t LE | Always |
| tx.nLockTime | uint32_t LE | Always |
| prevouts_single_hash | 32 bytes | Unless ANYONECANPAY |
| spent_amounts_single_hash | 32 bytes | Unless ANYONECANPAY |
| sequences_single_hash | 32 bytes | Unless ANYONECANPAY |
| outputs_single_hash | 32 bytes | Only if output_type == ALL |
| spend_type | uint8_t (always 0) | Always |
| input prevout | COutPoint | Only if ANYONECANPAY |
| input spent output | CTxOut | Only if ANYONECANPAY |
| input nSequence | uint32_t | Only if ANYONECANPAY |
| input index | uint32_t | Unless ANYONECANPAY |
| single output hash | SHA256 of tx.vout[nIn] | Only if SINGLE |
| conditions_hash | SHA256 of serialised conditions | Always |

### 8.3 Hash Types

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | SIGHASH_DEFAULT | Equivalent to ALL |
| `0x01` | SIGHASH_ALL | Commit to all outputs |
| `0x02` | SIGHASH_NONE | Do not commit to outputs |
| `0x03` | SIGHASH_SINGLE | Commit only to the output at the same index |
| `0x81` | SIGHASH_ALL\|ANYONECANPAY | ALL with single-input commitment |
| `0x82` | SIGHASH_NONE\|ANYONECANPAY | NONE with single-input commitment |
| `0x83` | SIGHASH_SINGLE\|ANYONECANPAY | SINGLE with single-input commitment |

### 8.4 Conditions Hash

For `0xC1` (inline) outputs, the conditions_hash is `SHA256(serialized_conditions)` where `serialized_conditions` is the wire format (Section 3) of the rung conditions from the spent output (rungs only, without the `0xc1` prefix).

For `0xC2` (MLSC) outputs, the conditions_hash is the `conditions_root` directly from the UTXO. The root already commits to all condition data through the Merkle tree, so hashing it again would add no security. Signers attest to the root, which is binding on all possible spending paths.

### 8.5 Differences from BIP-341

- Uses tagged hash `"LadderSighash"` instead of `"TapSighash"`.
- `spend_type` is always 0 (no annex, no tapscript extensions, no code separator).
- Commits to `conditions_hash` instead of `tapleaf_hash` / `key_version`.
- No `ext_flag`, no `annex_hash`.

### 8.6 Precomputed Data

The `PrecomputedTransactionData` structure has a `m_ladder_ready` flag. When a v4 transaction is initialized, the following hashes are precomputed:

- `m_prevouts_single_hash`: SHA256 of all prevouts
- `m_spent_amounts_single_hash`: SHA256 of all spent amounts
- `m_sequences_single_hash`: SHA256 of all sequences
- `m_outputs_single_hash`: SHA256 of all outputs

These are the same hashes used by BIP-341 but computed in the ladder initialization path.

---

## 9. Coil Types

The coil type determines how the output can be spent.

| Code | Name | Semantics |
|------|------|-----------|
| `0x01` | UNLOCK | Standard spend. The rung conditions must be satisfied. No destination constraint. |
| `0x02` | UNLOCK_TO | Spend to a specific destination. The coil's `address` field specifies the required recipient (raw scriptPubKey bytes). The rung conditions must be satisfied AND the spending transaction must send to the specified address. |
| `0x03` | COVENANT | Constrains the spending transaction structure. The coil's `conditions` field specifies additional rungs that the spending transaction must satisfy. This enables recursive covenants when combined with RECURSE_* blocks. |

---

## 10. Attestation Modes

| Code | Name | Status | Description |
|------|------|--------|-------------|
| `0x01` | INLINE | **Implemented** | Signatures are inline in the witness. Standard mode. |
| `0x02` | AGGREGATE | **Defined, fail-closed** | Block-level aggregate signature covering all AGGREGATE-mode spends. `VerifyAggregateSpend()` verifies spend_index + pubkey_commit against the aggregate proof. Not yet active. |
| `0x03` | DEFERRED | **Defined, fail-closed** | Deferred attestation via template hash. `VerifyDeferredAttestation()` always returns false (fail-closed). Not yet active. |

---

## 11. Signature Schemes

| Code | Name | Key Size | Signature Size | Library |
|------|------|----------|----------------|---------|
| `0x01` | SCHNORR | 32 bytes (x-only) | 64--65 bytes | libsecp256k1 |
| `0x02` | ECDSA | 33 bytes (compressed) | 8--72 bytes (DER) | libsecp256k1 |
| `0x10` | FALCON512 | 897 bytes | up to 690 bytes | liboqs (`OQS_SIG_alg_falcon_512`) |
| `0x11` | FALCON1024 | 1793 bytes | up to 1330 bytes | liboqs (`OQS_SIG_alg_falcon_1024`) |
| `0x12` | DILITHIUM3 | 1952 bytes | 3293 bytes | liboqs (`OQS_SIG_alg_dilithium_3`) |
| `0x13` | SPHINCS_SHA | 32 bytes | ~7,856 bytes | liboqs (`OQS_SIG_alg_sphincs_sha2_128f_simple`) |

Post-quantum schemes (codes >= `0x10`) are identified by `IsPQScheme()`. PQ support requires the build to be compiled with liboqs (`HAVE_LIBOQS`). `HasPQSupport()` returns whether the runtime has PQ verification capability. Without liboqs, all PQ verification returns false.

**PUBKEY_COMMIT for PQ keys:** Because PQ public keys are large (897--1952 bytes), outputs can store a 32-byte `PUBKEY_COMMIT = SHA256(pubkey)` in the conditions. The full public key is revealed only in the spending witness and verified against the commitment.

---

## 12. Policy Limits

| Limit | Value | Scope |
|-------|-------|-------|
| Maximum rungs per ladder | 16 (`MAX_RUNGS`) | Policy and deserialization |
| Maximum blocks per rung | 8 (`MAX_BLOCKS_PER_RUNG`) | Policy and deserialization |
| Maximum fields per block | 16 (`MAX_FIELDS_PER_BLOCK`) | Deserialization |
| Maximum ladder witness size | 10,000 bytes (`MAX_LADDER_WITNESS_SIZE`) | Deserialization |
| Maximum coil address size | 520 bytes | Deserialization |
| Maximum coil condition rungs | 16 (`MAX_RUNGS`) | Deserialization |
| Maximum PREIMAGE size | 252 bytes | Data type constraint |
| Maximum SIGNATURE size | 50,000 bytes | Data type constraint |
| Maximum PUBKEY size | 2,048 bytes | Data type constraint |

---

## 13. Inversion Semantics

Any block can be inverted by setting its `inverted` flag to `0x01`. Inversion is applied after the block's raw evaluation:

| Raw Result | Inverted Result |
|------------|-----------------|
| SATISFIED | UNSATISFIED |
| UNSATISFIED | SATISFIED |
| ERROR | ERROR (unchanged) |
| UNKNOWN_BLOCK_TYPE | ERROR |

Unknown block types are unconditionally unusable. Whether inverted or not, an unknown block type causes the rung to fail. When not inverted, UNKNOWN_BLOCK_TYPE propagates as a non-SATISFIED result (the rung fails and evaluation falls through to subsequent rungs). When inverted, it becomes ERROR (consensus failure). This prevents an attacker from using an inverted unknown block type to bypass spending conditions.

---

## 14. Address Format

Ladder Script outputs use the `rung1` human-readable prefix with Bech32m encoding (BIP-350).

### 14.1 Encoding

Given a conditions byte vector (the serialised `RungConditions` without the `0xc1` prefix):

1. Convert the conditions bytes to 5-bit groups using the Bech32 base conversion.
2. Encode with `bech32::Encode(bech32::Encoding::BECH32M, "rung", data)`.

The resulting address has the format `rung1<bech32m-data>`.

### 14.2 Decoding

1. Detect the `rung1` prefix (case-insensitive).
2. Decode with `bech32::Decode("rung1...", CharLimit::RUNG_ADDRESS)` where `RUNG_ADDRESS = 500`.
3. Verify the encoding is BECH32M.
4. Convert from 5-bit groups back to 8-bit bytes.
5. The resulting bytes are the raw conditions, producing a `LadderDestination`.

### 14.3 Character Limit

The `RUNG_ADDRESS` character limit of 500 accommodates the variable-length nature of serialised rung conditions. Simple conditions (e.g., a single SIG block) produce short addresses; complex multi-rung conditions with PQ keys produce longer addresses.

### 14.4 Script Detection

The `Solver` identifies rung conditions outputs by their `0xc1` prefix byte. The `TxoutType::RUNG_CONDITIONS` enum value is returned, and the conditions bytes (after the prefix) are provided as the solution vector.

### 14.5 CTxDestination

The `LadderDestination` type is a variant of `CTxDestination`. It stores the raw conditions bytes and supports:

- **GetScriptForDestination**: Reconstructs the `0xc1`-prefixed `scriptPubKey`.
- **IsValidDestination**: Returns true.
- **EncodeDestination**: Produces a `rung1`-prefixed Bech32m address.
- **DecodeDestination**: Parses `rung1` addresses back to `LadderDestination`.

---

## 15. RPC Interface

All Ladder Script RPCs are registered under the `"rung"` category.

### 15.1 encodeladderaddress

```
encodeladderaddress "conditions_hex"
```

Encode serialised rung conditions as a `rung1`-prefixed Bech32m address. The conditions hex is the raw conditions bytes (without the `0xc1` prefix). Returns the encoded address string.

### 15.2 decodeladderaddress

```
decodeladderaddress "rung1..."
```

Decode a `rung1`-prefixed Bech32m address back to its raw conditions hex. Returns the conditions bytes as hex.

### 15.3 decoderung

```
decoderung "hex"
```

Decode a serialised ladder witness from hex and return its typed structure as JSON. Includes rung/block/field breakdown with type names, hex data, sizes, coil metadata, and coil conditions.

### 15.4 createrung

```
createrung [{"blocks": [{"type": "SIG", "inverted": false, "fields": [{"type": "PUBKEY", "hex": "03..."}]}]}]
```

Create a serialised ladder witness from a JSON specification. Returns the serialised ladder witness as hex. Accepts an array of rungs, each containing an array of blocks with typed fields.

### 15.5 createrungtx

```
createrungtx [{"txid": "...", "vout": 0}] [{"amount": 0.001, "conditions": [...]}]
```

Create an unsigned v4 RUNG_TX transaction with rung condition outputs. Inputs are outpoints to spend. Outputs specify rung conditions (using the same JSON block/field format) and amounts. Returns the raw transaction hex.

### 15.6 signrungtx

```
signrungtx "txhex" [{"privkey": "cVt...", "input": 0}] [{"amount": 0.001, "scriptPubKey": "c1..."}]
```

Sign a v4 RUNG_TX transaction's inputs. Takes the raw transaction hex, an array of signing keys mapped to input indices, and an array of spent outputs (for sighash computation). Returns the signed transaction hex.

### 15.7 validateladder

```
validateladder "txhex"
```

Validate a raw v4 RUNG_TX transaction's ladder witnesses. Checks that all input witnesses are valid ladder witnesses with correct structure, known block types, and valid field sizes. Returns validation results per input.

### 15.8 computectvhash

```
computectvhash "txhex" input_index
```

Compute the BIP-119 CTV template hash for a v4 RUNG_TX transaction at the specified input index. Returns the 32-byte hash as hex.

### 15.9 generatepqkeypair

```
generatepqkeypair "scheme"
```

Generate a post-quantum keypair for the specified scheme (FALCON512, FALCON1024, DILITHIUM3). Requires liboqs support. Returns the public key and private key as hex.

### 15.10 pqpubkeycommit

```
pqpubkeycommit "pubkey_hex"
```

Compute the SHA256 commitment hash of a post-quantum public key. Use this to create PUBKEY_COMMIT condition fields for compact UTXO storage. Returns the 32-byte commitment as hex.

### 15.11 extractadaptorsecret

```
extractadaptorsecret "pre_sig_hex" "adapted_sig_hex"
```

Extract the adaptor secret from a pre-signature and adapted signature. Computes `t = s_adapted - s_pre (mod n)`. Both signatures must be 64 bytes. Returns the 32-byte secret as hex.

### 15.12 verifyadaptorpresig

```
verifyadaptorpresig "pubkey" "adaptor_point" "pre_sig" "sighash"
```

Verify an adaptor pre-signature. Checks that `s'*G == R + e*P` where `e = H(R+T || P || m)`. All parameters are 32-byte hex values (pubkey and adaptor_point are x-only), except pre_sig which is 64 bytes. Returns `{"valid": true/false}`.

---

## 16. COSIGN Mempool Interaction

The COSIGN block type (0x0681) requires that another input in the same transaction spends a UTXO whose `scriptPubKey` hashes to the committed `conditions_hash`. This creates a dependency between UTXOs at the mempool level.

### 16.1 Griefing Vector

An attacker who observes a pending child transaction (which requires co-spending an anchor) could attempt to independently spend the anchor UTXO, orphaning the child transaction. This is a mempool-level nuisance, not a consensus vulnerability — no funds can be stolen.

### 16.2 Mitigations

The attack is bounded by the anchor's own spending conditions:

1. **RECURSE_SAME protection.** Anchors typically use RECURSE_SAME, which requires the spending transaction to re-encumber an output with identical conditions. The attacker must create a valid re-encumbrance output, costing them a UTXO and fees. The anchor is not consumed — it is re-created.

2. **Signature requirement.** If the anchor's conditions include a SIG block (which they should for any production use), the attacker cannot spend the anchor without the private key. The griefing vector only exists for anchors with conditions that any party can satisfy.

3. **Fee economics.** The attacker pays transaction fees for each griefing attempt. The defender simply includes the new anchor UTXO in their next transaction. The cost asymmetry favours the defender.

4. **RBF interaction.** If the child transaction uses RBF (BIP-125), the defender can replace the griefing transaction with a higher-fee transaction that includes the intended co-spend, provided the defender can satisfy the anchor's conditions.

This is analogous to the anchor output griefing vector in Lightning Network commitment transactions (see BOLT-3), where the same economic mitigations apply.

---

## 17. Recursive Covenant Termination

Every RECURSE_* block type has a provably reachable terminal state. No combination of recursion blocks can create a UTXO that requires an unbounded number of intermediate transactions.

### 17.1 Termination Proof by Block Type

| Block Type | Termination Parameter | Terminal Condition | Proof |
|------------|----------------------|-------------------|-------|
| RECURSE_SAME (0x0401) | `max_depth` (NUMERIC) | `max_depth == 0` → UNSATISFIED | `max_depth` is a finite unsigned integer. Each spend requires `max_depth > 0`. The output must carry identical conditions, so `max_depth` is preserved. However, when `max_depth` reaches 0, the block returns UNSATISFIED, terminating the covenant. Maximum chain length = initial `max_depth` value. |
| RECURSE_MODIFIED (0x0402) | `max_depth` (NUMERIC[0]) | `max_depth == 0` → UNSATISFIED | Same as RECURSE_SAME. The `max_depth` parameter is checked before mutation verification. |
| RECURSE_UNTIL (0x0403) | `until_height` (NUMERIC) | `block_height >= until_height` → SATISFIED | Block height is monotonically increasing. The terminal condition is guaranteed to be reached at a deterministic future block height. Maximum chain length = `until_height - current_height` blocks. |
| RECURSE_COUNT (0x0404) | `count` (NUMERIC) | `count == 0` → SATISFIED | Each spend requires the output to carry `count - 1`. Since `count` is an unsigned integer decremented by 1 per spend, termination occurs in exactly `count` spends. |
| RECURSE_SPLIT (0x0405) | `max_splits` (NUMERIC) | `max_splits == 0` → UNSATISFIED | Each split output must carry `max_splits - 1`. Termination is reached in at most `max_splits` levels of splitting. Total outputs bounded by `2^max_splits` (binary split) or fewer. |
| RECURSE_DECAY (0x0406) | `max_depth` (NUMERIC[0]) | `max_depth == 0` → UNSATISFIED | Same as RECURSE_MODIFIED. The decay delta is applied per spend, but `max_depth` controls termination independently of the decayed parameter. |

### 17.2 Worst Case Analysis

The maximum covenant chain length is bounded by the initial value of the termination parameter, which is a `uint32_t` (maximum 4,294,967,295). In practice, policy enforcement limits the NUMERIC field to 4 bytes, so the theoretical maximum is ~4 billion intermediate transactions. This is infeasible to execute (it would take centuries at maximum throughput) and each intermediate transaction pays fees, making long chains economically prohibitive.

### 17.3 Composition

When multiple RECURSE_* blocks appear in the same rung (AND logic), the covenant terminates when *any* recursion block reaches its terminal state (since the rung requires all blocks to be SATISFIED). This means the shortest termination parameter dominates.

When RECURSE_* blocks appear in different rungs (OR logic), the covenant terminates when the first rung's recursion blocks all reach their terminal states. Alternative rungs may provide early exit paths (e.g., a SIG-only rung alongside a recursive rung).

---

## 18. Post-Quantum Library Dependency

### 18.1 liboqs Usage

Post-quantum signature verification uses the Open Quantum Safe (OQS) project's liboqs library. The dependency is:

- **Optional.** Nodes compile and run without liboqs. The `HAVE_LIBOQS` preprocessor flag controls availability. Without it, `HasPQSupport()` returns false and all PQ verification returns false (fail-closed).
- **Verification-only.** liboqs is used exclusively for signature verification (`OQS_SIG_verify`), not for key generation or signing in consensus-critical paths. Key generation and signing RPCs are wallet-side utilities.
- **Deterministic.** Given identical inputs (public key, message, signature), any correct implementation of FALCON or Dilithium produces the same verification result. This is a property of the underlying mathematical verification equations, not of any particular library.

### 18.2 Consensus Split Risk

A consensus split from a liboqs bug would require the bug to cause *different* verification results on different nodes — i.e., one node accepts a signature that another rejects. This is the same risk class as libsecp256k1 for ECDSA/Schnorr verification. Mitigations:

1. **Pinned version.** The build system pins a specific liboqs release. Nodes running the same ghost-core version use the same liboqs version.
2. **Algorithm stability.** FALCON and Dilithium are NIST-standardised algorithms (FIPS 204, FIPS 206). The verification equations are fixed by the standard.
3. **Fail-closed default.** Nodes without liboqs reject all PQ signatures. This means PQ transactions require explicit opt-in by node operators who install liboqs, reducing the surface area for version mismatches.
4. **Activation gating.** PQ signature block types activate with all other block types. Before activation, PQ transactions are non-standard and cannot enter the mempool. After activation, all nodes on the network must support PQ verification to validate blocks.

### 18.3 Future Path

If liboqs proves insufficient for consensus-critical use, the PQ verification functions can be replaced with in-tree implementations of the NIST-standardised algorithms without changing the wire format, block types, or evaluation semantics. The interface is a single function: `VerifyPQSignature(scheme, signature, message, pubkey) → bool`.

---

## 19. Prefix Collision Analysis (`0xC1` / `0xC2`)

The bytes `0xc1` (inline conditions) and `0xc2` (MLSC Merkle root) identify Ladder Script outputs as the first byte of `scriptPubKey`. This section demonstrates that neither collides with any existing or planned scriptPubKey format.

### 19.1 Existing scriptPubKey First Bytes

| scriptPubKey Type | First Byte | Hex |
|-------------------|------------|-----|
| P2PKH | `OP_DUP` | `0x76` |
| P2SH | `OP_HASH160` | `0xa9` |
| P2WPKH (witness v0) | `OP_0` | `0x00` |
| P2WSH (witness v0) | `OP_0` | `0x00` |
| P2TR (witness v1) | `OP_1` | `0x51` |
| OP_RETURN (null data) | `OP_RETURN` | `0x6a` |
| Bare multisig | `OP_1`..`OP_16` | `0x51`..`0x60` |
| Bare pubkey | Data push (33 or 65 bytes) | `0x21` or `0x41` |

### 19.2 Witness Version Range

BIP-141 defines witness programs as: `OP_n` (1 byte) followed by a data push of 2-40 bytes. The witness version opcodes are `OP_0` (`0x00`) through `OP_16` (`0x60`). Future witness versions occupy `0x51`-`0x60`. Both `0xc1` and `0xc2` are outside this range.

### 19.3 Opcode Identity

`0xc1` is `OP_NOP2` (repurposed as `OP_CHECKLOCKTIMEVERIFY`, BIP-65). `0xc2` is `OP_NOP3` (repurposed as `OP_CHECKSEQUENCEVERIFY`, BIP-112). However:

- Neither CLTV nor CSV ever appears as the *first byte* of a standard scriptPubKey. They are used within scripts (e.g., `<height> OP_CLTV OP_DROP ...`) where the first byte is a data push opcode.
- No wallet software generates scriptPubKeys beginning with `0xc1` or `0xc2`.
- The Bitcoin Core `Solver()` function does not recognise any standard output type beginning with either byte.

### 19.4 Data Push Range

Bitcoin Script data push opcodes occupy `0x01`-`0x4e` (direct pushes and `OP_PUSHDATA1/2/4`). Both `0xc1` and `0xc2` are outside this range and cannot be interpreted as data push prefixes.

### 19.5 Conclusion

Neither `0xc1` nor `0xc2` collides with any existing standard scriptPubKey first byte, any witness version opcode, or any data push prefix. They are safe to use as the Ladder Script conditions identifiers. The choice of repurposed NOP opcodes is intentional — non-upgraded nodes that encounter these scriptPubKey prefixes treat them as non-standard output types, which is the correct behaviour for soft fork compatibility.

---

## Appendix A: Block Type Code Reference

```
0x0001  SIG                 0x0401  RECURSE_SAME
0x0002  MULTISIG            0x0402  RECURSE_MODIFIED
0x0003  ADAPTOR_SIG         0x0403  RECURSE_UNTIL
0x0101  CSV                 0x0404  RECURSE_COUNT
0x0102  CSV_TIME            0x0405  RECURSE_SPLIT
0x0103  CLTV                0x0406  RECURSE_DECAY
0x0104  CLTV_TIME           0x0501  ANCHOR
0x0201  HASH_PREIMAGE       0x0502  ANCHOR_CHANNEL
0x0202  HASH160_PREIMAGE    0x0503  ANCHOR_POOL
0x0203  TAGGED_HASH         0x0504  ANCHOR_RESERVE
0x0301  CTV                 0x0505  ANCHOR_SEAL
0x0302  VAULT_LOCK          0x0506  ANCHOR_ORACLE
0x0303  AMOUNT_LOCK
0x0601  HYSTERESIS_FEE      0x0641  COMPARE
0x0602  HYSTERESIS_VALUE    0x0651  SEQUENCER
0x0611  TIMER_CONTINUOUS    0x0661  ONE_SHOT
0x0612  TIMER_OFF_DELAY     0x0671  RATE_LIMIT
0x0621  LATCH_SET           0x0681  COSIGN
0x0622  LATCH_RESET
0x0631  COUNTER_DOWN
0x0632  COUNTER_PRESET
0x0633  COUNTER_UP
```
