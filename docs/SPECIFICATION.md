# Ladder Script -- Technical Specification

**Version:** 2 (wire format v2)
**Transaction version:** 4 (`RUNG_TX_VERSION`)
**Status:** Implemented — all 48 block types consensus-valid and policy-standard

---

## 1. Overview

Ladder Script is a structured, typed transaction verification system for Bitcoin Ghost. It replaces Bitcoin Script's stack-based opcode model with a declarative model of typed function blocks organized into rungs.

A version 4 transaction (`RUNG_TX`) uses Ladder Script for both locking (output conditions) and unlocking (input witness). The system provides:

- **Typed data fields** -- every byte in a Ladder Script witness belongs to a declared data type with enforced size constraints. No arbitrary data pushes are possible.
- **Function blocks** -- each block evaluates a single spending condition (signature check, timelock, hash preimage, covenant, etc.).
- **AND/OR composition** -- blocks within a rung are combined with AND logic; rungs within a ladder are combined with OR logic (first satisfied rung wins).
- **Inversion** -- any block can be inverted, flipping SATISFIED to UNSATISFIED and vice versa.
- **Coil metadata** -- per-output semantics (unlock, unlock-to-destination, covenant) with attestation mode and signature scheme selection.
- **Post-quantum readiness** -- native support for FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+-SHA2 via liboqs.

---

## 2. Data Model

### 2.1 LadderWitness

The top-level witness structure for one input.

```
struct LadderWitness {
    rungs:  Vec<Rung>     // Input condition rungs (OR logic -- first satisfied wins)
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

## 3. Wire Format (v2)

All multi-byte integers are little-endian. Variable-length counts use Bitcoin's `CompactSize` (varint) encoding.

```
[n_rungs: varint]                          // Number of rungs (>= 1, <= 16)
  FOR EACH rung:
    [n_blocks: varint]                     // Number of blocks (>= 1, <= 8)
    FOR EACH block:
      [block_type: uint16_t LE]            // RungBlockType enum value
      [inverted: uint8_t]                  // 0x00 = normal, 0x01 = inverted
      [n_fields: varint]                   // Number of fields (<= 16)
      FOR EACH field:
        [data_type: uint8_t]               // RungDataType enum value
        [data_len: varint]                 // Length of data payload
        [data: bytes]                      // Raw data payload

[coil_type: uint8_t]                       // RungCoilType
[attestation: uint8_t]                     // RungAttestationMode
[scheme: uint8_t]                          // RungScheme
[address_len: varint]                      // Length of destination address (0 = none)
[address: bytes]                           // Raw scriptPubKey bytes

[n_coil_conditions: varint]                // Number of coil condition rungs (0 = none)
  FOR EACH coil condition rung:
    [n_blocks: varint]
    FOR EACH block:
      [block_type: uint16_t LE]
      [inverted: uint8_t]
      [n_fields: varint]
      FOR EACH field:
        [data_type: uint8_t]
        [data_len: varint]
        [data: bytes]
```

Trailing bytes after the complete structure are rejected. The maximum total serialized size is 100,000 bytes (`MAX_LADDER_WITNESS_SIZE`).

---

## 4. Output Format (scriptPubKey)

A v4 output's `scriptPubKey` is constructed as:

```
[0xc1] [serialized RungConditions]
```

The prefix byte `0xc1` (`RUNG_CONDITIONS_PREFIX`) identifies the script as Ladder Script conditions. It was chosen to avoid conflict with any existing `OP_` prefix byte.

The serialized conditions use the same wire format as a `LadderWitness` (Section 3), but **only condition data types are permitted**. The witness-only types PUBKEY (`0x01`), SIGNATURE (`0x06`), and PREIMAGE (`0x05`) must not appear in conditions. Blocks that need to reference a public key use PUBKEY_COMMIT (the SHA-256 hash of the key) in conditions; the raw PUBKEY is revealed only in the witness at spend time. This separation ensures that locking conditions never contain secret material or user-chosen bytes.

Deserialization strips the `0xc1` prefix and decodes the remainder as a `LadderWitness`, then validates that no witness-only fields are present.

---

## 5. Data Types

Every field in a Ladder Script witness or condition must be one of the following typed values. Size constraints are enforced at deserialization time.

| Code | Name | Min Size | Max Size | Condition | Witness | Purpose |
|------|------|----------|----------|-----------|---------|---------|
| `0x01` | PUBKEY | 1 | 2048 | No | Yes | Public key (32-byte x-only, 33-byte compressed, or PQ). Witness-only. |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Yes | No | SHA256 commitment to a public key |
| `0x03` | HASH256 | 32 | 32 | Yes | Yes | SHA-256 hash digest |
| `0x04` | HASH160 | 20 | 20 | Yes | Yes | RIPEMD160(SHA256()) hash digest |
| `0x05` | PREIMAGE | 1 | 252 | No | Yes | Hash preimage (witness-only) |
| `0x06` | SIGNATURE | 1 | 50,000 | No | Yes | Signature bytes (witness-only) |
| `0x07` | SPEND_INDEX | 4 | 4 | Yes | Yes | Spend index reference (uint32 LE) |
| `0x08` | NUMERIC | 1 | 4 | Yes | Yes | Numeric value, unsigned LE (threshold, locktime, count, etc.) |
| `0x09` | SCHEME | 1 | 1 | Yes | Yes | Signature scheme selector byte |

**Validation rules:**

- PUBKEY fields of exactly 33 bytes must begin with `0x02` or `0x03` (compressed SEC1 format). Other sizes (32 for x-only, or PQ key sizes) skip this prefix check.
- SCHEME fields must contain a known scheme value (see Section 11).
- Size violations are rejected at deserialization time with a descriptive error.

---

## 6. Block Types

Block types are encoded as `uint16_t` little-endian. They are organized into ranges by family.

### 6.1 Signature Family (0x0001--0x00FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0001` | SIG | PUBKEY_COMMIT (condition), PUBKEY + SIGNATURE (witness) | SCHEME |
| `0x0002` | MULTISIG | NUMERIC (threshold M), N x PUBKEY_COMMIT (condition), N x PUBKEY + M x SIGNATURE (witness) | SCHEME |
| `0x0003` | ADAPTOR_SIG | 2 x PUBKEY_COMMIT (condition), 2 x PUBKEY + SIGNATURE (witness) | -- |

### 6.2 Timelock Family (0x0100--0x01FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0101` | CSV | NUMERIC (sequence value) | -- |
| `0x0102` | CSV_TIME | NUMERIC (sequence value) | -- |
| `0x0103` | CLTV | NUMERIC (locktime value) | -- |
| `0x0104` | CLTV_TIME | NUMERIC (locktime value) | -- |

### 6.3 Hash Family (0x0200--0x02FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0201` | HASH_PREIMAGE | HASH256, PREIMAGE | -- |
| `0x0202` | HASH160_PREIMAGE | HASH160, PREIMAGE | -- |
| `0x0203` | TAGGED_HASH | 2 x HASH256 (tag_hash, expected_hash), PREIMAGE | -- |

### 6.4 Covenant Family (0x0300--0x03FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0301` | CTV | HASH256 (template hash) | -- |
| `0x0302` | VAULT_LOCK | 2 x PUBKEY_COMMIT (condition), 2 x PUBKEY + SIGNATURE (witness), NUMERIC (hot_delay) | -- |
| `0x0303` | AMOUNT_LOCK | 2 x NUMERIC (min_sats, max_sats) | -- |

### 6.5 Anchor/L2 Family (0x0500--0x05FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0501` | ANCHOR | >= 1 typed field (any) | -- |
| `0x0502` | ANCHOR_CHANNEL | 2 x PUBKEY_COMMIT (local_key, remote_key) | NUMERIC (commitment_number) |
| `0x0503` | ANCHOR_POOL | HASH256 (vtxo_tree_root) | NUMERIC (participant_count) |
| `0x0504` | ANCHOR_RESERVE | 2 x NUMERIC (threshold_n, threshold_m), HASH256 (guardian_set_hash) | -- |
| `0x0505` | ANCHOR_SEAL | 2 x HASH256 (asset_id, state_transition) | -- |
| `0x0506` | ANCHOR_ORACLE | PUBKEY_COMMIT (oracle_key) | NUMERIC (outcome_count) |

### 6.6 Recursion Family (0x0400--0x04FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0401` | RECURSE_SAME | NUMERIC (max_depth) | -- |
| `0x0402` | RECURSE_MODIFIED | >= 4 x NUMERIC (see Section 7 for format) | -- |
| `0x0403` | RECURSE_UNTIL | NUMERIC (until_height) | -- |
| `0x0404` | RECURSE_COUNT | NUMERIC (count) | -- |
| `0x0405` | RECURSE_SPLIT | 2 x NUMERIC (max_splits, min_split_sats) | -- |
| `0x0406` | RECURSE_DECAY | >= 4 x NUMERIC (same format as RECURSE_MODIFIED) | -- |

### 6.7 PLC Family (0x0600--0x06FF)

| Code | Name | Required Fields | Optional Fields |
|------|------|----------------|-----------------|
| `0x0601` | HYSTERESIS_FEE | 2 x NUMERIC (high_sat_vb, low_sat_vb) | -- |
| `0x0602` | HYSTERESIS_VALUE | 2 x NUMERIC (high_sats, low_sats) | -- |
| `0x0611` | TIMER_CONTINUOUS | 2 x NUMERIC (accumulated, target) | -- |
| `0x0612` | TIMER_OFF_DELAY | NUMERIC (remaining) | -- |
| `0x0621` | LATCH_SET | PUBKEY_COMMIT (setter_key), NUMERIC (state) | -- |
| `0x0622` | LATCH_RESET | PUBKEY_COMMIT (resetter_key), 2 x NUMERIC (state, delay_blocks) | -- |
| `0x0631` | COUNTER_DOWN | PUBKEY_COMMIT (event_signer), NUMERIC (count) | -- |
| `0x0632` | COUNTER_PRESET | 2 x NUMERIC (current, preset) | -- |
| `0x0633` | COUNTER_UP | PUBKEY_COMMIT (event_signer), 2 x NUMERIC (current, target) | -- |
| `0x0641` | COMPARE | 2-3 x NUMERIC (operator, value_b [, value_c]) | -- |
| `0x0651` | SEQUENCER | 2 x NUMERIC (current_step, total_steps) | -- |
| `0x0661` | ONE_SHOT | NUMERIC (state), HASH256 (commitment) | -- |
| `0x0671` | RATE_LIMIT | 3 x NUMERIC (max_per_block, accumulation_cap, refill_blocks) | -- |
| `0x0681` | COSIGN | HASH256 (conditions_hash) | -- |

---

## 7. Evaluation Semantics

### 7.1 General Rules

- **Rung evaluation (AND):** All blocks in a rung must return SATISFIED. If any block returns UNSATISFIED, ERROR, or UNKNOWN_BLOCK_TYPE, the rung fails.
- **Ladder evaluation (OR):** The first rung that returns SATISFIED wins. If no rung is satisfied, the ladder fails.
- **Inversion:** Applied after block evaluation via `ApplyInversion()`. See Section 13.
- **Merge:** At verification time, conditions (from the spent output) and witness (from the spending input) are merged. Condition fields are placed first in each block, followed by witness fields. The inverted flag is taken from conditions.

### 7.2 SIG (0x0001)

**Condition fields:** PUBKEY_COMMIT (required)
**Witness fields:** PUBKEY, SIGNATURE (required)
**Optional fields:** SCHEME

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

**Condition fields:** NUMERIC (threshold M), N x PUBKEY_COMMIT
**Witness fields:** N x PUBKEY, M x SIGNATURE
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

**Required fields:** 2 x PUBKEY (signing_key at index 0, adaptor_point at index 1), SIGNATURE

**Evaluation:**

1. If fewer than 2 PUBKEYs or no SIGNATURE, return ERROR.
2. The adaptor_point must be exactly 32 bytes (x-only). If not, return ERROR.
3. The adapted signature (64--65 bytes) is verified against the signing_key using `CheckSchnorrSignature()`.
4. The adapted signature is a valid BIP-340 signature; the adaptor secret has already been incorporated.
5. Return SATISFIED on successful verification, UNSATISFIED otherwise.

### 7.5 CSV (0x0101)

**Required fields:** NUMERIC (sequence value)

**Evaluation:**

1. Read the sequence value. If negative, return ERROR.
2. If the disable flag (`SEQUENCE_LOCKTIME_DISABLE_FLAG`) is set, return SATISFIED unconditionally.
3. Call `CheckSequence(nSequence)`. Return SATISFIED if it passes, UNSATISFIED otherwise.

**Context:** Uses `BaseSignatureChecker::CheckSequence()`, which compares against the input's `nSequence` field per BIP-68 block-height-based relative timelocks.

### 7.6 CSV_TIME (0x0102)

Identical logic to CSV. The distinction is semantic: the NUMERIC value should encode a time-based relative lock (BIP-68 with the type flag set). `CheckSequence()` handles both interpretations.

### 7.7 CLTV (0x0103)

**Required fields:** NUMERIC (locktime value)

**Evaluation:**

1. Read the locktime value. If negative, return ERROR.
2. Call `CheckLockTime(nLockTime)`. Return SATISFIED if it passes, UNSATISFIED otherwise.

**Context:** Uses `BaseSignatureChecker::CheckLockTime()`, which compares against `tx.nLockTime` per BIP-65 absolute block-height timelocks.

### 7.8 CLTV_TIME (0x0104)

Identical logic to CLTV. The distinction is semantic: the NUMERIC value should encode a median-time-past threshold.

### 7.9 HASH_PREIMAGE (0x0201)

**Required fields:** HASH256, PREIMAGE

**Evaluation:**

1. If PREIMAGE is missing, return ERROR.
2. If HASH256 is missing, return ERROR.
3. Compute `SHA256(PREIMAGE.data)` and compare to `HASH256.data`.
4. Return SATISFIED on match, UNSATISFIED otherwise.

### 7.10 HASH160_PREIMAGE (0x0202)

**Required fields:** HASH160, PREIMAGE

**Evaluation:**

1. If PREIMAGE is missing, return ERROR.
2. If HASH160 is missing, return ERROR.
3. Compute `RIPEMD160(SHA256(PREIMAGE.data))` and compare to `HASH160.data`.
4. Return SATISFIED on match, UNSATISFIED otherwise.

### 7.11 TAGGED_HASH (0x0203)

**Required fields:** 2 x HASH256 (tag_hash at index 0, expected_hash at index 1), PREIMAGE

**Evaluation:**

1. If fewer than 2 HASH256 fields or no PREIMAGE, return ERROR.
2. Both HASH256 fields must be exactly 32 bytes.
3. Compute `SHA256(tag_hash || tag_hash || PREIMAGE.data)`. Note: the tag_hash field IS `SHA256(tag)` already, so this produces the BIP-340 tagged hash.
4. Compare the result to expected_hash. Return SATISFIED on match.

### 7.12 CTV (0x0301)

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

### 7.13 VAULT_LOCK (0x0302)

**Condition fields:** 2 x PUBKEY_COMMIT (recovery_key, hot_key), NUMERIC (hot_delay)
**Witness fields:** 2 x PUBKEY, SIGNATURE

**Evaluation (two-path):**

1. If fewer than 2 PUBKEYs, no SIGNATURE, or no NUMERIC, return ERROR.
2. Read the hot_delay value. If negative, return ERROR.
3. **Recovery path:** Verify the signature against recovery_key (Schnorr). If valid, return SATISFIED immediately (cold sweep, no delay).
4. **Hot path:** Verify the signature against hot_key (Schnorr). If valid, call `CheckSequence(hot_delay)`. If the delay is met, return SATISFIED. If the delay is not met, return UNSATISFIED.
5. If neither key matches, return UNSATISFIED.

### 7.14 AMOUNT_LOCK (0x0303)

**Required fields:** 2 x NUMERIC (min_sats at index 0, max_sats at index 1)
**Context requirements:** `RungEvalContext.output_amount`

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. Read min_sats and max_sats. If either is negative, return ERROR.
3. If `min_sats <= output_amount <= max_sats`, return SATISFIED.
4. Otherwise, return UNSATISFIED.

### 7.15 ANCHOR (0x0501)

**Required fields:** At least one typed field of any type.

**Evaluation:**

1. If the block has no fields, return ERROR.
2. Return SATISFIED. (Generic anchor -- structural validation only.)

### 7.16 ANCHOR_CHANNEL (0x0502)

**Required fields:** 2 x PUBKEY_COMMIT (local_key, remote_key)
**Optional fields:** NUMERIC (commitment_number)

**Evaluation:**

1. If fewer than 2 PUBKEY_COMMITs, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.17 ANCHOR_POOL (0x0503)

**Required fields:** HASH256 (vtxo_tree_root)
**Optional fields:** NUMERIC (participant_count)

**Evaluation:**

1. If no HASH256, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.18 ANCHOR_RESERVE (0x0504)

**Required fields:** 2 x NUMERIC (threshold_n, threshold_m), HASH256 (guardian_set_hash)

**Evaluation:**

1. If fewer than 2 NUMERICs or no HASH256, return ERROR.
2. Read threshold_n and threshold_m. If either is negative or threshold_n > threshold_m, return UNSATISFIED.
3. Return SATISFIED.

### 7.19 ANCHOR_SEAL (0x0505)

**Required fields:** 2 x HASH256 (asset_id, state_transition)

**Evaluation:**

1. If fewer than 2 HASH256 fields, return ERROR.
2. Return SATISFIED.

### 7.20 ANCHOR_ORACLE (0x0506)

**Required fields:** PUBKEY_COMMIT (oracle_key)
**Optional fields:** NUMERIC (outcome_count)

**Evaluation:**

1. If no PUBKEY_COMMIT, return ERROR.
2. If NUMERIC is present and its value is <= 0, return UNSATISFIED.
3. Return SATISFIED.

### 7.21 RECURSE_SAME (0x0401)

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

### 7.22 RECURSE_MODIFIED (0x0402)

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

### 7.23 RECURSE_UNTIL (0x0403)

**Required fields:** NUMERIC (until_height)
**Context requirements:** `RungEvalContext.block_height`, `RungEvalContext.tx`, `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

1. Read until_height. If negative, return ERROR.
2. Compute the effective height as `max(block_height, tx.nLockTime)` (only if nLockTime < `LOCKTIME_THRESHOLD`, i.e., it represents a block height).
3. If effective_height >= until_height, return SATISFIED (covenant terminates).
4. Otherwise (before termination): verify the spending output carries identical conditions to the input. Return UNSATISFIED if conditions do not match.

### 7.24 RECURSE_COUNT (0x0404)

**Required fields:** NUMERIC (count)
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

1. Read count. If negative, return ERROR.
2. If count == 0, return SATISFIED (countdown complete -- covenant terminates).
3. If count > 0: verify the spending output contains a RECURSE_COUNT block with count == (input count - 1).
4. Return UNSATISFIED if the decremented count is not found.

### 7.25 RECURSE_SPLIT (0x0405)

**Required fields:** 2 x NUMERIC (max_splits, min_split_sats)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.input_conditions`, `RungEvalContext.input_amount`

**Evaluation:**

1. Read max_splits and min_split_sats. If max_splits <= 0 or min_split_sats < 0, return UNSATISFIED.
2. For each output in the transaction:
   - Verify `output.nValue >= min_split_sats`.
   - Deserialize the output conditions and verify any RECURSE_SPLIT block has `max_splits - 1`.
3. Verify value conservation: `sum(output values) <= input_amount`.
4. If output_amount > 0 but < min_split_sats (no full context), return UNSATISFIED.

### 7.26 RECURSE_DECAY (0x0406)

**Required fields:** >= 4 x NUMERIC (same format as RECURSE_MODIFIED)
**Context requirements:** `RungEvalContext.input_conditions`, `RungEvalContext.spending_output`

**Evaluation:**

Uses the same mutation parsing and verification as RECURSE_MODIFIED, but **negates all deltas**. This means the output value is `input_value - delta`, implementing a decaying parameter.

### 7.27 HYSTERESIS_FEE (0x0601)

**Required fields:** 2 x NUMERIC (high_sat_vb at index 0, low_sat_vb at index 1)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.spent_outputs`

**Evaluation:**

1. Read high and low bounds. If either is negative or low > high, return UNSATISFIED.
2. If no transaction context, return SATISFIED (structural-only mode).
3. Compute fee: `sum(spent output values) - sum(tx output values)`. If fee < 0, return UNSATISFIED.
4. Compute fee_rate: `fee / GetVirtualTransactionSize(tx)`. If vsize <= 0, return ERROR.
5. If `low <= fee_rate <= high`, return SATISFIED.

### 7.28 HYSTERESIS_VALUE (0x0602)

**Required fields:** 2 x NUMERIC (high_sats at index 0, low_sats at index 1)
**Context requirements:** `RungEvalContext.input_amount`

**Evaluation:**

1. Read high and low bounds. If either is negative or low > high, return UNSATISFIED.
2. If `low <= input_amount <= high`, return SATISFIED.

### 7.29 TIMER_CONTINUOUS (0x0611)

**Required fields:** 2 x NUMERIC (accumulated at index 0, target at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs: single-field backward compatibility (treat as target, satisfied if > 0).
2. If either value is negative, return ERROR.
3. If `accumulated >= target`, return SATISFIED (timer elapsed).
4. Otherwise, return UNSATISFIED. (Pair with RECURSE_MODIFIED to increment accumulated each covenant spend.)

### 7.30 TIMER_OFF_DELAY (0x0612)

**Required fields:** NUMERIC (remaining)

**Evaluation:**

1. Read remaining. If negative, return ERROR.
2. If `remaining > 0`, return SATISFIED (still in hold-off period).
3. If `remaining == 0`, return UNSATISFIED (delay expired).
4. Pair with RECURSE_MODIFIED to decrement remaining each covenant spend.

### 7.31 LATCH_SET (0x0621)

**Required fields:** PUBKEY_COMMIT (setter_key)
**Optional fields:** NUMERIC (state)

**Evaluation:**

1. If no PUBKEY_COMMIT, return ERROR.
2. If no NUMERIC (backward compat), return SATISFIED.
3. If `state == 0` (unset), return SATISFIED (the latch can be set).
4. If `state != 0` (already set), return UNSATISFIED.
5. Pair with RECURSE_MODIFIED to enforce state transition 0 -> 1 in the output.

### 7.32 LATCH_RESET (0x0622)

**Required fields:** PUBKEY_COMMIT (resetter_key), 2 x NUMERIC (state, delay_blocks)

**Evaluation:**

1. If no PUBKEY_COMMIT, return ERROR. If fewer than 2 NUMERICs, return ERROR.
2. Read state and delay. If delay < 0, return ERROR.
3. If `state >= 1` (set), return SATISFIED (the latch can be reset).
4. If `state == 0` (already unset), return UNSATISFIED.
5. Pair with RECURSE_MODIFIED to enforce state transition 1 -> 0 in the output.

### 7.33 COUNTER_DOWN (0x0631)

**Required fields:** PUBKEY_COMMIT (event_signer), NUMERIC (count)

**Evaluation:**

1. If no PUBKEY_COMMIT, return ERROR. If no NUMERIC, return ERROR.
2. Read count. If negative, return ERROR.
3. If `count > 0`, return SATISFIED (can still decrement).
4. If `count == 0`, return UNSATISFIED (countdown done).
5. Pair with RECURSE_MODIFIED to decrement each spend.

### 7.34 COUNTER_PRESET (0x0632)

**Required fields:** 2 x NUMERIC (current at index 0, preset at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. If either is negative, return ERROR.
3. If `current < preset`, return SATISFIED (still accumulating).
4. If `current >= preset`, return UNSATISFIED (threshold reached).

### 7.35 COUNTER_UP (0x0633)

**Required fields:** PUBKEY_COMMIT (event_signer), 2 x NUMERIC (current at index 0, target at index 1)

**Evaluation:**

1. If no PUBKEY_COMMIT, return ERROR. If fewer than 2 NUMERICs, return ERROR.
2. If either is negative, return ERROR.
3. If `current < target`, return SATISFIED (still counting).
4. If `current >= target`, return UNSATISFIED (target reached).

### 7.36 COMPARE (0x0641)

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

### 7.37 SEQUENCER (0x0651)

**Required fields:** 2 x NUMERIC (current_step at index 0, total_steps at index 1)

**Evaluation:**

1. If fewer than 2 NUMERICs, return ERROR.
2. Read current and total. If current < 0, total <= 0, or current >= total, return UNSATISFIED.
3. If `0 <= current < total`, return SATISFIED.

### 7.38 ONE_SHOT (0x0661)

**Required fields:** NUMERIC (state), HASH256 (commitment)

**Evaluation:**

1. If no NUMERIC, return ERROR. If no HASH256, return ERROR.
2. If `state == 0`, return SATISFIED (can fire).
3. If `state != 0`, return UNSATISFIED (already fired).

### 7.39 RATE_LIMIT (0x0671)

**Required fields:** 3 x NUMERIC (max_per_block, accumulation_cap, refill_blocks)
**Context requirements:** `RungEvalContext.output_amount`

**Evaluation:**

1. If fewer than 3 NUMERICs, return ERROR.
2. Read max_per_block. If negative, return ERROR.
3. If `output_amount > max_per_block`, return UNSATISFIED.
4. Return SATISFIED. (Full accumulation tracking requires UTXO chain state beyond single-transaction evaluation.)

### 7.40 COSIGN (0x0681)

**Required fields:** HASH256 (conditions_hash -- SHA256 of the required co-spent scriptPubKey)
**Context requirements:** `RungEvalContext.tx`, `RungEvalContext.spent_outputs`, `RungEvalContext.input_index`

**Evaluation:**

1. If no HASH256 or its size is not 32 bytes, return ERROR.
2. If no transaction context or spent outputs, return SATISFIED (structural-only mode).
3. For each other input (excluding self):
   - Compute `SHA256(spent_outputs[i].scriptPubKey)`.
   - If it matches the conditions_hash, return SATISFIED.
4. If no match found, return UNSATISFIED.

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
| conditions_hash | SHA256 of serialized conditions | Always |

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

The conditions_hash is `SHA256(serialized_conditions)` where `serialized_conditions` is the wire format (Section 3) of the rung conditions from the spent output (rungs only, without the `0xc1` prefix).

### 8.5 Differences from BIP-341

- Uses tagged hash `"LadderSighash"` instead of `"TapSighash"`.
- `spend_type` is always 0 (no annex, no tapscript extensions, no code separator).
- Commits to `conditions_hash` instead of `tapleaf_hash` / `key_version`.
- No `ext_flag`, no `annex_hash`.

### 8.6 Precomputed Data

The `PrecomputedTransactionData` structure has a `m_ladder_ready` flag. When a v4 transaction is initialized, the following hashes are precomputed:

- `m_prevouts_single_hash` -- SHA256 of all prevouts
- `m_spent_amounts_single_hash` -- SHA256 of all spent amounts
- `m_sequences_single_hash` -- SHA256 of all sequences
- `m_outputs_single_hash` -- SHA256 of all outputs

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
| `0x13` | SPHINCS_SHA | 64 bytes | 49,216 bytes | liboqs (`OQS_SIG_alg_sphincs_sha2_256f_simple`) |

Post-quantum schemes (codes >= `0x10`) are identified by `IsPQScheme()`. PQ support requires the build to be compiled with liboqs (`HAVE_LIBOQS`). `HasPQSupport()` returns whether the runtime has PQ verification capability. Without liboqs, all PQ verification returns false.

**PUBKEY_COMMIT for all keys:** Conditions use `PUBKEY_COMMIT = SHA256(pubkey)` (32 bytes) instead of raw PUBKEY. The full public key is revealed only in the spending witness and verified against the commitment. This eliminates user-chosen bytes from conditions (anti-spam) and is especially beneficial for PQ keys (897--1952 bytes reduced to 32 bytes). The `createrungtx` RPC auto-hashes any provided pubkey hex into PUBKEY_COMMIT when building conditions.

---

## 12. Policy Limits

| Limit | Value | Scope |
|-------|-------|-------|
| Maximum rungs per ladder | 16 (`MAX_RUNGS`) | Policy and deserialization |
| Maximum blocks per rung | 8 (`MAX_BLOCKS_PER_RUNG`) | Policy and deserialization |
| Maximum fields per block | 16 (`MAX_FIELDS_PER_BLOCK`) | Deserialization |
| Maximum ladder witness size | 100,000 bytes (`MAX_LADDER_WITNESS_SIZE`) | Deserialization |
| Maximum coil address size | 520 bytes | Deserialization |
| Maximum coil condition rungs | 16 (`MAX_RUNGS`) | Deserialization |
| Maximum PREIMAGE size | 252 bytes | Data type constraint |
| Maximum SIGNATURE size | 50,000 bytes | Data type constraint |
| Maximum preimage blocks per witness | 2 (`MAX_PREIMAGE_BLOCKS_PER_WITNESS`) | Policy |
| Maximum PUBKEY size | 2,048 bytes | Data type constraint |

---

## 13. Inversion Semantics

Any block can be inverted by setting its `inverted` flag to `0x01`. Inversion is applied after the block's raw evaluation:

| Raw Result | Inverted Result |
|------------|-----------------|
| SATISFIED | UNSATISFIED |
| UNSATISFIED | SATISFIED |
| ERROR | ERROR (unchanged) |
| UNKNOWN_BLOCK_TYPE | SATISFIED |

The UNKNOWN_BLOCK_TYPE -> SATISFIED rule for inverted blocks supports forward compatibility: an unknown block type that is inverted is treated as satisfied, allowing older nodes to accept transactions using newer block types in negated position.

---

## 14. RPC Interface

All Ladder Script RPCs are registered under the `"rung"` category.

### 14.1 decoderung

```
decoderung "hex"
```

Decode a serialized ladder witness from hex and return its typed structure as JSON. Includes rung/block/field breakdown with type names, hex data, sizes, coil metadata, and coil conditions.

### 14.2 createrung

```
createrung [{"blocks": [{"type": "SIG", "inverted": false, "fields": [{"type": "PUBKEY", "hex": "03..."}]}]}]
```

Create a serialized ladder witness from a JSON specification. Returns the serialized ladder witness as hex. Accepts an array of rungs, each containing an array of blocks with typed fields.

### 14.3 createrungtx

```
createrungtx [{"txid": "...", "vout": 0}] [{"amount": 0.001, "conditions": [...]}]
```

Create an unsigned v4 RUNG_TX transaction with rung condition outputs. Inputs are outpoints to spend. Outputs specify rung conditions (using the same JSON block/field format) and amounts. Returns the raw transaction hex. When building conditions, PUBKEY fields are automatically hashed to PUBKEY_COMMIT (SHA-256) -- users provide pubkey hex as before and the RPC performs the conversion.

### 14.4 signrungtx

```
signrungtx "txhex" [{"privkey": "cVt...", "input": 0}] [{"amount": 0.001, "scriptPubKey": "c1..."}]
```

Sign a v4 RUNG_TX transaction's inputs. Takes the raw transaction hex, an array of signing keys mapped to input indices, and an array of spent outputs (for sighash computation). Returns the signed transaction hex.

### 14.5 validateladder

```
validateladder "txhex"
```

Validate a raw v4 RUNG_TX transaction's ladder witnesses. Checks that all input witnesses are valid ladder witnesses with correct structure, known block types, and valid field sizes. Returns validation results per input.

### 14.6 computectvhash

```
computectvhash "txhex" input_index
```

Compute the BIP-119 CTV template hash for a v4 RUNG_TX transaction at the specified input index. Returns the 32-byte hash as hex.

### 14.7 generatepqkeypair

```
generatepqkeypair "scheme"
```

Generate a post-quantum keypair for the specified scheme (FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA). Requires liboqs support. Returns the public key and private key as hex.

### 14.8 pqpubkeycommit

```
pqpubkeycommit "pubkey_hex"
```

Compute the SHA256 commitment hash of a post-quantum public key. Use this to create PUBKEY_COMMIT condition fields for compact UTXO storage. Returns the 32-byte commitment as hex.

### 14.9 extractadaptorsecret

```
extractadaptorsecret "pre_sig_hex" "adapted_sig_hex"
```

Extract the adaptor secret from a pre-signature and adapted signature. Computes `t = s_adapted - s_pre (mod n)`. Both signatures must be 64 bytes. Returns the 32-byte secret as hex.

### 14.10 verifyadaptorpresig

```
verifyadaptorpresig "pubkey" "adaptor_point" "pre_sig" "sighash"
```

Verify an adaptor pre-signature. Checks that `s'*G == R + e*P` where `e = H(R+T || P || m)`. All parameters are 32-byte hex values (pubkey and adaptor_point are x-only), except pre_sig which is 64 bytes. Returns `{"valid": true/false}`.

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

0x0701  TIMELOCKED_SIG      0x0801  EPOCH_GATE
0x0702  HTLC                0x0802  WEIGHT_LIMIT
0x0703  HASH_SIG            0x0803  INPUT_COUNT
                            0x0804  OUTPUT_COUNT
                            0x0805  RELATIVE_VALUE
                            0x0806  ACCUMULATOR
```
