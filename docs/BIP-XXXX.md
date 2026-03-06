```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script -- Typed Structured Transaction Conditions
Author: Bitcoin Ghost
Status: Draft
Type: Standards Track
Created: 2026-03-06
```

## Abstract

Ladder Script introduces transaction version 3 (`RUNG_TX`) with typed, structured spending conditions that replace opcode-based Script for participating outputs. Conditions are organized as named function blocks within rungs, evaluated with AND-within-rung, OR-across-rungs, first-match semantics. Every byte in a Ladder Script witness belongs to a declared data type; no arbitrary data pushes are possible. The system supports three deployment phases: Phase 1 (signatures, timelocks, hashes), Phase 2 (covenants, anchors), and Phase 3 (recursion, programmable logic controllers).

## Motivation

Bitcoin Script was designed as a minimal stack-based language for expressing spending conditions. Over two decades of use, several limitations have become apparent:

**Opcode ambiguity.** Script opcodes operate on untyped stack elements. A 32-byte push could be a public key, a hash, a preimage, or arbitrary data. This ambiguity complicates static analysis, makes policy enforcement unreliable, and creates opportunities for data smuggling through witness fields.

**Compositional complexity.** Expressing compound conditions (e.g., "2-of-3 multisig AND CSV timelock, OR single-sig after CLTV") requires careful stack manipulation that is error-prone and difficult to audit. The resulting scripts are opaque to non-expert reviewers.

**Limited introspection.** Bitcoin Script cannot inspect the transaction that spends it beyond basic signature verification and timelock checks. Covenants, recursive conditions, and stateful logic require proposals (CTV, APO, VAULT) that each add individual opcodes without a unifying framework.

**Forward compatibility.** Adding new spending condition types to Script requires new opcodes, each consuming from a finite opcode space and requiring individual soft fork activation. There is no mechanism for structured extensibility.

**Post-quantum readiness.** Post-quantum signature schemes produce signatures and public keys significantly larger than ECDSA or Schnorr. Script's 520-byte push limit and 10,000-byte script limit are insufficient for FALCON-1024 (1793-byte keys) or SPHINCS+ (49,216-byte signatures).

Ladder Script addresses these limitations by replacing opcode sequences with a typed, structured format where every field has a declared type with enforced size constraints, conditions compose through explicit AND/OR rung logic, and new block types can be added to numbered families without consuming opcode space.

## Specification

### Transaction Format

A Ladder Script transaction is identified by `nVersion = 3` (constant `CTransaction::RUNG_TX_VERSION`). When a node encounters a version 3 transaction spending an output whose `scriptPubKey` begins with the byte `0xc1`, it invokes the ladder evaluator instead of the Script interpreter.

**Output (locking side):**

The `scriptPubKey` of a ladder-locked output is:

```
0xc1 || SerializedRungConditions
```

The prefix byte `0xc1` was chosen to avoid collision with all existing `OP_` prefixes and witness version programs. The payload is a serialized `RungConditions` structure containing only condition data types (PUBKEY, PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX). The witness-only types SIGNATURE and PREIMAGE are forbidden in conditions.

**Input (unlocking side):**

The first element of the segregated witness stack for each v3 input is a serialized `LadderWitness`. This structure contains the same rung/block layout as the conditions but additionally includes SIGNATURE and PREIMAGE fields that satisfy the locking conditions.

**Evaluation entry point:**

The function `VerifyRungTx` is called for each input of a v3 transaction. It deserializes both the conditions (from the spent output's `scriptPubKey`) and the witness (from the spending input), then evaluates the ladder.

### Wire Format (v2)

All multi-byte integers are encoded as Bitcoin compact-size varints unless otherwise noted. Block types are encoded as `uint16_t` little-endian. Single-byte enumerations are encoded as `uint8_t`.

```
LADDER WITNESS / RUNG CONDITIONS:

[n_rungs: varint]                         -- number of rungs (1..MAX_RUNGS)
  for each rung:
    [n_blocks: varint]                    -- number of blocks in this rung (1..MAX_BLOCKS_PER_RUNG)
      for each block:
        [block_type: uint16_t LE]         -- RungBlockType enum value
        [inverted: uint8_t]               -- 0x00 = normal, 0x01 = inverted
        [n_fields: varint]                -- number of typed fields (0..MAX_FIELDS_PER_BLOCK)
          for each field:
            [data_type: uint8_t]          -- RungDataType enum value
            [data_len: varint]            -- length of data payload
            [data: bytes]                 -- typed data (validated against type constraints)
[coil_type: uint8_t]                      -- RungCoilType enum
[attestation: uint8_t]                    -- RungAttestationMode enum
[scheme: uint8_t]                         -- RungScheme enum
[address_len: varint]                     -- length of destination address (0 = none)
[address: bytes]                          -- raw scriptPubKey bytes
[n_coil_conditions: varint]               -- number of coil condition rungs (0 = none)
  for each coil condition rung:
    [n_blocks: varint]
      for each block:                     -- same format as input blocks
        [block_type: uint16_t LE]
        [inverted: uint8_t]
        [n_fields: varint]
          for each field:
            [data_type: uint8_t]
            [data_len: varint]
            [data: bytes]
```

Deserialization performs full type and size validation. Any malformed data causes immediate rejection. Trailing bytes after the coil section cause rejection.

### Data Types

Every field in a Ladder Script witness or conditions structure has one of the following types. The type constrains the allowed data size, preventing abuse of witness space.

| Code | Name | Min Size | Max Size | Context | Description |
|------|------|----------|----------|---------|-------------|
| `0x01` | PUBKEY | 1 | 2,048 | Both | Public key (compressed 33B, x-only 32B, or post-quantum up to 1,793B) |
| `0x02` | PUBKEY_COMMIT | 32 | 32 | Both | SHA-256 commitment to a public key (for commit-reveal PQ migration) |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 hash digest |
| `0x04` | HASH160 | 20 | 20 | Both | RIPEMD160(SHA256()) hash digest |
| `0x05` | PREIMAGE | 1 | 252 | Witness only | Hash preimage (forbidden in conditions) |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness only | Signature (Schnorr 64-65B, ECDSA 8-72B, PQ up to 49,216B) |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Index reference (uint32 LE) for aggregate attestation |
| `0x08` | NUMERIC | 1 | 4 | Both | Unsigned 32-bit integer (LE) for thresholds, timelocks, counters |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector byte |

The SIGNATURE maximum of 50,000 bytes accommodates SPHINCS+-SHA2-256f signatures (49,216 bytes). The PUBKEY maximum of 2,048 bytes accommodates FALCON-1024 public keys (1,793 bytes).

Data type validity is checked by `IsKnownDataType()`. Unknown data type codes cause deserialization failure.

### Block Types

Block types are organized into numbered families corresponding to deployment phases. Each block type evaluates a single spending condition. The block type is encoded as a `uint16_t` (little-endian) on the wire.

#### Phase 1 -- Signature, Timelock, and Hash (0x0001-0x02FF)

These block types cover the fundamental spending conditions equivalent to existing Script capabilities.

**Signature Family (0x0001-0x00FF):**

| Code | Name | Required Fields | Description |
|------|------|----------------|-------------|
| `0x0001` | SIG | PUBKEY + SIGNATURE | Single signature verification. Supports Schnorr (BIP-340), ECDSA, and post-quantum schemes via SCHEME field. If a PUBKEY_COMMIT field is present, the PUBKEY must hash to it (commit-reveal). |
| `0x0002` | MULTISIG | NUMERIC(threshold) + N*(PUBKEY + SIGNATURE) | M-of-N threshold signature. First NUMERIC field is the threshold M. Exactly M valid signatures required from the N provided public keys. |
| `0x0003` | ADAPTOR_SIG | PUBKEY(signer) + PUBKEY(adaptor point) + SIGNATURE | Adaptor signature verification. The second PUBKEY is the adaptor point T. Verification checks that the signature is valid under the combined challenge H(R+T \|\| P \|\| m). Enables atomic swaps and payment channel protocols. |

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

#### Phase 2 -- Covenant and Anchor (0x0300-0x05FF)

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

#### Phase 3 -- Recursion and Programmable Logic Controllers (0x0400-0x06FF)

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
| `0x0681` | COSIGN | HASH256(conditions_hash) | Co-spend contact. SATISFIED when another input in the same transaction has rung conditions whose serialized hash matches conditions_hash. The evaluator skips the current input index when scanning. |

### Coil Types

The coil determines the output semantics of a ladder-locked UTXO. It is serialized after the rung data.

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
| `0x13` | SPHINCS_SHA | 64 B | 49,216 B | SPHINCS+-SHA2-256f post-quantum hash-based signatures. |

Post-quantum schemes (codes >= `0x10`) require liboqs support compiled into the node. Verification against a PQ scheme without liboqs support returns false.

The PUBKEY_COMMIT mechanism enables commit-reveal PQ migration: a conditions output commits to the SHA-256 hash of a PQ public key (32 bytes), while the witness reveals the full public key for verification. This prevents quantum adversaries from extracting keys from the conditions script before the spend occurs.

### Evaluation Rules

Ladder evaluation follows a strict three-level logic:

**Level 1 -- Ladder (OR):** Rungs are evaluated in order. The first rung that returns SATISFIED terminates evaluation with success. If all rungs return UNSATISFIED, the ladder fails. If any rung returns ERROR, the entire transaction is invalid (consensus failure).

**Level 2 -- Rung (AND):** All blocks within a rung must return SATISFIED for the rung to be SATISFIED. Evaluation short-circuits on the first UNSATISFIED or ERROR result.

**Level 3 -- Block Inversion:** Each block has an `inverted` flag. When set:
- SATISFIED becomes UNSATISFIED
- UNSATISFIED becomes SATISFIED
- ERROR remains ERROR (never inverted)
- UNKNOWN_BLOCK_TYPE becomes SATISFIED when inverted

**Unknown block types:** An unrecognized `block_type` value returns UNKNOWN_BLOCK_TYPE, which is treated as UNSATISFIED in normal evaluation and SATISFIED when inverted. This enables forward-compatible soft forks: a new block type can be deployed as "must fail unless the new rule is active," and upgraded nodes evaluate the actual condition.

### Sighash

Ladder Script uses a tagged hash `TaggedHash("LadderSighash")` for signature computation. The algorithm is derived from BIP-341 sighash but simplified (no annex, no tapscript extensions, no code separator).

**Sighash computation commits to:**

```
epoch              = 0x00 (uint8)
hash_type          = uint8 (SIGHASH_DEFAULT=0, ALL=1, NONE=2, SINGLE=3, ANYONECANPAY=0x80)
tx_version         = int32
tx_locktime        = uint32

-- Unless ANYONECANPAY:
prevouts_hash      = SHA256(all input prevouts)
amounts_hash       = SHA256(all spent output amounts)
sequences_hash     = SHA256(all input sequences)

-- If SIGHASH_ALL (or DEFAULT):
outputs_hash       = SHA256(all outputs)

spend_type         = 0x00 (uint8, always 0 for ladder)

-- Input-specific:
  If ANYONECANPAY: prevout + spent_output + sequence
  Else: input_index (uint32)

-- If SIGHASH_SINGLE:
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
| MAX_LADDER_WITNESS_SIZE | 100,000 bytes | Maximum total serialized witness size. Accommodates PQ signatures (SPHINCS+ at 49,216 bytes). |

Policy additionally restricts:
- Only Phase 1 block types are standard. Phase 2 and Phase 3 block types are consensus-valid but policy-non-standard, requiring miner cooperation to confirm.
- All data types must be known (`IsKnownDataType` returns true).
- All field sizes must conform to type constraints (`FieldMinSize` through `FieldMaxSize`).
- Conditions scripts must not contain SIGNATURE or PREIMAGE fields.

### RPC Interface

The following RPCs are provided for wallet and application integration:

- `createrung` -- Create a rung conditions structure from a JSON description of blocks and fields.
- `decoderung` -- Decode a hex-encoded rung conditions structure to human-readable JSON.
- `validateladder` -- Validate a raw v3 RUNG_TX transaction's ladder witnesses against its spent outputs.
- `createrungtx` -- Create an unsigned v3 RUNG_TX transaction with rung condition outputs.
- `signrungtx` -- Sign a v3 RUNG_TX transaction's inputs given private keys and spent output information.
- `computectvhash` -- Compute the BIP-119 CTV template hash for a v3 RUNG_TX transaction at a given input index.
- `pqkeygen` -- Generate a post-quantum keypair for a specified scheme.
- `pqpubkeycommit` -- Compute the SHA-256 PUBKEY_COMMIT for a given public key.
- `extractadaptorsecret` -- Extract the adaptor secret from a pre-signature and adapted signature pair.

## Rationale

**Typed fields over opcodes.** By requiring every byte of witness data to belong to a declared type with enforced size constraints, Ladder Script eliminates the data smuggling vector inherent in arbitrary `OP_PUSH` operations. Static analysis tools can parse any ladder witness without executing it.

**Rung/block composition.** The AND-within-rung, OR-across-rungs model maps directly to how spending conditions are naturally expressed: "condition A AND condition B, OR alternatively condition C." This is more readable than equivalent stack manipulation in Script.

**Block type families.** Organizing block types into numbered ranges (0x0001-0x00FF for signatures, 0x0100-0x01FF for timelocks, etc.) allows new conditions to be added within families without exhausting a flat namespace. The `uint16_t` encoding provides 65,536 possible types.

**Inversion.** The `inverted` flag on blocks provides NOT logic without a separate opcode. Combined with AND/OR rung semantics, this yields full boolean expressiveness. The rule that ERROR is never inverted prevents masking of consensus failures.

**Forward compatibility via unknown types.** Unknown block types return UNSATISFIED rather than ERROR. This means a rung containing a future block type simply fails to match, and evaluation falls through to subsequent rungs. Combined with inversion (where an unknown inverted block becomes SATISFIED), this enables soft fork deployment of new block types without breaking existing transaction validation.

**Post-quantum signature support.** The PUBKEY maximum of 2,048 bytes and SIGNATURE maximum of 50,000 bytes were chosen to accommodate all NIST post-quantum finalist schemes. The PUBKEY_COMMIT mechanism enables a commit-reveal migration path: users can lock funds to a 32-byte hash of their PQ public key today, revealing the full key only at spend time.

**Coil separation.** Separating input conditions (rungs) from output semantics (coil) provides a clean interface between "who can spend" and "where it can go." This makes covenant logic (UNLOCK_TO, COVENANT coil types) orthogonal to signature and timelock logic.

**PLC block types.** The Programmable Logic Controller family (hysteresis, timers, latches, counters, comparators, sequencers) is borrowed from industrial automation where these primitives have decades of proven reliability. They enable stateful transaction logic (e.g., rate-limited withdrawals, multi-step approval processes, time-delayed state machines) without requiring a general-purpose virtual machine.

**Conditions hash in sighash.** Including the SHA-256 hash of the serialized locking conditions in the sighash computation prevents signature reuse across different ladder outputs that happen to use the same key. This is analogous to BIP-341's tapleaf hash commitment.

**Policy vs. consensus limits.** MAX_RUNGS, MAX_BLOCKS_PER_RUNG, and MAX_FIELDS_PER_BLOCK are enforced at both policy and consensus layers. The MAX_LADDER_WITNESS_SIZE limit at 100,000 bytes is necessary to accommodate post-quantum signatures while preventing witness bloat attacks.

## Backward Compatibility

**Non-upgraded nodes.** Transaction version 3 is currently non-standard in Bitcoin Core. No existing software creates v3 transactions. Non-upgraded nodes treat v3 transactions as anyone-can-spend, which is the standard soft fork upgrade path established by BIP-141 (Segregated Witness) and BIP-341 (Taproot).

**Existing transactions.** Ladder Script does not modify the validation rules for transaction versions 1 or 2. All existing UTXOs, scripts, and spending paths remain valid and unchanged.

**Wallet compatibility.** Wallets that do not implement Ladder Script can still:
- Receive funds to ladder-locked outputs (they appear as non-standard scriptPubKey types).
- Track ladder-locked UTXOs in their UTXO set.
- Construct transactions that spend non-ladder inputs alongside ladder inputs (mixed-version inputs are valid).

Wallets cannot spend ladder-locked outputs without implementing the ladder evaluator and sighash computation.

**Phase-based deployment.** The three-phase activation schedule allows incremental rollout:
- Phase 1 activates the core framework plus signature, timelock, and hash blocks. This covers all functionality equivalent to existing Script capabilities.
- Phase 2 adds covenant and anchor blocks, enabling constrained spending and protocol-specific UTXO tagging.
- Phase 3 adds recursion and PLC blocks, enabling stateful and self-referencing conditions.

Each phase can be activated independently via BIP-9 versionbits signaling with its own activation threshold and timeout. Phase 2 blocks are consensus-valid but policy-non-standard until Phase 2 activation. Phase 3 blocks follow the same pattern.

## Reference Implementation

The reference implementation is located in the `src/rung/` directory of ghost-core:

| File | Purpose |
|------|---------|
| `types.h` / `types.cpp` | Core type definitions: `RungBlockType`, `RungDataType`, `RungCoilType`, `RungAttestationMode`, `RungScheme`, and all struct definitions. |
| `conditions.h` / `conditions.cpp` | Conditions (locking side): `RungConditions`, serialization to/from `CScript` with `0xc1` prefix, condition data type validation. |
| `serialize.h` / `serialize.cpp` | Wire format v2 serialization/deserialization with full validation. Policy limit constants. |
| `evaluator.h` / `evaluator.cpp` | Block evaluators for all 39 block types across three phases. Rung AND logic, ladder OR logic, inversion. `VerifyRungTx` entry point. `LadderSignatureChecker` for Schnorr/PQ signature verification. |
| `sighash.h` / `sighash.cpp` | `SignatureHashLadder` tagged hash computation. |
| `policy.h` / `policy.cpp` | Mempool policy enforcement: `IsStandardRungTx`, `IsStandardRungOutput`, phase classification. |
| `aggregate.h` / `aggregate.cpp` | Block-level signature aggregation and deferred attestation. |
| `adaptor.h` / `adaptor.cpp` | Adaptor signature creation, verification, and secret extraction. |
| `pq_verify.h` / `pq_verify.cpp` | Post-quantum signature verification via liboqs (FALCON-512/1024, Dilithium3, SPHINCS+-SHA). |
| `rpc.cpp` | RPC commands: `createrung`, `decoderung`, `validateladder`, `createrungtx`, `signrungtx`, `computectvhash`, `pqkeygen`, `pqpubkeycommit`, `extractadaptorsecret`. |

## Test Vectors

The implementation includes comprehensive test coverage across two layers:

**Unit tests** (`src/test/rung_tests.cpp`): 185 test cases covering:
- Field validation for all 9 data types with boundary conditions
- Serialization round-trips for all 39 block types
- Deserialization rejection of malformed inputs (empty, truncated, trailing bytes, oversized, unknown types)
- Block evaluation for all Phase 1, 2, and 3 block types
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
- `test/functional/rung_p2p.py`: P2P relay of v3 transactions between nodes.
- `test/functional/rung_pq_block.py`: Post-quantum block-level tests.

**Fuzz testing** (`src/test/fuzz/rung_deserialize.cpp`): Continuous fuzz testing of the deserialization path.

## Copyright

This document is placed in the public domain.
