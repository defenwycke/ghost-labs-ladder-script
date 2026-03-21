```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script: Typed Structured Transaction Conditions
Author: Bitcoin Ghost
Status: Draft
Type: Standards Track
Created: 2026-03-06
```

## Abstract

Ladder Script introduces transaction version 4 (`RUNG_TX`) with typed, structured spending conditions that replace opcode-based Script for participating outputs. Conditions are organised as named function blocks within rungs, evaluated with AND-within-rung, OR-across-rungs, first-match semantics. Every byte in a Ladder Script witness belongs to a declared data type with enforced size constraints. No arbitrary data pushes are possible. The system provides 61 block types (59 active + 2 deprecated) across 10 families covering signatures, timelocks, hashes, covenants, anchors, recursion, programmable logic controllers, compound patterns, governance constraints, and legacy Bitcoin wrappers. All block types activate as a single deployment.

## Motivation

Bitcoin Script was designed as a minimal stack-based language for expressing spending conditions. Over two decades of use, several limitations have become apparent:

**Opcode ambiguity.** Script opcodes operate on untyped stack elements. A data push of up to 520 bytes could be a public key, a hash, a preimage, a signature, or arbitrary data. There is no way to distinguish them structurally. This ambiguity complicates static analysis, makes policy enforcement unreliable, and creates opportunities for data smuggling through witness fields.

**Compositional complexity.** Expressing compound conditions (e.g., "2-of-3 multisig AND CSV timelock, OR single-sig after CLTV") requires careful stack manipulation that is error-prone and difficult to audit. The resulting scripts are opaque to non-expert reviewers.

**Limited introspection.** Bitcoin Script cannot inspect the transaction that spends it beyond basic signature verification and timelock checks. Covenants, recursive conditions, and stateful logic require proposals (CTV, APO, VAULT) that each add individual opcodes without a unifying framework.

**Forward compatibility.** Adding new spending condition types to Script requires new opcodes, each consuming from a finite opcode space and requiring individual soft fork activation. There is no mechanism for structured extensibility.

**Post-quantum readiness.** Post-quantum signature schemes produce signatures and public keys significantly larger than ECDSA or Schnorr. Script's 520-byte push limit and 10,000-byte script limit are insufficient for FALCON-1024 (1,793-byte keys) or Dilithium3 (3,293-byte signatures).

**Data embedding.** Script's arbitrary data push capability has been exploited by protocols that embed non-financial data in the UTXO set and witness. Typed fields with enforced size constraints close this surface structurally rather than by policy.

Ladder Script addresses these limitations by replacing opcode sequences with a typed, structured format where every field has a declared type with enforced size constraints, conditions compose through explicit AND/OR rung logic, and new block types can be added to numbered families without consuming opcode space.

## Specification

### Transaction Format

A Ladder Script transaction is identified by `nVersion = 4` (constant `CTransaction::RUNG_TX_VERSION`). When a node encounters a version 4 transaction spending an output whose `scriptPubKey` begins with `0xC2`, it invokes the ladder evaluator instead of the Script interpreter.

**Output format:**

**MLSC: Merkelised Ladder Script Conditions (`0xC2`).** A 32-byte Merkle root with an optional DATA_RETURN payload:
   ```
   0xC2 || conditions_root                    (33 bytes, standard)
   0xC2 || conditions_root || data            (34-73 bytes, DATA_RETURN)
   ```
   This is the required output format for mainnet. If the scriptPubKey is longer than 33 bytes, the bytes after the root are a DATA_RETURN payload (max 40 bytes). Outputs with a DATA_RETURN payload must be zero-value. Max one DATA_RETURN output per transaction. The data is visible on-chain in the scriptPubKey and sits on the conditions side at 4 WU per byte.

MLSC outputs store no condition data in the UTXO set. All conditions are revealed at spend time in the witness. This eliminates data embedding via fake conditions (unspendable outputs are never spent), reduces the UTXO footprint to 40 bytes per entry regardless of script complexity, and provides MAST-style privacy where unused spending paths are never revealed.

The Merkle tree uses BIP-341-style tagged hashes for domain separation. Leaf nodes are computed as `TaggedHash("LadderLeaf", SerializeRungBlocks(rung) || pk1 || pk2 || ... || pkN)` where `pk1...pkN` are the public keys consumed by blocks in the rung, walked left-to-right using `PubkeyCountForBlock()`. Interior nodes are computed as `TaggedHash("LadderInternal", min(A,B) || max(A,B))`. See the Merkle Leaf Computation section for the full specification.

The prefix byte `0xC2` was chosen after collision analysis against all existing standard scriptPubKey first bytes. It does not collide with P2PKH (`0x76`), P2SH (`0xa9`), witness v0 (`0x00`), witness v1 (`0x51`), OP_RETURN (`0x6a`), any witness version opcode (`0x00`-`0x60`), or any data push prefix (`0x01`-`0x4e`). The byte falls in the undefined opcode range (`0xBB`-`0xFE`) above `OP_CHECKSIGADD` (`0xBA`).

**Input (unlocking side):**

The first element of the segregated witness stack for each v4 input is a serialised `LadderWitness`. For `0xC2` (MLSC) outputs, the witness contains the revealed rung conditions, Merkle proof hashes, and coil data.

**Evaluation entry point:**

The function `VerifyRungTx` is called for each input of a v4 transaction. It deserializes the revealed conditions and Merkle proof from the witness, verifies the proof against the UTXO root, then evaluates the ladder. All 59 active block evaluators operate on the same deserialized structures.

### Wire Format

All multi-byte integers are encoded as Bitcoin compact-size varints unless otherwise noted. Single-byte enumerations are encoded as `uint8_t`. Serialization is context-aware: the same block type may use different implicit field layouts depending on whether it appears in CONDITIONS (locking) or WITNESS (spending) context.

#### Ladder Structure

```
LADDER WITNESS / RUNG CONDITIONS:

[n_rungs: varint]                         number of rungs (0 = template mode, 1..MAX_RUNGS = normal)
  for each rung:
    [n_blocks: varint]                    number of blocks in this rung (1..MAX_BLOCKS_PER_RUNG)
      for each block:
        <block encoding>                  micro-header or escape (see below)
[coil_type: uint8_t]                      RungCoilType enum
[attestation: uint8_t]                    RungAttestationMode enum
[scheme: uint8_t]                         RungScheme enum
[address_hash_len: varint]                length of address hash (0 = none, 32 = SHA256)
[address_hash: bytes]                     SHA256(destination scriptPubKey). Fixed 32 bytes when present. Raw address never on-chain.
[n_coil_conditions: varint]               number of coil condition rungs (0 = none)
  for each coil condition rung:
    [n_blocks: varint]
      for each block:
        <block encoding>                  same encoding as input blocks
[n_rung_destinations: varint]             number of per-rung destination overrides (0 = none)
  for each rung destination:
    [rung_index: uint16_t LE]             target rung index
    [address_hash: 32 bytes]              SHA256(destination scriptPubKey) for this rung
[n_relays: varint]                        number of relay definitions (0 = none)
  for each relay:
    [n_blocks: varint]                    number of blocks in this relay
      for each block:
        <block encoding>                  relay condition blocks
    [n_relay_refs: varint]                number of relay-to-relay references
      for each relay_ref:
        [relay_index: varint]             index into relay array (must be < current relay index)
[n_rung_relay_refs: varint]               must equal n_rungs (present only if n_relays > 0)
  for each rung:
    [n_refs: varint]                      number of relay references for this rung
      for each ref:
        [relay_index: varint]             index into relay array
```

#### Block Encoding: Micro-Headers

Each block begins with a single byte that determines the encoding mode:

| First Byte | Mode | Encoding |
|------------|------|----------|
| `0x00`-`0x7F` | Micro-header | Lookup table maps byte to block type; inverted = false |
| `0x80` | Escape | Followed by `type(uint16_t LE)`; inverted = false |
| `0x81` | Escape + inverted | Followed by `type(uint16_t LE)`; inverted = true |

The micro-header lookup table maps 128 slot indices to block type values. All 59 active block types have assigned slots. Slots `0x07` and `0x08` are reserved (formerly HASH_PREIMAGE and HASH160_PREIMAGE, now deprecated). Deprecated slots are rejected during deserialization.

| Slot | Block Type | Slot | Block Type | Slot | Block Type |
|------|------------|------|------------|------|------------|
| 0x00 | SIG | 0x15 | ANCHOR_POOL | 0x2A | PTLC |
| 0x01 | MULTISIG | 0x16 | ANCHOR_RESERVE | 0x2B | CLTV_SIG |
| 0x02 | ADAPTOR_SIG | 0x17 | ANCHOR_SEAL | 0x2C | TIMELOCKED_MULTISIG |
| 0x03 | CSV | 0x18 | ANCHOR_ORACLE | 0x2D | EPOCH_GATE |
| 0x04 | CSV_TIME | 0x19 | HYSTERESIS_FEE | 0x2E | WEIGHT_LIMIT |
| 0x05 | CLTV | 0x1A | HYSTERESIS_VALUE | 0x2F | INPUT_COUNT |
| 0x06 | CLTV_TIME | 0x1B | TIMER_CONTINUOUS | 0x30 | OUTPUT_COUNT |
| 0x07 | *(reserved)* | 0x1C | TIMER_OFF_DELAY | 0x31 | RELATIVE_VALUE |
| 0x08 | *(reserved)* | 0x1D | LATCH_SET | 0x32 | ACCUMULATOR |
| 0x09 | TAGGED_HASH | 0x1E | LATCH_RESET | 0x33 | MUSIG_THRESHOLD |
| 0x0A | CTV | 0x1F | COUNTER_DOWN | 0x34 | KEY_REF_SIG |
| 0x0B | VAULT_LOCK | 0x20 | COUNTER_PRESET | 0x35 | P2PK_LEGACY |
| 0x0C | AMOUNT_LOCK | 0x21 | COUNTER_UP | 0x36 | P2PKH_LEGACY |
| 0x0D | RECURSE_SAME | 0x22 | COMPARE | 0x37 | P2SH_LEGACY |
| 0x0E | RECURSE_MODIFIED | 0x23 | SEQUENCER | 0x38 | P2WPKH_LEGACY |
| 0x0F | RECURSE_UNTIL | 0x24 | ONE_SHOT | 0x39 | P2WSH_LEGACY |
| 0x10 | RECURSE_COUNT | 0x25 | RATE_LIMIT | 0x3A | P2TR_LEGACY |
| 0x11 | RECURSE_SPLIT | 0x26 | COSIGN | 0x3B | P2TR_SCRIPT_LEGACY |
| 0x12 | RECURSE_DECAY | 0x27 | TIMELOCKED_SIG | 0x3C | DATA_RETURN |
| 0x13 | ANCHOR | 0x28 | HTLC | 0x3D | HASH_GUARDED |
| 0x14 | ANCHOR_CHANNEL | 0x29 | HASH_SIG | 0x3E | OUTPUT_CHECK |

Slots `0x3F`-`0x7F` are reserved for future block types. Unknown micro-header slots are rejected during deserialization.

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
    <field data>                          encoding depends on type (see below)
```

**Implicit fields** (used with micro-headers when implicit layout matches):
```
n_fields is omitted (count known from layout)
data_type bytes are omitted (types known from layout)
  for each field:
    <field data>                          encoding depends on type (see below)
```

**Per-type field data encoding:**

| Data Type | Encoding |
|-----------|----------|
| NUMERIC | `CompactSize(value)`. The numeric value itself, not a length prefix. Values 0-252 use 1 byte; 253-65535 use 3 bytes; 65536-2^32-1 use 5 bytes. After deserialization, always stored as 4-byte LE internally. |
| Fixed-size (HASH256, HASH160, SPEND_INDEX, SCHEME) | Implicit: raw data only (size known from layout). Explicit: `CompactSize(len) + data`. |
| Variable-size (PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY) | `CompactSize(len) + data` (always length-prefixed). |
| DATA | `CompactSize(len) + data` (always length-prefixed, max 40 bytes). |

#### Implicit Field Layouts

For block types with a micro-header, the implicit field layout defines the expected field types and whether their sizes are fixed. This enables skipping field count, type bytes, and length prefixes for fixed-size fields.

**CONDITIONS context (locking side):**

Public keys are not stored in condition fields. They are folded into the Merkle leaf hash during leaf computation (see Merkle Leaf Computation). This means SIG-family condition layouts contain only non-key fields like SCHEME and NUMERIC.

| Block Type | Implicit Fields |
|------------|----------------|
| SIG | SCHEME(fixed 1) |
| CSV | NUMERIC(varint) |
| CSV_TIME | NUMERIC(varint) |
| CLTV | NUMERIC(varint) |
| CLTV_TIME | NUMERIC(varint) |
| TAGGED_HASH | HASH256(fixed 32) + HASH256(fixed 32) |
| HASH_GUARDED | HASH256(fixed 32) |
| CTV | HASH256(fixed 32) |
| AMOUNT_LOCK | NUMERIC(varint) + NUMERIC(varint) |
| COSIGN | HASH256(fixed 32) |
| TIMELOCKED_SIG | SCHEME(fixed 1) + NUMERIC(varint) |
| HTLC | HASH256(fixed 32) + NUMERIC(varint) |
| HASH_SIG | HASH256(fixed 32) + SCHEME(fixed 1) |
| CLTV_SIG | SCHEME(fixed 1) + NUMERIC(varint) |
| MUSIG_THRESHOLD | NUMERIC(varint) + NUMERIC(varint) |
| EPOCH_GATE | NUMERIC(varint) + NUMERIC(varint) |
| ANCHOR_SEAL | HASH256(fixed 32) + HASH256(fixed 32) |
| DATA_RETURN | DATA(variable, max 40) |
| P2PK_LEGACY | SCHEME(fixed 1) |
| P2PKH_LEGACY | HASH160(fixed 20) |
| P2SH_LEGACY | HASH160(fixed 20) |
| P2WPKH_LEGACY | HASH160(fixed 20) |
| P2WSH_LEGACY | HASH256(fixed 32) |
| P2TR_LEGACY | SCHEME(fixed 1) |
| P2TR_SCRIPT_LEGACY | HASH256(fixed 32) |

**WITNESS context (spending side):**

| Block Type | Implicit Fields |
|------------|----------------|
| SIG | PUBKEY(variable) + SIGNATURE(variable) |
| CSV | NUMERIC(varint) |
| CSV_TIME | NUMERIC(varint) |
| CLTV | NUMERIC(varint) |
| CLTV_TIME | NUMERIC(varint) |
| TAGGED_HASH | HASH256(fixed 32) + HASH256(fixed 32) + PREIMAGE(variable) |
| HASH_GUARDED | PREIMAGE(variable) |
| CTV | HASH256(fixed 32) |
| COSIGN | HASH256(fixed 32) |
| TIMELOCKED_SIG | PUBKEY(variable) + SIGNATURE(variable) + NUMERIC(varint) |
| HTLC | PUBKEY(variable) + SIGNATURE(variable) + PUBKEY(variable) + PREIMAGE(variable) + NUMERIC(varint) |
| HASH_SIG | PUBKEY(variable) + SIGNATURE(variable) + PREIMAGE(variable) |
| CLTV_SIG | PUBKEY(variable) + SIGNATURE(variable) + NUMERIC(varint) |
| MUSIG_THRESHOLD | PUBKEY(variable) + SIGNATURE(variable) |
| CSV_TIME | NUMERIC(varint) |
| CLTV | NUMERIC(varint) |
| CLTV_TIME | NUMERIC(varint) |
| P2PK_LEGACY | PUBKEY(variable) + SIGNATURE(variable) |
| P2PKH_LEGACY | PUBKEY(variable) + SIGNATURE(variable) |
| P2WPKH_LEGACY | PUBKEY(variable) + SIGNATURE(variable) |
| P2TR_LEGACY | PUBKEY(variable) + SIGNATURE(variable) |

Most block types have implicit layouts. Block types with variable witness field counts (e.g., MULTISIG with N pubkeys) use implicit layouts for conditions (MULTISIG conditions: NUMERIC threshold only, since pubkeys are in the Merkle leaf) but encode witness fields explicitly. The tables above show the most commonly referenced layouts; the full set of 50+ implicit layouts is defined in `types.h`.

#### Template Inheritance

When `n_rungs = 0` in a conditions script, the output uses **template inheritance**: conditions are copied from another input's conditions with optional field-level diffs.

```
TEMPLATE REFERENCE (n_rungs = 0):

[n_rungs: varint = 0]                    signals template mode
[input_index: varint]                    which input's conditions to inherit
[n_diffs: varint]                        number of field-level patches
  for each diff:
    [rung_index: varint]                 target rung
    [block_index: varint]                target block within rung
    [field_index: varint]                target field within block
    [data_type: uint8_t]                 replacement field type
    <field data>                         encoded per type (NUMERIC = varint, others = length-prefixed)
```

Template resolution rules:
- The referenced input must have non-template conditions (no chaining).
- Each diff's `data_type` must match the original field's type (type-safe patching).
- Only condition data types are permitted in diffs (PUBKEY, SIGNATURE, PREIMAGE, and SCRIPT_BODY are rejected).
- Resolution copies the source conditions and applies diffs in order.
- The sighash always commits to the **resolved** conditions, not the compact template reference.

#### Diff Witness (Witness Inheritance)

When `n_rungs = 0` in a ladder witness (the input's witness stack element), the witness inherits rungs and relays from another input's witness, with optional field-level diffs and a mandatory fresh coil. This is the witness-side counterpart to template inheritance.

```
DIFF WITNESS (n_rungs = 0 in witness):

[n_rungs: varint = 0]                    signals diff witness mode
[input_index: varint]                    source input to inherit from
[n_diffs: varint]                        number of field-level diffs
  for each diff:
    [rung_index: varint]                 target rung
    [block_index: varint]                target block within rung
    [field_index: varint]                target field within block
    [data_type: uint8_t]                 replacement field type
    <field data>                         encoded per type
[coil]                                   fresh coil (never inherited)
                                         no relays section (inherited from source)
```

Diff witness resolution rules:
- `input_index` must be strictly less than the current input index (forward-only, prevents cycles).
- The source witness must not itself be a diff witness (no chaining).
- Only witness-side data types are permitted in diffs: PUBKEY, SIGNATURE, PREIMAGE, SCRIPT_BODY, SCHEME.
- Each diff's type must match the source field's type (type-safe replacement).
- The coil is always provided fresh by the spender. Relays are inherited from the source.
- Resolution copies source rungs/relays, applies diffs, then proceeds through normal evaluation.
- The sighash is per-input (includes input index), so SIGNATURE fields almost always require a diff.

### Data Types

Every field in a Ladder Script witness or conditions structure has one of the following types. The type constrains the allowed data size, preventing abuse of witness space.

| Code | Name | Min Size | Max Size | Context | Description |
|------|------|----------|----------|---------|-------------|
| `0x01` | PUBKEY | 1 | 2,048 | Witness only | Public key (compressed 33B, x-only 32B, or post-quantum up to 1,793B). Forbidden in conditions. |
| `0x02` | *(reserved)* | | | | Formerly PUBKEY_COMMIT. Removed by merkle_pub_key. Rejected in both conditions and witness. |
| `0x03` | HASH256 | 32 | 32 | Both | SHA-256 hash digest. |
| `0x04` | HASH160 | 20 | 20 | Conditions only | RIPEMD160(SHA256()) hash digest. |
| `0x05` | PREIMAGE | 32 | 32 | Witness only | Hash preimage (forbidden in conditions). |
| `0x06` | SIGNATURE | 1 | 50,000 | Witness only | Signature (Schnorr 64-65B, ECDSA 8-72B, PQ up to ~49,216B for SPHINCS_SHA). |
| `0x07` | SPEND_INDEX | 4 | 4 | Both | Index reference (uint32 LE) for aggregate attestation. |
| `0x08` | NUMERIC | 1 | 4 | Both | Unsigned 32-bit integer. Encoded on wire as CompactSize(value); stored internally as 4-byte LE. |
| `0x09` | SCHEME | 1 | 1 | Both | Signature scheme selector byte. |
| `0x0A` | SCRIPT_BODY | 1 | 80 | Witness only | Serialised inner conditions (P2SH/P2WSH/P2TR_SCRIPT inner scripts). 80-byte cap limits data embedding (legacy blocks on deprecation path). |
| `0x0B` | DATA | 1 | 40 | Both | Opaque data payload (DATA_RETURN block only). Maximum 40 bytes. |

The SIGNATURE maximum of 50,000 bytes accommodates all post-quantum signature schemes including SPHINCS_SHA (~7,856 bytes) and Dilithium3 (3,293 bytes) with headroom. The PUBKEY maximum of 2,048 bytes accommodates FALCON-1024 public keys (1,793 bytes). The SCRIPT_BODY type supports inner conditions in legacy wrapping blocks, capped at 80 bytes. Legacy blocks are on the deprecation path.

Data type validity is checked by `IsKnownDataType()`. Unknown data type codes cause deserialization failure.

### Block Types

Block types are organised into numbered families. Each block type evaluates a single spending condition. The block type is encoded as a `uint16_t` (little-endian) on the wire.

#### Signature Family (0x0001-0x00FF)

| Code | Name | Condition Fields | Witness Fields | Description |
|------|------|-----------------|----------------|-------------|
| `0x0001` | SIG | SCHEME | PUBKEY + SIGNATURE | Single signature verification. Supports Schnorr (BIP-340), ECDSA, and post-quantum schemes via the SCHEME field. The pubkey is bound to the output via the Merkle leaf (see merkle_pub_key). |
| `0x0002` | MULTISIG | NUMERIC(threshold) | N × (PUBKEY + SIGNATURE) | M-of-N threshold signature. First NUMERIC field is the threshold M. Exactly M valid signatures required from the N provided public keys. |
| `0x0003` | ADAPTOR_SIG | (explicit) | PUBKEY(signer) + PUBKEY(adaptor point) + SIGNATURE | Adaptor signature verification. The second PUBKEY is the adaptor point T. Verification checks that the signature is valid under the combined challenge. Enables atomic swaps and payment channel protocols. |
| `0x0004` | MUSIG_THRESHOLD | NUMERIC(M) + NUMERIC(N) | PUBKEY + SIGNATURE | MuSig2/FROST aggregate threshold signature. On-chain: single aggregate key + single Schnorr signature (~131B total, constant regardless of M/N). M and N are policy/display only. Schnorr-only (no PQ path). |
| `0x0005` | KEY_REF_SIG | NUMERIC(relay_index) + NUMERIC(block_index) | PUBKEY + SIGNATURE | Resolve pubkey and scheme from a relay block at the specified indices. Verify witness PUBKEY against the Merkle-bound key. Verify SIGNATURE against resolved scheme. |

#### Timelock Family (0x0100-0x01FF)

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0101` | CSV | NUMERIC(blocks) | Relative timelock in blocks (BIP-68 sequence enforcement). |
| `0x0102` | CSV_TIME | NUMERIC(seconds) | Relative timelock in seconds (BIP-68 time-based). |
| `0x0103` | CLTV | NUMERIC(height) | Absolute timelock by block height (nLockTime enforcement). |
| `0x0104` | CLTV_TIME | NUMERIC(timestamp) | Absolute timelock by median-time-past. |

#### Hash Family (0x0200-0x02FF)

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0201` | ~~HASH_PREIMAGE~~ | | **Deprecated.** Rejected at deserialization. Use HTLC, HASH_SIG, or HASH_GUARDED instead. |
| `0x0202` | ~~HASH160_PREIMAGE~~ | | **Deprecated.** Rejected at deserialization. Use HTLC, HASH_SIG, or HASH_GUARDED instead. |
| `0x0203` | TAGGED_HASH | HASH256(tag) + HASH256(expected) + PREIMAGE | BIP-340 tagged hash verification. SATISFIED when TaggedHash(tag, preimage) equals the expected hash. |
| `0x0204` | HASH_GUARDED | HASH256(committed_hash) + PREIMAGE | Raw SHA-256 preimage verification. SATISFIED when SHA256(preimage) equals the committed hash. Non-invertible, fail-closed. Safe replacement for deprecated HASH_PREIMAGE. |

HASH_PREIMAGE and HASH160_PREIMAGE are deprecated as part of the anti-spam hardening (see Anti-Spam Hardening). Standalone hash preimage blocks with invertible, writable hash fields created a data embedding surface. HASH_GUARDED provides a safe, non-invertible alternative for raw SHA-256 preimage verification. All hash-lock use cases are also covered by the compound blocks HTLC (hash + signature + timelock) and HASH_SIG (hash + signature), which always require a signature and therefore cannot be satisfied with arbitrary data.

#### Covenant Family (0x0300-0x03FF)

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0301` | CTV | HASH256(template) | OP_CHECKTEMPLATEVERIFY covenant (BIP-119). SATISFIED when the spending transaction matches the committed template hash. |
| `0x0302` | VAULT_LOCK | PUBKEY + SIGNATURE + NUMERIC(delay) | Vault timelock covenant. Requires a valid signature plus an enforced delay period before the vault can be swept. |
| `0x0303` | AMOUNT_LOCK | NUMERIC(min) + NUMERIC(max) | Output amount range check. SATISFIED when the corresponding output amount is within [min, max] satoshis inclusive. |

#### Recursion Family (0x0400-0x04FF)

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0401` | RECURSE_SAME | NUMERIC(max_depth) | Recursive re-encumbrance. SATISFIED when max_depth > 0 and at least one output carries identical rung conditions as the input being spent. Because the output must be identical (including max_depth), the value never decrements. This creates a perpetual covenant. Termination requires companion blocks (e.g., alternative rungs with timelocks) or the UTXO balance falling below dust. |
| `0x0402` | RECURSE_MODIFIED | NUMERIC(rung_index) + NUMERIC(block_index) + NUMERIC(field_index) + NUMERIC/HASH256(new_value) | Recursive re-encumbrance with a single field mutation. The spending output must carry conditions identical to the input except for the specified field. Supports cross-rung mutation and multi-field mutation via multiple field groups. |
| `0x0403` | RECURSE_UNTIL | NUMERIC(target_height) | Recursive until block height. SATISFIED (allowing termination) when the current block height >= target. Below the target height, the output must re-encumber with identical conditions. |
| `0x0404` | RECURSE_COUNT | NUMERIC(count) | Recursive countdown. SATISFIED when count > 0. Paired with RECURSE_MODIFIED to decrement count in the re-encumbered output. UNSATISFIED when count reaches zero. |
| `0x0405` | RECURSE_SPLIT | NUMERIC(max_splits) + NUMERIC(min_split_sats) | Recursive output splitting. SATISFIED when max_splits > 0 and the output amount is at least min_split_sats. Enables controlled subdivision. |
| `0x0406` | RECURSE_DECAY | NUMERIC(rung) + NUMERIC(block) + NUMERIC(field) + NUMERIC(delta) | Recursive parameter decay. Like RECURSE_MODIFIED but the target field must decrease by exactly delta per spend. Supports multi-field decay via multiple field groups. |

#### Anchor Family (0x0500-0x05FF)

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0501` | ANCHOR | HASH256(protocol_id) | Generic anchor. Tags a UTXO as belonging to a protocol identified by the hash. |
| `0x0502` | ANCHOR_CHANNEL | PUBKEY + NUMERIC(commitment) | Lightning channel anchor. Binds a UTXO to a channel identified by the public key. |
| `0x0503` | ANCHOR_POOL | HASH256(pool_id) + NUMERIC(participant_count) | Pool anchor. Requires a pool identifier hash and a non-zero participant count. |
| `0x0504` | ANCHOR_RESERVE | NUMERIC(threshold_n) + NUMERIC(group_m) + HASH256(group_id) | Reserve anchor with N-of-M guardian set. Requires N <= M and a group identifier hash. |
| `0x0505` | ANCHOR_SEAL | HASH256(asset_id) + HASH256(state_transition) | Seal anchor. Permanently binds a UTXO to an asset identifier and state transition commitment. |
| `0x0506` | ANCHOR_ORACLE | PUBKEY(oracle) + NUMERIC(quorum) | Oracle anchor. Requires an oracle public key and a non-zero quorum count. |
| `0x0507` | DATA_RETURN | DATA(payload) | Unspendable data output (typed OP_RETURN replacement). Max 40 bytes. Output must be zero-value. Max one per transaction. The data payload is appended to the MLSC scriptPubKey after the 32-byte root (`0xC2 || root || data`), making it visible on-chain at 4 WU per byte. |

#### PLC Family (0x0600-0x06FF)

The Programmable Logic Controller family brings industrial automation concepts to transaction conditions, enabling stateful, rate-governed, and sequenced spending logic.

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0601` | HYSTERESIS_FEE | NUMERIC(high) + NUMERIC(low) | Fee hysteresis band. SATISFIED when the transaction fee rate falls within the [low, high] range. |
| `0x0602` | HYSTERESIS_VALUE | NUMERIC(high) + NUMERIC(low) | Value hysteresis band. SATISFIED when the input amount falls within the [low, high] range. |
| `0x0611` | TIMER_CONTINUOUS | NUMERIC(duration) [+ NUMERIC(elapsed)] | Continuous timer. Requires a specified number of consecutive blocks. With two NUMERIC fields, SATISFIED when elapsed >= duration. |
| `0x0612` | TIMER_OFF_DELAY | NUMERIC(remaining) | Off-delay timer. SATISFIED when remaining > 0 (still in hold-off period). UNSATISFIED when remaining reaches zero. Paired with RECURSE_MODIFIED to decrement remaining each spend. |
| `0x0621` | LATCH_SET | PUBKEY + [NUMERIC(state)] | Latch set (state activation). SATISFIED when the latch state is unset (0) or absent, allowing transition to set. UNSATISFIED if state is already non-zero. |
| `0x0622` | LATCH_RESET | PUBKEY + NUMERIC(state) + NUMERIC(delay) | Latch reset (state deactivation). SATISFIED when the latch state is set (non-zero), allowing transition to unset. UNSATISFIED if state is zero. |
| `0x0631` | COUNTER_DOWN | PUBKEY + NUMERIC(count) | Down counter. SATISFIED when count > 0. Paired with RECURSE_MODIFIED to decrement count each spend. |
| `0x0632` | COUNTER_PRESET | NUMERIC(current) + NUMERIC(preset) | Preset counter (approval accumulator). SATISFIED when current < preset (still accumulating). UNSATISFIED when current >= preset (threshold reached). |
| `0x0633` | COUNTER_UP | PUBKEY + NUMERIC(current) + NUMERIC(target) | Up counter. SATISFIED when current < target (still counting). UNSATISFIED when current >= target (done). |
| `0x0641` | COMPARE | NUMERIC(operator) + NUMERIC(operand) [+ NUMERIC(upper)] | Comparator. Operator encoding: 1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE. IN_RANGE requires a third NUMERIC (upper bound). Compares against the input amount from evaluation context. |
| `0x0651` | SEQUENCER | NUMERIC(current_step) + NUMERIC(total_steps) | Step sequencer. SATISFIED when current_step < total_steps. Total must be non-zero. |
| `0x0661` | ONE_SHOT | NUMERIC(state) + HASH256(commitment) | One-shot trigger. SATISFIED when state == 0 (can fire). UNSATISFIED when state != 0 (already fired). Paired with RECURSE_MODIFIED to set state to non-zero after firing. |
| `0x0671` | RATE_LIMIT | NUMERIC(max_per_block) + NUMERIC(accumulation_cap) + NUMERIC(refill_blocks) | Rate limiter. SATISFIED when the output amount does not exceed max_per_block. |
| `0x0681` | COSIGN | HASH256(conditions_hash) | Co-spend constraint. SATISFIED when another input in the same transaction has rung conditions whose serialised hash matches conditions_hash. The evaluator skips the current input index when scanning. |

#### Compound Family (0x0700-0x07FF)

The Compound family combines multiple conditions into single blocks for wire efficiency. Each block replaces a multi-block rung pattern with a single typed block that performs the same validation with fewer bytes on the wire.

| Code | Name | Condition Fields | Witness Fields | Description |
|------|------|-----------------|----------------|-------------|
| `0x0701` | TIMELOCKED_SIG | SCHEME + NUMERIC(sequence) | PUBKEY + SIGNATURE + NUMERIC | Signature with CSV relative timelock in one block. Equivalent to SIG + CSV on the same rung. Pubkey bound via Merkle leaf. |
| `0x0702` | HTLC | HASH256(payment_hash) + NUMERIC(timeout) | PUBKEY + SIGNATURE + PUBKEY + PREIMAGE + NUMERIC | Hash Time-Locked Contract. SATISFIED when the PREIMAGE hashes to payment_hash AND the signature verifies AND the timelock has not expired. Two pubkeys (claim and refund) bound via Merkle leaf. 5-field witness layout. |
| `0x0703` | HASH_SIG | HASH256(hash) + SCHEME | PUBKEY + SIGNATURE + PREIMAGE | Hash preimage combined with signature. SATISFIED when the PREIMAGE hashes to hash AND the signature verifies. Pubkey bound via Merkle leaf. |
| `0x0704` | PTLC | (explicit) | PUBKEY + SIGNATURE | Point Time-Locked Contract. Adaptor signature with CSV relative timelock for point-locked payments. |
| `0x0705` | CLTV_SIG | SCHEME + NUMERIC(locktime) | PUBKEY + SIGNATURE + NUMERIC | Signature with CLTV absolute timelock in one block. Pubkey bound via Merkle leaf. |
| `0x0706` | TIMELOCKED_MULTISIG | (explicit) | (explicit) | Multisig with CSV relative timelock. M-of-N multisig that additionally requires a BIP-68 relative lock-time to be satisfied. |

#### Governance Family (0x0800-0x08FF)

The Governance family provides transaction-level constraints that restrict how a UTXO can be spent based on properties of the spending transaction itself.

| Code | Name | Fields | Description |
|------|------|--------|-------------|
| `0x0801` | EPOCH_GATE | NUMERIC(epoch_size) + NUMERIC(window_size) | Spending windows within block epochs. Divides the blockchain into epochs of epoch_size blocks. SATISFIED when block_height % epoch_size < window_size. Enables scheduled spending windows. |
| `0x0802` | WEIGHT_LIMIT | NUMERIC(max_weight) | Maximum transaction weight. SATISFIED when the spending transaction's weight is at most max_weight weight units. |
| `0x0803` | INPUT_COUNT | NUMERIC(min_inputs) + NUMERIC(max_inputs) | Input count bounds. SATISFIED when the spending transaction has between min_inputs and max_inputs inputs (inclusive). |
| `0x0804` | OUTPUT_COUNT | NUMERIC(min_outputs) + NUMERIC(max_outputs) | Output count bounds. SATISFIED when the spending transaction has between min_outputs and max_outputs outputs (inclusive). |
| `0x0805` | RELATIVE_VALUE | NUMERIC(numerator) + NUMERIC(denominator) | Output-to-input value ratio. SATISFIED when the ratio of the output value to the input value is at least numerator/denominator. Ensures a minimum proportion of value is preserved. |
| `0x0806` | ACCUMULATOR | HASH256(merkle_root) + HASH256(leaf). Witness: PREIMAGE (Merkle proof). Max 10 HASH256 fields (root + 8 proof nodes + leaf). | Merkle set membership proof. SATISFIED when the witness Merkle proof demonstrates that leaf is a member of the set committed to by merkle_root. Enables whitelist/blacklist patterns. |
| `0x0807` | OUTPUT_CHECK | NUMERIC(output_index) + NUMERIC(min_sats) + NUMERIC(max_sats) + HASH256(script_hash) | Per-output value and script constraint. SATISFIED when the spending transaction's output at the specified index has a value within [min_sats, max_sats] and its scriptPubKey hashes to script_hash. Non-invertible. |

#### Legacy Family (0x0900-0x09FF)

The Legacy family wraps traditional Bitcoin transaction types as typed Ladder Script blocks. Each block preserves the original spending semantics while eliminating arbitrary data surfaces.

| Code | Name | Condition Fields | Witness Fields | Description |
|------|------|-----------------|----------------|-------------|
| `0x0901` | P2PK_LEGACY | SCHEME | PUBKEY + SIGNATURE | P2PK wrapped. Pubkey bound via Merkle leaf. Verification is identical to SIG but restricted to P2PK semantics. |
| `0x0902` | P2PKH_LEGACY | HASH160 | PUBKEY + SIGNATURE | P2PKH wrapped. The HASH160 field contains the public key hash. The witness PUBKEY must hash to the committed HASH160 value, and the SIGNATURE must verify against that key. |
| `0x0903` | P2SH_LEGACY | HASH160 | PREIMAGE + inner witness | P2SH wrapped. The HASH160 field is the script hash. The PREIMAGE must hash to HASH160 and must deserialize as valid Ladder Script conditions. Recursion depth limited to 2. |
| `0x0904` | P2WPKH_LEGACY | HASH160 | PUBKEY + SIGNATURE | P2WPKH wrapped. Delegates to P2PKH_LEGACY evaluation. |
| `0x0905` | P2WSH_LEGACY | HASH256 | PREIMAGE + inner witness | P2WSH wrapped. The HASH256 field is the witness script hash. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2. |
| `0x0906` | P2TR_LEGACY | SCHEME | PUBKEY + SIGNATURE | P2TR key-path wrapped. Pubkey bound via Merkle leaf. Verification uses Schnorr (BIP-340) by default. |
| `0x0907` | P2TR_SCRIPT_LEGACY | HASH256 | PREIMAGE + inner witness | P2TR script-path wrapped. HASH256 is the tapleaf hash. Internal key bound via Merkle leaf. The PREIMAGE must deserialize as valid Ladder Script conditions. Recursion depth limited to 2. |

**Inner-conditions semantics (P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY):** The PREIMAGE field in the witness must deserialize as a valid `RungConditions` structure. Arbitrary byte sequences that do not parse as valid Ladder Script conditions are rejected at deserialization. The recursion depth is limited to 2 (an inner script may not itself contain a P2SH/P2WSH/P2TR_SCRIPT_LEGACY block with another inner script). This prevents unbounded nesting while allowing one level of script wrapping.

#### Legacy Migration Model

The Legacy family supports a three-phase migration path from traditional Bitcoin transaction types to fully typed Ladder Script:

1. **Coexistence.** Both legacy Bitcoin transaction types (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and Ladder Script version 4 transactions are valid on-chain. No existing transaction type is deprecated. Wallets choose which format to use.

2. **Legacy-in-Blocks.** Legacy transaction types are wrapped as typed Ladder Script blocks in the Legacy family. The spending semantics are identical but all fields are typed and validated. No arbitrary data surfaces exist in the wrapped form.

3. **Sunset.** Raw legacy transaction formats are deprecated for new output creation. Only block-wrapped versions in the Legacy family are accepted. Existing legacy UTXOs remain spendable under their original rules indefinitely.

### Merkle Leaf Computation (merkle_pub_key)

Public keys are not stored as fields in condition layouts. Instead, they are folded into the Merkle leaf hash during leaf computation. This eliminates all writable pubkey fields from the on-chain conditions, closing the data embedding vector where an attacker could write arbitrary 32-byte values into PUBKEY_COMMIT fields.

**Leaf computation:**

```
L = TaggedHash("LadderLeaf", SerializeRungBlocks(rung, CONDITIONS) || pk1 || pk2 || ... || pkN)
```

Where `pk1...pkN` are the raw public keys consumed by blocks in the rung, extracted left-to-right. The function `PubkeyCountForBlock()` determines how many pubkeys each block consumes:

| Block Type | Pubkeys |
|------------|---------|
| SIG, TIMELOCKED_SIG, HASH_SIG, CLTV_SIG, MUSIG_THRESHOLD, P2PK_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY | 1 |
| ANCHOR_ORACLE, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_UP | 1 (PLC/anchor blocks with single key) |
| HTLC, ADAPTOR_SIG, PTLC, ANCHOR_CHANNEL, VAULT_LOCK | 2 |
| MULTISIG, TIMELOCKED_MULTISIG | N (count of PUBKEY fields) |
| KEY_REF_SIG, COSIGN, P2PKH_LEGACY, P2WPKH_LEGACY | 0 (KEY_REF_SIG resolves key from relay; COSIGN has no key; P2PKH/P2WPKH use HASH160, key in witness only) |
| All other non-key blocks | 0 |

**Relay leaf computation** follows the same pattern for relay blocks containing key-consuming types.

### Cross-Rung Mutation Targets (`revealed_mutation_targets`)

When a RECURSE_MODIFIED or RECURSE_DECAY block targets a rung different from the one being exercised, the verifier needs the target rung's condition blocks to validate the mutation. The `revealed_mutation_targets` field in the MLSC proof provides these:

```
MLSC PROOF (extended):

[...standard proof fields...]
[n_mutation_targets: varint]              number of cross-rung mutation targets (0 = none)
  for each target:
    [rung_index: uint16_t LE]             index of the target rung in the original leaf array
    [serialised_rung: bytes]              full condition blocks for the target rung
```

The verifier computes the leaf hash for each revealed mutation target and confirms it appears in the Merkle tree (via the proof hashes). This enables cross-rung mutation verification without revealing the entire ladder. Only the exercised rung and the mutation target rungs are disclosed.

**Spend-time verification (MLSC):**

1. Deserialize witness to extract pubkeys from PUBKEY fields.
2. Walk revealed rung blocks positionally to assign pubkeys to blocks.
3. Compute `ComputeRungLeaf(rung, pubkeys)` to get the leaf hash.
4. Verify Merkle proof against the committed root.

The positional binding is critical: if pubkeys are provided in the wrong order, the leaf hash will not match, and the Merkle proof will fail. This means the pubkey-to-block assignment is consensus-enforced without storing pubkeys in conditions.

### Leaf-Centric Covenant Verification (`MLSCVerifiedLeaves`)

Covenant verification (RECURSE_SAME, RECURSE_MODIFIED, RECURSE_DECAY, etc.) for MLSC outputs uses a leaf-centric algorithm rather than full-conditions comparison. The `MLSCVerifiedLeaves` structure caches the verified leaf hashes from the Merkle proof:

```cpp
struct MLSCVerifiedLeaves {
    uint256 conditions_root;          // The committed Merkle root
    std::vector<uint256> leaf_hashes; // Verified leaf hashes (rung + relay + coil)
    size_t n_rungs;                   // Number of rung leaves
    size_t n_relays;                  // Number of relay leaves
};
```

**Covenant algorithm (MLSC):**

1. The evaluator verifies the exercised rung's Merkle proof, populating `MLSCVerifiedLeaves` with all verified leaf hashes.
2. When a RECURSE_* block fires, it computes the expected output conditions root:
   a. Copy the verified leaf hashes from the input.
   b. For the mutated rung, recompute the leaf hash with the mutation applied.
   c. For cross-rung mutations, use `revealed_mutation_targets` to obtain the target rung's blocks, apply the mutation, and recompute the leaf hash.
   d. Rebuild the Merkle root from the modified leaf array.
3. Compare the recomputed root against the spending transaction's output `scriptPubKey` root.

This approach avoids deserializing the full input conditions for covenant verification. Only the exercised rung and any mutation targets are fully deserialized; all other rungs are represented by their opaque leaf hashes.

### Anti-Spam Hardening

Three coordinated defenses close all practical data embedding surfaces in Ladder Script:

**1. merkle_pub_key.** Public keys are folded into the Merkle leaf hash. There is no writable pubkey field in conditions. An attacker constructing a raw transaction cannot write arbitrary data into a PUBKEY_COMMIT field because the field does not exist. The only way to produce a valid Merkle proof is to provide the actual public keys that were committed at fund time.

**2. Selective inversion.** Key-consuming blocks cannot be inverted. Without this restriction, an attacker could invert a SIG block with a garbage pubkey: the signature check fails, returning UNSATISFIED, which inversion flips to SATISFIED. The garbage pubkey data lands in the block witness permanently. The function `IsInvertibleBlockType()` is a fail-closed allowlist. New block types default to non-invertible. The 24 key-consuming block types (SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG, COSIGN, P2PK_LEGACY, P2PKH_LEGACY, P2WPKH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY, ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_UP) are all non-invertible. Among non-key blocks, most are invertible (timelocks, covenants, most anchors, recursion, most PLC, ACCUMULATOR, P2SH_LEGACY, P2WSH_LEGACY). EPOCH_GATE and RELATIVE_VALUE are the only non-key blocks that are non-invertible. An inverted ACCUMULATOR enables blocklist patterns ("spend only if NOT in this set").

**3. Hash lock deprecation.** HASH_PREIMAGE and HASH160_PREIMAGE are removed. These were invertible non-key blocks with writable hash fields. An inverted HASH_PREIMAGE with a garbage hash and arbitrary preimage data could land up to 32 bytes in the block. Removing standalone hash locks and requiring the compound blocks HTLC, HASH_SIG (which always require a signature), or HASH_GUARDED (which is non-invertible and fail-closed) closes this vector entirely.

The combined effect is that every byte in a Ladder Script transaction must conform to its declared type. There is no field in any active block type where an attacker can write arbitrary data without also providing a valid cryptographic proof.

### Coil Types

The coil determines the output semantics of a ladder-locked UTXO. It is serialised after the rung data.

| Code | Name | Description |
|------|------|-------------|
| `0x01` | UNLOCK | Standard unlock. The UTXO can be spent to any destination. |
| `0x02` | UNLOCK_TO | Unlock to a specific destination. The coil's `address_hash` field contains `SHA256(destination scriptPubKey)`. The raw address is never stored on-chain. The recipient must also satisfy any coil conditions. |
| `0x03` | COVENANT | Covenant. Constrains the structure of the spending transaction via coil conditions. |

### Attestation Modes

The attestation mode determines how signatures are provided for spends within a block.

| Code | Name | Description |
|------|------|-------------|
| `0x01` | INLINE | Signatures are provided inline in the witness, one per SIG/MULTISIG block. This is the default mode. |
| `0x02` | AGGREGATE | Block-level signature aggregation. A single aggregate signature covers all AGGREGATE-mode spends in one block. Each spend is identified by a SPEND_INDEX. All spends in an aggregate proof must use the same signature scheme. |
| `0x03` | DEFERRED | Deferred attestation via template hash. Currently specified but not activated (verification always returns false, failing closed). Reserved for future cross-chain and batch verification protocols. |

### Signature Schemes

The scheme selector determines which signature algorithm is used for verification.

| Code | Name | Key Size | Sig Size | Description |
|------|------|----------|----------|-------------|
| `0x01` | SCHNORR | 32 B | 64-65 B | BIP-340 Schnorr signatures (default). |
| `0x02` | ECDSA | 33 B | 8-72 B | ECDSA for legacy compatibility. |
| `0x10` | FALCON512 | 897 B | ~666 B | FALCON-512 post-quantum lattice signatures. |
| `0x11` | FALCON1024 | 1,793 B | ~1..32 B | FALCON-1024 post-quantum lattice signatures. |
| `0x12` | DILITHIUM3 | 1,952 B | 3,293 B | Dilithium3 (ML-DSA) post-quantum lattice signatures. |
| `0x13` | SPHINCS_SHA | 32 B | ~7,856 B | SPHINCS+-SHA256 post-quantum hash-based signatures. Stateless. |

Post-quantum schemes (codes >= `0x10`) require liboqs support compiled into the node. Verification against a PQ scheme without liboqs support returns false.

The merkle_pub_key mechanism enables commit-reveal PQ migration: the Merkle leaf commits to the SHA-256 hash of a PQ public key at fund time, while the witness reveals the full public key for verification at spend time. This prevents quantum adversaries from extracting keys from the conditions script before the spend occurs.

### Evaluation Rules

Ladder evaluation follows a strict three-level logic:

**Level 1, Ladder (OR):** Rungs are evaluated in order. The first rung that returns SATISFIED terminates evaluation with success. If all rungs return UNSATISFIED or ERROR, the ladder fails. ERROR from a rung causes fallthrough to the next rung (same as UNSATISFIED at the ladder level). However, ERROR from a relay is fatal. If any relay returns ERROR, the entire ladder fails immediately.

**Level 2, Rung (AND):** All blocks within a rung must return SATISFIED for the rung to be SATISFIED. Evaluation short-circuits on the first UNSATISFIED or ERROR result.

**Level 3, Block Inversion:** Each block has an `inverted` flag. When set:
- SATISFIED becomes UNSATISFIED
- UNSATISFIED becomes SATISFIED
- ERROR remains ERROR (never inverted)
- UNKNOWN_BLOCK_TYPE becomes ERROR (unknown types must not satisfy)

Only blocks listed in `IsInvertibleBlockType()` may be inverted. Attempting to invert a non-invertible block (any key-consuming block type) is rejected at deserialization.

**Unknown block types:** Unrecognized `block_type` values are rejected at deserialization. The deserializer calls `IsKnownBlockType()` on every block type encountered, whether from a micro-header slot or an escape header. Unknown types cause immediate deserialization failure at the consensus layer. A miner cannot include a transaction with an unknown block type. As defense in depth, the evaluator also handles unknown types: if one were to reach evaluation, it returns UNKNOWN_BLOCK_TYPE (non-SATISFIED when not inverted, ERROR when inverted). New block types are deployed via soft fork activation, which updates `IsKnownBlockType()` to accept them.

### Sighash

Ladder Script uses a tagged hash `TaggedHash("LadderSighash")` for signature computation. The algorithm is derived from BIP-341 sighash but simplified (no annex, no tapscript extensions, no code separator).

**Sighash computation commits to:**

```
epoch              = 0x00 (uint8)
hash_type          = uint8 (SIGHASH_DEFAULT=0, ALL=1, NONE=2, SINGLE=3,
                           ANYPREVOUT=0x40, ANYPREVOUTANYSCRIPT=0xC0, ANYONECANPAY=0x80)
tx_version         = int32
tx_locktime        = uint32

Unless ANYONECANPAY:
prevouts_hash      = SHA256(all input prevouts) — skipped if ANYPREVOUT
amounts_hash       = SHA256(all spent output amounts)
sequences_hash     = SHA256(all input sequences)

If SIGHASH_ALL (or DEFAULT):
outputs_hash       = SHA256(all outputs)

spend_type         = 0x00 (uint8, always 0 for ladder)

Input-specific:
  If ANYONECANPAY: prevout (skipped if ANYPREVOUT) + spent_output + sequence
  Else: input_index (uint32)

If SIGHASH_SINGLE:
output_hash        = SHA256(output at input_index)

conditions_hash    = SHA256(serialised rung conditions from spent output) — skipped if ANYPREVOUTANYSCRIPT
```

The `conditions_hash` commitment binds the signature to the specific locking conditions, preventing signature replay across different ladder-locked outputs even if they use the same key.

Valid `hash_type` values: `0x00` (DEFAULT/ALL), `0x01` (ALL), `0x02` (NONE), `0x03` (SINGLE), `0x40`-`0x43` (ANYPREVOUT variants), `0x81` (ALL|ANYONECANPAY), `0x82` (NONE|ANYONECANPAY), `0x83` (SINGLE|ANYONECANPAY), `0xC0`-`0xC3` (ANYPREVOUTANYSCRIPT variants). All other values are rejected.

ANYPREVOUT (`0x40`): Skips the prevouts hash commitment, enabling LN-Symmetry/eltoo. Still commits to amounts, sequences, and conditions.

ANYPREVOUTANYSCRIPT (`0xC0`): Skips both prevouts and conditions commitments. Enables signatures rebindable across different scripts.

### Consensus Limits

All structural limits are enforced at the consensus layer. Policy (`IsStandardRungTx`) performs a thin deserialize-only check plus MLSC output validation via `ValidateRungOutputs`. There is no separate `IsStandardRungOutput` function — output validation is consensus.

| Limit | Value | Layer | Rationale |
|-------|-------|-------|-----------|
| MAX_RUNGS | 16 | Consensus | Maximum rungs per ladder witness. 16 rungs provides sufficient path diversity for institutional custody with only 1 extra Merkle proof hash vs 8. |
| MAX_BLOCKS_PER_RUNG | 8 | Consensus | Maximum blocks per rung. Limits AND-condition depth. |
| MAX_FIELDS_PER_BLOCK | 16 | Consensus | Maximum typed fields per block. |
| MAX_LADDER_WITNESS_SIZE | 100,000 bytes | Consensus | Maximum total serialised witness size. Accommodates post-quantum signatures with headroom for multi-block rungs. |
| MAX_PREIMAGE_FIELDS_PER_WITNESS | 2 | Consensus | Maximum PREIMAGE/SCRIPT_BODY fields per witness. Limits user-chosen data to ~64 bytes (2 x 32 bytes). |
| MAX_RELAYS | 8 | Consensus | Maximum relay definitions per ladder witness. |
| MAX_REQUIRES | 8 | Consensus | Maximum relay requirements (co-spend input indices) per rung or relay. |
| MAX_RELAY_DEPTH | 4 | Consensus | Maximum transitive relay chain depth. Prevents unbounded recursive relay evaluation. |

All limits are enforced during deserialization:
- All block types must be known (`IsKnownBlockType` returns true; deprecated types return false).
- All data types must be known (`IsKnownDataType` returns true).
- All field sizes must conform to type constraints (`FieldMinSize` through `FieldMaxSize`).
- Conditions scripts must not contain PUBKEY, SIGNATURE, PREIMAGE, or SCRIPT_BODY fields.
- Key-consuming blocks must not have the inverted flag set.

### Address Format

Ladder Script outputs use the `rung1` human-readable prefix with Bech32m encoding (BIP-350). The address encodes the 32-byte Merkle root (the `scriptPubKey` payload after the `0xC2` prefix).

**Encoding:** Convert conditions bytes to 5-bit groups using Bech32 base conversion, then encode with `bech32::Encode(bech32::Encoding::BECH32M, "rung", data)`.

**Decoding:** Detect the `rung1` prefix, decode with Bech32m, convert from 5-bit groups to 8-bit bytes. The result is a `LadderDestination` in the `CTxDestination` variant type.

**Character limit:** 500 characters (`CharLimit::RUNG_ADDRESS`), accommodating variable-length conditions from simple single-block to complex multi-rung PQ conditions.

**Script detection:** The `Solver` identifies MLSC outputs by the `0xC2` prefix, returning `TxoutType::RUNG_CONDITIONS`.

### RPC Interface

The following RPCs are provided for wallet and application integration:

- `createrung` creates a rung conditions structure from a JSON description of blocks and fields.
- `decoderung` decodes a hex-encoded rung conditions structure to human-readable JSON.
- `validateladder` validates a raw v4 RUNG_TX transaction's ladder witnesses against its spent outputs.
- `createrungtx` creates an unsigned v4 RUNG_TX transaction with rung condition outputs.
- `signrungtx` signs a v4 RUNG_TX transaction's inputs given private keys and spent output information.
- `computectvhash` computes the BIP-119 CTV template hash for a v4 RUNG_TX transaction at a given input index.
- `generatepqkeypair` generates a post-quantum keypair for a specified scheme.
- `pqpubkeycommit` computes the SHA-256 pubkey commitment for a given public key (used internally during Merkle leaf computation).
- `extractadaptorsecret` extracts the adaptor secret from a pre-signature and adapted signature pair.
- `verifyadaptorpresig` verifies an adaptor pre-signature against a public key and adaptor point.

## Rationale

**Typed fields over opcodes.** By requiring every byte of witness data to belong to a declared type with enforced size constraints, Ladder Script eliminates the data smuggling vector inherent in arbitrary `OP_PUSH` operations. Static analysis tools can parse any ladder witness without executing it.

**Rung/block composition.** The AND-within-rung, OR-across-rungs model maps directly to how spending conditions are naturally expressed: "condition A AND condition B, OR alternatively condition C." This is more readable than equivalent stack manipulation in Script.

**Block type families.** Organizing block types into numbered ranges (0x0001-0x00FF for signatures, 0x0100-0x01FF for timelocks, etc.) allows new conditions to be added within families without exhausting a flat namespace. The `uint16_t` encoding provides 65,536 possible types.

**merkle_pub_key over PUBKEY_COMMIT fields.** Storing public key commitments as writable condition fields created a data embedding surface. Even with MLSC, an attacker could share the preimage off-chain and prove the data matches the on-chain root. Folding pubkeys into the Merkle leaf eliminates the writable field entirely. With MLSC on mainnet, the on-chain output is just `0xC2` plus a 32-byte Merkle root. All condition fields and all pubkeys are inside the Merkle tree, revealed only at spend time in the witness. There is no writable surface on-chain.

**Selective inversion.** The `inverted` flag provides NOT logic without a separate opcode. The restriction to non-key blocks prevents the garbage-pubkey attack where an inverted SIG block with a garbage key evaluates as SATISFIED. The `IsInvertibleBlockType()` allowlist is fail-closed: new block types default to non-invertible and must be explicitly added.

**Hash lock deprecation.** Standalone HASH_PREIMAGE and HASH160_PREIMAGE blocks were invertible and had writable hash fields, creating a data embedding surface. Compound blocks (HTLC, HASH_SIG) serve all legitimate hash-lock use cases while requiring a signature, which makes inversion attacks infeasible. HASH_GUARDED provides a safe non-invertible alternative for raw SHA-256 preimage verification without requiring a signature.

**Fail-closed unknown type handling.** Unknown block types return UNSATISFIED when not inverted and ERROR when inverted. This prevents an attacker from crafting conditions with fabricated block types that pass validation via inversion.

**Post-quantum signature support.** The PUBKEY maximum of 2,048 bytes and SIGNATURE maximum of 50,000 bytes were chosen to accommodate all NIST post-quantum finalist schemes including SPHINCS_SHA. The merkle_pub_key mechanism enables commit-reveal PQ migration: the Merkle leaf commits to the SHA-256 hash of a PQ public key at fund time, revealing the full key only at spend time.

**Coil separation.** Separating input conditions (rungs) from output semantics (coil) provides a clean interface between "who can spend" and "where it can go." This makes covenant logic (UNLOCK_TO, COVENANT coil types) orthogonal to signature and timelock logic.

**PLC block types.** The Programmable Logic Controller family (hysteresis, timers, latches, counters, comparators, sequencers) is borrowed from industrial automation where these primitives have decades of proven reliability. They enable stateful transaction logic without requiring a general-purpose virtual machine.

**Conditions hash in sighash.** Including the SHA-256 hash of the serialised locking conditions in the sighash computation prevents signature reuse across different ladder outputs that happen to use the same key. This is analogous to BIP-341's tapleaf hash commitment.

**Policy vs. consensus limits.** MAX_RUNGS, MAX_BLOCKS_PER_RUNG, and MAX_FIELDS_PER_BLOCK are enforced at both policy and consensus layers. The MAX_LADDER_WITNESS_SIZE limit at 100,000 bytes accommodates post-quantum signatures with headroom for multi-block rungs while preventing witness bloat attacks.

## Examples

The following examples demonstrate common spending patterns expressed as Ladder Script conditions. Each example shows the rung/block structure and the RPC JSON for `createrungtx`.

### Example 1: Single Signature

The simplest possible RUNG_TX: a single SIG rung with one output.

**Rung structure:**
```
Rung 0 (SPEND):
  SIG { scheme: SCHNORR }
  Merkle leaf binds: pk_owner
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

The RPC accepts the full pubkey in the `pubkey` field. During condition construction, the pubkey is folded into the Merkle leaf hash. The on-chain conditions contain only the SCHEME field (1 byte). The full pubkey is provided in the witness at spend time and verified against the Merkle proof.

### Example 2: 2-of-3 Multisig Vault with Time-Locked Recovery

A vault with daily multisig spending and an emergency cold-key sweep after one year.

**Rung structure:**
```
Rung 0 (SPEND):
  MULTISIG { threshold: 2, pubkeys: [pk1, pk2, pk3] }
  AMOUNT_LOCK { min: 546, max: 5000000 }

Rung 1 (SWEEP):
  CSV { blocks: 52560 }
  SIG { scheme: SCHNORR }
  Merkle leaf binds: pk_cold
```

**Evaluation:** Rung 0 requires 2-of-3 signatures AND the output amount to be between 546 and 5,000,000 sats (AND logic within rung). If Rung 0 fails, Rung 1 is tried: it requires the UTXO to be at least ~1 year old (52,560 blocks) AND a cold key signature (OR logic across rungs).

### Example 3: Atomic Swap (HTLC)

Cross-chain atomic swap using the HTLC compound block. Alice claims with the hash preimage; Bob refunds after timeout.

**Rung structure:**
```
Rung 0 (CLAIM):
  HTLC { payment_hash: <sha256>, timeout: 144 }
  Merkle leaf binds: pk_alice, pk_bob

Rung 1 (REFUND):
  TIMELOCKED_SIG { scheme: SCHNORR, blocks: 144 }
  Merkle leaf binds: pk_bob
```

**Evaluation:** Alice spends via Rung 0 by providing the preimage (which Bob can then extract from the published transaction to claim on the other chain) plus her signature. If Alice never claims, Bob uses Rung 1 after 144 blocks.

### Example 4: DCA Covenant Chain

Dollar-cost averaging vault that enforces periodic fixed-amount withdrawals using RECURSE_SAME re-encumbrance.

**Rung structure:**
```
Rung 0 (DCA):
  SIG { scheme: SCHNORR }
  AMOUNT_LOCK { min: 100000, max: 100000 }
  RECURSE_SAME { max_depth: 1000 }
  Merkle leaf binds: pk_owner
```

**Evaluation:** Each spend is limited to exactly 100,000 sats by AMOUNT_LOCK. The RECURSE_SAME block forces at least one output to carry identical rung conditions, creating a perpetual chain of fixed-size withdrawals. The covenant continues until the UTXO balance falls below the withdrawal amount or the owner adds an alternative rung for termination.

### Example 5: Governance-Gated Treasury

Treasury with spending windows, I/O limits, weight cap, and anti-siphon ratio enforcement.

**Rung structure:**
```
Rung 0 (GOVERNED):
  SIG { scheme: SCHNORR }
  EPOCH_GATE { epoch_size: 2016, window_size: 144 }
  INPUT_COUNT { min: 1, max: 3 }
  OUTPUT_COUNT { min: 1, max: 2 }
  WEIGHT_LIMIT { max_weight: 400000 }
  RELATIVE_VALUE { numerator: 9, denominator: 10 }
  Merkle leaf binds: pk_treasurer

Rung 1 (OVERRIDE):
  MULTISIG { threshold: 3, pubkeys: [pk1, pk2, pk3, pk4] }
```

**Evaluation:** The treasurer can spend only during a 144-block window per 2016-block epoch, with at most 3 inputs and 2 outputs, under the standard weight limit, and must return at least 90% of the input value as change (anti-siphon). The 3-of-4 board override bypasses all governance constraints.

### Example 6: Post-Quantum Vault with Classical Hot Path

Hybrid vault: Schnorr for daily use, FALCON-512 for long-term cold storage.

**Rung structure:**
```
Rung 0 (HOT):
  SIG { scheme: SCHNORR }
  AMOUNT_LOCK { min: 546, max: 1000000 }
  Merkle leaf binds: pk_schnorr

Rung 1 (PQ_COLD):
  CSV { blocks: 4320 }
  SIG { scheme: FALCON512 }
  Merkle leaf binds: pk_falcon
```

**Evaluation:** Daily spending uses Schnorr with an amount cap. After ~30 days (4,320 blocks), the FALCON-512 cold key can sweep everything. The merkle_pub_key mechanism means the 897-byte FALCON-512 public key is only revealed at spend time. The on-chain conditions store only a 1-byte SCHEME field per SIG block.

### Example 7: Legacy P2PKH Wrapped as Ladder Block

Legacy Bitcoin P2PKH semantics wrapped in typed fields, closing arbitrary-data surfaces.

**Rung structure:**
```
Rung 0 (SPEND):
  P2PKH_LEGACY { hash160: <20-byte HASH160 of pubkey> }

Rung 1 (RECOVER):
  CSV { blocks: 52560 }
  SIG { scheme: SCHNORR }
  Merkle leaf binds: pk_recovery
```

**Evaluation:** Rung 0 uses P2PKH_LEGACY. The spender provides a pubkey whose HASH160 matches the committed hash, plus a signature. Identical to Bitcoin P2PKH semantics, but expressed as typed fields with no room for data embedding. Rung 1 adds a native Ladder Script recovery path that was not possible in legacy P2PKH.

## Backward Compatibility

**Non-upgraded nodes.** Transaction version 4 is currently non-standard in Bitcoin Core. No existing software creates v4 transactions. Non-upgraded nodes treat v4 transactions as anyone-can-spend, which is the standard soft fork upgrade path established by BIP-141 (Segregated Witness) and BIP-341 (Taproot).

**Existing transactions.** Ladder Script does not modify the validation rules for transaction versions 1 or 2. All existing UTXOs, scripts, and spending paths remain valid and unchanged.

**Wallet compatibility.** Wallets that do not implement Ladder Script can still:
- Receive funds to ladder-locked outputs (they appear as non-standard scriptPubKey types).
- Track ladder-locked UTXOs in their UTXO set.
- Construct transactions that spend non-ladder inputs alongside ladder inputs (mixed-version inputs are valid).

Wallets cannot spend ladder-locked outputs without implementing the ladder evaluator and sighash computation.

**Coexistence.** Version 4 transactions coexist with all existing transaction versions. No existing transaction type is deprecated or modified by this proposal.

## Weight and Fee Accounting

`RUNG_TX` inherits the SegWit witness discount without modification. Transaction weight is computed by Bitcoin Core's existing `GetTransactionWeight()` function, which applies the standard `WITNESS_SCALE_FACTOR` (4):

| Component | Location | Weight |
|-----------|----------|--------|
| MLSC output (`0xC2` prefix) | `scriptPubKey` (non-witness) | 4 WU per byte |
| Witness (signatures, keys, preimages, SCRIPT_BODY) | Witness field | 1 WU per byte |
| Transaction structure (version, inputs, outputs, locktime) | Non-witness | 4 WU per byte |

This weighting naturally incentivises the design choices Ladder Script already makes:

- **Small conditions, large witness.** With merkle_pub_key, SIG conditions are 1 byte (SCHEME only) in conditions (4 WU) rather than 33 bytes with a PUBKEY_COMMIT field (132 WU). The full key is revealed in the witness at 1 WU per byte.
- **Node-computed hashes.** Hash commitments in conditions are 20-32 bytes regardless of preimage size. The preimage or SCRIPT_BODY is witness-only.
- **MLSC (Merkelised conditions).** A Merkle root stores 32 bytes in conditions. Unrevealed branches have zero weight. Revealed conditions pay witness weight.

No custom weight function is required. Virtual transaction size (`vsize`) for fee estimation uses `GetVirtualTransactionSize()`, identical to SegWit and Taproot transactions.

## Deployment

Activation uses BIP-9 version bits signaling with Speedy Trial parameters, following the precedent established by BIP-341 (Taproot):

| Parameter | Value |
|-----------|-------|
| Consensus name | `ladder` |
| Bit | (to be assigned) |
| Start time | (to be determined) |
| Timeout | Start time + 31,536,000 seconds (365 days) |
| Threshold | 90% (1,815 of 2,016 blocks per retarget period) |
| Minimum activation height | (to be determined) |

All 59 active block types activate simultaneously as a single deployment. Upon activation, all block types across all ten families are consensus-enforced and policy-standard. Partial activation of individual block types is not supported; the evaluation engine, wire format, and sighash computation form an interdependent whole.

Nodes that have not upgraded treat version 4 transactions as anyone-can-spend, consistent with the soft fork upgrade path established by BIP-141 and BIP-341.

## Reference Implementation

The reference implementation is located in the `src/rung/` directory. A step-by-step review guide (`docs/REVIEW_GUIDE.md`) provides a recommended reading order. Start with `types.h` for the type system, then pick any single block evaluator to understand the pattern before reviewing the full set.

| File | Purpose |
|------|---------|
| `types.h` / `types.cpp` | Core type definitions: `RungBlockType`, `RungDataType`, `RungCoilType`, `RungAttestationMode`, `RungScheme`, helper functions (`IsKnownBlockType`, `IsKeyConsumingBlockType`, `IsInvertibleBlockType`, `PubkeyCountForBlock`), and all struct definitions. |
| `conditions.h` / `conditions.cpp` | Conditions (locking side): `RungConditions`, MLSC Merkle tree with `0xC2` prefix, `ComputeRungLeaf` with pubkey folding, `ComputeConditionsRoot`, template inheritance resolution. |
| `serialize.h` / `serialize.cpp` | Wire format serialization/deserialization with micro-headers, implicit fields, varint NUMERIC, context-aware encoding, and policy limit constants. |
| `evaluator.h` / `evaluator.cpp` | Block evaluators for all 61 block types (59 active + 2 deprecated). Rung AND logic, ladder OR logic, selective inversion enforcement. `VerifyRungTx` entry point. `ValidateRungOutputs` (consensus-level output validation). `LadderSignatureChecker` for Schnorr/PQ signature verification. |
| `sighash.h` / `sighash.cpp` | `SignatureHashLadder` tagged hash computation. |
| `policy.h` / `policy.cpp` | Mempool policy enforcement: `IsStandardRungTx` (thin deserialize-only check). `IsStandardRungOutput` removed — output validation is consensus via `ValidateRungOutputs`. |
| `aggregate.h` / `aggregate.cpp` | Block-level signature aggregation and deferred attestation. |
| `adaptor.h` / `adaptor.cpp` | Adaptor signature creation, verification, and secret extraction. |
| `pq_verify.h` / `pq_verify.cpp` | Post-quantum signature verification via liboqs (FALCON-512/1024, Dilithium3, SPHINCS_SHA). |
| `descriptor.h` / `descriptor.cpp` | Descriptor language: `ParseDescriptor` and `FormatDescriptor` for compact string representation of conditions. `parseladder` and `formatladder` RPCs. |
| `rpc.cpp` | RPC commands: `createrung`, `decoderung`, `validateladder`, `createrungtx`, `signrungtx`, `computectvhash`, `generatepqkeypair`, `pqpubkeycommit`, `extractadaptorsecret`, `verifyadaptorpresig`, `parseladder`, `formatladder`. |

### Implementation Footprint

Despite activating 59 active block types across 10 families, Ladder Script's consensus footprint is smaller and more contained than previous soft forks:

| Metric | SegWit (BIP 141/143/144) | Taproot (BIP 340/341/342) | Ladder Script |
|--------|--------------------------|---------------------------|---------------|
| **Consensus files changed** | 32 | 44 | 19 |
| **Lines added** | +5,305 | +2,985 | +9,846 |
| **Lines removed** | -571 | -121 | 0 |
| **Files outside new code** | ~60 | ~30 | ~5 |
| **Test lines** | (included above) | (included above) | +20,521 |
| **Core PRs** | PR #8149 | PR #19953 + secp256k1 #558 | Single patch |

**Key difference: containment.** SegWit modified 80 existing files across `src/script/`, `src/consensus/`, `src/primitives/`, `src/wallet/`, `src/net_processing.cpp`, and the serialization layer. Taproot modified 44 files across similar directories plus a prerequisite Schnorr module in libsecp256k1.

Ladder Script adds 19 new files in a single directory (`src/rung/`) and touches approximately 5 existing files for integration (transaction validation dispatch, RPC registration, build system). Removing `src/rung/` restores Bitcoin Core to its unmodified state. No existing consensus logic, serialization code, or wallet code is altered.

The line count is higher because Ladder Script replaces the entire Script evaluation model rather than extending it. But the review surface is modular: each block type is a self-contained evaluator function (~20-80 lines) with its own field layout and test cases. A reviewer can audit one block type without understanding the others.

## Test Vectors

The implementation includes comprehensive test coverage across two layers:

**Unit tests** (`src/test/rung_tests.cpp`): 480 test cases covering:
- Field validation for all 10 active data types with boundary conditions
- Serialization round-trips for all 59 active block types
- Deserialization rejection of deprecated types (HASH_PREIMAGE, HASH160_PREIMAGE)
- Deserialization rejection of malformed inputs (empty, truncated, trailing bytes, oversized, unknown types)
- Block evaluation for all 59 active block types
- Inversion logic including ERROR non-inversion and selective inversion enforcement
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
- merkle_pub_key leaf computation with positional pubkey binding
- Inverted key-consuming block rejection at deserialization
- Cross-phase integration (multi-block, multi-rung optimised roundtrips)

**Functional tests** (60 regtest functional tests across 6 test suites) covering:
- RPC interface for rung creation, decoding, and validation
- Full transaction lifecycle (create, sign, broadcast, confirm, spend) for all block types
- Negative tests (wrong signature, wrong preimage, timelock too early, wrong template, wrong key)
- Multi-input/multi-output transactions
- Inversion (inverted CSV, inverted hash, inverted compare)
- Compound conditions (SIG+CSV+HASH triple AND, hot/cold vault OR patterns)
- Recursive chains (RECURSE_SAME, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_MODIFIED, RECURSE_SPLIT, RECURSE_DECAY)
- PLC patterns (hysteresis, rate limit, sequencer, latch state machines, counter state gating, one-shot)
- COSIGN anchor spend and 10-child fan-out
- Post-quantum FALCON-512 signature verification
- Anti-spam validation (arbitrary preimage rejection, unknown data types, oversized fields, structure limits)
- Deeply nested covenant chains

Additional functional tests:
- `tests/functional/rung_p2p.py`: P2P relay of v4 transactions between nodes.
- `tests/functional/rung_pq_block.py`: Post-quantum block-level tests.
- `tests/functional/rung_mlsc.py`: MLSC (Merkelised Ladder Script Conditions) tests.
- `tests/functional/rung_signet.py`: Signet integration tests.
- `tests/functional/rung_key_ref_sig.py`: KEY_REF_SIG relay-based signature tests.

**Fuzz testing** (`src/test/fuzz/rung_deserialize.cpp`): Continuous fuzz testing of the deserialization path.

## Security Considerations

### Anti-Spam Surface Analysis

Ladder Script's typed field system eliminates all known data embedding vectors present in Bitcoin Script:

1. **No arbitrary pushes.** Every byte in a RUNG_TX witness belongs to a declared data type with enforced min/max sizes. There are no `OP_PUSH` equivalents and no `OP_FALSE OP_IF` envelopes.

2. **No writable pubkey fields.** The merkle_pub_key design removes PUBKEY_COMMIT from condition layouts. An attacker constructing a raw transaction cannot write arbitrary data into a commitment field because the field does not exist in any block's condition layout.

3. **No invertible key blocks.** Selective inversion prevents the garbage-pubkey attack on all 24 key-consuming block types. Attempting to set the inverted flag on a SIG, MULTISIG, or any other key block is rejected at deserialization.

4. **No standalone hash locks.** HASH_PREIMAGE and HASH160_PREIMAGE are deprecated and rejected at deserialization. The compound blocks HTLC and HASH_SIG require a valid signature alongside the hash preimage, preventing inversion attacks. HASH_GUARDED provides safe standalone hash verification by being non-invertible (fail-closed).

5. **Typed inner conditions.** The SCRIPT_BODY field in legacy wrapper blocks (P2SH_LEGACY, P2WSH_LEGACY, P2TR_SCRIPT_LEGACY) must deserialize as valid Ladder Script conditions. Arbitrary byte sequences are rejected.

6. **DATA_RETURN cap.** The DATA field type has a maximum of 40 bytes. DATA_RETURN data is appended to the MLSC scriptPubKey after the Merkle root (`0xC2 || root || data`), making it visible on-chain at 34-73 bytes total. The output must be zero-value. The data sits in `scriptPubKey` at 4 WU per byte, making 40 bytes cost 160 WU. This is significantly tighter than OP_RETURN's current default limit and more expensive per byte.

The combined effect is that every byte in a RUNG_TX must conform to its declared type. The only explicitly permitted data embedding is DATA_RETURN: 40 bytes maximum, zero-value, appended to the MLSC output, and economically disincentivised by the 4x weight multiplier on conditions-side data.

### COSIGN Mempool Griefing

The COSIGN block type (0x0681) creates a transaction-level dependency: a child UTXO can only be spent in a transaction that also spends a specific anchor UTXO. An attacker who observes a pending child spend could attempt to independently spend the anchor, orphaning the child transaction.

This is a mempool-level nuisance, not a consensus vulnerability. No funds can be stolen. Production anchors should include a SIG block to prevent unauthorised spending. Anchors using RECURSE_SAME require the spending transaction to create a new output with identical conditions. The attacker pays fees per griefing attempt while the defender's cost is updating a single outpoint reference. This is analogous to the anchor output griefing vector in Lightning Network commitment transactions (BOLT-3).

### Recursive Covenant Termination

RECURSE_* blocks fall into two categories:

**Bounded covenants:**

| Block Type | Termination | Proof |
|------------|-------------|-------|
| RECURSE_MODIFIED | `max_depth == 0` -> UNSATISFIED | Finite unsigned integer, decremented per spend |
| RECURSE_UNTIL | `block_height >= target` -> SATISFIED | Block height is monotonically increasing |
| RECURSE_COUNT | `count == 0` -> UNSATISFIED | Decremented per spend via RECURSE_MODIFIED |
| RECURSE_SPLIT | `max_splits == 0` -> UNSATISFIED | Decremented per split level |
| RECURSE_DECAY | `max_depth == 0` -> UNSATISFIED | Same as RECURSE_MODIFIED |

**Perpetual covenants:**

| Block Type | Behaviour | Termination |
|------------|-----------|-------------|
| RECURSE_SAME | Output must carry identical conditions. max_depth is a liveness gate (> 0 required) but never decrements because the output must be identical. | Requires companion blocks or UTXO balance falling below dust. |

### Post-Quantum Library Dependency

Post-quantum signature verification uses the Open Quantum Safe project's liboqs library. The dependency is structured to minimise consensus risk:

- **Optional.** Nodes compile and run without liboqs (`HAVE_LIBOQS` flag). Without it, all PQ verification returns false (fail-closed).
- **Verification-only.** liboqs is used exclusively for `OQS_SIG_verify`, not for key generation or signing in consensus paths.
- **Deterministic.** FALCON and Dilithium verification is a mathematical equation: given identical inputs, any correct implementation produces the same result.
- **Pinned version.** The build system pins a specific liboqs release.
- **Algorithm stability.** FALCON and Dilithium are NIST-standardised (FIPS 204, FIPS 206). The verification equations are fixed by the standard.

**Scheme swappability.** Adding or replacing a signature scheme requires only a new `RungScheme` enum value, a verification function in `pq_verify.cpp`, and key generation support in the `generatepqkeypair` RPC. No changes to the wire format, serialization, evaluation framework, sighash computation, or any existing block type. If NIST revises or deprecates a standard, a new scheme can be added in a soft fork while existing schemes continue to function.

### Post-Quantum Multi-Scheme Composition

Ladder Script's rung/block structure enables security constructions not possible in any other Bitcoin transaction format. Blocks compose with AND logic within a rung and OR logic across rungs, so multiple post-quantum schemes can be combined in a single output.

**AND composition (defence in depth):**
```
Rung 0:  SIG(SCHNORR) + SIG(FALCON-512)
```
Both signatures must be satisfied. A quantum computer breaking secp256k1 Schnorr cannot spend the output without also breaking FALCON. Neither cryptographic assumption failing alone is fatal.

**Cross-family scheme diversity:**
```
Rung 0:  SIG(FALCON-512) + SIG(DILITHIUM3)
```
FALCON is based on NTRU lattices. Dilithium is based on module lattices (Module-LWE). These are distinct mathematical structures. A cryptanalytic advance against one lattice family does not automatically break the other.

**OR fallback across rungs (scheme migration):**
```
Rung 0:  SIG(FALCON-512)        primary spend path
Rung 1:  SIG(FALCON-1024)       fallback if 512 is weakened
Rung 2:  SIG(SPHINCS_SHA)       hash-based, independent assumption
```
SPHINCS+ security reduces to SHA-256 collision resistance rather than any lattice assumption. If every lattice-based scheme is simultaneously broken, SPHINCS+ still stands.

**COSIGN (efficient PQ coverage for existing wallets):**
```
Anchor UTXO:   SIG(FALCON-512) + RECURSE_SAME(max_depth=1000)
Child UTXOs:   COSIGN(anchor_hash)
```
A single FALCON-512 anchor UTXO provides quantum protection for unlimited classical child outputs (theoretical max depth ~4.3 billion spends, limited by the 4-byte NUMERIC field). Each child spends only when the anchor is co-spent (and recreated via RECURSE_SAME). The PQ witness cost is paid once per transaction, not once per output. This is the practical migration path for wallets with many existing classical UTXOs.

### Condition Opacity

MLSC outputs (`0xC2`) store only a 32-byte Merkle root in the UTXO set. This root is computationally indistinguishable from random data.

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
| P2PKH | `OP_DUP OP_HASH160 <20B hash> ...` | HASH160 of pubkey. No target until spend |
| P2WPKH | `OP_0 <20B hash>` | Same as P2PKH |
| P2TR | `OP_1 <32B x-only pubkey>` | **Yes. x-only pubkey is a Shor's algorithm target** |
| P2QRH (BIP-360) | `OP_2 <32B hash>` | Hash of PQ key. Reveals a PQ key exists |
| MLSC | `0xC2 <32B Merkle root>` | **Nothing. Root is indistinguishable from random** |

At spend time, only the satisfied rung is revealed in the witness. Unsatisfied rungs remain hidden behind the Merkle proof.

**Caveat (condition reuse):** If identical conditions are used across multiple outputs (same Merkle root), spending one output reveals the structure for all outputs sharing that root. Implementations SHOULD generate unique condition trees per output where possible.

### 0xC2 Prefix Collision Analysis

The `0xC2` byte identifies Ladder Script MLSC outputs as the first byte of scriptPubKey.

- **Standard output types.** P2PKH starts with `0x76` (OP_DUP), P2SH with `0xa9` (OP_HASH160), witness v0 with `0x00` (OP_0), witness v1 with `0x51` (OP_1), OP_RETURN with `0x6a`. None use `0xC2`.
- **Witness version range.** BIP-141 witness versions use `OP_0` (`0x00`) through `OP_16` (`0x60`). `0xC2` is outside this range.
- **Data push range.** Script data push opcodes occupy `0x01`-`0x4E`. `0xC2` is outside this range.
- **Opcode range.** `0xC2` falls in the undefined opcode range (`0xBB`-`0xFE`), above `OP_CHECKSIGADD` (`0xBA`). It is not assigned to any defined Script opcode.
- **Soft fork compatibility.** Non-upgraded nodes encountering a `0xC2` scriptPubKey treat it as a non-standard output type, which is the correct behaviour for soft fork deployment.

## Copyright

This document is placed in the public domain.
