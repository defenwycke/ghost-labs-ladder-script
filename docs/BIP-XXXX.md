```
BIP: XXXX
Layer: Consensus (soft fork)
Title: Ladder Script: Typed Structured Transaction Conditions
Author: Bitcoin Ghost <dev@bitcoinghost.org>
Status: Draft
Type: Standards Track
Created: 2026-03-16
License: MIT
```

## Abstract

This document specifies Ladder Script, a typed transaction format that replaces
raw Bitcoin Script opcodes with a structured schema of typed function blocks.
Every byte in a Ladder Script witness belongs to a typed field; no arbitrary
data pushes are possible. Spending conditions are organized as a ladder of
rungs (OR logic) where each rung contains one or more blocks (AND logic).
Outputs use Merkelised Ladder Script Conditions (MLSC) to commit to a Merkle
root of the full condition set, revealing only the satisfied rung at spend
time. The format supports post-quantum signature schemes, covenant and
recursion primitives, programmable logic controller (PLC) blocks for stateful
contracts, and a descriptor language for human-readable policy specification.
Ladder Script transactions use version 4 (`RUNG_TX_VERSION = 4`).

## Motivation

Bitcoin Script is a stack-based language where spending conditions are
expressed as sequences of raw opcodes operating on untyped byte arrays. This
design creates several problems that Ladder Script addresses:

**Typed fields eliminate arbitrary data embedding.** In Bitcoin Script, any
opcode can push arbitrary bytes onto the stack. Ladder Script enforces that
every witness byte belongs to a typed field (PUBKEY, SIGNATURE, HASH256,
NUMERIC, etc.) with size constraints validated at deserialization. Combined
with the `merkle_pub_key` design (public keys are folded into the Merkle leaf
hash rather than carried in conditions), the maximum embeddable user-chosen
data per transaction is bounded to 64 bytes (two 32-byte PREIMAGE fields).

**Structured blocks enable bounded execution.** Each block type has a fixed
evaluation function with known computational cost. There are no loops, no
arbitrary stack manipulation, and no unbounded recursion. Evaluation
terminates in O(blocks * fields) time.

**Post-quantum readiness.** The SCHEME field routes signature verification to
classical (Schnorr, ECDSA) or post-quantum (FALCON-512, FALCON-1024,
Dilithium3, SPHINCS+-SHA2-256f) algorithms. PQ signatures require no script
changes; the same block types work with any supported scheme.

**Anti-spam by construction.** Selective inversion restricts which block types
may be inverted (key-consuming blocks are never invertible). The
`IsDataEmbeddingType` check rejects high-bandwidth data types in blocks
without implicit layouts. The DATA type is restricted to DATA_RETURN blocks.
PREIMAGE fields are capped at 2 per witness. These properties are enforced at
deserialization, not evaluation.

**MLSC privacy.** Merkelised conditions reveal only the spending path used.
Unused rungs, their pubkeys, and their conditions remain hidden behind Merkle
proof hashes.

## Specification

### 4.a Transaction Format

A Ladder Script transaction has `nVersion = 4`. All outputs MUST be valid
Ladder Script outputs. All inputs MUST provide a witness stack of exactly 2
elements:

- `witness[0]`: Serialized `LadderWitness` (the spending witness)
- `witness[1]`: Serialized `MLSCProof` (revealed conditions and Merkle proof)

The transaction is verified by `VerifyRungTx`, which:

1. Validates all outputs via `ValidateRungOutputs`
2. Deserializes the `LadderWitness` from `witness[0]`
3. Resolves witness references if the witness uses diff encoding
4. Deserializes the `MLSCProof` from `witness[1]`
5. Extracts pubkeys from the witness for `merkle_pub_key` leaf computation
6. Verifies the Merkle proof against the UTXO's conditions root
7. Merges conditions (from proof) with witness (from `witness[0]`)
8. Evaluates the merged ladder via `EvalLadder`

### 4.b Output Format

Every output in a version 4 transaction MUST use the MLSC format:

```
scriptPubKey = 0xC2 || conditions_root(32 bytes)
```

This produces a 33-byte scriptPubKey. Optionally, a DATA_RETURN payload of
1 to 40 bytes may be appended:

```
scriptPubKey = 0xC2 || conditions_root(32 bytes) || data(1-40 bytes)
```

DATA_RETURN outputs with appended data MUST have zero value (unspendable).
At most one DATA_RETURN output is permitted per transaction.

Inline conditions (prefix `0xC1`) are removed and always rejected.

### 4.c Block Type Families

Ladder Script defines 61 block types across 10 families. Each block type is
encoded as a `uint16_t` (little-endian).

#### Signature Family (0x0001 - 0x00FF)

| Code     | Name             | Description                                         |
|----------|------------------|-----------------------------------------------------|
| `0x0001` | SIG              | Single signature verification                       |
| `0x0002` | MULTISIG         | M-of-N threshold signature                          |
| `0x0003` | ADAPTOR_SIG      | Adaptor signature verification                      |
| `0x0004` | MUSIG_THRESHOLD  | MuSig2/FROST aggregate threshold signature          |
| `0x0005` | KEY_REF_SIG      | Signature using key commitment from a relay block    |

#### Timelock Family (0x0100 - 0x01FF)

| Code     | Name       | Description                                   |
|----------|------------|-----------------------------------------------|
| `0x0101` | CSV        | Relative timelock, block-height (BIP 68)      |
| `0x0102` | CSV_TIME   | Relative timelock, median-time-past           |
| `0x0103` | CLTV       | Absolute timelock, block-height (nLockTime)   |
| `0x0104` | CLTV_TIME  | Absolute timelock, median-time-past           |

#### Hash Family (0x0200 - 0x02FF)

| Code     | Name             | Description                                     |
|----------|------------------|-------------------------------------------------|
| `0x0203` | TAGGED_HASH      | BIP-340 tagged hash verification                 |
| `0x0204` | HASH_GUARDED     | Raw SHA256 preimage verification (non-invertible)|

Codes 0x0201 and 0x0202 are reserved (not assigned to any block type).

#### Covenant Family (0x0300 - 0x03FF)

| Code     | Name        | Description                                  |
|----------|-------------|----------------------------------------------|
| `0x0301` | CTV         | OP_CHECKTEMPLATEVERIFY covenant (BIP 119)     |
| `0x0302` | VAULT_LOCK  | Two-path vault timelock covenant              |
| `0x0303` | AMOUNT_LOCK | Output amount range check                     |

#### Recursion Family (0x0400 - 0x04FF)

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0401` | RECURSE_SAME     | Re-encumber with identical conditions          |
| `0x0402` | RECURSE_MODIFIED | Re-encumber with parameterized mutations       |
| `0x0403` | RECURSE_UNTIL    | Recursive until block height                   |
| `0x0404` | RECURSE_COUNT    | Recursive countdown                            |
| `0x0405` | RECURSE_SPLIT    | Recursive output splitting                     |
| `0x0406` | RECURSE_DECAY    | Recursive parameter decay                      |

#### Anchor Family (0x0500 - 0x05FF)

| Code     | Name           | Description                                  |
|----------|----------------|----------------------------------------------|
| `0x0501` | ANCHOR         | Generic anchor                                |
| `0x0502` | ANCHOR_CHANNEL | Lightning channel anchor                      |
| `0x0503` | ANCHOR_POOL    | Pool anchor                                   |
| `0x0504` | ANCHOR_RESERVE | Reserve anchor (guardian set)                  |
| `0x0505` | ANCHOR_SEAL    | Seal anchor                                   |
| `0x0506` | ANCHOR_ORACLE  | Oracle anchor                                 |
| `0x0507` | DATA_RETURN    | Unspendable data commitment (max 40 bytes)    |

#### PLC Family (0x0600 - 0x06FF)

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0601` | HYSTERESIS_FEE   | Fee rate hysteresis band                       |
| `0x0602` | HYSTERESIS_VALUE | Value hysteresis band                          |
| `0x0611` | TIMER_CONTINUOUS | Continuous timer (consecutive blocks)          |
| `0x0612` | TIMER_OFF_DELAY  | Off-delay timer (hold after trigger)           |
| `0x0621` | LATCH_SET        | Latch set (state activation)                   |
| `0x0622` | LATCH_RESET      | Latch reset (state deactivation)               |
| `0x0631` | COUNTER_DOWN     | Down counter (decrement on event)              |
| `0x0632` | COUNTER_PRESET   | Preset counter (approval accumulator)          |
| `0x0633` | COUNTER_UP       | Up counter (increment on event)                |
| `0x0641` | COMPARE          | Comparator (amount vs thresholds)              |
| `0x0651` | SEQUENCER        | Step sequencer                                 |
| `0x0661` | ONE_SHOT         | One-shot activation window                     |
| `0x0671` | RATE_LIMIT       | Rate limiter                                   |
| `0x0681` | COSIGN           | Cross-input co-spend constraint                |

COSIGN (`0x0681`) occupies the PLC range but functions as a cross-input
signature constraint, requiring another input with a matching conditions hash.

#### Compound Family (0x0700 - 0x07FF)

| Code     | Name                | Description                                |
|----------|---------------------|--------------------------------------------|
| `0x0701` | TIMELOCKED_SIG      | SIG + CSV combined                          |
| `0x0702` | HTLC                | Hash + Timelock + Sig (atomic swap)         |
| `0x0703` | HASH_SIG            | Hash preimage + signature combined                |
| `0x0704` | PTLC                | ADAPTOR_SIG + CSV combined                  |
| `0x0705` | CLTV_SIG            | SIG + CLTV combined                         |
| `0x0706` | TIMELOCKED_MULTISIG | MULTISIG + CSV combined                     |

#### Governance Family (0x0800 - 0x08FF)

| Code     | Name           | Description                                    |
|----------|----------------|------------------------------------------------|
| `0x0801` | EPOCH_GATE     | Periodic spending window                        |
| `0x0802` | WEIGHT_LIMIT   | Maximum transaction weight limit                |
| `0x0803` | INPUT_COUNT    | Input count bounds                              |
| `0x0804` | OUTPUT_COUNT   | Output count bounds                             |
| `0x0805` | RELATIVE_VALUE | Output value as ratio of input                  |
| `0x0806` | ACCUMULATOR    | Merkle accumulator (set membership proof)       |
| `0x0807` | OUTPUT_CHECK   | Per-output value and script constraint           |

#### Legacy Family (0x0900 - 0x09FF)

| Code     | Name               | Description                                |
|----------|--------------------|--------------------------------------------|
| `0x0901` | P2PK_LEGACY        | Wrapped P2PK                                |
| `0x0902` | P2PKH_LEGACY       | Wrapped P2PKH                               |
| `0x0903` | P2SH_LEGACY        | Wrapped P2SH                                |
| `0x0904` | P2WPKH_LEGACY      | Wrapped P2WPKH                              |
| `0x0905` | P2WSH_LEGACY       | Wrapped P2WSH                               |
| `0x0906` | P2TR_LEGACY        | Wrapped P2TR key-path                        |
| `0x0907` | P2TR_SCRIPT_LEGACY | Wrapped P2TR script-path                     |

### 4.d Data Types

Every field in a block carries one of 11 data types. Each type has fixed
minimum and maximum size constraints enforced at deserialization.

| Code   | Name          | Min  | Max    | Description                             |
|--------|---------------|------|--------|-----------------------------------------|
| `0x01` | PUBKEY        | 1    | 2048   | Public key (witness-only)               |
| `0x02` | PUBKEY_COMMIT | 32   | 32     | Public key commitment                   |
| `0x03` | HASH256       | 32   | 32     | SHA-256 hash                            |
| `0x04` | HASH160       | 20   | 20     | RIPEMD160(SHA256()) hash                |
| `0x05` | PREIMAGE      | 32   | 32     | SHA256 payment hash preimage            |
| `0x06` | SIGNATURE     | 1    | 50000  | Signature (Schnorr/ECDSA/PQ)           |
| `0x07` | SPEND_INDEX   | 4    | 4      | Spend index reference                   |
| `0x08` | NUMERIC       | 1    | 4      | Numeric value (varint-encoded on wire)  |
| `0x09` | SCHEME        | 1    | 1      | Signature scheme selector               |
| `0x0A` | SCRIPT_BODY   | 1    | 80     | Serialized inner conditions             |
| `0x0B` | DATA          | 1    | 40     | Opaque data (DATA_RETURN only)          |

**Condition data types** (allowed on the locking side): HASH256, HASH160,
NUMERIC, SCHEME, SPEND_INDEX, DATA. The types PUBKEY, PUBKEY_COMMIT,
SIGNATURE, PREIMAGE, and SCRIPT_BODY are witness-only and rejected in the
conditions context.

**PUBKEY** is witness-only. Public keys are bound to the Merkle leaf hash
via `merkle_pub_key` at fund time, not carried in conditions. This prevents
arbitrary data embedding through the 2048-byte PUBKEY field.

### 4.e Wire Format

Blocks are encoded using a compact wire format with micro-headers and
implicit field layouts.

#### Block Header

Each block begins with a single header byte:

- `0x00` - `0x7F`: Micro-header slot index. The block type is looked up from
  the micro-header table. The block is not inverted.
- `0x80`: Escape byte. A `uint16_t` block type follows (little-endian). The
  block is not inverted.
- `0x81`: Escape byte (inverted). A `uint16_t` block type follows
  (little-endian). The block is inverted.

#### Implicit Fields

When a micro-header is used and an implicit field layout exists for the block
type in the current serialization context (WITNESS or CONDITIONS), field
count and type bytes are omitted. Fields are read according to the implicit
layout:

- **NUMERIC** fields: encoded as a CompactSize value (no length prefix).
  Deserialized into 4-byte little-endian representation.
- **Fixed-size fields** (e.g., HASH256 at 32 bytes, SCHEME at 1 byte): data
  is written directly with no length prefix.
- **Variable-size fields** (e.g., PUBKEY, SIGNATURE): CompactSize length
  prefix followed by data bytes.

#### Explicit Fields

When micro-header encoding is not used (escape byte, or inverted block, or
no implicit layout):

```
[n_fields: CompactSize]
for each field:
    [data_type: uint8_t]
    if NUMERIC: [value: CompactSize]
    else: [data_len: CompactSize] [data: bytes]
```

### 4.f Micro-Header Table

The micro-header table maps 128 slot indices (`0x00` - `0x7F`) to block
types. Slots marked with `0xFFFF` are unused and rejected at deserialization.

| Slot   | Block Type         | Slot   | Block Type          |
|--------|--------------------|--------|---------------------|
| `0x00` | SIG                | `0x19` | HYSTERESIS_FEE      |
| `0x01` | MULTISIG           | `0x1A` | HYSTERESIS_VALUE    |
| `0x02` | ADAPTOR_SIG        | `0x1B` | TIMER_CONTINUOUS    |
| `0x03` | CSV                | `0x1C` | TIMER_OFF_DELAY     |
| `0x04` | CSV_TIME           | `0x1D` | LATCH_SET           |
| `0x05` | CLTV               | `0x1E` | LATCH_RESET         |
| `0x06` | CLTV_TIME          | `0x1F` | COUNTER_DOWN        |
| `0x07` | *(unused)*         | `0x20` | COUNTER_PRESET      |
| `0x08` | *(unused)*         | `0x21` | COUNTER_UP          |
| `0x09` | TAGGED_HASH        | `0x22` | COMPARE             |
| `0x0A` | CTV                | `0x23` | SEQUENCER           |
| `0x0B` | VAULT_LOCK         | `0x24` | ONE_SHOT            |
| `0x0C` | AMOUNT_LOCK        | `0x25` | RATE_LIMIT          |
| `0x0D` | RECURSE_SAME       | `0x26` | COSIGN              |
| `0x0E` | RECURSE_MODIFIED   | `0x27` | TIMELOCKED_SIG      |
| `0x0F` | RECURSE_UNTIL      | `0x28` | HTLC                |
| `0x10` | RECURSE_COUNT      | `0x29` | HASH_SIG            |
| `0x11` | RECURSE_SPLIT      | `0x2A` | PTLC                |
| `0x12` | RECURSE_DECAY      | `0x2B` | CLTV_SIG            |
| `0x13` | ANCHOR             | `0x2C` | TIMELOCKED_MULTISIG |
| `0x14` | ANCHOR_CHANNEL     | `0x2D` | EPOCH_GATE          |
| `0x15` | ANCHOR_POOL        | `0x2E` | WEIGHT_LIMIT        |
| `0x16` | ANCHOR_RESERVE     | `0x2F` | INPUT_COUNT         |
| `0x17` | ANCHOR_SEAL        | `0x30` | OUTPUT_COUNT        |
| `0x18` | ANCHOR_ORACLE      | `0x31` | RELATIVE_VALUE      |

| Slot   | Block Type           | Slot       | Block Type       |
|--------|----------------------|------------|------------------|
| `0x32` | ACCUMULATOR          | `0x38`     | P2WPKH_LEGACY    |
| `0x33` | MUSIG_THRESHOLD      | `0x39`     | P2WSH_LEGACY     |
| `0x34` | KEY_REF_SIG          | `0x3A`     | P2TR_LEGACY      |
| `0x35` | P2PK_LEGACY          | `0x3B`     | P2TR_SCRIPT_LEGACY |
| `0x36` | P2PKH_LEGACY         | `0x3C`     | DATA_RETURN      |
| `0x37` | P2SH_LEGACY          | `0x3D`     | HASH_GUARDED     |
|        |                      | `0x3E`     | OUTPUT_CHECK     |

Slots `0x07`, `0x08` (reserved) and `0x3F` - `0x7F` are unused.

### 4.g Implicit Field Layouts

Each block type has an implicit field layout for the CONDITIONS context and
optionally for the WITNESS context. When a micro-header is used and the
layout exists, field count and type bytes are omitted on the wire.

The following table summarizes the implicit layouts for all block types.
"Variable" means a CompactSize length prefix is present; a fixed number
means the data is written directly without a length prefix.

#### Conditions Context Layouts

| Block Type          | Fields                                                         |
|---------------------|----------------------------------------------------------------|
| SIG                 | SCHEME(1)                                                      |
| MULTISIG            | NUMERIC(var)                                                   |
| MUSIG_THRESHOLD     | NUMERIC(var), NUMERIC(var)                                     |
| KEY_REF_SIG         | NUMERIC(var), NUMERIC(var)                                     |
| CSV                 | NUMERIC(var)                                                   |
| CSV_TIME            | NUMERIC(var)                                                   |
| CLTV                | NUMERIC(var)                                                   |
| CLTV_TIME           | NUMERIC(var)                                                   |
| TAGGED_HASH         | HASH256(32), HASH256(32)                                       |
| HASH_GUARDED        | HASH256(32)                                                    |
| CTV                 | HASH256(32)                                                    |
| VAULT_LOCK          | NUMERIC(var)                                                   |
| AMOUNT_LOCK         | NUMERIC(var), NUMERIC(var)                                     |
| RECURSE_SAME        | NUMERIC(var)                                                   |
| RECURSE_UNTIL       | NUMERIC(var)                                                   |
| RECURSE_COUNT       | NUMERIC(var)                                                   |
| RECURSE_SPLIT       | NUMERIC(var), NUMERIC(var)                                     |
| ANCHOR              | NUMERIC(var)                                                   |
| ANCHOR_CHANNEL      | NUMERIC(var)                                                   |
| ANCHOR_POOL         | HASH256(32), NUMERIC(var)                                      |
| ANCHOR_RESERVE      | NUMERIC(var), NUMERIC(var), HASH256(32)                        |
| ANCHOR_SEAL         | HASH256(32), HASH256(32)                                       |
| ANCHOR_ORACLE       | NUMERIC(var)                                                   |
| DATA_RETURN         | DATA(var)                                                      |
| COSIGN              | HASH256(32)                                                    |
| TIMELOCKED_SIG      | SCHEME(1), NUMERIC(var)                                        |
| HTLC                | HASH256(32), NUMERIC(var)                                      |
| HASH_SIG            | HASH256(32), SCHEME(1)                                         |
| CLTV_SIG            | SCHEME(1), NUMERIC(var)                                        |
| PTLC                | NUMERIC(var)                                                   |
| TIMELOCKED_MULTISIG | NUMERIC(var), NUMERIC(var)                                     |
| EPOCH_GATE          | NUMERIC(var), NUMERIC(var)                                     |
| WEIGHT_LIMIT        | NUMERIC(var)                                                   |
| INPUT_COUNT         | NUMERIC(var), NUMERIC(var)                                     |
| OUTPUT_COUNT        | NUMERIC(var), NUMERIC(var)                                     |
| RELATIVE_VALUE      | NUMERIC(var), NUMERIC(var)                                     |
| ACCUMULATOR         | HASH256(32)                                                    |
| OUTPUT_CHECK        | NUMERIC(var), NUMERIC(var), NUMERIC(var), HASH256(32)          |
| COMPARE             | NUMERIC(var), NUMERIC(var), NUMERIC(var)                       |
| HYSTERESIS_FEE      | NUMERIC(var), NUMERIC(var)                                     |
| HYSTERESIS_VALUE    | NUMERIC(var), NUMERIC(var)                                     |
| TIMER_CONTINUOUS    | NUMERIC(var), NUMERIC(var)                                     |
| TIMER_OFF_DELAY     | NUMERIC(var)                                                   |
| LATCH_SET           | NUMERIC(var)                                                   |
| LATCH_RESET         | NUMERIC(var), NUMERIC(var)                                     |
| COUNTER_DOWN        | NUMERIC(var)                                                   |
| COUNTER_PRESET      | NUMERIC(var), NUMERIC(var)                                     |
| COUNTER_UP          | NUMERIC(var), NUMERIC(var)                                     |
| SEQUENCER           | NUMERIC(var), NUMERIC(var)                                     |
| ONE_SHOT            | NUMERIC(var), HASH256(32)                                      |
| RATE_LIMIT          | NUMERIC(var), NUMERIC(var), NUMERIC(var)                       |
| P2PK_LEGACY         | SCHEME(1)                                                      |
| P2PKH_LEGACY        | HASH160(20)                                                    |
| P2SH_LEGACY         | HASH160(20)                                                    |
| P2WPKH_LEGACY       | HASH160(20)                                                    |
| P2WSH_LEGACY        | HASH256(32)                                                    |
| P2TR_LEGACY         | SCHEME(1)                                                      |
| P2TR_SCRIPT_LEGACY  | HASH256(32)                                                    |

ADAPTOR_SIG has no condition fields (0 fields enforced in conditions context).
RECURSE_MODIFIED and RECURSE_DECAY have variable field counts (protected by
`IsDataEmbeddingType` rejection rather than implicit layout).

#### Witness Context Layouts

| Block Type          | Fields                                                         |
|---------------------|----------------------------------------------------------------|
| SIG                 | PUBKEY(var), SIGNATURE(var)                                    |
| MUSIG_THRESHOLD     | PUBKEY(var), SIGNATURE(var)                                    |
| CSV                 | NUMERIC(var)                                                   |
| CSV_TIME            | NUMERIC(var)                                                   |
| CLTV                | NUMERIC(var)                                                   |
| CLTV_TIME           | NUMERIC(var)                                                   |
| TAGGED_HASH         | HASH256(32), HASH256(32), PREIMAGE(var)                        |
| HASH_GUARDED        | PREIMAGE(var)                                                  |
| CTV                 | HASH256(32)                                                    |
| COSIGN              | HASH256(32)                                                    |
| TIMELOCKED_SIG      | PUBKEY(var), SIGNATURE(var), NUMERIC(var)                      |
| HTLC                | PUBKEY(var), SIGNATURE(var), PUBKEY(var), PREIMAGE(var), NUMERIC(var) |
| HASH_SIG            | PUBKEY(var), SIGNATURE(var), PREIMAGE(var)                     |
| CLTV_SIG            | PUBKEY(var), SIGNATURE(var), NUMERIC(var)                      |
| P2PK_LEGACY         | PUBKEY(var), SIGNATURE(var)                                    |
| P2PKH_LEGACY        | PUBKEY(var), SIGNATURE(var)                                    |
| P2WPKH_LEGACY       | PUBKEY(var), SIGNATURE(var)                                    |
| P2TR_LEGACY         | PUBKEY(var), SIGNATURE(var)                                    |

All other block types use explicit field encoding in the witness context
(no implicit witness layout).

### 4.h Serialization Format

#### LadderWitness Wire Format

```
[n_rungs: CompactSize]           -- 0 = diff witness mode
for each rung:
    [n_blocks: CompactSize]      -- must be >= 1
    for each block:
        <block encoding>         -- micro-header or escape + fields
[coil_type: uint8]
[attestation: uint8]
[scheme: uint8]
[address_len: CompactSize]       -- 0 or 32
[address_hash: bytes]            -- SHA256(raw_address), never raw on-chain
[n_coil_conditions: CompactSize] -- must be 0 (reserved)
[n_rung_destinations: CompactSize]
for each rung_destination:
    [rung_index: uint16 LE]
    [address_hash: 32 bytes]
```

#### Diff Witness Mode

When `n_rungs = 0`, the witness inherits rungs and relays from another input:

```
[0: CompactSize]                 -- signals diff witness
[input_index: CompactSize]       -- source input (must be < current input)
[n_diffs: CompactSize]
for each diff:
    [rung_index: CompactSize]
    [block_index: CompactSize]
    [field_index: CompactSize]
    [data_type: uint8]
    <field data>
<coil fields>                    -- always fresh (never inherited)
```

Diff fields must be witness-side types: PUBKEY, SIGNATURE, PREIMAGE,
SCRIPT_BODY, or SCHEME. Chaining (diff pointing to another diff) is
prohibited.

#### Relay Sections

After the coil and rung_destinations, relays are serialized:

```
[n_relays: CompactSize]
for each relay:
    [n_blocks: CompactSize]
    for each block: <block encoding>
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
```

Rung relay_refs are serialized after each rung's blocks:

```
[n_relay_refs: CompactSize]
for each relay_ref: [index: CompactSize]
```

Forward-only indexing: relay N can only reference relays 0..N-1. Maximum
transitive relay chain depth is 4.

#### Coil Metadata

| Field         | Type    | Values                                            |
|---------------|---------|---------------------------------------------------|
| coil_type     | uint8   | UNLOCK (0x01), UNLOCK_TO (0x02), COVENANT (0x03)  |
| attestation   | uint8   | INLINE (0x01), AGGREGATE (0x02), DEFERRED (0x03)  |
| scheme        | uint8   | SCHNORR (0x01), ECDSA (0x02), FALCON512 (0x10), FALCON1024 (0x11), DILITHIUM3 (0x12), SPHINCS_SHA (0x13) |
| address_hash  | 0 or 32 | SHA256 of the destination address                 |

#### Rung Destinations (rung_destinations)

Per-rung destination overrides carried in the coil. Each entry is a
`(rung_index, address_hash)` pair. Bounded by MAX_RUNGS. Duplicate rung
indices are rejected.

### 4.i MLSC Merkle Tree

#### Leaf Order

```
[rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

The tree is padded to the next power of 2 with `MLSC_EMPTY_LEAF =
TaggedHash("LadderLeaf", "")`.

#### Leaf Computation

**Rung leaf:**
```
TaggedHash("LadderLeaf", SerializeRungBlocks(rung, CONDITIONS) || pubkey[0] || pubkey[1] || ...)
```

Pubkeys are appended in positional order, walked left-to-right across
key-consuming blocks using `PubkeyCountForBlock()`. This is the
`merkle_pub_key` design: public keys are committed in the leaf hash rather
than carried in the conditions on the wire.

**Coil leaf:**
```
TaggedHash("LadderLeaf", SerializeCoilData(coil))
```

**Relay leaf:**
```
TaggedHash("LadderLeaf", SerializeRelayBlocks(relay, CONDITIONS) || pubkey[0] || ...)
```

#### Interior Nodes

Interior nodes use sorted lexicographic ordering:

```
TaggedHash("LadderInternal", min(left, right) || max(left, right))
```

This eliminates the need to track left/right ordering in proofs.

#### MLSC Proof Structure

The `MLSCProof` is carried in `witness[1]` and contains:

```
[total_rungs: CompactSize]
[total_relays: CompactSize]
[rung_index: CompactSize]        -- which rung is revealed
<revealed rung blocks>           -- CONDITIONS-context serialized blocks
[n_rung_relay_refs: CompactSize]
<rung relay_refs>
[n_revealed_relays: CompactSize]
for each revealed relay:
    [relay_index: CompactSize]
    <relay blocks>
    [n_relay_refs: CompactSize]
    <relay relay_refs>
[n_proof_hashes: CompactSize]
for each proof_hash:
    [hash: 32 bytes]             -- unrevealed leaf hashes
[n_mutation_targets: CompactSize] -- optional, backward-compatible
for each mutation target:
    [rung_index: CompactSize]
    <rung blocks>
    [n_relay_refs: CompactSize]
    <relay_refs>
```

#### Verification

`VerifyMLSCProof` reconstructs the full leaf array:

1. For the revealed rung, compute the leaf from the proof's condition blocks
   and the witness's pubkeys
2. For revealed relays, compute leaves similarly
3. For the coil, compute the leaf from the witness coil
4. Fill unrevealed positions with `proof_hashes` in leaf order
5. Build the Merkle tree and compare the root against the UTXO's
   `conditions_root`

### 4.j Sighash Algorithm

Ladder Script uses `SignatureHashLadder`, a tagged hash similar to BIP 341:

```
sighash = TaggedHash("LadderSighash",
    epoch(0) ||
    hash_type ||
    tx.version || tx.nLockTime ||
    [prevouts_hash]   -- skip if ANYPREVOUT or ANYONECANPAY
    amounts_hash ||   -- skip if ANYONECANPAY
    sequences_hash || -- skip if ANYONECANPAY
    [outputs_hash]    -- skip if SIGHASH_NONE
    spend_type(0) ||
    <input-specific data> ||
    [conditions_hash] -- skip if ANYPREVOUTANYSCRIPT
    [single_output]   -- only for SIGHASH_SINGLE
)
```

#### Valid Hash Types

| Hash Type | Value  | Description                                       |
|-----------|--------|---------------------------------------------------|
| DEFAULT   | `0x00` | Equivalent to ALL                                  |
| ALL       | `0x01` | Commit to all outputs                              |
| NONE      | `0x02` | Do not commit to outputs                           |
| SINGLE    | `0x03` | Commit to corresponding output only                |
| ANYPREVOUT| `0x40` | Skip prevout commitment (BIP 118 analogue)         |
| ANYONECANPAY | `0x80` | Commit only to this input                       |
| ANYPREVOUTANYSCRIPT | `0xC0` | Skip prevout and conditions commitment  |

Valid combinations: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

#### Field Commitments

- **epoch**: Always 0 (reserved for future sighash upgrades)
- **spend_type**: Always 0 (no annex, no extensions)
- **conditions_hash**: For MLSC outputs, this is the `conditions_root`
  directly. Skipped with ANYPREVOUTANYSCRIPT.
- **ANYPREVOUT** (`0x40`): Skips the prevout hash but still commits to
  amounts, sequences, and conditions. Enables LN-Symmetry/eltoo.
- **ANYPREVOUTANYSCRIPT** (`0xC0`): Skips both prevout and conditions
  commitment. Enables rebindable signatures across different scripts.

### 4.k Evaluation Semantics

#### Rung Evaluation (AND within rung)

All blocks within a rung must return `SATISFIED`. If any block returns
`UNSATISFIED` or `ERROR`, the rung fails.

```
EvalRung = AND(EvalBlock(block[0]), EvalBlock(block[1]), ...)
```

Before evaluating blocks, relay requirements (`relay_refs`) are checked.
All referenced relays must have already been evaluated as `SATISFIED`.

#### Ladder Evaluation (OR across rungs)

Relays are evaluated first (index 0 through N-1, forward-only). Then rungs
are evaluated in order. The first satisfied rung wins.

```
EvalLadder = OR(EvalRung(rung[0]), EvalRung(rung[1]), ...)
```

#### Relay Evaluation

Relays are shared condition sets. A relay is evaluated like a rung (AND
logic). Relay N can only reference relays 0..N-1 (forward-only, no cycles).
Results are cached and made available to rungs via `relay_refs`.

#### Inversion

Blocks may be inverted (result flipped):

- `SATISFIED` becomes `UNSATISFIED`
- `UNSATISFIED` becomes `SATISFIED`
- `ERROR` remains `ERROR`
- `UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR`

Inversion is restricted to the `IsInvertibleBlockType` allowlist.
Key-consuming blocks are never invertible (prevents garbage-pubkey data
embedding). The inverted flag is set via the `0x81` escape byte in the wire
format.

#### EvalResult Values

| Value                | Meaning                                            |
|----------------------|----------------------------------------------------|
| `SATISFIED`          | All conditions met                                  |
| `UNSATISFIED`        | Conditions not met (valid but fails)                |
| `ERROR`              | Malformed block (consensus failure)                 |
| `UNKNOWN_BLOCK_TYPE` | Unknown type (treated as unsatisfied for forward compatibility) |

#### Merge Step

Before evaluation, conditions (from the MLSC proof) and witness data are
merged. For each rung and block, the conditions provide the locking data
(hashes, timelocks, scheme selectors) and the witness provides the unlocking
data (pubkeys, signatures, preimages). The merged block contains all fields
from both sides. Block types and inverted flags come from conditions.

### 4.l Block Evaluation Rules

The following table summarizes the evaluation pattern for each block type
family. All block types follow the dispatch in `EvalBlock`.

#### Signature Family

| Type            | Evaluation Pattern                                        |
|-----------------|-----------------------------------------------------------|
| SIG             | Verify SIGNATURE against PUBKEY using `CheckSchnorrSignature` or `CheckECDSASignature` (routed by SCHEME or signature size). PQ schemes routed via `VerifyPQSignature`. |
| MULTISIG        | M-of-N: NUMERIC threshold, N PUBKEY fields, M SIGNATURE fields. Each signature must match a distinct pubkey. |
| ADAPTOR_SIG     | Verify adapted SIGNATURE against signing PUBKEY. The adaptor secret is applied off-chain. |
| MUSIG_THRESHOLD | Verify aggregate SIGNATURE against aggregate PUBKEY. FROST/MuSig2 ceremony is off-chain; on-chain appears as single-sig. |
| KEY_REF_SIG     | Resolve PUBKEY_COMMIT from a relay block via relay_refs, then verify SIGNATURE against the referenced key. |

#### Timelock Family

| Type      | Evaluation Pattern                                            |
|-----------|---------------------------------------------------------------|
| CSV       | Read NUMERIC sequence value; call `CheckSequence`. SATISFIED if the relative timelock (block-height) is met. |
| CSV_TIME  | Same as CSV but interprets the sequence value as median-time-past. |
| CLTV      | Read NUMERIC locktime value; call `CheckLockTime`. SATISFIED if the absolute block-height locktime is met. |
| CLTV_TIME | Same as CLTV but interprets the locktime as median-time-past. |

#### Hash Family

| Type          | Evaluation Pattern                                       |
|---------------|----------------------------------------------------------|
| TAGGED_HASH   | Two HASH256 fields (tag_hash, expected) and one PREIMAGE. Compute `SHA256(tag_hash \|\| tag_hash \|\| preimage)` and compare to expected. |
| HASH_GUARDED  | One HASH256 (committed hash) and one PREIMAGE. Compute `SHA256(preimage)` and compare. Non-invertible. |

#### Covenant Family

| Type        | Evaluation Pattern                                         |
|-------------|------------------------------------------------------------|
| CTV         | Compute BIP-119 template hash for the spending transaction at the current input index. Compare against HASH256 field. |
| VAULT_LOCK  | Two-path: try recovery PUBKEY (immediate spend), then hot PUBKEY (requires CSV delay). |
| AMOUNT_LOCK | Two NUMERICs (min_sats, max_sats). SATISFIED if output amount is within range. |

#### Recursion Family

| Type             | Evaluation Pattern                                    |
|------------------|-------------------------------------------------------|
| RECURSE_SAME     | Output MLSC root must equal input root (identity).    |
| RECURSE_MODIFIED | Apply parameterized mutations to condition fields, recompute Merkle root, compare against output root. Supports multi-rung mutations. |
| RECURSE_UNTIL    | Before target block height: output must re-encumber with same root. At or after: covenant terminates (SATISFIED). |
| RECURSE_COUNT    | Decrement counter field; output must carry decremented conditions. At zero: terminates. |
| RECURSE_SPLIT    | Decrement max_splits; all outputs must carry decremented conditions. Enforces min_split_sats per output and value conservation. |
| RECURSE_DECAY    | Like RECURSE_MODIFIED but negates deltas (output = input minus decay). |

All recursion evaluators use leaf-centric Merkle verification: mutate a copy
of the revealed leaf, rebuild the tree from the verified leaf array, and
compare the computed root against the output's MLSC root.

#### Anchor Family

| Type           | Evaluation Pattern                                      |
|----------------|---------------------------------------------------------|
| ANCHOR         | Marker block; SATISFIED if at least one field is present. |
| ANCHOR_CHANNEL | Requires 2 PUBKEYs (local, remote) and NUMERIC commitment_number > 0. |
| ANCHOR_POOL    | Requires HASH256 vtxo_tree_root with hash-preimage binding and NUMERIC participant_count > 0. |
| ANCHOR_RESERVE | Requires 2 NUMERICs (threshold_n <= threshold_m) and HASH256 guardian_hash with hash-preimage binding. |
| ANCHOR_SEAL    | Requires 2 HASH256 fields (asset_id, state_transition) with hash-preimage binding. |
| ANCHOR_ORACLE  | Requires 1 PUBKEY (oracle key) and NUMERIC outcome_count > 0. |
| DATA_RETURN    | Unspendable. Evaluation always returns ERROR (spending should never reach this block). |

#### PLC Family

| Type             | Evaluation Pattern                                    |
|------------------|-------------------------------------------------------|
| HYSTERESIS_FEE   | Fee rate must fall within [low_sat_vb, high_sat_vb] band. |
| HYSTERESIS_VALUE | UTXO value must fall within [low_sats, high_sats] band. |
| TIMER_CONTINUOUS | SATISFIED if accumulated >= target (timer elapsed). State updated via RECURSE_MODIFIED. |
| TIMER_OFF_DELAY  | SATISFIED if remaining blocks <= 0. |
| LATCH_SET        | State activation with PUBKEY-authenticated event. |
| LATCH_RESET      | State deactivation with PUBKEY-authenticated event and delay. |
| COUNTER_DOWN     | Decrement counter; SATISFIED when counter reaches zero. |
| COUNTER_PRESET   | Approval accumulator; SATISFIED when current reaches preset. |
| COUNTER_UP       | Increment counter; SATISFIED when current reaches target. |
| COMPARE          | Comparator: compares input amount against thresholds using operator byte (1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE). |
| SEQUENCER        | Step through sequence; SATISFIED at final step. |
| ONE_SHOT         | One-time activation window with hash commitment. |
| RATE_LIMIT       | SATISFIED if spending rate within limits (max_per_block, accumulation_cap, refill_blocks). |
| COSIGN           | Cross-input constraint: another input must have matching HASH256 conditions hash. |

#### Compound Family

| Type               | Evaluation Pattern                                   |
|--------------------|------------------------------------------------------|
| TIMELOCKED_SIG     | SIG + CSV: verify signature, then check relative timelock. |
| HTLC               | Two PUBKEYs, PREIMAGE, SIGNATURE, NUMERIC timelock. Hash-timelock contract for atomic swaps and Lightning. |
| HASH_SIG           | PUBKEY, SIGNATURE, PREIMAGE. Verify signature and hash preimage. |
| PTLC               | ADAPTOR_SIG + CSV: adaptor signature with relative timelock. |
| CLTV_SIG           | SIG + CLTV: verify signature, then check absolute timelock. |
| TIMELOCKED_MULTISIG| MULTISIG + CSV: M-of-N threshold with relative timelock. |

#### Governance Family

| Type           | Evaluation Pattern                                      |
|----------------|---------------------------------------------------------|
| EPOCH_GATE     | SATISFIED only within periodic block-height windows. |
| WEIGHT_LIMIT   | Transaction weight must be <= max_weight. |
| INPUT_COUNT    | Number of inputs must be within [min, max] bounds. |
| OUTPUT_COUNT   | Number of outputs must be within [min, max] bounds. |
| RELATIVE_VALUE | Output value must be >= input_amount * numerator / denominator. |
| ACCUMULATOR    | Merkle set membership proof: verify leaf inclusion in committed root. |
| OUTPUT_CHECK   | Specific output at given index must have value within [min, max] and match a script hash. |

#### Legacy Family

| Type               | Evaluation Pattern                                   |
|--------------------|------------------------------------------------------|
| P2PK_LEGACY        | PUBKEY + SIGNATURE verification (like P2PK).          |
| P2PKH_LEGACY       | HASH160 in conditions; PUBKEY + SIGNATURE in witness. Verify `HASH160(pubkey) == committed_hash`, then verify signature. |
| P2SH_LEGACY        | HASH160 in conditions; SCRIPT_BODY + inner witness. Verify `HASH160(script) == committed_hash`, deserialize inner conditions, recurse. |
| P2WPKH_LEGACY      | Delegates to P2PKH evaluation path.                   |
| P2WSH_LEGACY       | HASH256 in conditions; SCRIPT_BODY + inner witness. Verify `SHA256(script) == committed_hash`, deserialize inner conditions, recurse. |
| P2TR_LEGACY        | PUBKEY + SIGNATURE key-path verification.              |
| P2TR_SCRIPT_LEGACY | HASH256 + internal PUBKEY; SCRIPT_BODY + inner witness. Deserialize inner conditions, recurse. |

P2SH_LEGACY, P2WSH_LEGACY, and P2TR_SCRIPT_LEGACY support recursive
evaluation with a depth parameter to prevent unbounded nesting.

### 4.m Anti-Spam Properties

Ladder Script enforces several properties at deserialization time to prevent
abuse of the witness for arbitrary data storage:

1. **Selective inversion.** The `IsInvertibleBlockType` allowlist determines
   which blocks may be inverted. Key-consuming blocks (SIG, MULTISIG,
   ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, compound signature types,
   legacy key types, and others listed in `IsKeyConsumingBlockType`) are
   never invertible. Inverting a key-consuming block would allow embedding
   arbitrary data as a garbage pubkey (fail the check, invert to SATISFIED).

2. **`IsDataEmbeddingType` rejection.** For blocks without an implicit layout
   (where the deserializer cannot predict field count and types), the types
   PUBKEY_COMMIT (32 bytes), HASH256 (32 bytes), HASH160 (20 bytes), and
   DATA (up to 40 bytes) are rejected. This prevents using layout-less
   blocks to embed unvalidated payloads. ACCUMULATOR is exempted (its
   HASH256 fields carry Merkle proof data).

3. **PREIMAGE field limit.** At most `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`
   PREIMAGE or SCRIPT_BODY fields are permitted per witness. This limits
   user-chosen data to 64 bytes (2 x 32-byte PREIMAGE).

4. **DATA type restriction.** The DATA data type (`0x0B`) is only permitted
   in DATA_RETURN blocks. Any other block carrying a DATA field is rejected.

5. **`merkle_pub_key`.** Public keys are not carried in conditions. They
   exist only in the witness (PUBKEY fields) and are bound to the Merkle
   leaf at fund time. This eliminates the PUBKEY writable surface from
   conditions, preventing key-field data embedding.

6. **Strict field enforcement.** When an implicit layout exists for a block
   type in the current context, the explicit field count and types must
   match exactly. Extra fields are rejected.

7. **Blanket HASH256 rejection.** High-bandwidth data types (PUBKEY_COMMIT,
   HASH256, HASH160, DATA) are classified as `IsDataEmbeddingType` and
   blocked in all blocks that lack an implicit layout, regardless of context.

### 4.n Consensus Limits

| Parameter                       | Value   | Source                    |
|---------------------------------|---------|---------------------------|
| MAX_RUNGS                       | 16      | `serialize.h`             |
| MAX_BLOCKS_PER_RUNG             | 8       | `serialize.h`             |
| MAX_FIELDS_PER_BLOCK            | 16      | `serialize.h`             |
| MAX_LADDER_WITNESS_SIZE         | 100,000 | `serialize.h`             |
| MAX_PREIMAGE_FIELDS_PER_WITNESS | 2       | `serialize.h`             |
| COIL_ADDRESS_HASH_SIZE          | 32      | `serialize.h`             |
| MAX_COIL_CONDITION_RUNGS        | 0       | `serialize.h`             |
| MAX_RELAYS                      | 8       | `serialize.h`             |
| MAX_REQUIRES                    | 8       | `serialize.h`             |
| MAX_RELAY_DEPTH                 | 4       | `serialize.h`             |
| MICRO_HEADER_SLOTS              | 128     | `types.h`                 |
| MAX_IMPLICIT_FIELDS             | 8       | `types.h`                 |
| PUBKEY max size                  | 2,048   | `types.h` (FieldMaxSize)  |
| SIGNATURE max size               | 50,000  | `types.h` (FieldMaxSize)  |
| SCRIPT_BODY max size             | 80      | `types.h` (FieldMaxSize)  |
| DATA max size                    | 40      | `types.h` (FieldMaxSize)  |
| DATA_RETURN max data per output  | 40      | `conditions.cpp` (MLSC)   |
| DATA_RETURN outputs per tx       | 1       | `evaluator.cpp`           |
| Witness stack elements           | 2       | `evaluator.cpp`           |

### 4.o Descriptor Language

Ladder Script conditions can be expressed in a human-readable descriptor
language parsed by `ParseDescriptor` and formatted by `FormatDescriptor`.

#### Grammar

```
ladder     = "ladder(" "or(" rung { "," rung } ")" ")"
rung       = block | "and(" block { "," block } ")"
block      = base_block | "!" base_block
base_block = sig_block | csv_block | multisig_block | hash_block
           | ctv_block | amount_block | compound_block | output_check_block

sig_block     = "sig(" "@" alias ["," scheme] ")"
csv_block     = "csv(" N ")" | "csv_time(" N ")"
                | "cltv(" N ")" | "cltv_time(" N ")"
multisig_block= "multisig(" M "," "@" pk1 "," "@" pk2 ... ["," scheme] ")"
hash_block    = "hash_guarded(" hex ")" | "tagged_hash(" hex1 "," hex2 ")"
ctv_block     = "ctv(" hex ")"
amount_block  = "amount_lock(" min "," max ")"
compound_block= "timelocked_sig(" "@" alias "," N ")"
              | "htlc(" "@" a1 "," "@" a2 "," hex "," N ")"
              | "hash_sig(" "@" alias "," hex ")"
              | "cltv_sig(" "@" alias "," N ")"
output_check_block = "output_check(" idx "," min "," max "," hex ")"
```

#### Scheme Names

`schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`

#### Example

```
ladder(or(
    sig(@alice),
    and(sig(@bob), csv(144)),
    multisig(2, @alice, @bob, @carol)
))
```

## Activation

All 61 block types activate together as a single
soft fork. On mainnet, only MLSC (0xC2) outputs are accepted. Inline
conditions (0xC1) are removed and always rejected.

The activation mechanism is outside the scope of this specification.

## Reference Implementation

| File                    | Description                                          |
|-------------------------|------------------------------------------------------|
| `src/rung/types.h`     | Block type enum (61 types), data type enum (11 types), micro-header table (128 slots), implicit field layouts, `BlockDescriptor` table, `IsKnownBlockType`, `IsInvertibleBlockType`, `IsKeyConsumingBlockType`, `PubkeyCountForBlock` |
| `src/rung/types.cpp`   | `RungField::IsValid` implementation                  |
| `src/rung/evaluator.h` | `EvalResult`, `RungEvalContext`, `BatchVerifier`, `LadderSignatureChecker`, evaluator function declarations |
| `src/rung/evaluator.cpp`| Block evaluators (all 61 types), `EvalBlock` dispatch, `EvalRung`, `EvalLadder`, `VerifyRungTx`, `ValidateRungOutputs`, `MergeConditionsAndWitness` |
| `src/rung/sighash.h`   | `LADDER_SIGHASH_ANYPREVOUT` (`0x40`), `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT` (`0xC0`) |
| `src/rung/sighash.cpp` | `SignatureHashLadder` implementation                 |
| `src/rung/serialize.h` | Consensus limits, `SerializationContext`, `DeserializeLadderWitness`, `SerializeLadderWitness` |
| `src/rung/serialize.cpp`| Wire format implementation, micro-header encoding, implicit field serialization, `DeserializeBlock` |
| `src/rung/conditions.h`| MLSC format, `MLSCProof`, `RungConditions`, `MLSCVerifiedLeaves`, leaf computation functions |
| `src/rung/conditions.cpp`| MLSC Merkle tree implementation, proof verification, `ComputeConditionsRoot`, `BuildMerkleTree` |
| `src/rung/descriptor.h`| `ParseDescriptor`, `FormatDescriptor`                |
| `src/rung/descriptor.cpp`| Descriptor language parser and formatter            |
| `src/rung/aggregate.h` | `TxAggregateContext`, `AggregateProof`               |
| `src/rung/aggregate.cpp`| Aggregate signature verification                    |
| `src/rung/policy.h`    | `IsBaseBlockType`, `IsCovenantBlockType`, `IsStatefulBlockType`, `IsStandardRungTx` |
| `src/rung/policy.cpp`  | Policy implementation                                |
| `src/rung/pq_verify.h` | PQ signature scheme support declarations             |
| `src/rung/pq_verify.cpp`| PQ verification via liboqs (optional build dependency) |
| `src/rung/adaptor.cpp` | Adaptor signature helpers                            |
| `src/rung/rpc.cpp`     | RPC commands for Ladder Script transactions          |

## Test Vectors

The reference implementation includes:

- **480 unit tests** covering individual block evaluators, serialization
  round-trips, field validation, anti-spam rejection, micro-header encoding,
  implicit layout matching, and inversion semantics.
- **60 functional tests** covering end-to-end transaction construction,
  MLSC proof generation and verification, covenant evaluation, recursion
  depth enforcement, diff witness resolution, and relay chain evaluation.
- **9 TLA+ specifications** formally modeling evaluation semantics,
  Merkle proof verification, sighash computation, inversion rules, and
  anti-spam properties.

## Security Considerations

### Anti-Spam

The maximum user-chosen data per transaction is bounded by the PREIMAGE
field limit (2 x 32 = 64 bytes) plus one DATA_RETURN output (40 bytes) for
a total of approximately 104 bytes. All other witness bytes are constrained
to typed fields with semantic validation (signatures are verified, hashes
are committed in the Merkle tree, public keys are bound by
`merkle_pub_key`).

The residual embeddable surface is approximately 116 bytes per transaction,
accounting for NUMERIC field manipulation and SCHEME byte choices. This
represents a significant reduction from the arbitrary data capacity of raw
Bitcoin Script witnesses.

### Recursion Termination

All recursion block types terminate:

- RECURSE_SAME: No parameter mutation; covenant persists indefinitely but
  does not grow.
- RECURSE_COUNT: Counter decrements each spend; terminates at zero.
- RECURSE_UNTIL: Terminates at a specified block height.
- RECURSE_SPLIT: max_splits decrements; terminates at zero.
- RECURSE_MODIFIED / RECURSE_DECAY: Bounded by max_depth parameter.

There is no unbounded recursion. Legacy block types (P2SH, P2WSH,
P2TR_SCRIPT) support inner-conditions recursion but are depth-limited.

### Sighash Binding

The `SignatureHashLadder` algorithm commits to the `conditions_root` (the
MLSC Merkle root from the UTXO), binding signatures to the full condition
set. ANYPREVOUTANYSCRIPT (`0xC0`) explicitly skips this commitment to
enable rebindable signatures for protocols like LN-Symmetry.

### Post-Quantum Signatures

PQ signature support is compile-time optional (requires liboqs). When liboqs
is not available, PQ scheme verification returns `UNSATISFIED` (fail-closed).
The SIGNATURE field maximum size of 50,000 bytes accommodates the largest PQ
signature schemes (SPHINCS+-SHA2-256f at approximately 49,216 bytes).

### Batch Verification

`BatchVerifier` collects Schnorr signature verification requests during
evaluation and verifies them in a single batch after all inputs pass. On
batch failure, `FindFailure` identifies the first invalid entry for error
reporting.

## Acknowledgements

This specification was developed as part of the Bitcoin Ghost project.
The MLSC Merkle tree design follows the BIP-341 tagged hash pattern. The
CTV implementation follows BIP-119. The ANYPREVOUT sighash flags follow the
design principles of BIP-118.
