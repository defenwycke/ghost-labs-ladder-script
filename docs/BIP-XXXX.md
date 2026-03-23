```
BIP: 110
Layer: Consensus (soft fork)
Title: Ladder Script: Typed Structured Transaction Conditions
Author: Defenwycke <defenwycke@icloud.com>
Status: Draft
Type: Standards Track
Created: 2026-03-16
License: MIT
Requires: 119, 340, 341
```

## Abstract

This document specifies Ladder Script, a typed transaction condition format
for Bitcoin that replaces raw opcodes with 61 typed function blocks organized
into 10 families. Every byte in a Ladder Script witness belongs to a typed
field with enforced size constraints; no arbitrary data pushes are possible.
Spending conditions are structured as a ladder of rungs (OR logic), where each
rung contains one or more blocks (AND logic), supporting signatures,
timelocks, hash verifications, covenants, bounded recursion, stateful contract
primitives (counters, latches, rate limiters), and governance constraints.
Outputs commit to a Merkle root of conditions via Merkelised Ladder Script
Conditions (MLSC), revealing only the satisfied spending path. Ladder Script
transactions use version 4 (`nVersion = 4`).

## Motivation

### Arbitrary Data Embedding Is Unsolved

Bitcoin Script permits arbitrary byte pushes in witness data, making every
transaction a potential carrier for unvalidated payloads. Inscription
protocols have demonstrated that the witness discount creates an economic
incentive to embed large data blobs in witness fields, with no mechanism to
distinguish intended cryptographic material from arbitrary content.

Ladder Script addresses this structurally. Every witness byte must belong to
one of 11 typed fields (PUBKEY, SIGNATURE, HASH256, NUMERIC, etc.), each
with enforced minimum and maximum sizes. The `merkle_pub_key` design binds
public keys into the Merkle leaf hash at fund time rather than carrying them
in conditions, eliminating the 2048-byte PUBKEY field as a data embedding
channel. PREIMAGE fields are capped at 2 per witness. The result is a
residual embeddable surface of approximately 116 bytes per transaction --
down from effectively unlimited in raw Script.

**Before (raw Script):** Any `OP_PUSH` can embed arbitrary bytes. A single
witness can carry megabytes of non-cryptographic data under the witness
discount.

**After (Ladder Script):** Maximum user-chosen data per transaction:
2 PREIMAGE fields (64 bytes) + 1 DATA_RETURN output (40 bytes) + NUMERIC
field manipulation (~12 bytes) = ~116 bytes.

### Script Complexity Is a Barrier

Expressing even simple contracts in raw Bitcoin Script requires deep knowledge
of stack manipulation, opcode sequencing, and subtle failure modes.

**Before (raw Script HTLC -- 11 opcodes):**

```
OP_IF
  OP_SHA256 <hash> OP_EQUALVERIFY
  <receiver_pubkey> OP_CHECKSIG
OP_ELSE
  <144> OP_CHECKSEQUENCEVERIFY OP_DROP
  <sender_pubkey> OP_CHECKSIG
OP_ENDIF
```

**After (Ladder Script descriptor):**

```
ladder(or(
    htlc(@sender, @receiver, <preimage>, 144)
))
```

The HTLC block is a single typed construct with fixed field layout, static
analysis support, and deterministic resource bounds. No stack manipulation,
no opcode ordering errors, no untyped byte arrays.

### Post-Quantum Readiness

Current Bitcoin transactions are bound to ECDSA and Schnorr signature
schemes. Adding post-quantum signature support requires either new opcodes
or a hard fork.

Ladder Script routes signature verification through a 1-byte SCHEME field:

| Code   | Scheme        |
|--------|---------------|
| `0x01` | Schnorr (BIP-340) |
| `0x02` | ECDSA         |
| `0x10` | FALCON-512    |
| `0x11` | FALCON-1024   |
| `0x12` | Dilithium3    |
| `0x13` | SPHINCS+-SHA2-256f |

Transitioning to post-quantum signatures requires no wire format changes, no
new block types, and no hard fork. The same SIG block that verifies a 64-byte
Schnorr signature also verifies a 49,216-byte SPHINCS+ signature -- the
SCHEME byte selects the algorithm, and the SIGNATURE field accommodates up
to 50,000 bytes.

### Covenants Lack a Unified Framework

Bitcoin covenant proposals (CTV, OP_VAULT, APO, OP_CAT) each address one
use case with a dedicated opcode. They cannot be composed: a vault with
rate-limiting requires combining proposals that were not designed to
interoperate.

Ladder Script provides CTV (BIP-119 template hash verification), vaults
(VAULT_LOCK with two-path recovery/hot spend), amount constraints
(AMOUNT_LOCK), recursive covenants (6 RECURSE_ block types), and
transaction-level governance (EPOCH_GATE, INPUT_COUNT, OUTPUT_COUNT,
WEIGHT_LIMIT, RELATIVE_VALUE, OUTPUT_CHECK) -- all composable within a
single rung via AND logic:

```
ladder(or(
    and(sig(@hot_key), csv(144), amount_lock(0, 1000000), rate_limit(1, 10, 6))
))
```

This rung requires a signature AND a 144-block delay AND an amount cap AND
a rate limiter -- four conditions that compose without custom opcodes.

## Design Overview

### The Ladder Metaphor

A Ladder Script condition set is organized as a **ladder**: a list of
**rungs** connected by OR logic. Each rung contains one or more **blocks**
connected by AND logic. To spend an output, the spender must satisfy all
blocks in at least one rung.

```
Ladder (OR)
  ├── Rung 0: sig(@alice)                          [single signer]
  ├── Rung 1: and(sig(@bob), csv(144))             [backup after 1 day]
  └── Rung 2: multisig(2, @alice, @bob, @carol)    [2-of-3 multisig]
```

Each rung may also reference **relays** -- shared condition blocks that
factor out common requirements. Relays are evaluated once and their results
are available to any rung that references them.

The **coil** is per-output metadata attached to each ladder witness:
the unlock type (UNLOCK or UNLOCK_TO), attestation mode, signature scheme,
and optional destination address.

### The merkle_pub_key Design

In most covenant systems, public keys appear in the locking conditions
on-chain, creating a writable surface for data embedding (an attacker can
commit an arbitrary 33-byte "public key" that encodes data rather than a
valid point).

Ladder Script moves public keys out of conditions entirely. At fund time,
the funder's public keys are hashed into the Merkle leaf alongside the
serialized condition blocks. The conditions themselves carry only a SCHEME
byte (1 byte) for signature blocks. At spend time, the witness provides the
actual public keys, and the verifier recomputes the Merkle leaf to confirm
they match the commitment.

This is the single most important anti-spam property: it eliminates the
largest unvalidated data channel (up to 2048 bytes per PUBKEY field) from
the conditions side, without any loss of functionality.

### Merkelised Ladder Script Conditions (MLSC)

An MLSC output commits to the root of a Merkle tree whose leaves are the
individual rungs, relays, and coil metadata. At spend time, only the
satisfied rung (and any referenced relays) are revealed; all other spending
paths remain hidden behind Merkle proof hashes.

This provides the same privacy benefit as Taproot's script tree, but uses
sorted interior nodes (eliminating left/right tracking in proofs) and
embeds public keys in leaves rather than in script branches.

### Conditions vs. Witness: Dual-Context Serialization

Every block type has two serialization contexts:

- **Conditions context:** The locking side, committed in the MLSC Merkle
  tree. Contains hashes, timelocks, scheme selectors -- no secrets.
- **Witness context:** The spending side, provided at spend time. Contains
  public keys, signatures, preimages -- the unlocking data.

Each context has its own implicit field layout. A SIG block in conditions
is 1 byte (SCHEME). The same SIG block in witness is variable-length
(PUBKEY + SIGNATURE). The deserializer selects the correct layout based
on context.

## Specification

### Transaction Format

A Ladder Script transaction has `nVersion = 4`. All outputs MUST use the
MLSC format. All inputs MUST provide a witness stack of exactly 2 elements:

- `witness[0]`: Serialized `LadderWitness` (the spending proof)
- `witness[1]`: Serialized `MLSCProof` (revealed conditions and Merkle proof)

Verification proceeds via `VerifyRungTx` in 8 steps:

1. Validate all outputs via `ValidateRungOutputs` (33-byte 0xC2 prefix)
2. Deserialize the `LadderWitness` from `witness[0]`
3. Resolve witness references if the witness uses diff encoding
4. Deserialize the `MLSCProof` from `witness[1]`
5. Extract pubkeys from the witness for `merkle_pub_key` leaf computation
6. Verify the Merkle proof against the UTXO's `conditions_root`
7. Merge conditions (from proof) with witness (from `witness[0]`)
8. Evaluate the merged ladder via `EvalLadder`

#### Byte-Level Diagram: Minimal SIG Transaction

A transaction spending a single SIG-protected output (Schnorr, 32-byte
x-only pubkey, 64-byte signature):

```
witness[0] (LadderWitness):
  01                      # n_rungs = 1
  01                      # rung 0: n_blocks = 1
  00                      # micro-header 0x00 = SIG (witness context)
  20                      # PUBKEY length = 32
  <32 bytes pubkey>       # x-only public key
  40                      # SIGNATURE length = 64
  <64 bytes signature>    # Schnorr signature
  00                      # n_relay_refs = 0
  01                      # coil_type = UNLOCK
  01                      # attestation = INLINE
  01                      # scheme = SCHNORR
  00                      # address_len = 0 (no destination)
  00                      # n_coil_conditions = 0
  00                      # n_rung_destinations = 0
  00                      # n_relays = 0
  Total: 1+1+1+1+32+1+64+1+1+1+1+1+1+1+1 = 109 bytes

witness[1] (MLSCProof):
  01                      # total_rungs = 1
  00                      # total_relays = 0
  00                      # rung_index = 0
  01                      # n_blocks = 1
  00                      # micro-header 0x00 = SIG (conditions context)
  01                      # SCHEME = 0x01 (Schnorr)
  00                      # n_relay_refs = 0
  00                      # n_revealed_relays = 0
  00                      # n_proof_hashes = 0 (single rung, no siblings)
  Total: 1+1+1+1+1+1+1+1+1 = 9 bytes
```

### Output Format

Every output in a version 4 transaction MUST use the MLSC format:

```
scriptPubKey = 0xC2 || conditions_root (32 bytes)
```

This produces a 33-byte scriptPubKey. Optionally, a DATA_RETURN payload of
1 to 40 bytes may be appended:

```
scriptPubKey = 0xC2 || conditions_root (32 bytes) || data (1-40 bytes)
```

DATA_RETURN outputs with appended data MUST have zero value (unspendable).
At most one DATA_RETURN output is permitted per transaction.

### Data Types

Every field in a block carries one of 11 data types. Each type has fixed
minimum and maximum size constraints enforced at deserialization.

| Code   | Name          | Min  | Max    | Context     | Description                             |
|--------|---------------|------|--------|-------------|-----------------------------------------|
| `0x01` | PUBKEY        | 1    | 2,048  | Witness     | Public key (folded into Merkle leaf via merkle_pub_key) |
| `0x02` | PUBKEY_COMMIT | 32   | 32     | Witness     | Public key commitment (SHA-256 of pubkey) |
| `0x03` | HASH256       | 32   | 32     | Both        | SHA-256 hash                            |
| `0x04` | HASH160       | 20   | 20     | Both        | RIPEMD160(SHA256()) hash                |
| `0x05` | PREIMAGE      | 1    | 32     | Witness     | Hash preimage (SHA-256 payment hash)    |
| `0x06` | SIGNATURE     | 1    | 50,000 | Witness     | Signature (Schnorr 64-65, ECDSA 8-72, PQ up to 49,216) |
| `0x07` | SPEND_INDEX   | 4    | 4      | Both        | Spend index reference                   |
| `0x08` | NUMERIC       | 1    | 4      | Both        | Numeric value (CompactSize on wire)     |
| `0x09` | SCHEME        | 1    | 1      | Both        | Signature scheme selector               |
| `0x0A` | SCRIPT_BODY   | 1    | 80     | Witness     | Serialized inner conditions (for legacy wrappers) |
| `0x0B` | DATA          | 1    | 40     | Conditions  | Opaque data (DATA_RETURN blocks only)   |

**Condition data types** (allowed in the locking context): HASH256, HASH160,
NUMERIC, SCHEME, SPEND_INDEX, DATA. The types PUBKEY, PUBKEY_COMMIT,
SIGNATURE, PREIMAGE, and SCRIPT_BODY are witness-only and rejected in the
conditions context.

**PREIMAGE minimum is 1 byte**, not 32. P2SH and P2WSH inner conditions can
be shorter than 32 bytes, and the PREIMAGE type is shared across hash
verification and legacy script wrapping.

### Block Type Families

Ladder Script defines 61 block types across 10 families. Each block type is
encoded as a `uint16_t` (little-endian) on the wire.

#### Signature Family (0x0001 - 0x00FF)

Signature blocks verify that the spender controls a private key. Public keys
are bound to the MLSC Merkle leaf via `merkle_pub_key` -- conditions carry
only the SCHEME byte, and the witness provides the actual key and signature.

| Code     | Name             | Description                                         |
|----------|------------------|-----------------------------------------------------|
| `0x0001` | SIG              | Single signature verification                       |
| `0x0002` | MULTISIG         | M-of-N threshold signature                          |
| `0x0003` | ADAPTOR_SIG      | Adaptor signature verification (atomic swap secret revelation) |
| `0x0004` | MUSIG_THRESHOLD  | MuSig2/FROST aggregate threshold signature          |
| `0x0005` | KEY_REF_SIG      | Signature using key commitment from a relay block    |

#### Timelock Family (0x0100 - 0x01FF)

Timelock blocks restrict when an output can be spent. They wrap the existing
BIP-68 (CSV) and BIP-65 (CLTV) mechanisms as typed conditions with explicit
block-height vs. median-time-past variants.

| Code     | Name       | Description                                   |
|----------|------------|-----------------------------------------------|
| `0x0101` | CSV        | Relative timelock, block-height (BIP-68 sequence) |
| `0x0102` | CSV_TIME   | Relative timelock, median-time-past           |
| `0x0103` | CLTV       | Absolute timelock, block-height (nLockTime)   |
| `0x0104` | CLTV_TIME  | Absolute timelock, median-time-past           |

#### Hash Family (0x0200 - 0x02FF)

Hash blocks verify knowledge of a preimage. TAGGED_HASH uses the BIP-340
tagged hash construction for domain separation. HASH_GUARDED is a raw
SHA-256 verification that is non-invertible (cannot be used to embed data
via the inversion trick).

| Code     | Name             | Description                                     |
|----------|------------------|-------------------------------------------------|
| `0x0203` | TAGGED_HASH      | BIP-340 tagged hash verification                |
| `0x0204` | HASH_GUARDED     | Raw SHA-256 preimage verification (non-invertible) |


#### Covenant Family (0x0300 - 0x03FF)

Covenant blocks constrain how an output may be spent, beyond mere
authorization. CTV provides BIP-119 template hash verification. VAULT_LOCK
implements a two-path vault with recovery and hot-spend paths. AMOUNT_LOCK
bounds the output value range.

| Code     | Name        | Description                                  |
|----------|-------------|----------------------------------------------|
| `0x0301` | CTV         | OP_CHECKTEMPLATEVERIFY covenant (BIP-119)     |
| `0x0302` | VAULT_LOCK  | Two-path vault timelock covenant              |
| `0x0303` | AMOUNT_LOCK | Output amount range check                     |

#### Recursion Family (0x0400 - 0x04FF)

Recursion blocks allow an output to re-encumber itself with the same or
modified conditions, enabling state machines, countdown contracts, and
value-splitting trees. All 6 types are bounded: RECURSE_SAME persists
indefinitely but cannot grow; the others terminate via depth limits,
countdown, block height, or split exhaustion.

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0401` | RECURSE_SAME     | Re-encumber with identical conditions          |
| `0x0402` | RECURSE_MODIFIED | Re-encumber with parameterized mutations       |
| `0x0403` | RECURSE_UNTIL    | Recursive until target block height            |
| `0x0404` | RECURSE_COUNT    | Recursive countdown (terminates at zero)       |
| `0x0405` | RECURSE_SPLIT    | Recursive output splitting                     |
| `0x0406` | RECURSE_DECAY    | Recursive parameter decay                      |

#### Anchor Family (0x0500 - 0x05FF)

Anchor blocks mark outputs for L2 protocol use (channels, pools, oracles)
and provide the DATA_RETURN block for unspendable data commitments, replacing
OP_RETURN with typed, size-bounded fields.

| Code     | Name           | Description                                  |
|----------|----------------|----------------------------------------------|
| `0x0501` | ANCHOR         | Generic anchor marker                         |
| `0x0502` | ANCHOR_CHANNEL | Lightning channel anchor (2 pubkeys + commitment number) |
| `0x0503` | ANCHOR_POOL    | Pool anchor (VTXO tree root + participant count) |
| `0x0504` | ANCHOR_RESERVE | Reserve anchor (guardian threshold + guardian hash) |
| `0x0505` | ANCHOR_SEAL    | Seal anchor (asset ID + state transition hash) |
| `0x0506` | ANCHOR_ORACLE  | Oracle anchor (oracle pubkey + outcome count) |
| `0x0507` | DATA_RETURN    | Unspendable data commitment (max 40 bytes)    |

#### PLC Family (0x0600 - 0x06FF)

The PLC (Programmable Logic Controller) family provides stateful contract
primitives. These blocks model industrial control patterns -- hysteresis
bands, timers, latches, counters, comparators, sequencers, and rate
limiters -- as on-chain spending conditions. State transitions are driven
by RECURSE_MODIFIED, which mutates condition fields between spends.

| Code     | Name             | Description                                   |
|----------|------------------|-----------------------------------------------|
| `0x0601` | HYSTERESIS_FEE   | Fee rate hysteresis band                       |
| `0x0602` | HYSTERESIS_VALUE | Value hysteresis band                          |
| `0x0611` | TIMER_CONTINUOUS | Continuous timer (consecutive blocks)          |
| `0x0612` | TIMER_OFF_DELAY  | Off-delay timer (hold after trigger)           |
| `0x0621` | LATCH_SET        | Latch set (state activation via signed event)  |
| `0x0622` | LATCH_RESET      | Latch reset (state deactivation with delay)    |
| `0x0631` | COUNTER_DOWN     | Down counter (decrement on signed event)       |
| `0x0632` | COUNTER_PRESET   | Preset counter (approval accumulator)          |
| `0x0633` | COUNTER_UP       | Up counter (increment on signed event)         |
| `0x0641` | COMPARE          | Comparator (amount vs thresholds)              |
| `0x0651` | SEQUENCER        | Step sequencer                                 |
| `0x0661` | ONE_SHOT         | One-shot activation window                     |
| `0x0671` | RATE_LIMIT       | Rate limiter (per-block cap, accumulation, refill) |
| `0x0681` | COSIGN           | Cross-input co-spend constraint                |

COSIGN (`0x0681`) occupies the PLC range but functions as a cross-input
signature constraint, requiring another input in the same transaction to
carry a matching conditions hash.

#### Compound Family (0x0700 - 0x07FF)

Compound blocks collapse common multi-block patterns into single blocks,
reducing witness size and eliminating field-ordering errors. A TIMELOCKED_SIG
is a SIG + CSV in one block; an HTLC is a hash + timelock + two signatures
in one block.

| Code     | Name                | Description                                |
|----------|---------------------|--------------------------------------------|
| `0x0701` | TIMELOCKED_SIG      | SIG + CSV combined                          |
| `0x0702` | HTLC                | Hash + Timelock + dual-Sig (atomic swap)    |
| `0x0703` | HASH_SIG            | Hash preimage + SIG combined                |
| `0x0704` | PTLC                | ADAPTOR_SIG + CSV combined (point-locked)   |
| `0x0705` | CLTV_SIG            | SIG + CLTV combined                         |
| `0x0706` | TIMELOCKED_MULTISIG | MULTISIG + CSV combined                     |

#### Governance Family (0x0800 - 0x08FF)

Governance blocks impose transaction-level constraints that go beyond
individual input authorization. They enable spending windows, weight caps,
input/output count bounds, value ratios, set membership proofs, and
per-output constraints.

| Code     | Name           | Description                                    |
|----------|----------------|------------------------------------------------|
| `0x0801` | EPOCH_GATE     | Periodic spending window (block-height epochs)  |
| `0x0802` | WEIGHT_LIMIT   | Maximum transaction weight limit                |
| `0x0803` | INPUT_COUNT    | Input count bounds (min/max)                    |
| `0x0804` | OUTPUT_COUNT   | Output count bounds (min/max)                   |
| `0x0805` | RELATIVE_VALUE | Output value as ratio of input value            |
| `0x0806` | ACCUMULATOR    | Merkle accumulator (set membership proof)       |
| `0x0807` | OUTPUT_CHECK   | Per-output value range and script hash constraint |

#### Legacy Family (0x0900 - 0x09FF)

Legacy blocks wrap existing Bitcoin output types as Ladder Script blocks,
enabling migration from v1/v2/v3 transaction patterns to v4 without
re-keying. Each legacy block evaluates identically to its Bitcoin Script
counterpart but within the typed block framework.

| Code     | Name               | Description                                |
|----------|--------------------|--------------------------------------------|
| `0x0901` | P2PK_LEGACY        | Wrapped P2PK (pubkey + signature)           |
| `0x0902` | P2PKH_LEGACY       | Wrapped P2PKH (hash160 + pubkey + signature)|
| `0x0903` | P2SH_LEGACY        | Wrapped P2SH (hash160 + inner script)       |
| `0x0904` | P2WPKH_LEGACY      | Wrapped P2WPKH (delegates to P2PKH path)    |
| `0x0905` | P2WSH_LEGACY       | Wrapped P2WSH (hash256 + inner script)       |
| `0x0906` | P2TR_LEGACY        | Wrapped P2TR key-path (pubkey + signature)   |
| `0x0907` | P2TR_SCRIPT_LEGACY | Wrapped P2TR script-path (hash256 + internal key + inner script) |

### Wire Format

Blocks are encoded using a compact wire format with micro-headers and
implicit field layouts, minimizing witness size while maintaining full
type safety.

#### Block Header

Each block begins with a single header byte:

- `0x00` - `0x7F`: Micro-header slot index. The block type is looked up
  from the micro-header table. The block is not inverted.
- `0x80`: Escape byte. A `uint16_t` block type follows (little-endian).
  The block is not inverted.
- `0x81`: Escape byte (inverted). A `uint16_t` block type follows
  (little-endian). The block is inverted.

#### Implicit Fields

When a micro-header is used and an implicit field layout exists for the
block type in the current serialization context (WITNESS or CONDITIONS),
field count and type bytes are omitted. Fields are read according to the
implicit layout:

- **NUMERIC** fields: encoded as a CompactSize value (no length prefix).
  Deserialized into a 4-byte little-endian representation.
- **Fixed-size fields** (e.g., HASH256 at 32 bytes, SCHEME at 1 byte):
  data is written directly with no length prefix.
- **Variable-size fields** (e.g., PUBKEY, SIGNATURE, PREIMAGE): CompactSize
  length prefix followed by data bytes.

#### Explicit Fields

When micro-header encoding is not used (escape byte, inverted block, or no
implicit layout):

```
[n_fields: CompactSize]
for each field:
    [data_type: uint8_t]
    if NUMERIC: [value: CompactSize]
    else: [data_len: CompactSize] [data: bytes]
```

#### Annotated Examples

**SIG block in CONDITIONS context (micro-header, implicit layout):**

```
00              # micro-header 0x00 → SIG
01              # SCHEME = 0x01 (Schnorr) — fixed 1 byte, no length prefix
Total: 2 bytes
```

**TIMELOCKED_SIG block in WITNESS context (micro-header, implicit layout):**

```
27              # micro-header 0x27 → TIMELOCKED_SIG
20              # PUBKEY length = 32
<32 bytes>      # x-only public key
40              # SIGNATURE length = 64
<64 bytes>      # Schnorr signature
90 01           # NUMERIC = 144 (CompactSize encoding of 0x90)
Total: 1+1+32+1+64+2 = 101 bytes
```

**Inverted CSV block (escape byte, explicit fields):**

```
81              # escape byte (inverted)
01 01           # block_type = 0x0101 (CSV), little-endian
01              # n_fields = 1
08              # data_type = 0x08 (NUMERIC)
90 01           # value = 144 (CompactSize)
Total: 7 bytes
```

### Micro-Header Table

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
| `0x07` | *(reserved)*       | `0x20` | COUNTER_PRESET      |
| `0x08` | *(reserved)*       | `0x21` | COUNTER_UP          |
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

| Slot   | Block Type           | Slot   | Block Type           |
|--------|----------------------|--------|----------------------|
| `0x32` | ACCUMULATOR          | `0x38` | P2WPKH_LEGACY        |
| `0x33` | MUSIG_THRESHOLD      | `0x39` | P2WSH_LEGACY         |
| `0x34` | KEY_REF_SIG          | `0x3A` | P2TR_LEGACY          |
| `0x35` | P2PK_LEGACY          | `0x3B` | P2TR_SCRIPT_LEGACY   |
| `0x36` | P2PKH_LEGACY         | `0x3C` | DATA_RETURN          |
| `0x37` | P2SH_LEGACY          | `0x3D` | HASH_GUARDED         |
|        |                      | `0x3E` | OUTPUT_CHECK         |

`0x7F` are unused.

### Implicit Field Layouts

Each block type has an implicit field layout for the CONDITIONS context and
optionally for the WITNESS context. When a micro-header is used and the
layout exists, field count and type bytes are omitted on the wire.

Notation: `TYPE(N)` means fixed N bytes with no length prefix. `TYPE(var)`
means CompactSize length prefix followed by data. NUMERIC is always
CompactSize-encoded (no length prefix, variable 1-5 bytes on wire).

#### Conditions Context Layouts

| Block Type          | Fields                                                |
|---------------------|-------------------------------------------------------|
| SIG                 | SCHEME(1)                                             |
| MULTISIG            | NUMERIC(var), SCHEME(1)                               |
| ADAPTOR_SIG         | *(no layout -- 0 condition fields)*                   |
| MUSIG_THRESHOLD     | NUMERIC(var), NUMERIC(var)                            |
| KEY_REF_SIG         | NUMERIC(var), NUMERIC(var)                            |
| CSV                 | NUMERIC(var)                                          |
| CSV_TIME            | NUMERIC(var)                                          |
| CLTV                | NUMERIC(var)                                          |
| CLTV_TIME           | NUMERIC(var)                                          |
| TAGGED_HASH         | HASH256(32), HASH256(32)                              |
| HASH_GUARDED        | HASH256(32)                                           |
| CTV                 | HASH256(32)                                           |
| VAULT_LOCK          | NUMERIC(var)                                          |
| AMOUNT_LOCK         | NUMERIC(var), NUMERIC(var)                            |
| COSIGN              | HASH256(32)                                           |
| TIMELOCKED_SIG      | SCHEME(1), NUMERIC(var)                               |
| HTLC                | HASH256(32), NUMERIC(var), SCHEME(1)                  |
| HASH_SIG            | HASH256(32), SCHEME(1)                                |
| CLTV_SIG            | SCHEME(1), NUMERIC(var)                               |
| PTLC                | NUMERIC(var)                                          |
| TIMELOCKED_MULTISIG | NUMERIC(var), NUMERIC(var), SCHEME(1)                 |
| EPOCH_GATE          | NUMERIC(var), NUMERIC(var)                            |
| WEIGHT_LIMIT        | NUMERIC(var)                                          |
| INPUT_COUNT         | NUMERIC(var), NUMERIC(var)                            |
| OUTPUT_COUNT        | NUMERIC(var), NUMERIC(var)                            |
| RELATIVE_VALUE      | NUMERIC(var), NUMERIC(var)                            |
| ACCUMULATOR         | HASH256(32)                                           |
| OUTPUT_CHECK        | NUMERIC(var), NUMERIC(var), NUMERIC(var), HASH256(32) |
| COMPARE             | NUMERIC(var), NUMERIC(var), NUMERIC(var)              |
| RECURSE_SAME        | NUMERIC(var)                                          |
| RECURSE_UNTIL       | NUMERIC(var)                                          |
| RECURSE_COUNT       | NUMERIC(var)                                          |
| RECURSE_SPLIT       | NUMERIC(var), NUMERIC(var)                            |
| ANCHOR              | NUMERIC(var)                                          |
| ANCHOR_CHANNEL      | NUMERIC(var)                                          |
| ANCHOR_POOL         | HASH256(32), NUMERIC(var)                             |
| ANCHOR_RESERVE      | NUMERIC(var), NUMERIC(var), HASH256(32)               |
| ANCHOR_SEAL         | HASH256(32), HASH256(32)                              |
| ANCHOR_ORACLE       | NUMERIC(var)                                          |
| DATA_RETURN         | DATA(var)                                             |
| HYSTERESIS_FEE      | NUMERIC(var), NUMERIC(var)                            |
| HYSTERESIS_VALUE    | NUMERIC(var), NUMERIC(var)                            |
| TIMER_CONTINUOUS    | NUMERIC(var), NUMERIC(var)                            |
| TIMER_OFF_DELAY     | NUMERIC(var)                                          |
| LATCH_SET           | NUMERIC(var)                                          |
| LATCH_RESET         | NUMERIC(var), NUMERIC(var)                            |
| COUNTER_DOWN        | NUMERIC(var)                                          |
| COUNTER_PRESET      | NUMERIC(var), NUMERIC(var)                            |
| COUNTER_UP          | NUMERIC(var), NUMERIC(var)                            |
| SEQUENCER           | NUMERIC(var), NUMERIC(var)                            |
| ONE_SHOT            | NUMERIC(var), HASH256(32)                             |
| RATE_LIMIT          | NUMERIC(var), NUMERIC(var), NUMERIC(var)              |
| P2PK_LEGACY         | SCHEME(1)                                             |
| P2PKH_LEGACY        | HASH160(20)                                           |
| P2SH_LEGACY         | HASH160(20)                                           |
| P2WPKH_LEGACY       | HASH160(20)                                           |
| P2WSH_LEGACY        | HASH256(32)                                           |
| P2TR_LEGACY         | SCHEME(1)                                             |
| P2TR_SCRIPT_LEGACY  | HASH256(32)                                           |

ADAPTOR_SIG has 0 condition fields (no implicit layout; conditions are
empty). RECURSE_MODIFIED and RECURSE_DECAY have variable field counts
(2 + 4*N mutation descriptors) and use explicit encoding; they are
protected by `IsDataEmbeddingType` rejection rather than implicit layouts.

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

### MLSC Merkle Tree

#### Leaf Order

```
[rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

The tree is padded to the next power of 2 with empty leaves:
`MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "")`.

#### Leaf Computation

**Rung leaf:**
```
TaggedHash("LadderLeaf", SerializeRungBlocks(rung, CONDITIONS) || pubkey[0] || pubkey[1] || ...)
```

Pubkeys are appended in positional order, walked left-to-right across
key-consuming blocks using `PubkeyCountForBlock()`. This is the
`merkle_pub_key` commitment: public keys are bound in the leaf hash rather
than carried in conditions.

**Relay leaf:**
```
TaggedHash("LadderLeaf", SerializeRelayBlocks(relay, CONDITIONS) || pubkey[0] || ...)
```

**Coil leaf:**
```
TaggedHash("LadderLeaf", SerializeCoilData(coil))
```

#### Interior Nodes

Interior nodes use sorted lexicographic ordering:

```
TaggedHash("LadderInternal", min(left, right) || max(left, right))
```

Sorting eliminates the need to track left/right ordering in proofs, reducing
proof size and simplifying verification.

#### Worked Example: 2-Rung Ladder

Consider a ladder with 2 rungs (SIG and TIMELOCKED_SIG), no relays:

```
Leaves (before padding):
  leaf[0] = TaggedHash("LadderLeaf", SerializeRungBlocks(rung0, COND) || alice_pk)
  leaf[1] = TaggedHash("LadderLeaf", SerializeRungBlocks(rung1, COND) || bob_pk)
  leaf[2] = TaggedHash("LadderLeaf", SerializeCoilData(coil))

Padded to 4 leaves:
  leaf[3] = TaggedHash("LadderLeaf", "")   [empty]

Interior nodes:
  node_01 = TaggedHash("LadderInternal", min(leaf[0], leaf[1]) || max(leaf[0], leaf[1]))
  node_23 = TaggedHash("LadderInternal", min(leaf[2], leaf[3]) || max(leaf[2], leaf[3]))

Root:
  root = TaggedHash("LadderInternal", min(node_01, node_23) || max(node_01, node_23))
```

To spend via rung 0 (SIG with alice), the MLSC proof reveals rung 0 and
provides `leaf[1]` and `node_23` as proof hashes. The verifier recomputes
`leaf[0]` from the revealed conditions + alice's pubkey, then rebuilds the
tree to verify the root matches the UTXO's `conditions_root`.

#### MLSC Proof Structure

```
[total_rungs: CompactSize]
[total_relays: CompactSize]
[rung_index: CompactSize]          -- which rung is revealed
<revealed rung blocks>             -- CONDITIONS-context serialized
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
    [hash: 32 bytes]               -- unrevealed sibling hashes
[n_mutation_targets: CompactSize]  -- for RECURSE_MODIFIED/DECAY
for each mutation target:
    [rung_index: CompactSize]
    <rung blocks>
    [n_relay_refs: CompactSize]
    <relay_refs>
```

### Sighash Algorithm

Ladder Script uses `SignatureHashLadder`, a tagged hash following the
BIP-341 pattern:

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

| Hash Type               | Value  | Description                              |
|-------------------------|--------|------------------------------------------|
| DEFAULT                 | `0x00` | Equivalent to ALL                        |
| ALL                     | `0x01` | Commit to all outputs                    |
| NONE                    | `0x02` | Do not commit to outputs                 |
| SINGLE                  | `0x03` | Commit to corresponding output only      |
| ANYPREVOUT              | `0x40` | Skip prevout commitment (BIP-118 analogue) |
| ANYONECANPAY            | `0x80` | Commit only to this input                |
| ANYPREVOUTANYSCRIPT     | `0xC0` | Skip prevout and conditions commitment   |

Valid combinations: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

#### Comparison with BIP-341 Hash Types

| Feature                | BIP-341 (Taproot)       | BIP-110 (Ladder Script) |
|------------------------|-------------------------|--------------------------|
| Base types             | DEFAULT, ALL, NONE, SINGLE | Same                  |
| ANYONECANPAY           | `0x80` flag             | Same                     |
| ANYPREVOUT             | Not in BIP-341 (BIP-118)| `0x40` (native support)  |
| ANYPREVOUTANYSCRIPT    | Not in BIP-341          | `0xC0` (native support)  |
| Script commitment      | `tapleaf_hash`          | `conditions_root` (MLSC) |
| Epoch field            | 0 (ext_flag dependent)  | 0 (reserved)             |
| Annex                  | Supported               | Not supported (spend_type=0) |

Key difference: BIP-341 commits to a `tapleaf_hash` computed from the
specific Tapscript leaf. Ladder Script commits to the `conditions_root`
(the full MLSC Merkle root), which covers all rungs, relays, and the coil.
ANYPREVOUTANYSCRIPT skips this commitment to enable rebindable signatures.

#### Field Commitments

- **epoch**: Always 0 (reserved for future sighash upgrades).
- **spend_type**: Always 0 (no annex, no extensions).
- **conditions_hash**: The `conditions_root` from the UTXO. Skipped with
  ANYPREVOUTANYSCRIPT.
- **ANYPREVOUT** (`0x40`): Skips prevout hash but commits to amounts,
  sequences, and conditions. Enables LN-Symmetry/eltoo.
- **ANYPREVOUTANYSCRIPT** (`0xC0`): Skips both prevout and conditions.
  Enables rebindable signatures across different condition sets.

### Evaluation Semantics

#### EvalResult Values

| Value                | Meaning                                                |
|----------------------|--------------------------------------------------------|
| `SATISFIED`          | All conditions met                                     |
| `UNSATISFIED`        | Conditions not met (valid failure, not consensus error) |
| `ERROR`              | Malformed block (consensus failure)                    |
| `UNKNOWN_BLOCK_TYPE` | Unknown type (forward compatibility: treated as UNSATISFIED) |

#### Ladder Evaluation (OR across rungs)

Relays are evaluated first (index 0 through N-1, forward-only). Then rungs
are evaluated in order. The first satisfied rung determines the spending
path.

```
EvalLadder = OR(EvalRung(rung[0]), EvalRung(rung[1]), ...)
```

#### Rung Evaluation (AND within rung)

All blocks within a rung must return `SATISFIED`. If any block returns
`UNSATISFIED` or `ERROR`, the rung fails. Before evaluating blocks, relay
requirements (`relay_refs`) are checked: all referenced relays must have
been evaluated as `SATISFIED`.

```
EvalRung = AND(EvalBlock(block[0]), EvalBlock(block[1]), ...)
```

#### Relay Evaluation

Relays are shared condition sets evaluated like rungs (AND logic). Relay N
can only reference relays 0..N-1 (forward-only indexing; no cycles). Results
are cached and made available to rungs via `relay_refs`.

#### Merge Step

Before evaluation, conditions (from the MLSC proof) and witness data are
merged. For each block, the conditions provide the locking data (hashes,
timelocks, scheme selectors) and the witness provides the unlocking data
(pubkeys, signatures, preimages). Block types and inverted flags are taken
from the conditions side.

#### Inversion Rules

Blocks may be inverted (result flipped):

- `SATISFIED` becomes `UNSATISFIED`
- `UNSATISFIED` becomes `SATISFIED`
- `ERROR` remains `ERROR`
- `UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR`

Inversion is restricted to the `IsInvertibleBlockType` allowlist (fail-closed:
new block types default to non-invertible). Key-consuming blocks are never
invertible. The inverted flag is set via the `0x81` escape byte.

### Consensus Limits

| Parameter                       | Value   | Source                    |
|---------------------------------|---------|---------------------------|
| MAX_RUNGS                       | 16      | `serialize.h`             |
| MAX_BLOCKS_PER_RUNG             | 8       | `serialize.h`             |
| MAX_FIELDS_PER_BLOCK            | 16      | `serialize.h`             |
| MAX_LADDER_WITNESS_SIZE         | 100,000 | `serialize.h`             |
| MAX_PREIMAGE_FIELDS_PER_WITNESS | 2       | `serialize.h`             |
| COIL_ADDRESS_HASH_SIZE          | 32      | `serialize.h`             |
| MAX_RELAYS                      | 8       | `serialize.h`             |
| MAX_REQUIRES                    | 8       | `serialize.h`             |
| MAX_RELAY_DEPTH                 | 4       | `serialize.h`             |
| MICRO_HEADER_SLOTS              | 128     | `types.h`                 |
| MAX_IMPLICIT_FIELDS             | 8       | `types.h`                 |
| PUBKEY max size                 | 2,048   | `types.h` (FieldMaxSize)  |
| SIGNATURE max size              | 50,000  | `types.h` (FieldMaxSize)  |
| SCRIPT_BODY max size            | 80      | `types.h` (FieldMaxSize)  |
| DATA max size                   | 40      | `types.h` (FieldMaxSize)  |
| DATA_RETURN outputs per tx      | 1       | `evaluator.cpp`           |
| Witness stack elements          | 2       | `evaluator.cpp`           |

### Descriptor Language

Ladder Script conditions can be expressed in a human-readable descriptor
language parsed by `ParseDescriptor` and formatted by `FormatDescriptor`.

#### Grammar

```
ladder     = "ladder(" "or(" rung { "," rung } ")" ")"
rung       = block | "and(" block { "," block } ")"
block      = base_block | "!" base_block
```

#### Complete Block Grammar (all 61 types)

**Signature family:**
```
sig(@alias) | sig(@alias, scheme)
multisig(M, @pk1, @pk2, ...)
adaptor_sig(@signer, @adaptor_point) | adaptor_sig(@signer, @adaptor_point, scheme)
musig_threshold(M, @pk1, @pk2, ...)
key_ref_sig(relay_idx, block_idx)
```

**Timelock family:**
```
csv(N) | csv_time(N) | cltv(N) | cltv_time(N)
```

**Hash family:**
```
tagged_hash(tag_hex, expected_hex)
hash_guarded(hash_hex)
```

**Covenant family:**
```
ctv(template_hash_hex)
vault_lock(@recovery, @hot, delay)
amount_lock(min, max)
```

**Recursion family:**
```
recurse_same(max_depth)
recurse_modified(max_depth, block_idx, param_idx, delta)
recurse_until(height)
recurse_count(count)
recurse_split(max_splits, min_sats)
recurse_decay(max_depth, block_idx, param_idx, decay)
```

**Anchor family:**
```
anchor() | anchor_channel() | anchor_pool()
anchor_reserve() | anchor_seal() | anchor_oracle()
data_return(hex)
```

**PLC family:**
```
hysteresis_fee(N, N) | hysteresis_value(N, N)
timer_continuous(N) | timer_off_delay(N, N)
latch_set(@pk, N) | latch_reset(@pk, N)
counter_down(@pk, N) | counter_preset(@pk, N) | counter_up(@pk, N)
compare(op, value_b) | compare(op, value_b, value_c)
sequencer(N) | one_shot(@pk, N) | rate_limit(N, N, N)
cosign(conditions_hash_hex)
```

**Compound family:**
```
timelocked_sig(@pk, csv_blocks) | cltv_sig(@pk, height)
htlc(@sender, @receiver, preimage_hex, csv_blocks)
hash_sig(@pk, preimage_hex)
ptlc(@pk, @adaptor_point, csv_blocks)
timelocked_multisig(M, @pk1, @pk2, ..., csv_blocks)
```

**Governance family:**
```
epoch_gate(epoch_size, window_size) | weight_limit(max_weight)
input_count(min, max) | output_count(min, max)
relative_value(numerator, denominator) | accumulator(root_hex)
output_check(idx, min, max, script_hash_hex)
```

**Legacy family:**
```
p2pk(@pk) | p2pkh(@pk) | p2wpkh(@pk) | p2tr(@pk)
p2sh(inner_hex) | p2wsh(inner_hex) | p2tr_script(inner_hex)
```

#### Scheme Names

`schnorr`, `ecdsa`, `falcon512`, `falcon1024`, `dilithium3`, `sphincs_sha`

#### Examples

**Simple vault with recovery and hot-spend paths:**
```
ladder(or(
    sig(@recovery_key),
    and(sig(@hot_key), csv(144))
))
```

**HTLC for Lightning / atomic swap:**
```
ladder(or(
    htlc(@alice, @bob, <preimage_hex>, 144)
))
```

**Rate-limited wallet (max 1 BTC per 6 blocks, 2-of-3 multisig backup):**
```
ladder(or(
    and(sig(@daily_key), rate_limit(1, 100000000, 6)),
    multisig(2, @alice, @bob, @carol)
))
```

**Legacy P2PKH migration:**
```
ladder(or(
    p2pkh(@old_key)
))
```

### Anti-Spam Properties

Ladder Script enforces 7 mechanisms at deserialization time to prevent abuse
of the witness for arbitrary data storage:

1. **Selective inversion.** The `IsInvertibleBlockType` allowlist determines
   which blocks may be inverted. Key-consuming blocks (SIG, MULTISIG,
   ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG, compound signature types,
   legacy key types, ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET,
   LATCH_RESET, COUNTER_DOWN, COUNTER_UP) are never invertible. This
   prevents embedding arbitrary data as a garbage pubkey (fail the
   verification, invert to SATISFIED). The allowlist is fail-closed: new
   block types added in future versions default to non-invertible.

2. **`IsDataEmbeddingType` rejection.** For blocks without an implicit
   layout (where the deserializer cannot predict field count and types),
   the types PUBKEY_COMMIT (32 bytes), HASH256 (32 bytes), HASH160 (20
   bytes), and DATA (up to 40 bytes) are rejected. This prevents using
   layout-less blocks to embed unvalidated payloads.

3. **PREIMAGE field limit.** At most `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`
   PREIMAGE or SCRIPT_BODY fields are permitted per ladder witness. This
   limits user-chosen data to 64 bytes (2 x 32-byte PREIMAGE).

4. **DATA type restriction.** The DATA data type (`0x0B`) is only permitted
   in DATA_RETURN blocks. Any other block carrying a DATA field is rejected.

5. **`merkle_pub_key`.** Public keys are not carried in conditions. They
   exist only in the witness (PUBKEY fields) and are bound to the Merkle
   leaf at fund time. This eliminates the PUBKEY writable surface from
   conditions.

6. **Strict field enforcement.** When an implicit layout exists for a block
   type in the current context, the field count and types must match exactly.
   Extra fields are rejected.

7. **Blanket HASH256 rejection.** High-bandwidth data types (PUBKEY_COMMIT,
   HASH256, HASH160, DATA) classified as `IsDataEmbeddingType` are blocked
   in all blocks that lack an implicit layout, regardless of serialization
   context.

**Residual embeddable surface arithmetic:**

| Channel                | Max bytes | Notes                           |
|------------------------|-----------|---------------------------------|
| PREIMAGE fields        | 64        | 2 x 32 bytes (consensus cap)    |
| DATA_RETURN            | 40        | 1 per tx, max 40 bytes          |
| NUMERIC manipulation   | ~8        | 8 blocks x 1 byte each          |
| SCHEME byte choices    | ~4        | 4 SCHEME fields x 1 byte        |
| **Total**              | **~116**  |                                 |

### Serialization Format

#### LadderWitness Wire Format

```
[n_rungs: CompactSize]           -- 0 = diff witness mode
for each rung:
    [n_blocks: CompactSize]      -- must be >= 1
    for each block:
        <block encoding>         -- micro-header or escape + fields
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
[coil_type: uint8]               -- UNLOCK (0x01) or UNLOCK_TO (0x02)
[attestation: uint8]             -- INLINE (0x01)
[scheme: uint8]                  -- SCHNORR (0x01), ECDSA (0x02), FALCON512 (0x10),
                                    FALCON1024 (0x11), DILITHIUM3 (0x12), SPHINCS_SHA (0x13)
[address_len: CompactSize]       -- 0 or 32
[address_hash: bytes]            -- SHA256(raw_address), never raw on-chain
[n_coil_conditions: CompactSize] -- must be 0 (reserved, removed)
[n_rung_destinations: CompactSize]
for each rung_destination:
    [rung_index: uint16 LE]
    [address_hash: 32 bytes]
[n_relays: CompactSize]
for each relay:
    [n_blocks: CompactSize]
    for each block: <block encoding>
    [n_relay_refs: CompactSize]
    for each relay_ref: [index: CompactSize]
```

#### Coil Metadata

| Field         | Type    | Valid Values                                           |
|---------------|---------|--------------------------------------------------------|
| coil_type     | uint8   | UNLOCK (`0x01`), UNLOCK_TO (`0x02`)                    |
| attestation   | uint8   | INLINE (`0x01`)                                        |
| scheme        | uint8   | SCHNORR (`0x01`), ECDSA (`0x02`), FALCON512 (`0x10`), FALCON1024 (`0x11`), DILITHIUM3 (`0x12`), SPHINCS_SHA (`0x13`) |
| address_hash  | 0 or 32 | SHA-256 of the destination address                     |

#### Diff Witness Mode

When `n_rungs = 0`, the witness inherits rungs and relays from another
input's witness:

```
[0: CompactSize]                 -- signals diff witness
[input_index: CompactSize]       -- source input (must be < current input index)
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
SCRIPT_BODY, or SCHEME. Chaining (diff pointing to another diff witness) is
prohibited.

## Rationale

### Why typed blocks instead of opcodes?

Bitcoin Script's opcode model provides maximum generality at the cost of
static analysis. Given an arbitrary Script program, determining its resource
consumption, the conditions it enforces, or whether it terminates requires
executing it. This makes formal verification impractical and forces
conservative resource limits.

Typed blocks provide deterministic bounds at parse time. Each block type has
a fixed evaluation function, a known maximum field count, and bounded
computational cost. A verifier can determine the worst-case cost of
evaluating a ladder witness without executing any block. This property
enables:

- **Static analysis:** Wallets can display exactly which conditions a UTXO
  requires without simulation.
- **Formal verification:** The 10 TLA+ specifications model evaluation
  semantics, Merkle proofs, sighash computation, inversion rules, and
  anti-spam properties as state machines with bounded state spaces.
- **Deterministic resource bounds:** MAX_RUNGS (16) x MAX_BLOCKS_PER_RUNG (8)
  x MAX_FIELDS_PER_BLOCK (16) gives a hard upper bound on evaluation work
  per input. No per-block computational surprises.

### Why 61 types instead of fewer generic primitives?

A minimal design might provide only SIG, TIMELOCK, HASH, and COVENANT as
generic blocks with sub-type parameters. This approach has three problems:

1. **Wire overhead.** A generic TIMELOCK block needs a sub-type field
   (relative/absolute, blocks/time) plus the value -- 3 fields minimum.
   CSV needs only 1 field (the sequence value). Over millions of
   transactions, compound blocks save significant witness space.

2. **Error surface.** Generic primitives require the spender to assemble
   correct field combinations. A TIMELOCKED_SIG block cannot be constructed
   with a missing CSV field or a mismatched scheme -- the implicit layout
   enforces the exact field sequence. An HTLC expressed as 4 separate
   generic blocks (2 SIG + HASH + CSV) has 4 independent failure modes;
   the compound HTLC block has 1.

3. **Static analysis cost.** With 61 concrete types, a verifier can
   dispatch to a specific evaluation function in O(1) via the block type.
   Generic primitives require parsing sub-type fields before dispatching,
   complicating formal models.

### Why merkle_pub_key?

Without `merkle_pub_key`, conditions would carry PUBKEY or PUBKEY_COMMIT
fields on-chain. A PUBKEY field can hold up to 2,048 bytes (to accommodate
PQ public keys). An attacker could create a SIG block with a garbage
2,048-byte "public key" that encodes arbitrary data, then never spend the
output -- the data is permanently stored in the UTXO set.

By moving public keys to the Merkle leaf, conditions carry only a SCHEME
byte (1 byte) for signature blocks. The 2,048-byte channel is closed.
The cost is one additional hash computation per key-consuming block during
MLSC verification, which is negligible relative to signature verification.

### Why MLSC instead of Taproot's script tree?

MLSC and Taproot's script tree serve the same purpose (commit to multiple
spending paths, reveal only one) but differ in structure:

1. **Sorted interior nodes.** MLSC uses
   `TaggedHash("LadderInternal", min(L, R) || max(L, R))`. This eliminates
   left/right bits from Merkle proofs, saving 1 bit per tree level and
   simplifying proof generation. Taproot's unsorted tree requires left/right
   tracking.

2. **Pubkeys in leaves.** MLSC folds public keys into the leaf hash
   (`merkle_pub_key`). Taproot carries public keys inside Tapscript leaves.
   This is the structural basis for anti-spam.

3. **Coil leaf.** MLSC includes a dedicated coil leaf for output metadata
   (unlock type, attestation mode, scheme, destination). Taproot has no
   equivalent -- output metadata must be encoded within individual scripts.

### Why forward-only relay indexing?

Relay N can only reference relays 0..N-1. This constraint guarantees
acyclicity without graph traversal: a forward-only ordering is a topological
sort by construction. The maximum transitive depth is bounded at 4
(`MAX_RELAY_DEPTH`). Without this constraint, detecting cycles would require
a graph search at deserialization time, adding complexity and a potential
denial-of-service vector.

### Why is the inversion allowlist fail-closed?

When a new block type is added in a future soft fork, it defaults to
non-invertible. This is the safe default because inversion of an unknown
block type would allow an attacker to embed arbitrary data (construct a
block that fails, invert to SATISFIED) without the network understanding
the block's semantics. The `UNKNOWN_BLOCK_TYPE` result inverted to `ERROR`
(not SATISFIED) enforces this at evaluation time.

### Why PREIMAGE min=1?

The PREIMAGE data type has a minimum size of 1 byte, not 32. This is
required for P2SH and P2WSH legacy wrappers, where the inner conditions
(serialized as SCRIPT_BODY, which shares the PREIMAGE count limit) can be
shorter than 32 bytes. Restricting PREIMAGE to exactly 32 bytes would
prevent wrapping small P2SH scripts.

### Why SCHEME is 1 byte?

A single byte provides 256 possible signature scheme selectors. The current
allocation uses 6 values (2 classical, 4 post-quantum). When new PQ schemes
are standardized (e.g., from NIST Round 4), they receive new SCHEME codes
within the existing byte. No wire format changes, no new data types, no
hard fork. The SCHEME byte is the single extension point for cryptographic
algorithm agility.

## Comparison with Existing Proposals

| Feature                    | BIP-110 (Ladder Script) | BIP-119 (CTV) | BIP-118 (APO) | BIP-345 (OP_VAULT) | BIP-420 (OP_CAT) |
|----------------------------|:-----------------------:|:--------------:|:--------------:|:-------------------:|:-----------------:|
| Covenants                  | CTV + VAULT_LOCK + AMOUNT_LOCK + RECURSE_* + OUTPUT_CHECK | Template hash only | No | Vault-specific | Composable via stack |
| Vaults                     | VAULT_LOCK (native)    | Via template chain | No | Native | Via composition |
| HTLC (native)              | HTLC block             | No             | No | No | Via composition |
| Post-quantum signatures    | SCHEME byte (6 schemes)| No             | No | No | No |
| Anti-spam enforcement      | 7 mechanisms, ~116 bytes residual | None (opcodes) | None | None | None |
| Formal specification       | 10 TLA+ specs          | None           | None | None | None |
| Static analysis            | Full (typed blocks)    | Partial (single opcode) | Partial | Partial | No (arbitrary stack) |
| Composability              | AND/OR within ladder   | External (multiple outputs) | Sighash flags | Vault-specific | Stack composition |
| Descriptor language         | 61-type grammar        | N/A            | N/A | N/A | N/A |
| Stateful contracts         | 14 PLC block types     | No             | No | No | Via composition |
| ANYPREVOUT                 | Native (`0x40`)        | No             | Native | No | No |
| Recursion (bounded)        | 6 RECURSE_* types      | Via template chain | No | Unvaulting only | Unbounded risk |
| Transaction-level governance | 7 governance types    | No             | No | No | No |

## Backwards Compatibility

### Soft Fork Deployment

Version 4 transactions are currently non-standard and invalid under
consensus rules. Existing nodes treat v4 transactions as anyone-can-spend
(the `0xC2` prefix is not a recognized script pattern). This satisfies the
soft fork requirement: old nodes accept blocks containing v4 transactions;
upgraded nodes enforce the full Ladder Script rules.

### No Impact on Existing Transactions

Ladder Script rules apply exclusively to transactions with `nVersion = 4`.
Transactions with `nVersion` 1, 2, or 3 are completely unaffected.

### Legacy Family for Migration

The 7 legacy block types (P2PK_LEGACY through P2TR_SCRIPT_LEGACY) allow
existing key material to be used within Ladder Script conditions without
re-keying. A P2PKH address holder can migrate to a v4 output using
`p2pkh(@key)` in the descriptor, retaining their existing public key and
signing workflow.

### Wallet Compatibility

Outputs with `0xC2` scriptPubKeys are unknown to wallets that have not been
upgraded. Such wallets will not recognize these outputs as spendable or
display them in balance calculations. This is the standard behavior for new
output types in Bitcoin and does not represent a compatibility regression.

### Removed Features

- **Inline conditions (`0xC1` prefix):** Removed and always rejected. All
  outputs must use the MLSC Merkle root format (`0xC2`).
- **COVENANT coil type (`0x03`):** Removed. Only UNLOCK (`0x01`) and
  UNLOCK_TO (`0x02`) are valid coil types.
- **AGGREGATE (`0x02`) and DEFERRED (`0x03`) attestation modes:** Removed.
  Only INLINE (`0x01`) is valid.

## Activation

All 61 block types activate together as a single soft fork. Partial
activation (enabling a subset of block types) is not supported, as block
types are interdependent: compound blocks reference signature and timelock
semantics, recursion blocks reference MLSC leaf computation, and PLC blocks
reference recursion for state transitions.

The activation mechanism (BIP-9 signaling or BIP-8 mandatory activation) is
outside the scope of this specification. See `SOFT_FORK_GUIDE.md` for a
phased deployment approach.

## Reference Implementation

| File                      | Description                                          |
|---------------------------|------------------------------------------------------|
| `src/rung/types.h`       | Block type enum (61 types), data type enum (11 types), micro-header table (128 slots), implicit field layouts, `BlockDescriptor` table, `IsKnownBlockType`, `IsInvertibleBlockType`, `IsKeyConsumingBlockType`, `PubkeyCountForBlock` |
| `src/rung/types.cpp`     | `RungField::IsValid` implementation                  |
| `src/rung/evaluator.h`   | `EvalResult`, `RungEvalContext`, `BatchVerifier`, `LadderSignatureChecker`, evaluator function declarations |
| `src/rung/evaluator.cpp` | Block evaluators (all 61 types), `EvalBlock` dispatch, `EvalRung`, `EvalLadder`, `VerifyRungTx`, `ValidateRungOutputs`, `MergeConditionsAndWitness` |
| `src/rung/sighash.h`     | `LADDER_SIGHASH_ANYPREVOUT` (`0x40`), `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT` (`0xC0`) |
| `src/rung/sighash.cpp`   | `SignatureHashLadder` implementation                 |
| `src/rung/serialize.h`   | Consensus limits, `SerializationContext`, `DeserializeLadderWitness`, `SerializeLadderWitness` |
| `src/rung/serialize.cpp` | Wire format implementation, micro-header encoding, implicit field serialization, `DeserializeBlock` |
| `src/rung/conditions.h`  | MLSC format, `MLSCProof`, `RungConditions`, `MLSCVerifiedLeaves`, leaf computation functions |
| `src/rung/conditions.cpp`| MLSC Merkle tree, proof verification, `ComputeConditionsRoot`, `BuildMerkleTree` |
| `src/rung/descriptor.h`  | `ParseDescriptor`, `FormatDescriptor`                |
| `src/rung/descriptor.cpp`| Descriptor language parser and formatter             |
| `src/rung/aggregate.h`   | `TxAggregateContext`, `AggregateProof`               |
| `src/rung/aggregate.cpp` | Aggregate signature verification                     |
| `src/rung/policy.h`      | `IsBaseBlockType`, `IsCovenantBlockType`, `IsStatefulBlockType`, `IsStandardRungTx` |
| `src/rung/policy.cpp`    | Policy implementation                                |
| `src/rung/pq_verify.h`   | PQ signature scheme support declarations             |
| `src/rung/pq_verify.cpp` | PQ verification via liboqs (optional build dependency) |
| `src/rung/adaptor.cpp`   | Adaptor signature helpers                            |
| `src/rung/rpc.cpp`       | RPC commands for Ladder Script transactions          |

## Test Vectors

The reference implementation includes:

- **480 unit tests** covering individual block evaluators, serialization
  round-trips, field validation, anti-spam rejection, micro-header encoding,
  implicit layout matching, and inversion semantics.

- **60 functional tests** covering end-to-end transaction construction,
  MLSC proof generation and verification, covenant evaluation, recursion
  depth enforcement, diff witness resolution, and relay chain evaluation.

- **10 TLA+ specifications** formally modeling:
  1. `LadderEval` -- top-level ladder/rung evaluation semantics
  2. `LadderEvalCheck` -- evaluation result consistency checking
  3. `LadderComposition` -- AND/OR composition and relay interaction
  4. `LadderBlockEval` -- per-block evaluation dispatch and field validation
  5. `LadderAntiSpam` -- anti-spam property enforcement (inversion, data embedding, field limits)
  6. `LadderWireFormat` -- wire format serialization/deserialization invariants
  7. `LadderMerkle` -- MLSC Merkle tree construction and proof verification
  8. `LadderSighash` -- sighash computation and hash type validation
  9. `LadderCovenant` -- covenant and recursion termination properties
  10. `LadderCrossInput` -- cross-input constraints (COSIGN, diff witness)

- **61/61 block types verified on signet** (all block types exercised in
  end-to-end transactions on the Ladder Script signet node).

## Security Considerations

### Anti-Spam Surface

The maximum embeddable user-chosen data per transaction is approximately
116 bytes:

- 2 PREIMAGE fields x 32 bytes = 64 bytes
- 1 DATA_RETURN output x 40 bytes = 40 bytes
- NUMERIC field manipulation (up to 8 blocks x ~1 byte entropy each) = ~8 bytes
- SCHEME byte choices (up to 4 signature blocks x 1 byte each) = ~4 bytes
- Total: ~116 bytes

All other witness bytes are semantically validated: signatures are verified
against committed public keys, hashes are checked against committed values,
timelocks are verified against chain state. This represents a reduction from
the effectively unlimited data embedding capacity of raw Bitcoin Script
witnesses to a bounded, calculable surface.

### Recursion Termination

All 6 recursion block types terminate:

- **RECURSE_SAME:** No parameter mutation; the covenant persists indefinitely
  but does not grow or consume additional resources per spend.
- **RECURSE_COUNT:** Counter decrements each spend; terminates at zero.
- **RECURSE_UNTIL:** Terminates at a specified block height.
- **RECURSE_SPLIT:** `max_splits` decrements; terminates at zero.
  `min_split_sats` prevents dust output creation.
- **RECURSE_MODIFIED:** Bounded by `max_depth` parameter.
- **RECURSE_DECAY:** Bounded by `max_depth` parameter.

There is no unbounded recursion. Legacy block types (P2SH_LEGACY,
P2WSH_LEGACY, P2TR_SCRIPT_LEGACY) support inner-conditions recursion but
are depth-limited at evaluation time.

### Sighash Binding

The `SignatureHashLadder` algorithm commits to the `conditions_root` (the
MLSC Merkle root from the UTXO being spent), binding every signature to the
full condition set. An attacker cannot extract a signature from one condition
set and replay it against a different one, unless the signer explicitly
opted out via ANYPREVOUTANYSCRIPT (`0xC0`).

### Post-Quantum: Fail-Closed

PQ signature support is compile-time optional (requires liboqs). When liboqs
is not available, PQ scheme verification returns `UNSATISFIED` (fail-closed,
not fail-open). This means:

- Outputs locked with PQ schemes cannot be spent on nodes without liboqs.
- No funds are at risk from missing PQ support (spending fails, it does not
  succeed with a weaker algorithm).
- The SIGNATURE field maximum of 50,000 bytes accommodates SPHINCS+-SHA2-256f
  signatures (approximately 49,216 bytes).

### Batch Verification

`BatchVerifier` collects Schnorr signature verification requests during
ladder evaluation and verifies them in a single batch after all inputs pass
individual evaluation. On batch failure, `FindFailure` identifies the first
invalid entry for error reporting. ECDSA and PQ signatures are verified
individually (they do not support batch verification).

## Acknowledgements

This specification was developed as part of the Bitcoin Ghost project. The
MLSC Merkle tree design follows the BIP-341 tagged hash pattern. The CTV
block implements BIP-119 template hash verification. The ANYPREVOUT and
ANYPREVOUTANYSCRIPT sighash flags follow the design principles of BIP-118.

## Appendix A: Block Evaluation Rules

The following sections detail the evaluation semantics for each of the 61
block types, grouped by family. All block types follow the dispatch in
`EvalBlock`.

### Signature Family

| Type            | Evaluation                                                |
|-----------------|-----------------------------------------------------------|
| SIG             | Verify SIGNATURE against PUBKEY using `CheckSchnorrSignature` or `CheckECDSASignature` (routed by SCHEME or signature size). PQ schemes routed via `VerifyPQSignature`. |
| MULTISIG        | M-of-N: NUMERIC threshold M, N PUBKEY fields, M SIGNATURE fields. Each signature must match a distinct pubkey. Pubkeys are ordered; signatures must appear in the same order as their corresponding pubkeys. |
| ADAPTOR_SIG     | Verify adapted SIGNATURE against signing PUBKEY with respect to adaptor point. The adaptor secret is revealed off-chain when the signature is published. |
| MUSIG_THRESHOLD | Verify aggregate SIGNATURE against aggregate PUBKEY. The FROST/MuSig2 ceremony is performed off-chain; on-chain verification appears as single-sig. NUMERIC fields carry M (threshold) and N (group size). |
| KEY_REF_SIG     | Resolve PUBKEY_COMMIT from a relay block via relay_refs (NUMERIC relay_index, NUMERIC block_index), then verify SIGNATURE against the referenced key. Enables DRY key reuse across rungs. |

### Timelock Family

| Type      | Evaluation                                                    |
|-----------|---------------------------------------------------------------|
| CSV       | Read NUMERIC sequence value; call `CheckSequence` against the input's nSequence. SATISFIED if the relative timelock (block-height) is met. |
| CSV_TIME  | Same as CSV but the sequence value is interpreted as median-time-past (BIP-68 time flag set). |
| CLTV      | Read NUMERIC locktime value; call `CheckLockTime` against the transaction's nLockTime. SATISFIED if the absolute block-height is met. |
| CLTV_TIME | Same as CLTV but the locktime is interpreted as median-time-past. |

### Hash Family

| Type          | Evaluation                                               |
|---------------|----------------------------------------------------------|
| TAGGED_HASH   | Two HASH256 fields (tag_hash, expected_hash) from conditions; one PREIMAGE from witness. Compute `SHA256(tag_hash \|\| tag_hash \|\| preimage)` and compare to expected_hash. Follows the BIP-340 tagged hash construction. |
| HASH_GUARDED  | One HASH256 (committed hash) from conditions; one PREIMAGE from witness. Compute `SHA256(preimage)` and compare. Non-invertible (not in `IsInvertibleBlockType`). |

### Covenant Family

| Type        | Evaluation                                                 |
|-------------|------------------------------------------------------------|
| CTV         | Compute the BIP-119 template hash for the spending transaction at the current input index. Compare against the HASH256 field. SATISFIED on match. |
| VAULT_LOCK  | Two-path vault: first try recovery PUBKEY (immediate spend with no delay), then hot PUBKEY (requires CSV delay of NUMERIC blocks). Both pubkeys are committed via merkle_pub_key. |
| AMOUNT_LOCK | Two NUMERICs (min_sats, max_sats). SATISFIED if the output amount is within [min_sats, max_sats]. |

### Recursion Family

| Type             | Evaluation                                                |
|------------------|-----------------------------------------------------------|
| RECURSE_SAME     | The spending transaction's output MLSC root must equal the input's root (identity covenant). NUMERIC max_depth is informational. |
| RECURSE_MODIFIED | Apply parameterized mutations (block_idx, param_idx, delta tuples) to condition fields, recompute the MLSC Merkle root from the mutated leaf array, and compare against the output's root. Supports multi-rung mutations via mutation_targets in the MLSC proof. |
| RECURSE_UNTIL    | Before target block height (NUMERIC): output must re-encumber with same root. At or after target: covenant terminates (SATISFIED unconditionally). |
| RECURSE_COUNT    | Decrement NUMERIC counter each spend. Output must carry the decremented conditions. At zero: terminates (SATISFIED). |
| RECURSE_SPLIT    | Decrement NUMERIC max_splits. All outputs must carry decremented conditions. Enforces NUMERIC min_split_sats per output and value conservation (sum of outputs >= input value minus fee). |
| RECURSE_DECAY    | Like RECURSE_MODIFIED but negates deltas (output parameter = input parameter minus decay value). Bounded by NUMERIC max_depth. |

All recursion evaluators use leaf-centric Merkle verification: mutate a copy
of the revealed leaf, rebuild the tree from the verified leaf array, and
compare the computed root against the output's MLSC root.

### Anchor Family

| Type           | Evaluation                                              |
|----------------|---------------------------------------------------------|
| ANCHOR         | Marker block. SATISFIED if NUMERIC anchor_id field is present and > 0. |
| ANCHOR_CHANNEL | Requires 2 PUBKEYs (local, remote) via merkle_pub_key and NUMERIC commitment_number > 0. |
| ANCHOR_POOL    | Requires HASH256 vtxo_tree_root (with hash-preimage binding) and NUMERIC participant_count > 0. |
| ANCHOR_RESERVE | Requires 2 NUMERICs (threshold_n <= threshold_m) and HASH256 guardian_hash (with hash-preimage binding). |
| ANCHOR_SEAL    | Requires 2 HASH256 fields (asset_id, state_transition) with hash-preimage binding. |
| ANCHOR_ORACLE  | Requires 1 PUBKEY (oracle key) via merkle_pub_key and NUMERIC outcome_count > 0. |
| DATA_RETURN    | Unspendable. Evaluation always returns ERROR. Spending should never reach this block; it exists only as an output marker. |

### PLC Family

| Type             | Evaluation                                                |
|------------------|-----------------------------------------------------------|
| HYSTERESIS_FEE   | Transaction fee rate (sat/vB) must fall within [low_sat_vb, high_sat_vb] band. |
| HYSTERESIS_VALUE | UTXO value must fall within [low_sats, high_sats] band. |
| TIMER_CONTINUOUS | SATISFIED if NUMERIC accumulated >= NUMERIC target. State is advanced via RECURSE_MODIFIED (incrementing accumulated). |
| TIMER_OFF_DELAY  | SATISFIED if NUMERIC remaining blocks <= 0. |
| LATCH_SET        | State activation: PUBKEY-authenticated event sets NUMERIC state to 1. |
| LATCH_RESET      | State deactivation: PUBKEY-authenticated event resets state after NUMERIC delay. |
| COUNTER_DOWN     | Decrement NUMERIC count on PUBKEY-authenticated event. SATISFIED when count reaches zero. |
| COUNTER_PRESET   | Approval accumulator: SATISFIED when NUMERIC current reaches NUMERIC preset. |
| COUNTER_UP       | Increment NUMERIC current on PUBKEY-authenticated event. SATISFIED when current reaches NUMERIC target. |
| COMPARE          | Comparator: compares input amount against NUMERIC thresholds using NUMERIC operator byte (1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE). |
| SEQUENCER        | Step through NUMERIC total_steps. SATISFIED at final step (current_step == total_steps). |
| ONE_SHOT         | One-time activation window. SATISFIED if NUMERIC state is 0 (unused) and HASH256 commitment matches. |
| RATE_LIMIT       | SATISFIED if spending rate is within limits: NUMERIC max_per_block, NUMERIC accumulation_cap, NUMERIC refill_blocks. |
| COSIGN           | Cross-input constraint: another input in the same transaction must have a conditions root matching the HASH256 field. |

### Compound Family

| Type               | Evaluation                                               |
|--------------------|----------------------------------------------------------|
| TIMELOCKED_SIG     | SIG + CSV: verify SIGNATURE against PUBKEY (routed by SCHEME), then check NUMERIC relative timelock via `CheckSequence`. |
| HTLC               | Two PUBKEYs (sender, receiver), one PREIMAGE, one SIGNATURE, one NUMERIC timelock. Verify `SHA256(preimage)` against committed HASH256, verify signature, check CSV timelock. |
| HASH_SIG           | PUBKEY + SIGNATURE + PREIMAGE. Verify `SHA256(preimage)` against committed HASH256, then verify signature. |
| PTLC               | ADAPTOR_SIG + CSV: adaptor signature verification with NUMERIC relative timelock. Two pubkeys (signer, adaptor_point) via merkle_pub_key. |
| CLTV_SIG           | SIG + CLTV: verify SIGNATURE against PUBKEY, then check NUMERIC absolute timelock via `CheckLockTime`. |
| TIMELOCKED_MULTISIG| MULTISIG + CSV: NUMERIC threshold M, N pubkeys via merkle_pub_key, M signatures, NUMERIC CSV delay, SCHEME. |

### Governance Family

| Type           | Evaluation                                              |
|----------------|---------------------------------------------------------|
| EPOCH_GATE     | SATISFIED only when current block height falls within a periodic window: `(height % epoch_size) < window_size`. |
| WEIGHT_LIMIT   | Transaction weight must be <= NUMERIC max_weight. |
| INPUT_COUNT    | Number of transaction inputs must be within [NUMERIC min, NUMERIC max]. |
| OUTPUT_COUNT   | Number of transaction outputs must be within [NUMERIC min, NUMERIC max]. |
| RELATIVE_VALUE | Output value must be >= `input_amount * NUMERIC numerator / NUMERIC denominator`. |
| ACCUMULATOR    | Merkle set membership proof: verify that a leaf is included in the committed HASH256 root. Inverted ACCUMULATOR = blocklist ("NOT in set"). |
| OUTPUT_CHECK   | Output at NUMERIC index must have value within [NUMERIC min_sats, NUMERIC max_sats] and scriptPubKey hash matching HASH256 script_hash. |

### Legacy Family

| Type               | Evaluation                                               |
|--------------------|----------------------------------------------------------|
| P2PK_LEGACY        | PUBKEY + SIGNATURE verification (equivalent to P2PK). Pubkey committed via merkle_pub_key. |
| P2PKH_LEGACY       | HASH160 in conditions; PUBKEY + SIGNATURE in witness. Verify `RIPEMD160(SHA256(pubkey)) == committed_hash`, then verify signature. Pubkey is NOT in merkle_pub_key (hash-locked). |
| P2SH_LEGACY        | HASH160 in conditions; SCRIPT_BODY (inner conditions) in witness. Verify `RIPEMD160(SHA256(script)) == committed_hash`, deserialize inner conditions, recurse with depth limit. |
| P2WPKH_LEGACY      | Delegates to P2PKH evaluation path. Identical semantics. |
| P2WSH_LEGACY       | HASH256 in conditions; SCRIPT_BODY (inner conditions) in witness. Verify `SHA256(script) == committed_hash`, deserialize inner conditions, recurse with depth limit. |
| P2TR_LEGACY        | PUBKEY + SIGNATURE key-path verification. Pubkey committed via merkle_pub_key. |
| P2TR_SCRIPT_LEGACY | HASH256 + internal PUBKEY (via merkle_pub_key); SCRIPT_BODY in witness. Deserialize inner conditions, recurse with depth limit. |

P2SH_LEGACY, P2WSH_LEGACY, and P2TR_SCRIPT_LEGACY support recursive
evaluation of inner conditions with a depth parameter to prevent unbounded
nesting.

## Appendix B: Byte-Level Wire Format Examples

### Example 1: Minimal SIG Transaction

A complete v4 transaction spending one SIG-protected UTXO to one output.
Alice's x-only public key is `02...aa` (32 bytes), signature is `sig...` (64 bytes).

**witness[0] (LadderWitness) -- WITNESS context:**

```
Offset  Hex              Field
------  ---------------  ------------------------------------
0x00    01               n_rungs = 1
0x01    01               rung[0].n_blocks = 1
0x02    00               micro-header 0x00 = SIG
                         implicit witness layout: [PUBKEY(var), SIGNATURE(var)]
0x03    20               PUBKEY length = 32
0x04    0279be667e...aa  PUBKEY data (32 bytes, x-only)
0x24    40               SIGNATURE length = 64
0x25    e907831f80...ff  SIGNATURE data (64 bytes, Schnorr)
0x65    00               rung[0].n_relay_refs = 0
0x66    01               coil_type = 0x01 (UNLOCK)
0x67    01               attestation = 0x01 (INLINE)
0x68    01               scheme = 0x01 (SCHNORR)
0x69    00               address_len = 0
0x6A    00               n_coil_conditions = 0
0x6B    00               n_rung_destinations = 0
0x6C    00               n_relays = 0
                         Total: 109 bytes
```

**witness[1] (MLSCProof) -- CONDITIONS context:**

```
Offset  Hex    Field
------  -----  ------------------------------------
0x00    01     total_rungs = 1
0x01    00     total_relays = 0
0x02    00     rung_index = 0 (revealing rung 0)
0x03    01     n_blocks = 1
0x04    00     micro-header 0x00 = SIG
               implicit conditions layout: [SCHEME(1)]
0x05    01     SCHEME = 0x01 (Schnorr, fixed 1 byte)
0x06    00     n_rung_relay_refs = 0
0x07    00     n_revealed_relays = 0
0x08    00     n_proof_hashes = 0
               Total: 9 bytes
```

### Example 2: HTLC Conditions + Witness

An HTLC block: Alice (sender) and Bob (receiver) with a 144-block timeout
and a SHA-256 payment hash `abcd...ef` (32 bytes).

**Conditions context (in MLSCProof):**

```
Offset  Hex              Field
------  ---------------  ------------------------------------
0x00    28               micro-header 0x28 = HTLC
                         implicit layout: [HASH256(32), NUMERIC(var), SCHEME(1)]
0x01    abcd...ef        HASH256 = payment hash (32 bytes, no length prefix)
0x21    90 01            NUMERIC = 144 (CompactSize)
0x23    01               SCHEME = 0x01 (Schnorr)
                         Total: 36 bytes
```

**Witness context (in LadderWitness):**

```
Offset  Hex              Field
------  ---------------  ------------------------------------
0x00    28               micro-header 0x28 = HTLC
                         implicit layout: [PUBKEY(var), SIGNATURE(var),
                                           PUBKEY(var), PREIMAGE(var), NUMERIC(var)]
0x01    20               PUBKEY[0] length = 32 (Alice, sender)
0x02    <32 bytes>       Alice's x-only pubkey
0x22    40               SIGNATURE length = 64
0x23    <64 bytes>       Alice's Schnorr signature
0x63    20               PUBKEY[1] length = 32 (Bob, receiver)
0x64    <32 bytes>       Bob's x-only pubkey
0x84    20               PREIMAGE length = 32
0x85    <32 bytes>       SHA-256 preimage (reveals payment secret)
0xA5    90 01            NUMERIC = 144 (CSV blocks)
                         Total: 167 bytes
```

### Example 3: MLSC Proof for a 2-Rung Ladder

A ladder with 2 rungs (rung 0 = SIG, rung 1 = TIMELOCKED_SIG), no relays.
Spending via rung 0.

```
Offset  Hex              Field
------  ---------------  ------------------------------------
0x00    02               total_rungs = 2
0x01    00               total_relays = 0
0x02    00               rung_index = 0 (spending via rung 0)

                         -- Revealed rung 0 (CONDITIONS context) --
0x03    01               n_blocks = 1
0x04    00               micro-header 0x00 = SIG
0x05    01               SCHEME = 0x01 (Schnorr)
0x06    00               n_rung_relay_refs = 0

0x07    00               n_revealed_relays = 0

                         -- Merkle proof hashes --
0x08    02               n_proof_hashes = 2
0x09    <32 bytes>       proof_hash[0] = leaf[1] (rung 1, unrevealed)
0x29    <32 bytes>       proof_hash[1] = node covering leaf[2..3]
                           (coil_leaf paired with empty_leaf)
                         Total: 73 bytes
```

The verifier:
1. Computes `leaf[0]` from the revealed SIG conditions + alice's pubkey
   (from the witness)
2. Computes `node_01 = TaggedHash("LadderInternal", min(leaf[0], proof_hash[0])
   || max(leaf[0], proof_hash[0]))`
3. Computes `root = TaggedHash("LadderInternal", min(node_01, proof_hash[1])
   || max(node_01, proof_hash[1]))`
4. Compares `root` against the UTXO's `conditions_root`
