# Ladder Script Block Library

59 block types across 10 families. Each block evaluates a single spending condition within a rung. Blocks are combined with AND logic within a rung and OR logic across rungs (first satisfied rung wins).

Full reference with field tables, evaluation logic, and ladder diagrams: [Block Reference](/labs/block-docs/)

**Source of truth:** `src/rung/types.h` (type definitions), `src/rung/evaluator.cpp` (evaluation logic).

---

## Signature Family (0x00xx)

Single and multi-party signature verification. Supports Schnorr (BIP-340), ECDSA, and post-quantum schemes (FALCON-512, FALCON-1024, Dilithium3, SPHINCS-SHA) via the SCHEME field.

| Code | Block | Description |
|------|-------|-------------|
| 0x0001 | SIG | Single signature verification |
| 0x0002 | MULTISIG | M-of-N threshold signature verification |
| 0x0003 | ADAPTOR_SIG | Adaptor signature with secret extraction |
| 0x0004 | MUSIG_THRESHOLD | MuSig2-compatible threshold signature |
| 0x0005 | KEY_REF_SIG | Signature verification using a key referenced by index |

## Timelock Family (0x01xx)

Block-height and time-based spending constraints.

| Code | Block | Description |
|------|-------|-------------|
| 0x0101 | CSV | Relative timelock by block count (BIP-68/112) |
| 0x0102 | CSV_TIME | Relative timelock by elapsed seconds |
| 0x0103 | CLTV | Absolute timelock by block height (BIP-65) |
| 0x0104 | CLTV_TIME | Absolute timelock by Unix timestamp |

## Hash Family (0x02xx)

Hash verification for tagged commitments. Pure hash locks (HASH_PREIMAGE, HASH160_PREIMAGE) are deprecated. Use HTLC or HASH_SIG instead.

| Code | Block | Description |
|------|-------|-------------|
| ~~0x0201~~ | ~~HASH_PREIMAGE~~ | **Deprecated.** Rejected at consensus. Use HTLC or HASH_SIG. |
| ~~0x0202~~ | ~~HASH160_PREIMAGE~~ | **Deprecated.** Rejected at consensus. Use HTLC or HASH_SIG. |
| 0x0203 | TAGGED_HASH | Tagged hash preimage (BIP-340 style) |

## Covenant Family (0x03xx)

Transaction introspection and output restriction.

| Code | Block | Description |
|------|-------|-------------|
| 0x0301 | CTV | CheckTemplateVerify — commit to transaction template |
| 0x0302 | VAULT_LOCK | Time-delayed vault with cooling period |
| 0x0303 | AMOUNT_LOCK | Output amount bounds enforcement |

## Recursion Family (0x04xx)

Self-perpetuating conditions that carry forward across transaction chains.

| Code | Block | Description |
|------|-------|-------------|
| 0x0401 | RECURSE_SAME | Re-encumber output with identical conditions |
| 0x0402 | RECURSE_MODIFIED | Re-encumber with mutated field values |
| 0x0403 | RECURSE_UNTIL | Recurse until a block height is reached |
| 0x0404 | RECURSE_COUNT | Countdown recursion (N spends remaining) |
| 0x0405 | RECURSE_SPLIT | Binary split into multiple outputs |
| 0x0406 | RECURSE_DECAY | Progressive parameter relaxation |

## Anchor Family (0x05xx)

Protocol-tagged UTXOs with semantic meaning.

| Code | Block | Description |
|------|-------|-------------|
| 0x0501 | ANCHOR | Basic protocol anchor |
| 0x0502 | ANCHOR_CHANNEL | Lightning channel anchor |
| 0x0503 | ANCHOR_POOL | Mining pool anchor |
| 0x0504 | ANCHOR_RESERVE | Reserve proof anchor |
| 0x0505 | ANCHOR_SEAL | Sealed state commitment (asset ID + state transition) |
| 0x0506 | ANCHOR_ORACLE | Oracle data attestation anchor |
| 0x0507 | DATA_RETURN | On-chain data (max 32 bytes) appended to MLSC output, replaces OP_RETURN |

## PLC Family (0x06xx)

Programmable Logic Controller blocks. State machines, counters, timers, and comparators for multi-step spending logic.

| Code | Block | Description |
|------|-------|-------------|
| 0x0601 | HYSTERESIS_FEE | Fee-rate hysteresis band (high/low thresholds) |
| 0x0602 | HYSTERESIS_VALUE | Output value hysteresis band |
| 0x0611 | TIMER_CONTINUOUS | Continuous elapsed-time gate |
| 0x0612 | TIMER_OFF_DELAY | Off-delay timer |
| 0x0621 | LATCH_SET | Set-dominant latch |
| 0x0622 | LATCH_RESET | Reset-dominant latch |
| 0x0631 | COUNTER_DOWN | Decrementing counter |
| 0x0632 | COUNTER_PRESET | Counter with preset reload |
| 0x0633 | COUNTER_UP | Incrementing counter |
| 0x0641 | COMPARE | Numeric comparison (equal, greater, less, range) |
| 0x0651 | SEQUENCER | Multi-step sequence enforcer |
| 0x0661 | ONE_SHOT | Single-use trigger |
| 0x0671 | RATE_LIMIT | Spending rate limiter |
| 0x0681 | COSIGN | Co-signature requirement with timeout fallback |

## Compound Family (0x07xx)

Composite blocks that combine multiple primitives into a single evaluation. Syntactic sugar — each delegates to the same verification routines as the corresponding separate blocks.

| Code | Block | Description |
|------|-------|-------------|
| 0x0701 | TIMELOCKED_SIG | Signature + relative timelock |
| 0x0702 | HTLC | Hash Time-Locked Contract (signature + hash + timelock) |
| 0x0703 | HASH_SIG | Signature + hash preimage |
| 0x0704 | PTLC | Point Time-Locked Contract (adaptor signature + timelock) |
| 0x0705 | CLTV_SIG | Signature + absolute timelock |
| 0x0706 | TIMELOCKED_MULTISIG | M-of-N multisig + relative timelock |

## Governance Family (0x08xx)

Transaction structure introspection and spending policy enforcement.

| Code | Block | Description |
|------|-------|-------------|
| 0x0801 | EPOCH_GATE | Block height window gate (start/end range) |
| 0x0802 | WEIGHT_LIMIT | Transaction weight ceiling |
| 0x0803 | INPUT_COUNT | Input count constraint |
| 0x0804 | OUTPUT_COUNT | Output count constraint |
| 0x0805 | RELATIVE_VALUE | Output-to-input value ratio enforcement |
| 0x0806 | ACCUMULATOR | Merkle proof membership verification |

## Legacy Family (0x09xx)

Wrapped Bitcoin transaction types as typed blocks. Same spending semantics as the originals, but all fields are typed — closing arbitrary data surfaces. Inner conditions in P2SH, P2WSH, and P2TR script-path must be valid Ladder Script.

| Code | Block | Description |
|------|-------|-------------|
| 0x0901 | P2PK_LEGACY | Pay-to-Public-Key |
| 0x0902 | P2PKH_LEGACY | Pay-to-Public-Key-Hash |
| 0x0903 | P2SH_LEGACY | Pay-to-Script-Hash (inner conditions = Ladder Script) |
| 0x0904 | P2WPKH_LEGACY | Pay-to-Witness-Public-Key-Hash |
| 0x0905 | P2WSH_LEGACY | Pay-to-Witness-Script-Hash (inner conditions = Ladder Script) |
| 0x0906 | P2TR_LEGACY | Pay-to-Taproot key-path |
| 0x0907 | P2TR_SCRIPT_LEGACY | Pay-to-Taproot script-path (revealed leaf = Ladder Script) |
