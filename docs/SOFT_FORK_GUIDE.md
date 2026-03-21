# Ladder Script Soft Fork Guide

How Ladder Script activates as a soft fork. All 61 block types (59 active, 2 deprecated)
activate together in a single deployment. Transactions use `RUNG_TX_VERSION = 4`.

## Activation Summary

Ladder Script introduces transaction version 4 (`RUNG_TX`). Pre-activation nodes treat v4
transactions as anyone-can-spend (standard soft fork semantics). Post-activation nodes
enforce the full Ladder Script validation rules. There is no phased rollout of individual
block types.

## Output Format

All v4 transaction outputs must use MLSC (Merkelized Ladder Script Conditions):

```
0xC2 + conditions_root (32 bytes) = 33-byte scriptPubKey
```

Inline conditions (0xC1) have been removed. `ValidateRungOutputs()` in `evaluator.cpp`
enforces this as a consensus rule: every output of a v4 transaction must be a valid MLSC
output or a DATA_RETURN block (exactly one per transaction, max 40 bytes). Raw OP_RETURN
and legacy scriptPubKey types are rejected.

## Consensus Validation Changes

### Transaction-Level

`VerifyRungTx()` in `evaluator.cpp` is the top-level entry point. For each input of a v4
transaction:

1. Witness `stack[0]` is deserialized via `DeserializeLadderWitness()`. The deserializer
   enforces all structural limits at consensus:
   - `MAX_RUNGS = 16`
   - `MAX_BLOCKS_PER_RUNG = 8`
   - `MAX_FIELDS_PER_BLOCK = 16`
   - `MAX_LADDER_WITNESS_SIZE = 100000`
   - `MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`
   - `MAX_RELAYS = 8`, `MAX_RELAY_DEPTH = 4`
   - Known block types only (`IsKnownBlockType` returns true)
   - Deprecated blocks (HASH_PREIMAGE, HASH160_PREIMAGE) rejected
   - Non-invertible block types cannot have `inverted = true`
   - Implicit layout enforcement (field count and types must match)
   - `IsDataEmbeddingType` rejection for layout-less blocks
   - DATA type restricted to DATA_RETURN blocks
   - No trailing bytes

2. Witness `stack[1]` is deserialized as an MLSC proof via `DeserializeMLSCProof()`.

3. `VerifyMLSCProof()` reconstructs the Merkle tree from revealed and proof data, verifies
   the computed root matches the UTXO's conditions root.

4. `EvalLadder()` evaluates relays (if any), then evaluates the revealed rung. All blocks
   in the rung must return `SATISFIED` (AND logic).

5. `BatchVerifier::Verify()` batch-verifies all collected Schnorr signatures.

6. `ValidateRungOutputs()` checks every output.

### Script Flags

`RUNG_VERIFY_MLSC_ONLY` (bit 28) is set for mainnet. When active, inline conditions (0xC1)
are always rejected. This flag is checked in `ValidateRungOutputs()`.

### Integration Points

The soft fork modifies the following existing Bitcoin Core functions:

- **`CheckInputScripts()`** — detects v4 transactions and routes to `VerifyRungTx()`.
- **`CScriptCheck`** — extended to handle `SigVersion::LADDER`.
- **`GetBlockScriptFlags()`** — returns `RUNG_VERIFY_MLSC_ONLY` after activation height.

Pre-activation nodes see v4 transactions as valid (anyone-can-spend semantics). Post-activation
nodes enforce the full Ladder Script rules.

## Policy Changes

`IsStandardRungTx()` in `policy.cpp` provides mempool-level filtering:

1. Every input must have a non-empty witness that deserializes successfully via the consensus
   deserializer (`DeserializeLadderWitness`).
2. Every output must be MLSC (`IsMLSCScript()`).

Policy delegates all structural validation to the consensus deserializer. There is no
separate policy-only check for block types, field sizes, or layouts.

## Sighash

Ladder Script uses its own sighash algorithm: `SignatureHashLadder()` in `sighash.cpp`.
It is similar to BIP-341 but without annex, tapscript, or codeseparator extensions.
Uses tagged hash `TaggedHash("LadderSighash")`.

New sighash flags (BIP-118 analogues):
- `LADDER_SIGHASH_ANYPREVOUT = 0x40` — skip prevout commitment
- `LADDER_SIGHASH_ANYPREVOUTANYSCRIPT = 0xC0` — skip prevout + conditions commitment

Valid hash types: `{0x00-0x03, 0x40-0x43, 0x81-0x83, 0xC0-0xC3}`.

## Block Types

All 61 block types activate simultaneously:

| Family | Types | Count |
|--------|-------|-------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG | 5 |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME | 4 |
| Hash | HASH_PREIMAGE (deprecated), HASH160_PREIMAGE (deprecated), TAGGED_HASH, HASH_GUARDED | 4 |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK | 3 |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | 6 |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN | 7 |
| PLC | HYSTERESIS_FEE/VALUE, TIMER_CONTINUOUS/OFF_DELAY, LATCH_SET/RESET, COUNTER_DOWN/PRESET/UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | 14 |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG | 6 |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK | 7 |
| Legacy | P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT | 7 |

Total: 61 (59 active + 2 deprecated)

## Anti-Spam Hardening

The soft fork includes comprehensive anti-spam measures enforced at consensus:

1. **Fail-closed deserialization.** Unknown block types, unknown data types, and deprecated
   blocks are rejected at the wire format level.
2. **Selective inversion.** Explicit allowlist. Key-consuming blocks are never invertible.
3. **IsDataEmbeddingType.** PUBKEY_COMMIT, HASH256, HASH160, and DATA are blocked in blocks
   without implicit layouts.
4. **PREIMAGE/SCRIPT_BODY cap.** Maximum 2 per witness (combined), bounding user-chosen
   data to 64 bytes.
5. **DATA type restriction.** Only allowed in DATA_RETURN blocks.
6. **merkle_pub_key.** Pubkeys folded into Merkle leaves, not stored as condition fields.
7. **Relay chain depth cap.** Maximum 4 levels of relay chaining.

## Test Coverage

| Suite | Count | Purpose |
|-------|-------|---------|
| Unit tests | 480 | All block evaluators, serialization, Merkle tree, sighash, anti-spam |
| Functional tests | 60 | End-to-end regtest: create, sign, broadcast, verify v4 transactions |
| TLA+ formal specs | 10 specs, 80+ properties | Evaluation semantics, composition, anti-spam, wire format, Merkle, sighash, covenants, cross-input |

The 10 TLA+ specifications are:

1. **LadderEval** — rung/ladder evaluation with inversion and recursion termination
2. **LadderEvalCheck** — type invariants and safety properties
3. **LadderBlockEval** — individual block evaluation
4. **LadderComposition** — AND/OR composition with relays
5. **LadderAntiSpam** — anti-spam field limits
6. **LadderWireFormat** — serialization invariants
7. **LadderMerkle** — Merkle tree construction and verification
8. **LadderSighash** — sighash computation properties
9. **LadderCovenant** — covenant/recursion safety and termination
10. **LadderCrossInput** — cross-input (COSIGN) dependency safety
