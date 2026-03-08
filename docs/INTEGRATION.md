# Ladder Script -- Bitcoin Integration Guide

This document describes how Ladder Script integrates with the Bitcoin transaction model, consensus layer, mempool policy, and related subsystems.

---

## 1. Transaction Lifecycle

### 1.1 Creating a v3 Transaction

A Ladder Script transaction uses version 3 (`CTransaction::RUNG_TX_VERSION = 3`). Creation follows this sequence:

1. **Select inputs.** Any UTXOs can be spent by a v3 transaction, including outputs locked by v1/v2 scripts (bootstrap mode) or prior v3 rung conditions.

2. **Define output conditions.** Each output's `scriptPubKey` is constructed as `0xc1 || serialized_conditions`. The conditions encode the typed blocks and fields that a future spender must satisfy. Only condition-allowed data types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX) may appear. PUBKEY, SIGNATURE, and PREIMAGE are forbidden in conditions. The `createrungtx` RPC auto-hashes PUBKEY to PUBKEY_COMMIT when building conditions -- users provide pubkey hex as before.

3. **Construct the transaction.** Use the `createrungtx` RPC, which takes an array of input outpoints and an array of output specifications (amount + conditions JSON). The RPC returns a raw unsigned v3 transaction.

4. **Sign the transaction.** Use the `signrungtx` RPC, which takes the unsigned transaction hex, an array of `{privkey, input_index}` pairs, and an array of spent outputs (needed for sighash computation). The RPC computes `LadderSighash` for each input and produces witness data.

5. **Broadcast.** Submit via `sendrawtransaction`. The mempool validates the transaction through `IsStandardRungTx()` before acceptance.

### 1.2 Witness Construction

For each input, the witness stack contains a single element: the serialized `LadderWitness`. This witness provides the "unlocking" data -- signatures, preimages, and other witness-only fields -- that pairs with the conditions from the spent output.

The witness structure mirrors the conditions: same number of rungs, same number of blocks per rung, same block types. The evaluator merges conditions and witness by concatenating their fields within each block.

### 1.3 Validation

At consensus time, `VerifyRungTx()` is called for each input. It:

1. Extracts the witness from `tx.vin[nIn].scriptWitness.stack[0]`.
2. Deserializes the witness as a `LadderWitness`.
3. Attempts to deserialize the spent output's `scriptPubKey` as `RungConditions`.
4. If conditions are present (rung-to-rung spend), merges conditions with witness.
5. Constructs a `LadderSignatureChecker` wrapping the standard signature checker.
6. Calls `EvalLadder()` with `SigVersion::LADDER`.
7. Returns true if any rung is satisfied (OR logic).

---

## 2. Consensus Integration

### 2.1 Routing in validation.cpp

The v3 routing occurs in `CScriptCheck::operator()` within `validation.cpp`:

```cpp
if (ptxTo->version == CTransaction::RUNG_TX_VERSION) {
    CachingTransactionSignatureChecker checker(ptxTo, nIn, m_tx_out.nValue, ...);
    if (rung::VerifyRungTx(*ptxTo, nIn, m_tx_out, nFlags, checker, *txdata, &error, m_block_height)) {
        return std::nullopt;  // Verification succeeded
    } else {
        // Verification failed -- return script error
    }
}
```

This routing is the sole entry point for Ladder Script consensus validation. All v3 transactions bypass the standard Bitcoin Script interpreter entirely and are evaluated exclusively through the rung evaluator.

### 2.2 Precomputed Transaction Data

When `PrecomputedTransactionData::Init()` detects a v3 transaction, it initializes ladder-specific caches:

- `m_prevouts_single_hash` -- SHA256 of all input prevouts
- `m_spent_amounts_single_hash` -- SHA256 of all spent amounts
- `m_sequences_single_hash` -- SHA256 of all input sequence values
- `m_outputs_single_hash` -- SHA256 of all outputs
- `m_ladder_ready = true`

The function returns immediately after setting these, skipping BIP-143 and BIP-341 cache initialization. The ladder caches are structurally identical to BIP-341 precomputed hashes but are separated by the `m_ladder_ready` flag.

### 2.3 SigVersion::LADDER

A new `SigVersion` enum value, `LADDER`, is added to the script interpreter. This value is passed to `CheckSchnorrSignature()` within `LadderSignatureChecker`. When the checker receives `SigVersion::LADDER`, it computes `SignatureHashLadder()` instead of `SignatureHashSchnorr()`.

For non-LADDER sig versions, the checker falls through to the wrapped `BaseSignatureChecker`.

---

## 3. scriptPubKey Format

### 3.1 Structure

A v3 rung conditions output has the following `scriptPubKey` format:

```
[0xc1] [serialized conditions using ladder wire format v2]
```

The `0xc1` prefix byte is defined as `RUNG_CONDITIONS_PREFIX`. The function `IsRungConditionsScript()` performs a quick check: `scriptPubKey.size() >= 2 && scriptPubKey[0] == 0xc1`.

### 3.2 Serialization

`SerializeRungConditions()` converts a `RungConditions` structure to a `CScript`:

1. Serialize the conditions as a `LadderWitness` (same wire format).
2. Prepend the `0xc1` prefix byte.

`DeserializeRungConditions()` performs the reverse:

1. Verify the `0xc1` prefix.
2. Strip the prefix and deserialize as a `LadderWitness`.
3. Validate that no witness-only data types (PUBKEY, SIGNATURE, PREIMAGE) appear in the conditions.

### 3.3 Non-Conditions Outputs

A v3 transaction may also include non-conditions outputs:

- **OP_RETURN outputs** (data carrier) are permitted.
- **Standard P2TR outputs** are permitted for change during bootstrap transitions.
- The mempool policy checks (`IsStandardRungTx`) only validate outputs that begin with `0xc1`.

---

## 4. Witness Format

### 4.1 Placement

The ladder witness occupies `scriptWitness.stack[0]` -- the first (and typically only) element of the segregated witness stack. This is a single byte vector containing the serialized `LadderWitness`.

### 4.2 Conditions-Witness Merge

At verification time, the conditions from the spent output and the witness from the spending input are merged into a single `LadderWitness` for evaluation:

1. Both must have the same number of rungs.
2. Each rung must have the same number of blocks.
3. Each block must have the same `RungBlockType`.
4. For each block, the merged fields are: all condition fields first, then all witness fields appended.
5. The `inverted` flag is taken from the conditions (not the witness).

This merge step is handled by `MergeConditionsAndWitness()`. If the structures do not match, verification fails.

### 4.3 Bootstrap Mode

When a v3 transaction spends a v1/v2 UTXO (one whose `scriptPubKey` does not begin with `0xc1`), no merge is performed. The witness is evaluated directly with empty conditions. This allows v3 transactions to spend existing UTXOs by providing self-contained witness data.

---

## 5. Sighash Computation

### 5.1 LadderSighash vs BIP-341 Taproot Sighash

Ladder Script defines its own sighash algorithm, `SignatureHashLadder()`, which is structurally similar to BIP-341's `SignatureHashSchnorr()` but with key differences:

| Aspect | BIP-341 (Taproot) | Ladder Script |
|--------|-------------------|---------------|
| Tagged hash | `"TapSighash"` | `"LadderSighash"` |
| spend_type | Variable (key path, script path, annex) | Always 0 |
| Script commitment | `tapleaf_hash` or none | `conditions_hash` (always) |
| Annex | Optional | Not supported |
| Code separator | `codeseparator_pos` field | Not supported |
| key_version | 0 or 1 | Not present |

### 5.2 Conditions Hash

The sighash always commits to `conditions_hash = SHA256(serialized_conditions)`. This is computed by `HashRungConditions()`:

1. Copy the conditions rungs into a `LadderWitness`.
2. Serialize via `SerializeLadderWitness()`.
3. Compute SHA256 of the serialized bytes.

This commitment binds the signature to the specific locking conditions, preventing signature reuse across outputs with different conditions.

### 5.3 LadderSignatureChecker

The `LadderSignatureChecker` class wraps a standard `BaseSignatureChecker` and overrides `CheckSchnorrSignature()`:

- For `SigVersion::LADDER`: computes `SignatureHashLadder()` and verifies the BIP-340 Schnorr signature against the computed hash.
- For other sig versions: delegates to the wrapped checker.

It also exposes `ComputeSighash()` for PQ signature verification, which needs the hash but uses a different verification algorithm.

---

## 6. Mempool Policy

### 6.1 IsStandardRungTx()

The mempool policy function `IsStandardRungTx()` validates v3 transactions before acceptance. It is called from `policy.cpp` when `tx.version == CTransaction::RUNG_TX_VERSION`.

**Output validation:**

- OP_RETURN outputs are allowed (skipped).
- Outputs with the `0xc1` prefix must pass `IsStandardRungOutput()`.
- Non-conditions outputs (e.g., P2TR change) are allowed during bootstrap.

**Input witness validation:**

- Each input must have a non-empty witness stack.
- `stack[0]` must deserialize as a valid `LadderWitness`.
- Maximum 16 rungs per witness.
- Maximum 8 blocks per rung.
- All block types must be known (`IsKnownBlockType()`).
- All fields must pass `RungField::IsValid()` size/content checks.

### 6.2 IsStandardRungOutput()

Validates a `0xc1`-prefixed `scriptPubKey`:

- Must deserialize as valid `RungConditions`.
- Maximum 16 rungs, 8 blocks per rung.
- All block types must be known.
- All fields must be condition-allowed data types (no PUBKEY, no SIGNATURE, no PREIMAGE).
- All fields must pass size validation.

### 6.3 Phase Restrictions

The current policy implementation accepts all known block types. Block types are categorized by family:

- **Base** (0x0001--0x02FF): SIG, MULTISIG, ADAPTOR_SIG, CSV, CSV_TIME, CLTV, CLTV_TIME, HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH.
- **Covenant + Anchor** (0x0300--0x05FF): CTV, VAULT_LOCK, AMOUNT_LOCK, ANCHOR_*.
- **Recursion + PLC** (0x0400--0x06FF): RECURSE_*, HYSTERESIS_*, TIMER_*, LATCH_*, COUNTER_*, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN.

The functions `IsPhase1BlockType()`, `IsPhase2BlockType()`, and `IsPhase3BlockType()` classify blocks into these families. These are available for future policy tightening where covenant/recursion/PLC blocks could be made non-standard while remaining consensus-valid.

---

## 7. Covenant Verification

### 7.1 Recursion Model

Covenant enforcement in Ladder Script uses the RECURSE_* block family. These blocks verify that the spending transaction's outputs carry conditions that satisfy a specified relationship with the input's conditions.

The verification follows a common pattern:

1. The block reads parameters from its fields (max_depth, mutation specs, etc.).
2. If `RungEvalContext.spending_output` and `RungEvalContext.input_conditions` are available, the block deserializes the output's `scriptPubKey` as `RungConditions`.
3. The block compares the output conditions to the input conditions according to its rules.

### 7.2 RECURSE_SAME

Enforces that the output carries identical conditions. This creates an immutable covenant that must be re-encumbered on every spend. The `max_depth` parameter limits the recursion depth.

### 7.3 RECURSE_MODIFIED

Allows specific NUMERIC parameters to change by a declared delta. The mutation specification identifies the target by `(rung_idx, block_idx, param_idx)` and declares an additive `delta`. All other condition fields must remain identical. This enables parameterized covenants where, for example, a counter is incremented each spend.

### 7.4 RECURSE_DECAY

Identical to RECURSE_MODIFIED but with negated deltas. The output value is `input - delta`, implementing monotonically decreasing parameters.

### 7.5 RECURSE_COUNT

A countdown covenant. Each spend must decrement the count by exactly 1. When count reaches 0, the covenant terminates and the funds are unlocked.

### 7.6 RECURSE_SPLIT

Allows a UTXO to be split into multiple outputs, each carrying the same covenant with a decremented `max_splits`. Enforces value conservation (`sum(outputs) <= input`) and minimum split size.

### 7.7 RECURSE_UNTIL

A time-bounded covenant. Before `until_height`, the output must be re-encumbered with identical conditions. At or after `until_height`, the covenant terminates.

### 7.8 Comparison Functions

The helper `FullConditionsEqual()` performs a deep structural comparison of two `RungConditions` objects. For mutated blocks, `VerifyMutatedConditions()` allows declared parameters to differ by the specified delta while requiring all other fields to match exactly.

Only condition data types are compared (PUBKEY_COMMIT, HASH256, etc.). Witness-only types (PUBKEY, SIGNATURE, PREIMAGE) are excluded from comparison since they are never present in conditions.

---

## 8. Post-Quantum Integration

### 8.1 Overview

Ladder Script provides native post-quantum signature support through four NIST-standardized algorithms implemented by liboqs. PQ signatures are a first-class feature, not an extension: the same SIG and MULTISIG blocks handle both classical and PQ signatures via the SCHEME field.

### 8.2 PQ Key Generation

Use the `generatepqkeypair` RPC to generate a keypair for a specific scheme:

```
generatepqkeypair FALCON512
```

Returns `{pubkey: "...", privkey: "..."}` in hex. Key sizes vary by scheme (897 bytes for FALCON-512 public keys, up to 1952 bytes for Dilithium3).

### 8.3 PUBKEY_COMMIT Pattern

Because PQ public keys are large, the recommended pattern for compact outputs is:

1. Compute `commitment = SHA256(pq_pubkey)` using the `pqpubkeycommit` RPC.
2. Store a PUBKEY_COMMIT field (32 bytes) in the output conditions instead of the full PUBKEY.
3. At spend time, include the full PUBKEY in the witness. The evaluator verifies `SHA256(witness_pubkey) == commitment` before checking the signature.

This keeps output conditions compact (32 bytes per key) regardless of the PQ scheme.

### 8.4 SCHEME Field Routing

When a SIG or MULTISIG block contains a SCHEME field with a PQ value (`>= 0x10`), the evaluator routes to `EvalPQSig()` instead of the classical signature verification path:

1. Cast the checker to `LadderSignatureChecker`.
2. Compute the ladder sighash via `ComputeSighash(SIGHASH_DEFAULT, hash_out)`.
3. Call `VerifyPQSignature(scheme, sig, sighash, pubkey)` via liboqs.

The sighash computation is identical for classical and PQ signatures. Only the verification algorithm differs.

### 8.5 COSIGN Anchor Pattern

For maximum quantum resistance, combine PQ signatures with the COSIGN block to create a dual-signature anchor:

1. Create a classical (Schnorr) anchor output with known conditions.
2. Create a PQ-protected output with a COSIGN block referencing `SHA256(anchor_scriptPubKey)`.
3. To spend the PQ output, the anchor output must also be spent in the same transaction.

This pattern ensures that even if the classical anchor is compromised, the PQ output remains protected.

### 8.6 Build Requirements

PQ support requires compilation with liboqs (`HAVE_LIBOQS` preprocessor define). Without it, `HasPQSupport()` returns false and all PQ verification fails. This is a build-time dependency, not a runtime toggle.

---

## 9. Adaptor Signatures

### 9.1 Overview

Ladder Script supports adaptor signatures for atomic swaps, payment channels, and other protocols that require conditional signature revelation. The implementation uses BIP-340 Schnorr signatures with an adaptor secret incorporated into the nonce.

### 9.2 CreateAdaptedSignature

```cpp
bool CreateAdaptedSignature(const CKey& privkey,
                             const uint256& sighash,
                             const std::vector<uint8_t>& adaptor_secret,
                             std::vector<uint8_t>& sig_out);
```

Creates an adapted Schnorr signature by using the 32-byte adaptor secret as auxiliary randomness (`aux_rand`) in BIP-340 nonce generation. The result is a standard 64-byte BIP-340 signature that verifies against the signing key. The adaptor secret is bound to the signature through its effect on the nonce.

### 9.3 ExtractAdaptorSecret

```cpp
bool ExtractAdaptorSecret(const std::vector<uint8_t>& pre_sig,
                           const std::vector<uint8_t>& adapted_sig,
                           std::vector<uint8_t>& secret_out);
```

Extracts the adaptor secret by computing `t = s_adapted - s_pre (mod n)`, where `s` is the scalar component (last 32 bytes) of each BIP-340 signature. This uses secp256k1 scalar arithmetic (`secp256k1_ec_seckey_negate`, `secp256k1_ec_seckey_tweak_add`).

Available via the `extractadaptorsecret` RPC.

### 9.4 VerifyAdaptorPreSignature

```cpp
bool VerifyAdaptorPreSignature(const std::vector<uint8_t>& pubkey_bytes,
                                const std::vector<uint8_t>& adaptor_point,
                                const std::vector<uint8_t>& pre_sig,
                                const uint256& sighash);
```

Verifies that a pre-signature is valid relative to the adaptor point:

1. Parse R (from pre_sig, first 32 bytes) and T (adaptor_point) as compressed public keys.
2. Compute `R + T` via point addition.
3. Compute the BIP-340 challenge: `e = tagged_hash("BIP0340/challenge", (R+T)_x || P || m)`.
4. Verify: `s'*G == R + e*P` (where `s'` is the pre-signature scalar).

Available via the `verifyadaptorpresig` RPC.

### 9.5 ADAPTOR_SIG Block Evaluation

The ADAPTOR_SIG block (0x0003) verifies the adapted signature at consensus time. The adapted signature is a valid BIP-340 signature against the signing key -- the evaluator does not need the adaptor point for verification. The adaptor point is stored in the conditions so that counterparties can verify the pre-signature off-chain and extract the secret after the adapted signature is published on-chain.

---

## 10. Compatibility

### 10.1 Transaction Version Coexistence

Version 3 transactions coexist with existing transaction types:

- **v1 transactions** (legacy) continue to be processed through the standard script interpreter.
- **v2 transactions** (BIP-68/BIP-112/taproot) continue to be processed through BIP-341 tapscript evaluation.
- **v3 transactions** are routed exclusively to `VerifyRungTx()`.

The routing decision is made solely on `tx.version` in `validation.cpp`. There is no interaction between the script interpreter and the rung evaluator.

### 10.2 Spending v1/v2 UTXOs from v3

A v3 transaction can spend any UTXO, including v1/v2 outputs. When the spent output's `scriptPubKey` does not begin with `0xc1`:

- No conditions merge is performed.
- The witness is evaluated directly as a self-contained `LadderWitness`.
- An empty `RungConditions` is used for sighash computation.
- The `LadderSignatureChecker` wraps the standard checker but operates in bootstrap mode.

This bootstrap path enables migration from existing outputs to Ladder Script without requiring a special transition mechanism.

### 10.3 Spending v3 UTXOs from v1/v2

A v1 or v2 transaction cannot spend a v3 rung conditions output. The `0xc1` prefix does not correspond to a valid Bitcoin Script opcode sequence, so any attempt to evaluate it as standard script would fail.

### 10.4 Block Validation

Block-level validation applies the same `CScriptCheck` framework used for all transaction types. The v3 routing in `CScriptCheck::operator()` is transparent to the block validation pipeline. Script verification parallelism (`CCheckQueue`) works identically for v3 transactions.

### 10.5 Wallet Integration

The current wallet does not natively construct v3 transactions. The `SigVersion::LADDER` case is explicitly noted as unused in wallet fee bumping (`feebumper.h`). Transaction construction and signing are performed through the dedicated RPC interface (`createrungtx`, `signrungtx`).

### 10.6 P2P Relay

v3 transactions are relayed through the standard P2P transaction relay mechanism. The mempool's `IsStandard()` check delegates to `IsStandardRungTx()` for v3 transactions. Nodes without Ladder Script support would reject v3 transactions as non-standard but would accept blocks containing them (consensus-valid).
