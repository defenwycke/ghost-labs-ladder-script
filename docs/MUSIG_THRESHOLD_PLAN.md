# MUSIG_THRESHOLD Implementation Plan

**Status:** Planned (not yet implemented)
**Complexity:** Low — new block type only, no architectural changes
**Breakage risk:** Zero — pure addition to existing block system
**Savings:** 43-88% vs MULTISIG depending on group size

## Motivation

Current MULTISIG encodes all N pubkeys on-chain and requires M individual signatures. A 3-of-5 costs ~365 bytes and reveals the group size, threshold, and every key.

MUSIG_THRESHOLD uses MuSig2/FROST aggregate keys and signatures. On-chain it looks like single-sig: one 32-byte pubkey commitment in conditions, one 33-byte aggregate pubkey + one 64-byte aggregate signature in the witness. ~131 bytes regardless of M or N. The blockchain cannot distinguish it from a single-sig spend.

The FROST/MuSig2 key generation and threshold signing protocols are entirely off-chain (wallet-side). The block type only validates the final aggregate result using standard Schnorr verification.

## Block Type

```cpp
MUSIG_THRESHOLD = 0x0004,  // Signature family, next after ADAPTOR_SIG (0x0003)
```

Micro-header slot: `0x03` (shift ADAPTOR_SIG from slot 0x02 to keep Signature family contiguous, or use next free slot — see below).

**Actually:** Current micro-header table has ADAPTOR_SIG at slot 0x02. MUSIG_THRESHOLD takes slot 0x03. Slots 0x03-0x06 are currently Timelock family (CSV, CSV_TIME, CLTV, CLTV_TIME) which shift to 0x04-0x07. All subsequent slots shift by 1.

**Simpler approach:** Don't shift anything. Append MUSIG_THRESHOLD at the end of the currently-used slots. Slot 0x33 (first unused). Micro-header table order doesn't need to match enum order — it's just a lookup table. This avoids breaking existing serialised data.

**Decision: Use slot 0x33.** No existing slots change. No serialization breakage.

## Field Layout

### Conditions (locking side)

```
MUSIG_THRESHOLD conditions:
  PUBKEY_COMMIT  (32 bytes)  — SHA256 of the aggregate public key
  NUMERIC        (varint)    — threshold M (for policy/display, not used in verification)
  NUMERIC        (varint)    — group size N (for policy/display, not used in verification)
```

Total conditions footprint: ~35 bytes (micro-header + 32 + varint + varint)

**Why include M and N?** They're not needed for cryptographic verification (the aggregate key already encodes the threshold scheme). They exist for:
1. Policy enforcement: mempool can reject nonsensical values (M=0, M>N, N=0)
2. Wallet tooling: block explorers and wallets can display "3-of-5" without off-chain metadata
3. Fee estimation: helps nodes evaluate the "real" security level of the output

### Witness (spending side)

```
MUSIG_THRESHOLD witness:
  PUBKEY     (33 bytes)  — the aggregate public key (compressed)
  SIGNATURE  (64 bytes)  — the aggregate Schnorr signature
```

Total witness footprint: ~99 bytes (micro-header + length-prefixed pubkey + length-prefixed sig)

### Implicit Field Layouts

```cpp
// Conditions context
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_CONDITIONS = {3, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::NUMERIC, 0},  // M (varint)
    {RungDataType::NUMERIC, 0},  // N (varint)
}};

// Witness context
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_WITNESS = {2, {
    {RungDataType::PUBKEY, 0},       // aggregate pubkey (variable, typically 33)
    {RungDataType::SIGNATURE, 0},    // aggregate signature (variable, typically 64)
}};
```

## Evaluator Function

```cpp
EvalResult EvalMusigThresholdBlock(const RungBlock& block,
                                    const BaseSignatureChecker& checker,
                                    SigVersion sigversion,
                                    ScriptExecutionData& execdata)
{
    // 1. Extract fields
    const RungField* pubkey_commit = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (!pubkey_commit || !pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    // 2. Verify aggregate pubkey matches commitment
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pubkey_field->data.data(), pubkey_field->data.size()).Finalize(hash);
    if (pubkey_commit->data.size() != 32 ||
        memcmp(hash, pubkey_commit->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // 3. Policy-only: validate M and N if present
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() >= 2) {
        int64_t m = ReadNumeric(*numerics[0]);
        int64_t n = ReadNumeric(*numerics[1]);
        if (m <= 0 || n <= 0 || m > n) {
            return EvalResult::ERROR;
        }
    }

    // 4. Verify aggregate Schnorr signature
    //    This is identical to SIG block verification from here
    if (sig_field->data.size() < 64 || sig_field->data.size() > 65) {
        return EvalResult::ERROR;
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    // Convert compressed pubkey (33 bytes) to x-only (32 bytes)
    std::vector<unsigned char> xonly;
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};
    if (pubkey_field->data.size() == 33) {
        xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
        pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
    }

    if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}
```

**Key observation:** Steps 2 and 4 are identical to `EvalSigBlock`. The only additions are the M/N policy validation (step 3) and the block type identity. The cryptographic verification is exactly the same — one Schnorr verify against one aggregate key.

**No PQ path.** MuSig/FROST rely on Schnorr's linear aggregation property. Post-quantum schemes don't support this. If PQ threshold signing is needed, use MULTISIG with PQ keys. MUSIG_THRESHOLD is Schnorr-only by definition.

## Dispatch (evaluator.cpp)

In `EvalBlock()`, add after the ADAPTOR_SIG case (~line 2128):

```cpp
case RungBlockType::MUSIG_THRESHOLD:
    raw = EvalMusigThresholdBlock(block, checker, sigversion, execdata);
    break;
```

## Type Registration (types.h)

### Enum

```cpp
// Signature family
SIG              = 0x0001,
MULTISIG         = 0x0002,
ADAPTOR_SIG      = 0x0003,
MUSIG_THRESHOLD  = 0x0004,  // NEW: MuSig2/FROST aggregate threshold signature
```

### IsKnownBlockType

Add `case RungBlockType::MUSIG_THRESHOLD:` to the switch (after ADAPTOR_SIG).

### BlockTypeName

Add `case RungBlockType::MUSIG_THRESHOLD: return "MUSIG_THRESHOLD";`

### Micro-header table

Add at slot 0x33 (first unused):
```cpp
0x0004, // 0x33: MUSIG_THRESHOLD
```

### GetImplicitLayout

Add to both CONDITIONS and WITNESS contexts:
```cpp
case RungBlockType::MUSIG_THRESHOLD: return MUSIG_THRESHOLD_CONDITIONS;
// and
case RungBlockType::MUSIG_THRESHOLD: return MUSIG_THRESHOLD_WITNESS;
```

## Policy (policy.cpp)

### IsBaseBlockType

Add `case RungBlockType::MUSIG_THRESHOLD:` — it's a base (non-covenant, non-stateful) block.

### IsStandardRungTx / IsStandardRungOutput

No changes needed — the existing loop validates all known block types. Adding MUSIG_THRESHOLD to `IsKnownBlockType` is sufficient. The field validation (size, type) is handled by the existing per-field checks.

### Optional: dedicated policy check

Could add MUSIG_THRESHOLD-specific policy:
- M must be >= 1 and <= N
- N must be >= 2 (otherwise just use SIG)
- N should be <= 256 (reasonable upper bound for display)

This would go in the per-block validation loop in `IsStandardRungTx`.

## RPC (rpc.cpp)

The `decoderungwitness` and related RPCs should display MUSIG_THRESHOLD blocks with:
- The pubkey commitment hash
- The threshold M and group size N
- The aggregate pubkey and signature
- A label indicating this is a threshold aggregate (not raw multisig)

## Tests (rung_tests.cpp)

| # | Test | Purpose |
|---|------|---------|
| 1 | `musig_threshold_basic_eval` | Construct MUSIG_THRESHOLD block with valid aggregate key/sig, verify SATISFIED |
| 2 | `musig_threshold_wrong_commitment` | Pubkey doesn't match PUBKEY_COMMIT, verify UNSATISFIED |
| 3 | `musig_threshold_wrong_signature` | Invalid aggregate signature, verify UNSATISFIED |
| 4 | `musig_threshold_missing_fields` | Missing pubkey or sig, verify ERROR |
| 5 | `musig_threshold_invalid_mn` | M=0, M>N, N=0, verify ERROR |
| 6 | `musig_threshold_serialization_roundtrip` | Serialize/deserialize conditions + witness with implicit layouts |
| 7 | `musig_threshold_micro_header` | Verify micro-header encoding at slot 0x33 |
| 8 | `musig_threshold_policy_standard` | Verify IsStandardRungTx accepts valid MUSIG_THRESHOLD |
| 9 | `musig_threshold_conditions_no_witness_types` | Conditions reject PUBKEY/SIGNATURE fields |
| 10 | `musig_threshold_wire_size` | Verify total size ~131 bytes for a complete spend |

### Test Implementation Notes

For tests 1-3, we need a valid Schnorr keypair to sign against. The existing test infrastructure already creates these for SIG block tests — reuse the same pattern. The "aggregate" key is just a normal Schnorr keypair from the evaluator's perspective. The FROST/MuSig2 ceremony that produced it is invisible on-chain.

## Files Touched

| File | Change | Lines (est.) |
|------|--------|-------------|
| `types.h` | Enum value, IsKnownBlockType, BlockTypeName, micro-header slot, implicit layouts, GetImplicitLayout | ~20 |
| `evaluator.cpp` | EvalMusigThresholdBlock function + dispatch case | ~50 |
| `policy.cpp` | IsBaseBlockType case | ~1 |
| `rpc.cpp` | Display formatting for MUSIG_THRESHOLD | ~10 |
| `rung_tests.cpp` | 10 new tests | ~200 |

**Total: ~280 lines of new code.** No existing lines modified beyond adding switch cases.

## Breakage Analysis

**Zero breakage.**

- New enum value 0x0004: doesn't conflict with any existing value
- New micro-header slot 0x33: currently unused (0xFFFF)
- New evaluator function: standalone, no existing function modified
- New implicit layouts: standalone constants, no existing layout modified
- GetImplicitLayout: new case in switch, no existing case changed
- IsKnownBlockType: new case, no existing case changed
- IsBaseBlockType: new case, no existing case changed
- Serialization: existing serialize/deserialize paths handle any known block type — adding a new known type just works
- Existing tests: unaffected (no existing behaviour changes)
- Wire format: old nodes reject unknown block type 0x0004 (expected for new features)

## Savings Summary

| Scheme | Group | MULTISIG | MUSIG_THRESHOLD | Saving |
|--------|-------|----------|-----------------|--------|
| 2-of-3 | 3 | ~230B | ~131B | 43% |
| 3-of-5 | 5 | ~365B | ~131B | 64% |
| 5-of-9 | 9 | ~640B | ~131B | 80% |
| 7-of-11 | 11 | ~780B | ~131B | 83% |
| 11-of-15 | 15 | ~1,060B | ~131B | 88% |

Flat ~131 bytes regardless of M and N. The on-chain footprint is constant.

## Comparison to Taproot

| Scenario | P2TR | RUNG_TX MUSIG_THRESHOLD |
|----------|------|------------------------|
| Single-sig keypath | 57B | N/A (use SIG block) |
| 3-of-5 scriptpath | ~400B+ | ~131B |
| 7-of-11 scriptpath | ~800B+ | ~131B |

MUSIG_THRESHOLD beats Taproot scriptpath by 3-6x on any threshold scenario.

## Implementation Order

1. `types.h` — register block type, layouts, micro-header
2. `evaluator.cpp` — write EvalMusigThresholdBlock + dispatch
3. `policy.cpp` — add to IsBaseBlockType
4. `rung_tests.cpp` — write tests, verify all pass
5. `rpc.cpp` — display formatting
6. Sync to ghost-labs-ladder-script repo
