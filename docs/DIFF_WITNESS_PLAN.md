# DIFF_WITNESS Implementation Plan

**Status:** Planned (not yet implemented)
**Depends on:** RUNG_TEMPLATE_INHERIT (complete on signet)
**Purpose:** Witness-side counterpart to template inheritance — inherit rungs/relays from a previous input's witness, provide only field-level diffs + fresh coil.

## Motivation

In covenant chains (RECURSE_SAME, RECURSE_MODIFIED, PLC state machines), consecutive spends have witnesses that are 90%+ identical — same pubkeys, same structure, same relays. Only signatures and maybe one preimage differ. RUNG_TEMPLATE_INHERIT already eliminates redundant conditions. DIFF_WITNESS eliminates redundant witness data. Together they make covenant chains economical.

## Design Decision: Coil Is Never Inherited

The witness coil (coil_type, attestation, scheme, address, conditions) describes *how you're spending*, not how the output is locked. Each spend in a covenant chain may send to a different address. Inheriting another input's destination address would be a dangerous footgun. Therefore:

- **Rungs + relays:** Inherited from source, diffs applied
- **Coil:** Always provided fresh by the spender

## Wire Format

```
DIFF_WITNESS:
  [n_rungs: varint(0)]          <- sentinel: diff witness mode
  [input_index: varint]         <- which input's witness to inherit rungs/relays from
  [n_diffs: varint]             <- field-level patches to inherited rungs
    per diff:
      [rung_index: varint]
      [block_index: varint]
      [field_index: varint]
      [data_type: uint8]
      [data...]                 <- varint for NUMERIC, len+bytes otherwise
  [coil_type: uint8]            <- always provided fresh
  [attestation: uint8]
  [scheme: uint8]
  [address_len: varint]
  [address: bytes]
  [n_coil_conditions: varint]
  [coil condition rungs...]
  — no relays section (inherited from source) —
```

Minimum size with no diffs: ~8 bytes header + coil overhead.

## Data Structures

### New types (types.h)

```cpp
struct WitnessDiff {
    uint16_t rung_index;
    uint16_t block_index;
    uint16_t field_index;
    RungField new_field;
};

struct WitnessReference {
    uint32_t input_index;
    std::vector<WitnessDiff> diffs;
};
```

### Extended LadderWitness (types.h)

```cpp
struct LadderWitness {
    std::vector<Rung> rungs;
    RungCoil coil;
    std::vector<Relay> relays;
    std::optional<WitnessReference> witness_ref;  // NEW

    bool IsEmpty() const { return rungs.empty() && !witness_ref.has_value(); }
    bool IsWitnessRef() const { return witness_ref.has_value(); }  // NEW
};
```

## Deserialisation (serialize.cpp)

In `DeserializeLadderWitness`, replace the `n_rungs == 0` error:

```cpp
if (n_rungs == 0) {
    // Diff witness mode
    uint64_t input_index = ReadCompactSize(ss);
    uint64_t n_diffs = ReadCompactSize(ss);
    // validate cap: MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS

    WitnessReference ref;
    ref.input_index = input_index;
    ref.diffs.resize(n_diffs);

    for each diff:
        read rung_index, block_index, field_index
        read data_type byte
        validate: must be witness-only (PUBKEY, SIGNATURE, PREIMAGE)
        read field data (varint for NUMERIC — though NUMERIC is not witness-only)
        validate field via IsValid()

    ladder_out.witness_ref = std::move(ref);

    // Read fresh coil (same code as normal path)
    read coil_type, attestation, scheme, address, coil_conditions

    // No relays section — inherited from source

    reject trailing bytes
    return true;
}
```

## Serialisation (serialize.cpp)

In `SerializeLadderWitness`, add path for witness references:

```cpp
if (ladder.IsWitnessRef()) {
    WriteCompactSize(ss, 0);  // sentinel
    WriteCompactSize(ss, ladder.witness_ref->input_index);
    WriteCompactSize(ss, ladder.witness_ref->diffs.size());
    for (const auto& diff : ladder.witness_ref->diffs) {
        WriteCompactSize(ss, diff.rung_index);
        WriteCompactSize(ss, diff.block_index);
        WriteCompactSize(ss, diff.field_index);
        // write field: type + data (same as template inherit)
    }
    // write fresh coil (same as normal path)
    // no relays section
    return;
}
```

## Resolution (evaluator.cpp)

New function:

```cpp
bool ResolveWitnessReference(LadderWitness& witness,
                             const CTransaction& tx,
                             unsigned int nIn,
                             std::string& error);
```

Steps:
1. Validate `input_index < nIn` (forward-only, prevents cycles)
2. Deserialise `tx.vin[input_index].scriptWitness.stack[0]` as LadderWitness
3. Reject if source is itself a witness reference (no chaining)
4. Copy source's `rungs` and `relays` into `witness`
5. Apply diffs: bounds check indices, enforce type match
6. Keep witness's own coil (already populated from deserialisation)
7. Clear `witness_ref`

## Integration into VerifyRungTx (evaluator.cpp)

After existing witness deserialisation (line ~2518):

```cpp
if (witness_ladder.IsWitnessRef()) {
    std::string ref_error;
    if (!ResolveWitnessReference(witness_ladder, tx, nIn, ref_error)) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }
}
// ... rest of flow unchanged (conditions, template resolve, merge, eval)
```

## Validation Rules

| Rule | Rationale |
|------|-----------|
| `input_index < nIn` | Forward-only: prevents cycles, matches template inherit |
| Source must not be a diff witness | No chaining: prevents resolution complexity |
| Diff field types: PUBKEY, SIGNATURE, PREIMAGE only | Witness-only types (inverse of template inherit) |
| Diff indices in range | Bounds safety |
| Diff type must match source field type | Type preservation (same as template inherit) |
| Max diffs: `MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS` | Same cap as template inherit |

## Policy Updates (policy.cpp)

`IsStandardRungTx` updated to:
- Recognise diff witness format (n_rungs == 0 with valid reference)
- Apply same field/size limits to diffs
- Validate forward-only and no-chaining at relay time

## Tests (rung_tests.cpp)

| # | Test | Purpose |
|---|------|---------|
| 1 | `diff_witness_basic_roundtrip` | Serialise/deserialise, no diffs, fresh coil |
| 2 | `diff_witness_with_sig_diff` | Replace only signature field |
| 3 | `diff_witness_resolution` | Full resolve from source witness |
| 4 | `diff_witness_fresh_coil` | Verify inherited rungs but own coil/address |
| 5 | `diff_witness_rejects_self_reference` | `input_index == nIn` rejected |
| 6 | `diff_witness_rejects_backward_reference` | `input_index >= nIn` rejected |
| 7 | `diff_witness_rejects_chained_reference` | Source is also a diff witness |
| 8 | `diff_witness_rejects_condition_only_type` | No HASH256/NUMERIC/PUBKEY_COMMIT in diffs |
| 9 | `diff_witness_rejects_type_mismatch` | Diff type != source field type |
| 10 | `diff_witness_rejects_out_of_range` | Bad rung/block/field indices |
| 11 | `diff_witness_compact_wire_size` | Verify size savings vs full witness |
| 12 | `diff_witness_combined_with_template_inherit` | Both optimizations on same input |

## Files Touched

| File | Change |
|------|--------|
| `types.h` | WitnessDiff, WitnessReference, witness_ref on LadderWitness |
| `serialize.cpp` | Diff witness deserialize/serialize paths |
| `evaluator.cpp` | ResolveWitnessReference + call site in VerifyRungTx |
| `policy.cpp` | Recognise diff witness in standardness checks |
| `rung_tests.cpp` | 12 new tests |
| `rpc.cpp` | Display diff witness in decoderungwitness |

## Breakage Analysis

No breakage to existing code. Full analysis:

- **Sentinel (n_rungs == 0):** Currently rejected in witness deserializer. Safe to repurpose — no valid witness on chain uses it.
- **Conditions deserializer:** Separate code path, uses n_rungs == 0 for template mode independently. No interaction.
- **VerifyRungTx ordering:** Forward-only + no-chaining rules prevent cycles. Same pattern as template inheritance.
- **MergeConditionsAndWitness:** Resolved diff witness is structurally identical to a full witness. No change needed.
- **Sighash:** Commits to conditions, not witness encoding. Unaffected.
- **Existing tests:** No existing test exercises n_rungs == 0 in witness. No breakage.
- **Wire compatibility:** Expansion of valid set (soft-fork pattern).

## Savings Estimate

| Scenario | Full Witness | DIFF_WITNESS | Savings |
|----------|-------------|--------------|---------|
| Schnorr covenant hop (1 sig diff) | ~170 bytes | ~80 bytes | ~53% |
| HTLC chain hop (sig + preimage diff) | ~220 bytes | ~130 bytes | ~41% |
| PLC state machine (sig only) | ~150 bytes | ~75 bytes | ~50% |

Combined with RUNG_TEMPLATE_INHERIT on the conditions side, a full covenant chain hop drops from ~300+ bytes (conditions + witness) to ~80-90 bytes total.
