# Relay Coil Implementation Plan

## Overview

Relay coils are rungs whose conditions are evaluated but don't map to a TX output. Other rungs (and other relays) can reference them via `requires`, enabling AND composition across rungs and DRY condition reuse.

**Key constraint:** Output refs (coil references on input contacts) are restricted to relay coils only. Normal coils cannot be referenced — if it can't go on the wire, the engine won't let you build it.

---

## Wire Format

```json
{
  "inputs": [{"txid": "...", "vout": 0}],
  "relays": [
    { "blocks": [{"type": "MULTISIG", "fields": [...]}] },
    { "blocks": [{"type": "CSV_TIMELOCK", "fields": [...]}], "requires": [0] }
  ],
  "outputs": [
    {
      "amount": 0.001,
      "conditions": [
        { "blocks": [{"type": "HASH_PREIMAGE", "fields": [...]}], "requires": [0] }
      ]
    },
    {
      "amount": 0.002,
      "conditions": [
        { "blocks": [{"type": "SIG", "fields": [...]}], "requires": [0, 1] }
      ]
    }
  ]
}
```

- `relays` is top-level, shared across all outputs.
- Both relays and conditions get optional `requires: [index, ...]`.
- Forward-only indexing: relay N can only require relays 0..N-1 (makes cycles structurally impossible).

### Binary Wire Format

Appended after existing coil conditions section:

```
[n_relays: varint]                    // 0 for backward compat
for each relay:
  [n_blocks: varint]
  for each block: (same format as rung blocks)
  [n_relay_requires: varint]
  for each: [relay_index: varint]
[n_rung_requires_entries: varint]     // per-rung requires
for each rung (in order):
  [n_requires: varint]
  for each: [relay_index: varint]
```

Old data with 0 relays remains valid. Older deserializers hit EOF after coil — acceptable for consensus change.

---

## C++ Changes

### 1. types.h

```cpp
/** A relay: blocks evaluated for cross-referencing, not tied to an output. */
struct Relay {
    std::vector<RungBlock> blocks;
    std::vector<uint16_t> relay_refs;  //!< Indices of other relays (must be < own index)
};
```

Extend `Rung`:
```cpp
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};
    std::vector<uint16_t> relay_refs;  //!< Indices into relay array
};
```

Extend `LadderWitness` and `RungConditions`:
```cpp
std::vector<Relay> relays;  // Add to both structs
```

### 2. serialize.cpp

**Constants (serialize.h):**
```cpp
static constexpr size_t MAX_RELAYS = 8;
static constexpr size_t MAX_REQUIRES_PER_RUNG = 8;
```

**DeserializeLadderWitness:** After reading coil conditions, if stream not empty:
1. Read `n_relays`. For each: read blocks + requires indices.
2. Read `n_rung_requires_entries`. For each rung: read requires indices.
3. Validate forward-only rule.
4. If stream still not empty → reject trailing bytes.

**SerializeLadderWitness:** After coil conditions, write relay data and per-rung requires.

**Conditions (conditions.cpp):** Propagate relays through `DeserializeRungConditions` / `SerializeRungConditions`. Validate relay blocks for condition-only data types (no SIGNATURE, PREIMAGE in conditions).

### 3. evaluator.cpp

New function:
```cpp
bool EvalRelays(const std::vector<Relay>& relays,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out);
```

**Implementation:**
1. Iterate relays in order (0, 1, 2...).
2. For each relay: check `requires` against cached results. If any required relay not SATISFIED → UNSATISFIED. Otherwise evaluate blocks (same AND as `EvalRung`).
3. Cache result.

**Modified `EvalRung`:** Takes `const std::vector<EvalResult>& relay_results`. Before evaluating blocks, check `rung.requires` — if any relay not SATISFIED, return UNSATISFIED immediately.

**Modified `EvalLadder`:** Call `EvalRelays` first. Pass results to each `EvalRung`.

**Modified `MergeConditionsAndWitness`:** Merge relay blocks from conditions with relay witness data. Relay count must match between conditions and witness.

**Modified `VerifyRungTx`:** Merged `LadderWitness` carries combined relays.

### 4. policy.cpp

**New limits:**

| Limit | Value | Scope |
|-------|-------|-------|
| MAX_RELAYS | 8 | Per output/witness |
| MAX_REQUIRES_PER_RUNG | 8 | Per rung or relay |
| MAX_RELAY_DEPTH | 4 | Transitive chain depth |
| MAX_BLOCKS_PER_RELAY | 8 | Same as rungs |

**IsStandardRungTx:** Validate:
- Relay count ≤ MAX_RELAYS
- Relay block count ≤ MAX_BLOCKS_PER_RELAY
- All requires indices valid (forward-only for relays, < n_relays for rungs)
- Transitive depth ≤ MAX_RELAY_DEPTH
- Preimage block count includes relay blocks
- All relay block types known

**Cycle detection:** Forward-only rule makes cycles structurally impossible. No separate algorithm needed.

### 5. rpc.cpp

**`createrungtx`:** Add optional `relays` top-level parameter. Add optional `requires` to each condition rung.

**`ParseConditionsSpec`:** Parse `relays` array, each relay's blocks (condition-only types), each relay's `requires`. Parse per-rung `requires`. Store in `RungConditions`.

**`LadderWitnessToJSON` / `CoilToJSON`:** Output relays and requires in decoded JSON.

**`signrungtx`:** Relay blocks that need witness data (signatures) must be signable. Call `BuildWitnessBlock` for relay blocks too.

### 6. Sighash

No changes needed. Relays serialized in conditions are committed in the scriptPubKey and thus automatically included in `SignatureHashLadder`.

---

## Frontend Engine (index.html)

### Data Model

1. New coil type in `COIL_TYPES`:
   ```js
   { value: 'relay', symbol: '◇R', label: 'Relay' }
   ```

2. Relay rungs: `output.type = 'relay'`, `output.txOutputId = null`. Coil name (`output.name`) is the relay identifier.

3. **Output refs restricted to relay coils only.** The input contact "Coil References" panel only lists rungs where `output.type === 'relay'`. Normal coils don't appear as options.

4. Remove `OUTPUT_REF` block type — refs handled exclusively via input contact panel, relay-only.

### Wire Export (`exportCreateRungtx`)

1. Collect relay rungs (where `output.type === 'relay'`), assign indices 0, 1, 2...
2. Build `relays` array with blocks and requires.
3. For each non-relay rung's `outputRefs`, convert relay coil names to relay indices → populate `requires` on conditions.
4. Relay-to-relay: if a relay rung has `outputRefs` pointing to another relay, add to that relay's `requires`.

### Wire Import

1. Parse `data.relays`. Create rung with `output.type = 'relay'` for each.
2. Parse `requires` on conditions. Convert relay indices to relay coil names → populate `outputRefs`.

### UI

- Relay coils: distinct amber/diamond symbol `◇R`, visually different from standard coils.
- No TX output badge on relay rungs.
- Input contact "REQUIRES" section shows relay references.
- Properties panel for relay rung shows which rungs depend on it.

---

## Tests (rung_tests.cpp)

| # | Test | Description |
|---|------|-------------|
| 1 | serialize_relay_roundtrip | 2 relays, serialize → deserialize, verify all fields |
| 2 | relay_forward_only | Relay 1 requires relay 0 ✓. Relay 0 requires relay 1 ✗ |
| 3 | relay_self_reference | Relay requires itself → rejected |
| 4 | rung_requires_valid_index | Requires index < n_relays ✓, requires index ≥ n_relays ✗ |
| 5 | eval_relay_satisfied | Relay blocks pass → rung requiring it passes |
| 6 | eval_relay_unsatisfied | Relay blocks fail → rung requiring it fails (even if rung's own blocks pass) |
| 7 | eval_relay_chain | Relay 1 requires relay 0. Both satisfied. Rung requires relay 1 → passes |
| 8 | eval_relay_chain_broken | Relay 0 fails. Relay 1 requires 0. Rung requires 1 → fails |
| 9 | policy_max_relays | 9 relays → rejected by policy |
| 10 | policy_relay_depth | 5-deep chain exceeds MAX_RELAY_DEPTH=4 → rejected |
| 11 | backward_compat | Old-format witness (no relay data) deserializes with empty relays |
| 12 | conditions_reject_witness_in_relay | SIGNATURE in relay conditions → rejected |
| 13 | merge_relay_conditions_witness | Conditions relay has PUBKEY_COMMIT, witness relay has PUBKEY+SIG → merge + eval succeeds |
| 14 | rpc_relay_roundtrip | createrungtx with relays → valid hex → decoderung shows relays → validateladder passes |

---

## Build Order

```
1. types.h         — Relay struct, extend Rung/LadderWitness/RungConditions
2. serialize.cpp   — Binary format extension (backward compatible)
3. policy.cpp      — Limits and validation
4. evaluator.cpp   — EvalRelays, modified EvalRung/EvalLadder/Merge/Verify
5. rpc.cpp         — createrungtx/signrungtx/decode relay support
6. rung_tests.cpp  — All 14 test cases
7. index.html      — Relay coil type, restricted output refs, wire export/import, UI
```

Steps 1-3 can be a single commit. Step 4 depends on 1-3. Step 5 depends on 1-4. Step 7 (frontend) is independent of C++ work.

---

## Use Case Examples

### Corporate Treasury
```
Relay 0: 3-of-5 board MULTISIG (shared auth, 8 blocks)
Output 0: requires [0] + HASH_PREIMAGE(payroll) → payroll disbursement
Output 1: requires [0] + HASH_PREIMAGE(vendor)  → vendor payment
Output 2: requires [0] + CSV_TIMELOCK(90 days)   → sweep to cold storage
```

### Escrow
```
Relay 0: escrow agent SIG
Output 0: requires [0] + buyer SIG  → release to seller
Output 1: requires [0] + seller SIG → refund to buyer
```

### Tiered Access
```
Relay 0: basic auth (single SIG)
Relay 1: requires [0] + HASH_PREIMAGE(2FA)
Output 0: requires [0]              → small withdrawals
Output 1: requires [1] + TIMELOCK   → large withdrawals
```

### Multi-Party Atomic Swap
```
Relay 0: party A SIG
Relay 1: party B SIG
Output 0: requires [0, 1]               → swap executes
Output 1: requires [0] + CSV_TIMELOCK   → A refund path
Output 2: requires [1] + CSV_TIMELOCK   → B refund path
```
