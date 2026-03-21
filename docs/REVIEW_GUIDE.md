# Ladder Script Review Guide

This document is a starting point for reviewers. Ladder Script is 60 block types (2 deprecated) across 10 families, but each block type is a self-contained unit that can be reviewed independently.

## Where to Start

### 1. Read the Type System (15 minutes)

**File:** `src/rung/types.h`

This single header defines everything: the `RungBlockType` enum (61 entries), the `RungDataType` enum (11 entries), field size bounds (`FieldMinSize`, `FieldMaxSize`), block type names, micro-header slots, and implicit field layouts.

After reading this file, you know every block type that exists and what data types they use.

### 2. Pick One Block Type (10 minutes)

**File:** `src/rung/evaluator.cpp`

Each block type has a single evaluator function (~20-80 lines). Start with `EvalSigBlock` — it's the simplest and most familiar (public key + signature verification). Then read `EvalCSVBlock` (relative timelock) or `EvalHashPreimageBlock` (hash preimage reveal).

Each evaluator follows the same pattern:
1. Find required fields by type
2. Validate field sizes
3. Check the condition (hash match, signature verify, timelock check)
4. Return SATISFIED, UNSATISFIED, or ERROR

### 3. Understand Ladder Logic (5 minutes)

**File:** `src/rung/evaluator.cpp` — search for `VerifyRungTx`

The top-level entry point evaluates a ladder witness:
- **AND within rungs:** All blocks in a rung must be SATISFIED
- **OR across rungs:** First satisfied rung wins
- **Inversion:** A block marked `inverted` flips SATISFIED↔UNSATISFIED (ERROR stays ERROR)

### 4. Understand Serialization (15 minutes)

**File:** `src/rung/serialize.cpp`

Wire format v3 uses micro-headers (single-byte encoding for common block types), implicit fields (block types with known layouts omit type bytes), and varint NUMERIC encoding. The key insight: deserialization validates every byte against the type system. Unknown types, oversized fields, and malformed data are all rejected.

### 5. Understand the Anti-Spam Property (5 minutes)

**File:** `src/rung/rpc.cpp` — search for "Auto-convert PUBKEY" and "Auto-convert SCRIPT_BODY"

Every hash commitment stored in the UTXO set is computed by the node:
- User provides PUBKEY → node computes PUBKEY_COMMIT (SHA-256) or HASH160 (RIPEMD160(SHA-256))
- User provides PREIMAGE/SCRIPT_BODY → node computes HASH256 (SHA-256) or HASH160
- Raw hash values are rejected for all node-computed block types

No condition field across all 60 block types accepts arbitrary user-chosen bytes.

## File Map

| File | Lines | What It Does |
|------|-------|-------------|
| `types.h` | ~910 | All type definitions, enums, size bounds, micro-header table |
| `evaluator.cpp` | ~3400 | 61 block evaluators + ladder logic + signature verification |
| `serialize.cpp` | ~785 | Wire format serialization/deserialization |
| `conditions.cpp` | ~920 | Conditions (locking side) parsing and validation |
| `rpc.cpp` | ~2200 | RPC interface + node-computed hash enforcement |
| `policy.cpp` | ~435 | Mempool policy (standard/non-standard) |
| `sighash.cpp` | ~130 | Tagged sighash computation |
| `pq_verify.cpp` | ~145 | Post-quantum signature verification (FALCON, Dilithium) |
| `adaptor.cpp` | ~190 | Adaptor signatures for atomic swaps |
| `aggregate.cpp` | ~40 | Block-level signature aggregation |

## Block Families at a Glance

| Family | Blocks | Range | Purpose |
|--------|--------|-------|---------|
| Signature | 5 | 0x0001-0x00FF | Key-based authorization |
| Timelock | 4 | 0x0100-0x01FF | Time and height constraints |
| Hash | 3 | 0x0200-0x02FF | Preimage reveals and tagged hashes |
| Covenant | 3 | 0x0300-0x03FF | CTV templates, vaults, amount locks |
| Recursion | 6 | 0x0400-0x04FF | Self-referencing outputs (perpetual, decay, split) |
| Anchor | 6 | 0x0500-0x05FF | L2 anchors (channels, pools, oracles) |
| PLC | 14 | 0x0600-0x06FF | Industrial logic (timers, counters, latches, rate limits) |
| Compound | 6 | 0x0700-0x07FF | Collapsed multi-block patterns (HTLC, PTLC) |
| Governance | 6 | 0x0800-0x08FF | Transaction-level constraints (weight, I/O counts) |
| Legacy | 7 | 0x0900-0x09FF | Wrapped Bitcoin tx types (P2PK through P2TR) |

## Running Tests

```bash
# Unit tests (422 test cases)
make -j2 && src/test/test_bitcoin --run_test=rung_tests

# Functional tests (on signet)
test/functional/rung_basic.py
test/functional/rung_signet.py
```

## What to Look For

- **Correctness:** Does each evaluator implement its stated semantics?
- **Completeness:** Are all field types validated before use?
- **Determinism:** Can evaluation produce different results on different nodes?
- **DoS resistance:** Are all loops bounded? Are recursion depths limited?
- **Anti-spam:** Can any code path store user-chosen bytes in the UTXO set?
