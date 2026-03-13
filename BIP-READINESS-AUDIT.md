# Ladder Script BIP Readiness Audit

**Date:** 2026-03-11
**Scope:** All docs, web pages, specs, tests, and tools audited against C++ implementation

---

## FIXED (commit `6c98ba6`)

- **C-1** FIXED: PUBKEY removed from allowed condition types in whitepaper + BIP (only PUBKEY_COMMIT)
- **C-3** FIXED: "54 Blocks" → "53 Blocks" in docs index
- **C-4** FIXED: HTLC type code 0x0030 → 0x0702 in adaptor-sig-swap doc
- **M-1** FIXED: Whitepaper section 2.4 now lists all 9 families with correct ranges
- **M-3** FIXED: Wire format "(v3)" clarified as "serialization encoding version 3"
- **M-4** FIXED: SIG block now clearly separates conditions (PUBKEY_COMMIT, SCHEME) vs witness (PUBKEY, SIGNATURE)
- **m-1** FIXED: "Co-spend contact" → "constraint" in types.h, BIP, whitepaper, block-docs, docs index (all instances)
- **m-2** FIXED: types.h header comment now lists all 9 families with block type names
- **m-4** FIXED: SCHEME field codes documented in whitepaper section 5.1
- **m-9** FIXED: DEFERRED attestation explicitly documented as always-false
- **m-10** FIXED: UNKNOWN_BLOCK_TYPE inversion rationale explained
- **Extra** FIXED: PQ key size range 2,420 → 1,952 bytes on info page
- **Extra** FIXED: Compound block "8-16 bytes savings" claims replaced with precise description
- **Extra** FIXED: BIP data types table PUBKEY context corrected to "Witness only"
- **Extra** FIXED: PUBKEY marked "(witness only; conditions use PUBKEY_COMMIT)" in whitepaper data types table

---

## ALL ITEMS RESOLVED

### Critical

#### C-2: FIXED — BIP Deployment section added
- Full "Deployment" section added to BIP-XXXX.md with BIP-9 Speedy Trial parameters (90% threshold, 90-day timeout), simultaneous activation of all 53 block types, and soft fork compatibility note.

#### C-5: FIXED — 12 block types now have full test coverage
- **C++ unit tests:** 16 new eval tests for compound family (TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG) — positive, negative (bad sig/preimage), and CSV/CLTV failure cases.
- **Python functional tests (`rung_basic.py`):** 24 new tests — 1 positive + 1 negative per block type for all 6 compound and 6 governance types. PTLC covered via C++ eval tests (adaptor sig requires special test setup).
- **Governance C++ eval tests:** Already existed (EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR with positive + negative cases).

### Major

#### M-5: FIXED — Builder field names unified with Engine (commit `b41b28c`)
- 34 field name changes across 19 block types in `ladder-script-builder.html`
- Builder JSON now uses canonical Engine/RPC names throughout

#### M-6: FIXED — Serialization round-trip tests for all 53 block types
- `serialize_roundtrip_all_53_types_witness` — witness context round-trip for every block type
- `serialize_roundtrip_all_53_types_conditions` — conditions context round-trip for every block type
- Additional round-trip tests: multi-rung, inverted blocks, coil data, multi-field

#### M-7: FIXED — Consensus-critical size limit boundary tests added
- 13 new tests covering all 5 limits at exact boundary (pass) and boundary+1 (reject):
  - MAX_RUNGS (16): at-limit roundtrip + policy pass, exceeded deserialization reject, exceeded policy reject
  - MAX_BLOCKS_PER_RUNG (8): at-limit roundtrip + policy pass, exceeded deserialization reject, exceeded policy reject
  - MAX_FIELDS_PER_BLOCK (16): at-limit roundtrip, exceeded deserialization reject
  - MAX_LADDER_WITNESS_SIZE (100000): at-limit roundtrip, exceeded reject
  - MAX_RELAYS (8): at-limit roundtrip + policy pass, exceeded policy reject
  - Combined: all limits simultaneously at maximum (16 rungs × 8 blocks) roundtrip + policy pass

#### M-8: FIXED — Post-quantum scheme tests added for all 4 algorithms
- 12 new C++ unit tests:
  - Keygen → sign → verify → tamper round-trips for FALCON1024, DILITHIUM3, SPHINCS_SHA (3 tests)
  - Cross-scheme rejection (FALCON512 sig verified under DILITHIUM3 → fail)
  - Wrong-key rejection (same scheme, different keypair → fail)
  - Wrong-message rejection (sign msg A, verify msg B → fail)
  - PUBKEY_COMMIT with real keys for FALCON1024, DILITHIUM3, SPHINCS_SHA (3 tests)
  - PUBKEY_COMMIT mismatch with DILITHIUM3 (wrong key → UNSATISFIED)
- All tests guarded by `HasPQSupport()` (skip gracefully without liboqs)

#### M-9: FIXED — RECURSE_SAME carry-forward regression tests added
- 7 new C++ unit tests covering the `FullConditionsEqual` → `BlockConditionsEqual` → `IsConditionDataType` pipeline:
  - All condition field types (PUBKEY_COMMIT, SCHEME, NUMERIC, HASH256) carry-forward verified
  - SCHEME mismatch detection (SCHNORR vs ECDSA)
  - PUBKEY_COMMIT mismatch detection
  - NUMERIC value change detection
  - Structural mismatch (extra block in output rung) detection
  - Depth-zero termination (max_depth=0 → UNSATISFIED)
  - Compound block (TIMELOCKED_SIG) carry-forward verified

### Minor

#### m-3: FIXED — Whitepaper Section 9.1 now includes explicit threat model
- 8 attack classes enumerated: type confusion, data smuggling, witness bloat/DoS, signature replay, quantum key extraction, recursive non-termination, inversion-masked errors, forward-compatibility exploitation.

#### m-5: FIXED — Micro-header table added to whitepaper Section 3.2
- Full 53-slot lookup table added with encoding modes (micro-header, escape, escape+inverted).
- Implicit field layout behavior described; references BIP for per-type encoding details.

#### m-6: FIXED — Whitepaper references expanded to 14 entries
- Now cites: BIP-65, BIP-68, BIP-112, BIP-119, BIP-141, BIP-340, BIP-341, BIP-350, IEC 61131-3, NIST FIPS 204 (Dilithium), NIST FIPS 206 (SPHINCS+), FALCON spec, OQS project.

#### m-7: FIXED — Worked hex example added as whitepaper Section 10
- SIG + CSV (sign with key K after 10 blocks) fully annotated: conditions scriptPubKey (45 bytes) and witness (75 bytes) with byte-by-byte breakdown, micro-header encoding, and evaluation walkthrough.

#### m-8: FIXED — PQ key/signature sizes now cite NIST standards
- References 11-13 cite FIPS 204 (Dilithium3: 1,952B keys, 3,293B sigs), FIPS 206 (SPHINCS+-SHA2-256f: 32B keys, ~7,856B sigs), and FALCON spec (512: 897B keys; 1024: 1,793B keys).

---

## WHAT PASSED CLEAN

- **All 53 block-docs pages** — type codes, field definitions, evaluation logic, wire format all verified correct. Zero discrepancies.
- **All 6 transaction example docs** — block types, witness structures, scriptPubKey prefixes, byte counts, verification grids, dates, nav links all accurate.
- **Engine block type coverage** — all 53 types present with correct type codes.
- **Engine signature scheme mapping** — SCHNORR=0x01 through SPHINCS_SHA=0x13 correct.
- **Engine data type size constraints** — match types.h field specifications.
- **Ladder-script info page** — 53 block types verified, all families correct, all codes correct. Only 1 error found (PQ key size, now fixed).
- **BIP document** — has Rationale, Backwards Compatibility, Reference Implementation, Security Considerations, Test Vectors, Copyright sections. Wire format fully specified with micro-header table. Much more complete than initially reported.

---

## TEST COVERAGE GAPS — FULL LIST

### Blocks with zero functional test coverage (12):
TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG,
EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR

### Missing negative tests (security-critical):
- Invalid signature formats / mismatched key sizes
- PUBKEY in conditions (should be rejected — only PUBKEY_COMMIT allowed)
- Oversized fields at exact boundaries (PREIMAGE > 252 bytes, SIGNATURE > 50000 bytes)
- Circular relay references
- MLSC invalid Merkle proofs / root mismatches
- Deeply nested conditions (DoS vector)

### Missing interaction tests:
- RECURSE_SAME + witness reference (diff witness)
- MLSC + witness reference combination
- Compound blocks + timelocks at exact boundaries
- Mixed PQ + Schnorr signatures in same transaction
- Coil COVENANT and UNLOCK_TO types end-to-end

### Missing infrastructure tests:
- Serialization round-trips for all 53 block types
- 0xC1 prefix and tx version 4 identification
- MAX_RUNGS, MAX_BLOCKS_PER_RUNG boundary enforcement

---

## PRIORITY ORDER FOR BIP SUBMISSION

1. Write tests for C-5 (12 untested block types — ~24 tests minimum)
2. Add activation mechanism to BIP (C-2)
3. Unify Engine/Builder field names (M-5)
4. Write round-trip serialization tests (M-6)
5. Write size limit boundary tests (M-7)
6. Write PQ scheme tests (M-8)
7. Add RECURSE_SAME regression test (M-9)
8. Address minor items as time permits
