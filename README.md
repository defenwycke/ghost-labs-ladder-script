# Ladder Script

A typed transaction format for Bitcoin, derived from industrial PLC ladder logic.

**[Full overview, examples, and live demo](https://ladder-script.org/ladder-script.html)** | **[Try the Engine](https://ladder-script.org/ladder-engine.html)** | **[BIP Draft](docs/BIP-XXXX.md)**

```
  RUNG 0: ──[ SIG: Alice ]──[ CSV: 144 ]──────────────( UNLOCK )──
  RUNG 1: ──[ MULTISIG: 2-of-3 ]──────────────────────( UNLOCK )──
  RUNG 2: ──[ /CSV: 144 ]──[ SIG: Bob ]───────────────( UNLOCK )──   ← breach remedy
```

Bitcoin Script is a stack machine where every element is an opaque byte array. A public key, a hash, a timelock, and a JPEG are indistinguishable at the protocol level. Each new capability requires a new opcode, a soft fork, and years of coordination.

Ladder Script replaces this with **typed function blocks** organised into **rungs**. Every byte has a declared type. Every condition is a named block with validated fields. Evaluation is deterministic: AND within rungs, OR across rungs, first satisfied rung wins. Untyped data is a parse error —not policy, not non-standard, a *parse error*.

## How it works

The name and structure are borrowed from ladder logic, the programming model used in industrial PLCs (programmable logic controllers) for decades. A spending policy is a ladder. Each rung is a possible spending path containing typed condition blocks. Blocks on the same rung are AND —all must be satisfied. Rungs are OR —the first satisfied rung authorises the spend.

The output format is **MLSC** (Merkelized Ladder Script Conditions): a shared 33-byte commitment (`0xDF || conditions_root`) regardless of policy complexity. Only the exercised spending path is revealed at spend time. Unused paths stay permanently hidden. Each UTXO entry stores its value (8 bytes) plus a reference to the shared conditions_root.

Transaction version 4 (`RUNG_TX`). Soft fork activation —non-upgraded nodes see v4 as anyone-can-spend, the same upgrade path as SegWit and Taproot.

## What makes it different

**Contact inversion.** Non-key blocks can be inverted. `[/CSV: 144]` means "spend BEFORE 144 blocks" —a primitive Bitcoin has never had. Key-consuming blocks (SIG, MULTISIG, etc.) cannot be inverted, closing the garbage-pubkey data embedding vector. This enables breach remedies, dead man's switches, governance vetoes, and time-bounded escrows natively.

**Anti-spam hardening.** Eleven data types, enforced at the deserialiser before any cryptographic operation. Three coordinated defenses close all practical data embedding surfaces: `merkle_pub_key` folds public keys into the Merkle leaf hash (no writable pubkey field in conditions), selective inversion prevents key-consuming blocks from being inverted, and hash lock deprecation removes standalone preimage blocks. If it doesn't parse as a typed field, it doesn't enter the mempool.

**Post-quantum signatures.** FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ are native signature schemes, implemented and running on the live signet. A single SCHEME field on any signature block routes verification to classical Schnorr or any PQ algorithm. The COSIGN pattern lets a single PQ anchor protect unlimited child UTXOs. Incremental migration without a flag day.

**Wire efficiency.** Compound blocks collapse common multi-block patterns (HTLC, PTLC, TIMELOCKED_MULTISIG) into single blocks. Relays allow shared conditions across rungs without duplication. Template references let inputs inherit conditions with field-level diffs.

**Legacy migration.** Seven legacy block types wrap P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR key-path, and P2TR script-path as typed Ladder Script blocks. Identical spending semantics, fully typed fields. Designed for a three-phase migration: coexistence, legacy-in-blocks, then sunset of raw legacy formats.

## 61 Block Types

| Family | Blocks |
|--------|--------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME |
| Hash | TAGGED_HASH, HASH_GUARDED |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN |
| PLC | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR, OUTPUT_CHECK |
| Legacy | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY |

## Try it

The [Ladder Engine](https://ladder-script.org/ladder-engine.html) is a browser-based visual builder. Load an example from the preset library, switch to SIMULATE, step through evaluation. The RPC tab shows the wire-format JSON. The SIGNET tab lets you fund, sign, and broadcast transactions on the live signet.

## Tests

- **480 unit tests** (`src/test/rung_tests.cpp`), serialization, evaluation, all 61 block types, inversion, anti-spam, PQ signatures, legacy blocks
- **60 regtest functional tests** across 6 test suites, end-to-end RPC flows, P2P relay, MLSC Merkle proofs, PQ block stress tests, signet integration

```bash
# Unit tests
make -j2 && src/test/test_bitcoin --run_test=rung_tests

# Functional tests
python3 tests/functional/rung_basic.py
python3 tests/functional/rung_mlsc.py
python3 tests/functional/rung_pq_block.py
python3 tests/functional/rung_signet.py
python3 tests/functional/rung_p2p.py
python3 tests/functional/rung_key_ref_sig.py
```

## Repository

```
src/rung/              C++ reference implementation (19 files)
tests/                 Unit tests, fuzz target, 6 functional test suites
patches/               Diff for applying to Bitcoin Core v30.1
docs/                  BIP draft, block library, examples, FAQ, glossary
tools/                 Ladder Engine, block reference docs, tx preset docs
proxy/                 FastAPI signet proxy for live testing
```

## Documentation

- [BIP Draft](docs/BIP-XXXX.md) —formal Bitcoin Improvement Proposal
- [Block Library](docs/BLOCK_LIBRARY.md) —all 61 blocks with fields and semantics
- [Examples](docs/EXAMPLES.md) —worked scenarios with RPC JSON
- [Review Guide](docs/REVIEW_GUIDE.md) —recommended reading order for the C++
- [Engine Guide](docs/ENGINE_GUIDE.md) —how to use the visual builder
- [FAQ](docs/FAQ.md) —common questions
- [Glossary](docs/GLOSSARY.md) —terminology reference
- [Integration](docs/INTEGRATION.md) —wallet and application integration guide
- [Implementation Notes](docs/IMPLEMENTATION_NOTES.md) —spec deviations and why

## Reference Implementation

| File | Purpose |
|------|---------|
| `src/rung/types.h` | Core types: block types, data types, schemes, structs |
| `src/rung/evaluator.cpp` | Block evaluators for all 61 types, rung/ladder logic |
| `src/rung/serialize.cpp` | Wire format with micro-headers and implicit fields |
| `src/rung/conditions.cpp` | MLSC Merkle tree, `merkle_pub_key` leaf computation |
| `src/rung/sighash.cpp` | Tagged sighash computation |
| `src/rung/pq_verify.cpp` | Post-quantum signature verification (liboqs) |
| `src/rung/adaptor.cpp` | Adaptor signature support |
| `src/rung/descriptor.cpp` | Descriptor language: `parseladder` / `formatladder` RPCs |
| `src/rung/rpc.cpp` | 15 RPC commands: `createtxmlsc`, `signladder`, `parseladder`, `formatladder`, etc. |
| `src/rung/policy.cpp` | Mempool policy enforcement |

## Links

- [Ladder Engine (hosted)](https://ladder-script.org/ladder-engine.html) —build and broadcast on signet
- [Block Reference (hosted)](https://ladder-script.org/block-docs/) —visual docs for all block types
- [Ladder Script Overview](https://ladder-script.org/ladder-script.html) —how it works, use cases, diagrams

## License

MIT
