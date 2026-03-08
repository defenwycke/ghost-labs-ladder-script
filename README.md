# Ladder Script

A typed transaction format for Bitcoin, derived from industrial PLC ladder logic.

```
  RUNG 0: ──[ SIG: Alice ]──[ CSV: 144 ]──────────────( UNLOCK )──
  RUNG 1: ──[ MULTISIG: 2-of-3 ]──────────────────────( UNLOCK )──
  RUNG 2: ──[ /CSV: 144 ]──[ SIG: Bob ]───────────────( UNLOCK )──   ← breach remedy
```

Bitcoin Script is a stack machine where every element is an opaque byte array. A public key, a hash, a timelock, and a JPEG are indistinguishable at the protocol level. Each new capability requires a new opcode, a soft fork, and years of coordination.

Ladder Script replaces this with **typed function blocks** organised into **rungs**. Every byte has a declared type. Every condition is a named block with validated fields. Evaluation is deterministic: AND within rungs, OR across rungs, first satisfied rung wins. Untyped data is a parse error — not policy, not non-standard, a *parse error*.

The format is a single soft fork that subsumes OP_CTV, OP_VAULT, OP_CAT, and every pending covenant proposal as individual block types within a unified system.

## What makes it different

**Contact inversion.** Any block can be inverted. `[/CSV: 144]` means "spend BEFORE 144 blocks" — a primitive Bitcoin has never had. This enables breach remedies, dead man's switches, governance vetoes, and time-bounded escrows natively.

**Spam is structural.** Nine data types, enforced at the deserialiser before any cryptographic operation. Conditions contain zero user-chosen bytes — every field is a hash digest or bounded numeric. PUBKEY is witness-only; conditions use PUBKEY_COMMIT (SHA-256 hash). Preimage blocks are limited to 2 per witness. There is no push-data opcode. If it doesn't parse as a typed field, it doesn't enter the mempool.

**Post-quantum ready.** FALCON-512 signatures work today. All keys use PUBKEY_COMMIT in conditions (32-byte SHA-256 hash), keeping UTXO size constant regardless of key type. The COSIGN pattern lets a single PQ anchor protect unlimited child UTXOs.

**Human readable.** A CFO can audit a ladder diagram. A PLC engineer can read it immediately. No stack simulation required.

## 48 Block Types

| Category | Blocks |
|----------|--------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME |
| Hash | HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE |
| PLC | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| Compound | TIMELOCKED_SIG, HTLC, HASH_SIG |
| Governance | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR |

## Try it

Open `tools/ladder-engine/index.html` in a browser. Load an example, switch to SIMULATE, step through evaluation. The RPC tab shows the wire-format JSON.

Or use the hosted version at [bitcoinghost.org/labs/ladder-engine.html](https://bitcoinghost.org/labs/ladder-engine.html).

## Repository

```
src/rung/          C++ reference implementation (20 files)
tests/             Unit tests, fuzz target, 4 functional test suites
patches/           Diff for applying to Bitcoin Core v30
docs/              Whitepaper, BIP draft, specification, block library, examples
tools/             Visual builder and simulator
proxy/             FastAPI signet proxy for live testing
```

## Documentation

- [Whitepaper](docs/WHITEPAPER.md) — design rationale and architecture
- [Specification](docs/SPECIFICATION.md) — wire format, evaluation rules, data types
- [Block Library](docs/BLOCK_LIBRARY.md) — all 48 blocks with fields and semantics
- [BIP Draft](docs/BIP-XXXX.md) — formal Bitcoin Improvement Proposal
- [Examples](docs/EXAMPLES.md) — 18 worked scenarios with JSON
- [Implementation Notes](docs/IMPLEMENTATION_NOTES.md) — spec deviations and why

## Links

| Resource | Path |
|----------|------|
| Ladder Engine (visual tool) | `tools/ladder-engine/index.html` |
| Block Reference (visual docs) | `tools/block-docs/index.html` |
| Rung evaluator (C++) | `src/rung/evaluator.cpp` |
| Rung types and enums | `src/rung/types.h` |
| Conditions (de)serialization | `src/rung/conditions.cpp` |
| Wire format serialization | `src/rung/serialize.cpp` |
| Sighash computation | `src/rung/sighash.cpp` |
| RPC interface | `src/rung/rpc.cpp` |
| PQ signature verification | `src/rung/pq_verify.cpp` |
| Adaptor signature support | `src/rung/adaptor.cpp` |
| Policy validation | `src/rung/policy.cpp` |
| Unit tests | `tests/unit/rung_tests.cpp` |

## License

MIT
