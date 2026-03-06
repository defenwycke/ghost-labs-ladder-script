# Ladder Script

**Typed Structured Transaction Conditions for Bitcoin**

Ladder Script is a declarative transaction condition system for Bitcoin that replaces opcode-based scripting with a typed block model inspired by industrial Programmable Logic Controllers (PLC). Every byte is typed, every condition is a named block with validated fields, and evaluation follows deterministic ladder logic: AND within rungs, OR across rungs, first match wins.

Transaction version 3 (`RUNG_TX`) carries structured conditions in outputs (prefixed `0xc1`) and typed witnesses, enabling signatures, timelocks, hash locks, covenants, recursive state machines, and post-quantum cryptography — all without new opcodes.

## Repository Structure

```
docs/                    Documentation package
  WHITEPAPER.md          Vision, motivation, architecture
  BIP-XXXX.md            Formal Bitcoin Improvement Proposal
  SPECIFICATION.md       Complete technical specification
  BLOCK_LIBRARY.md       All 39 block types with fields and evaluation logic
  GLOSSARY.md            Terminology reference
  EXAMPLES.md            Worked examples with JSON wire format
  INTEGRATION.md         Bitcoin integration guide
  SOFT_FORK_GUIDE.md     Activation strategy and timeline
  FAQ.md                 30 questions and answers
  SUMMARY.md             One-page executive summary
  LADDER_SCRIPT_SCENARIOS.md  Functional test results (19 scenarios)

src/rung/                C++ reference implementation
  evaluator.cpp/h        Block evaluation engine (consensus)
  serialize.cpp/h        Wire format v2 serialization
  conditions.cpp/h       Output condition parsing (0xc1 prefix)
  sighash.cpp/h          LadderSighash tagged hash
  rpc.cpp                RPC commands (createrungtx, signrungtx, etc.)
  adaptor.cpp/h          Adaptor signature math
  pq_verify.cpp/h        Post-quantum signature verification
  aggregate.cpp/h        Aggregate attestation (fail-closed)
  types.cpp/h            Block type, data type, and enum definitions
  policy.cpp/h           Mempool policy validation

tools/ladder-engine/     Visual editor and simulator
  index.html             Single-page React application

tests/
  functional/rung_basic.py   19 end-to-end signet test scenarios
  unit/rung_tests.cpp        185+ unit tests for evaluator logic
```

## Quick Start

1. Open `tools/ladder-engine/index.html` in a browser
2. Click **EXAMPLES** and load a scenario (e.g., "Atomic Swap HTLC")
3. Switch to **SIMULATE** mode and click rung labels to step through evaluation
4. Click the **RPC** tab to see the `createrungtx` wire-format JSON

## Block Type Families

| Family | Blocks | Purpose |
|--------|--------|---------|
| Signature | SIG, MULTISIG, ADAPTOR_SIG | Identity verification |
| Timelock | CSV, CSV_TIME, CLTV, CLTV_TIME | Temporal constraints |
| Hash | HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH | Knowledge proofs |
| Covenant | CTV, VAULT_LOCK, AMOUNT_LOCK | Output constraints |
| Recursion | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | Self-referential conditions |
| Anchor | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE | Typed metadata |
| PLC | HYSTERESIS_FEE/VALUE, TIMER_CONTINUOUS/OFF_DELAY, LATCH_SET/RESET, COUNTER_DOWN/PRESET/UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | State machines |

## Post-Quantum Support

Ladder Script natively supports FALCON-512/1024, Dilithium3, and SPHINCS+ via the SCHEME field. The PUBKEY_COMMIT block reduces PQ key storage from 897 bytes to 32 bytes per UTXO. The COSIGN anchor pattern enables a single perpetual PQ UTXO to protect unlimited children via co-spending.

## License

MIT

## Links

- [Bitcoin Ghost](https://github.com/bitcoin-ghost)
- [ghost-core](https://github.com/bitcoin-ghost/ghost) (parent Bitcoin Core fork)
