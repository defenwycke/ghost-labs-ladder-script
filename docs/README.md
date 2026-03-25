# Ladder Script Documentation

Ladder Script is a typed, structured transaction scripting system for Bitcoin Ghost.
It replaces Bitcoin Script's stack machine with declarative function blocks, typed fields,
and Merkelized conditions (MLSC). Transactions use version 4 (`RUNG_TX_VERSION = 4`).

## Documentation Index

| Document | Description |
|----------|-------------|
| [INTRODUCTION.md](INTRODUCTION.md) | What Ladder Script is, key properties, and design rationale |
| [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) | Complete table of all 61 block types |
| [GLOSSARY.md](GLOSSARY.md) | Alphabetical glossary of every term and block type |
| [INTEGRATION.md](INTEGRATION.md) | How to integrate Ladder Script into wallets and applications |
| [SOFT_FORK_GUIDE.md](SOFT_FORK_GUIDE.md) | Activation mechanics, validation changes, and deployment |
| [POSSIBILITIES.md](POSSIBILITIES.md) | Capabilities that Ladder Script enables beyond Bitcoin Script |
| [REVIEW_GUIDE.md](REVIEW_GUIDE.md) | Guide for code reviewers with file-by-file walkthrough |
| [SUMMARY.md](SUMMARY.md) | One-paragraph summary with key stats |

## Source Files

| File | Purpose |
|------|---------|
| `src/rung/types.h` | All 61 block types, 11 data types, RungCoil, implicit layouts, micro-header table, BlockDescriptor table |
| `src/rung/types.cpp` | RungField::IsValid implementation |
| `src/rung/evaluator.h` | EvalResult, RungEvalContext, BatchVerifier, LadderSignatureChecker |
| `src/rung/evaluator.cpp` | All 61 block evaluators, EvalBlock dispatch, EvalRung (AND), EvalLadder (OR), VerifyRungTx |
| `src/rung/sighash.h` | ANYPREVOUT flags, SignatureHashLadder declaration |
| `src/rung/sighash.cpp` | LadderSighash computation with ANYPREVOUT/ANYPREVOUTANYSCRIPT |
| `src/rung/serialize.h` | Wire format constants (MAX_RUNGS=16, MAX_BLOCKS_PER_RUNG=8, etc.), SerializationContext |
| `src/rung/serialize.cpp` | Wire format serialization/deserialization, micro-headers, implicit fields |
| `src/rung/conditions.h` | RungConditions, MLSC proof structures, Merkle tree functions |
| `src/rung/conditions.cpp` | MLSC proof verification, Merkle tree construction, template reference resolution |
| `src/rung/descriptor.h` | ParseDescriptor, FormatDescriptor |
| `src/rung/descriptor.cpp` | Descriptor language parser and formatter |
| `src/rung/policy.h` | IsBaseBlockType, IsCovenantBlockType, IsStatefulBlockType, IsStandardRungTx |
| `src/rung/policy.cpp` | Mempool policy checks |
| `src/rung/adaptor.h/cpp` | Adaptor signature utilities |
| `src/rung/pq_verify.h/cpp` | Post-quantum signature verification |
| `src/rung/rpc.cpp` | 14 RPC commands (decoderung, createrung, validateladder, createrungtx, signrungtx, signladder, computectvhash, computemutation, generatepqkeypair, pqpubkeycommit, extractadaptorsecret, verifyadaptorpresig, parseladder, formatladder) |

## Test Coverage

| Suite | Count |
|-------|-------|
| Unit tests (`rung_tests.cpp`) | 480 |
| Functional tests (`test_rung_regtest.py`) | 60 |
| TLA+ formal specs (`spec/`) | 10 specs, 80+ properties |

## Repository

Source: [github.com/bitcoin-ghost/ghost-labs-ladder-script](https://github.com/bitcoin-ghost/ghost-labs-ladder-script)
