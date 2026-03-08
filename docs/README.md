# Ladder Script

**Typed Structured Transaction Conditions for Bitcoin**

Ladder Script is a transaction condition system that replaces Bitcoin Script's
stack-based opcode interpreter with a typed, structured, declarative model.
Spending conditions are organized into rungs (AND-combined blocks) and ladders
(OR-combined rungs), following the visual and logical conventions of
Programmable Logic Controller (PLC) ladder diagrams. Every byte in a Ladder
Script transaction belongs to a known data type with enforced size constraints,
eliminating arbitrary data embedding and enabling machine-verifiable
composability of complex spending policies, covenants, post-quantum
cryptography, and stateful smart contracts.

---

## Document Index

| Document | Description |
|----------|-------------|
| [SUMMARY.md](SUMMARY.md) | One-page executive summary of Ladder Script's design and capabilities |
| [WHITEPAPER.md](WHITEPAPER.md) | Vision, motivation, and architecture -- the case for structured conditions |
| [BIP-XXXX.md](BIP-XXXX.md) | Formal Bitcoin Improvement Proposal for v3 RUNG_TX transactions |
| [SPECIFICATION.md](SPECIFICATION.md) | Complete technical specification: wire format, evaluation rules, sighash |
| [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) | Block type reference with field layouts, evaluation semantics, and examples |
| [GLOSSARY.md](GLOSSARY.md) | Terminology definitions for Ladder Script concepts |
| [EXAMPLES.md](EXAMPLES.md) | Worked examples with ASCII diagrams, JSON wire format, and evaluation walkthroughs |
| [INTEGRATION.md](INTEGRATION.md) | Bitcoin integration guide: consensus changes, script interpreter, mempool policy |
| [SOFT_FORK_GUIDE.md](SOFT_FORK_GUIDE.md) | Activation strategy and deployment considerations |
| [FAQ.md](FAQ.md) | Frequently asked questions organized by topic |

---

## Quick Start

1. **Open the Ladder Engine.**
   Load `tools/ladder-engine/index.html` in a browser. The tool runs entirely
   client-side with no build step required.

2. **Load an example.**
   Click the **EXAMPLES** button in the header bar. Select a pre-built program
   (e.g., "2-of-3 MULTISIG VAULT" or "ATOMIC SWAP (HTLC)"). The ladder diagram
   populates with the example's rungs, blocks, and transaction structure.

3. **Export JSON.**
   The right panel displays the `createrungtx` RPC JSON in real time. Copy the
   JSON and submit it to a Ghost node via `ghost-cli createrungtx '<json>'` to
   create a v3 transaction. Use `signrungtx` to sign and `sendrawtransaction`
   to broadcast.

---

## Block Type Overview

Ladder Script defines 37 block types across 7 families. Each block evaluates a
single spending condition within a rung.

| Family | Range | Block Types |
|--------|-------|-------------|
| **Signature** | 0x0001-0x00FF | `SIG`, `MULTISIG`, `ADAPTOR_SIG` |
| **Timelock** | 0x0100-0x01FF | `CSV`, `CSV_TIME`, `CLTV`, `CLTV_TIME` |
| **Hash** | 0x0200-0x02FF | `HASH_PREIMAGE`, `HASH160_PREIMAGE`, `TAGGED_HASH` |
| **Covenant** | 0x0300-0x03FF | `CTV`, `VAULT_LOCK`, `AMOUNT_LOCK` |
| **Recursion** | 0x0400-0x04FF | `RECURSE_SAME`, `RECURSE_MODIFIED`, `RECURSE_UNTIL`, `RECURSE_COUNT`, `RECURSE_SPLIT`, `RECURSE_DECAY` |
| **Anchor** | 0x0500-0x05FF | `ANCHOR`, `ANCHOR_CHANNEL`, `ANCHOR_POOL`, `ANCHOR_RESERVE`, `ANCHOR_SEAL`, `ANCHOR_ORACLE` |
| **PLC** | 0x0600-0x06FF | `HYSTERESIS_FEE`, `HYSTERESIS_VALUE`, `TIMER_CONTINUOUS`, `TIMER_OFF_DELAY`, `LATCH_SET`, `LATCH_RESET`, `COUNTER_DOWN`, `COUNTER_PRESET`, `COUNTER_UP`, `COMPARE`, `SEQUENCER`, `ONE_SHOT`, `RATE_LIMIT`, `COSIGN` |

Each block type accepts typed fields (PUBKEY, HASH256, NUMERIC, SCHEME, etc.)
with enforced size constraints. See [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) for
complete field layouts and evaluation semantics.

---

## Data Types

Every field in a Ladder Script transaction is typed. The following data types
are defined:

| Type | Byte | Size | Allowed In |
|------|------|------|------------|
| PUBKEY | 0x01 | 1-2048 bytes | Witness only |
| PUBKEY_COMMIT | 0x02 | 32 bytes (fixed) | Conditions |
| HASH256 | 0x03 | 32 bytes (fixed) | Conditions |
| HASH160 | 0x04 | 20 bytes (fixed) | Conditions |
| PREIMAGE | 0x05 | 1-252 bytes | Witness only |
| SIGNATURE | 0x06 | 1-50000 bytes | Witness only |
| SPEND_INDEX | 0x07 | 4 bytes (fixed) | Conditions |
| NUMERIC | 0x08 | 1-4 bytes | Conditions, Witness |
| SCHEME | 0x09 | 1 byte (fixed) | Conditions |

---

## Evaluation Model

```
Transaction Input
       |
       v
  +---------+
  | Rung 0  |--[ Block A ]--[ Block B ]--[ Block C ]-->  (Coil)   --> SATISFIED
  +---------+                                              |
       | (if any block fails)                              |
       v                                                   |
  +---------+                                              |
  | Rung 1  |--[ Block D ]--[ Block E ]-->  (Coil)   -----+-------> SATISFIED
  +---------+                                              |
       | (if any block fails)                              |
       v                                                   |
  +---------+                                              |
  | Rung N  |--[ Block F ]-->  (Coil)   ------------------+-------> SATISFIED
  +---------+                                              |
       |                                                   |
       v                                                   v
  UNSATISFIED                                     (first match wins)
```

- **AND** within a rung: all blocks must be SATISFIED.
- **OR** across rungs: first satisfied rung wins.
- **Inversion**: per-block flag that flips SATISFIED/UNSATISFIED.
- **Fail-closed**: unknown block types return UNSATISFIED.

---

## Links

| Resource | Path |
|----------|------|
| Ladder Engine (visual tool) | `tools/ladder-engine/index.html` |
| Rung evaluator (C++) | `src/rung/evaluator.cpp` |
| Rung types and enums | `src/rung/types.h` |
| Conditions (de)serialization | `src/rung/conditions.cpp` |
| Wire format serialization | `src/rung/serialize.cpp` |
| Sighash computation | `src/rung/sighash.cpp` |
| RPC interface | `src/rung/rpc.cpp` |
| PQ signature verification | `src/rung/pq_verify.cpp` |
| Adaptor signature support | `src/rung/adaptor.cpp` |
| Policy validation | `src/rung/policy.cpp` |
| Unit tests | `src/test/rung_tests.cpp` |
| Functional tests | `test/functional/rung_basic.py` |
| PQ functional tests | `test/functional/rung_pq_block.py` |
| P2P relay tests | `test/functional/rung_p2p.py` |
| Fuzz target | `src/test/fuzz/rung_deserialize.cpp` |
| Scenario test results | `docs/LADDER_SCRIPT_SCENARIOS.md` |
