# Ladder Script Executive Summary

Ladder Script is a typed, structured transaction format for Bitcoin that replaces opcode-based scripting with a declarative block model. Introduced as transaction version 4, it organizes spending conditions as named function blocks within rungs: all blocks in a rung must be satisfied (AND logic), and the first satisfied rung among alternatives wins (OR logic). Every byte in a Ladder Script witness is typed, every condition is a named block with validated fields, and evaluation is deterministic with bounded execution time. The design draws directly from industrial Programmable Logic Controller ladder diagrams, which solved analogous reliability problems in safety-critical control systems.

## Key Innovations

- **Typed data model.** Nine declared data types (PUBKEY, HASH256, SIGNATURE, NUMERIC, SCHEME, etc.) with enforced size bounds replace untyped stack elements. No arbitrary data pushes are possible.
- **Named block architecture.** 52 block types across nine families replace opcode sequences. New capabilities are added as block types, not opcodes, using the same wire format.
- **Declarative evaluation.** Conditions are stated, not computed. Static analysis requires only parsing, not execution simulation.
- **Native post-quantum support.** The SCHEME field routes SIG blocks to FALCON-512/1024, Dilithium3, or SPHINCS+ verification. PUBKEY_COMMIT reduces 897-byte PQ keys to 32-byte UTXO commitments.
- **Covenant recursion.** Six recursion block types (RECURSE_SAME through RECURSE_DECAY) enable perpetual covenants, state machines, countdowns, UTXO tree splitting, and progressive relaxation.
- **Structural spam resistance.** Mandatory typing, witness-only field restrictions, and size limits make arbitrary data embedding economically prohibitive.

## Block Type Families

| Family | Range | Block Types | Purpose |
|--------|-------|-------------|---------|
| Signature | 0x0001--0x00FF | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD | Identity verification |
| Timelock | 0x0100--0x01FF | CSV, CSV_TIME, CLTV, CLTV_TIME | Temporal constraints |
| Hash | 0x0200--0x02FF | HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH | Knowledge proofs |
| Covenant | 0x0300--0x03FF | CTV, VAULT_LOCK, AMOUNT_LOCK | Output constraints |
| Recursion | 0x0400--0x04FF | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY | Self-referential conditions |
| Anchor | 0x0500--0x05FF | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE | Typed L2 metadata |
| PLC | 0x0600--0x06FF | HYSTERESIS, TIMER, LATCH, COUNTER, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN | State machines |
| Compound | 0x0700--0x07FF | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG | Wire-optimized patterns |
| Governance | 0x0800--0x08FF | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR | Transaction constraints |

## Transaction Format

A version 4 transaction output contains a `0xc1` prefix followed by serialized rung conditions (the lock). The input witness contains a serialized ladder witness (the key). At verification time, conditions and witness are merged field-by-field -- the conditions provide key commitments (PUBKEY_COMMIT), hashes, and parameters; the witness provides public keys, signatures, and preimages. The merged structure is evaluated by the three-level dispatch: `EvalLadder` (OR across rungs), `EvalRung` (AND within a rung), `EvalBlock` (type-specific logic). The sighash uses a tagged hash ("LadderSighash") that commits to the conditions hash, binding signatures to the exact conditions they satisfy.

## Post-Quantum Support

Ladder Script supports four post-quantum signature schemes (FALCON-512, FALCON-1024, Dilithium3, SPHINCS+-SHA2-256f) through the SCHEME data type and liboqs integration. The PUBKEY_COMMIT field allows conditions to store a 32-byte hash commitment instead of the full PQ public key, reducing UTXO set overhead by up to 96%. The COSIGN block type enables a single PQ-secured UTXO to serve as a guardian for unlimited classical UTXOs through mandatory co-spending.

## Implementation Status

Ladder Script is implemented in the `src/rung/` directory of ghost-core (Bitcoin Ghost's fork of Bitcoin Core). The implementation comprises 10 source files: type definitions, serialization, conditions, evaluation for all block types, sighash computation, PQ verification, adaptor signatures, aggregate proofs, and policy enforcement. The wire format supports two inheritance mechanisms: template inheritance (conditions-side, §3.5) and diff witness (witness-side, §3.6), which together reduce wire overhead by up to 93% for repeated conditions and 28%+ for repeated witnesses in multi-input transactions. The test suite includes 288 unit tests (`src/test/rung_tests.cpp`) and 117 functional test scenarios (`test/functional/rung_basic.py`) covering serialization round-trips, field validation, all block evaluators, PQ signature verification, covenant evaluation, diff witness resolution, and full transaction verification through the node's mempool acceptance path.
