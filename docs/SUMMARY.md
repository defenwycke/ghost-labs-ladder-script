# Ladder Script — Executive Summary

## The Problem

Bitcoin Script is a stack-based interpreter designed in 2009. It has served Bitcoin well, but its untyped data model creates fundamental limitations: arbitrary data can be embedded in transactions, complex spending policies require fragile opcode sequences that resist static analysis, and adding new capabilities (post-quantum signatures, covenants, stateful contracts) means bolting more opcodes onto an already opaque execution model. The result is a scripting system where composability is difficult, auditability requires execution simulation, and the attack surface grows with every new opcode.

## The Solution

Ladder Script replaces opcode-based scripting with a declarative, typed block model. Instead of writing programs that compute whether spending is allowed, users declare the conditions that must hold. The system draws from industrial Programmable Logic Controller (PLC) ladder diagrams — a proven model for expressing complex combinatorial logic in safety-critical environments.

**Conditions are organised as a ladder:**

- A **rung** contains one or more **blocks**, each expressing a single condition (signature check, timelock, hash preimage, covenant constraint, etc.). All blocks in a rung must be satisfied — AND logic.
- Multiple rungs provide alternative spending paths. The first satisfied rung wins — OR logic.
- **Relay rungs** define shared sub-conditions that other rungs can reference, enabling reusable logic without duplication.
- Any block can be **inverted**, flipping its result. Unknown block types fail closed (UNSATISFIED), ensuring forward compatibility.

Every field in every block is typed (PUBKEY, HASH256, NUMERIC, SCHEME, and others) with enforced byte-level size constraints. There are no arbitrary data pushes, no untyped stack elements, and no implicit type coercion.

## What This Enables

**Post-quantum cryptography, natively.** A single SCHEME field on any signature block routes verification to FALCON-512, FALCON-1024, Dilithium3, or SPHINCS+-SHA2. PUBKEY_COMMIT allows conditions to store a 32-byte hash rather than the full PQ public key (up to 1,793 bytes), reducing UTXO set overhead by up to 96%. The COSIGN block lets one PQ-secured UTXO serve as a co-spending guardian for unlimited classical UTXOs — incremental migration without a flag day.

**Covenants and stateful contracts.** Six recursion block types (RECURSE_SAME through RECURSE_DECAY) enable perpetual covenants, countdown locks, UTXO tree splitting, and progressive parameter relaxation. PLC-family blocks (latches, counters, timers, comparators, sequencers) bring stateful logic to Bitcoin transactions. Compound blocks (HTLC, PTLC, TIMELOCKED_SIG) fuse common patterns into single wire-efficient units.

**Structural spam resistance.** Because every byte must conform to a declared type with a valid range, embedding arbitrary data in Ladder Script outputs is economically prohibitive. MLSC outputs (see below) take this further — unused conditions are never revealed on-chain, so fake conditions cannot serve as data carriers.

**Machine-verifiable composability.** Static analysis requires only parsing, not execution simulation. Wallets, block explorers, and policy engines can inspect and reason about spending conditions without running a script interpreter.

## MLSC — Merkelised Ladder Script Conditions

Ladder Script defines two output formats:

- **Inline (`0xC1`)** stores fully serialised conditions in the output. Useful for debugging and simple cases.
- **MLSC (`0xC2`)** stores only a 32-byte Merkle root. All conditions are deferred to the spending witness, where the spender reveals only the exercised rung, coil, any referenced relays, and a Merkle proof. Unused spending paths remain permanently hidden.

MLSC reduces every UTXO entry to a fixed 40 bytes regardless of how many conditions or spending paths exist. The Merkle tree uses BIP-341-style tagged hashes ("LadderLeaf" / "LadderInternal") for domain separation. This is the standard output format for production use.

## Wire Efficiency

Two inheritance mechanisms minimise transaction size:

- **Template inheritance** (conditions-side): multiple outputs sharing the same conditions reference a single serialised copy, reducing condition overhead by up to 93%.
- **Diff witness** (witness-side): when multiple inputs spend outputs with identical conditions, subsequent inputs inherit the first input's rung and relay structure and provide only field-level diffs and a fresh coil, reducing witness overhead by 28% or more.

## Implementation

Ladder Script is fully implemented and running on a dedicated signet, built on a fork of Bitcoin Core with modified consensus rules. The implementation comprises 10 source files under `src/rung/`, covering type definitions, serialisation, condition parsing, block evaluation, sighash computation, PQ verification, adaptor signatures, aggregate proofs, and policy enforcement. The test suite includes 303 unit tests and 190 functional test scenarios covering all block types, serialisation round-trips, PQ signatures, covenant evaluation, diff witness resolution, and full mempool acceptance paths.

The Ladder Script Engine (`tools/ladder-engine/`) provides a browser-based visual programming environment for designing, simulating, and exporting Ladder Script transactions with no build step or server dependency.
