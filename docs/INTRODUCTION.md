# Ladder Script

Hello world.

Ladder Script is a new transaction format for Bitcoin. It replaces opcode-based scripting with typed, structured blocks organised into rungs, a model borrowed from industrial PLC ladder diagrams. The result is that complex Bitcoin transactions become readable, composable, and accessible to people who aren't Script experts.

Today, building anything beyond a basic Bitcoin transaction requires deep knowledge of opcodes, stack manipulation, and serialisation quirks. Multi-party custody, time-locked vaults, atomic swaps. These are powerful tools, but they're locked behind a wall of complexity that keeps most people out. Ladder Script removes that wall. You pick blocks from a library, wire them into rungs, and the engine handles the rest. Every byte is typed. Every field has enforced size constraints. There's nothing to simulate. You can read a Ladder Script transaction and understand exactly what it does.

This matters because Bitcoin adoption depends on people being able to use it. Not just hold it. Actually use it for custody, commerce, inheritance, governance. The simpler we make that, the more people Bitcoin reaches.

## What this enables

By restructuring how transactions work at the wire level, Ladder Script opens up capabilities that weren't practical before:

- **59 block types across 10 families.** Signatures, timelocks, hash verification, covenants, recursion, anchors, programmable logic, compound patterns, governance constraints, and legacy Bitcoin wrappers. These compose freely. A vault with fee-gated spending and a dead man's switch is three blocks on a rung.

- **MLSC (Merkelised Ladder Script Conditions).** The entire spending policy compresses to a 33-byte output regardless of complexity. Only the exercised path is revealed at spend time. Unused paths stay permanently hidden. This is better for privacy and significantly lighter on-chain.

- **Compound blocks.** Common multi-block patterns (HTLC, TIMELOCKED_SIG, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG) collapse into single blocks, eliminating redundant headers and saving wire bytes.

- **Relays.** Shared condition blocks that multiple rungs can reference, enabling cross-rung AND composition without duplicating conditions.

- **Template references.** Inputs can inherit conditions from other inputs with field-level diffs, dramatically reducing transaction size for batched operations.

## What comes with it

As a consequence of this typed, structured design, several important properties fall out naturally:

- **Post-quantum signatures.** FALCON-512, FALCON-1024, Dilithium3, and SPHINCS+ are native signature schemes, implemented and running on the live signet right now. A single SCHEME field on any signature block routes verification to classical Schnorr or any PQ algorithm. Any spending policy (single-sig, multisig, vaults, covenants) can use quantum-resistant keys today with zero structural changes. COSIGN lets a single PQ-secured UTXO co-sign for unlimited classical UTXOs. Incremental PQ migration without a flag day.

- **Anti-spam hardening.** Three coordinated defenses close all practical data embedding surfaces. merkle_pub_key folds public keys into the Merkle leaf hash so there is no writable pubkey field in conditions. Selective inversion prevents key-consuming blocks from being inverted, closing the garbage-pubkey attack. Hash lock deprecation removes standalone hash preimage blocks, closing the invertible-preimage attack. The on-chain footprint is a typed structure where every byte must conform to its declared type.

- **Programmable logic.** The PLC family brings 14 block types drawn from decades of industrial automation: hysteresis controllers, timers, latches, counters, comparators, sequencers, rate limiters. State machines, approval accumulators, watchdog patterns, all as composable blocks within the same wire format.

## Explore

This site has everything you need to understand, experiment with, and build on Ladder Script:

- **[Ladder Script Overview](/labs/ladder-script.html)**. How it works, block families, MLSC, use cases, and 30 example diagrams
- **[Documentation](/labs/docs/)** . BIP spec, technical specification, block library, integration guide, glossary
- **[Ladder Engine](/labs/ladder-engine.html)** . Visual IDE: build, simulate, and broadcast transactions on the live signet. Pick an example from the preset library or build from scratch
- **[Block Reference](/labs/docs/#BLOCKS)** . Deep-dive documentation on all 59 block types

The best way to understand Ladder Script is to play with it. Open the Engine, load an example, and see how the blocks wire together. Modify something. Break something. See what happens.

## Signet

Ladder Script is fully implemented and running on a dedicated signet. Build transactions in the Engine, fund them from the signet faucet, and spend them. No local node required.

Open the [Ladder Engine](/labs/ladder-engine.html) and start building.

---

If you find a bug, have a suggestion, or just want to talk about this, reach me on X: **[@defenwycke](https://x.com/defenwycke)**
