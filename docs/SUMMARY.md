# Ladder Script Summary

Ladder Script is a typed, structured transaction scripting system that replaces Bitcoin
Script's untyped stack machine with 61 declarative function blocks (61)
across 10 families: Signature, Timelock, Hash, Covenant, Recursion, Anchor, PLC, Compound,
Governance, and Legacy. Blocks are grouped into rungs (AND logic) and ladders (OR logic),
with all data constrained to 11 typed fields. Outputs use MLSC (Merkelized Ladder Script
Conditions): a 33-byte `0xC2 + SHA256 root` that reveals conditions only at spend time.
Public keys are folded into Merkle leaves via `merkle_pub_key`, and key-consuming blocks
are never invertible, closing data-embedding vectors. The system supports post-quantum
signatures (FALCON-512/1024, Dilithium3, SPHINCS+), ANYPREVOUT sighash flags for
LN-Symmetry, batch Schnorr verification, relays for cross-rung composition, and recursive
covenants. Transactions use `RUNG_TX_VERSION = 4`. Test coverage: 480 unit tests,
60 functional tests, 10 TLA+ specs with 80+ checked properties.

- [Full Documentation](README.md)
- [Block Library](BLOCK_LIBRARY.md)
- [Integration Guide](INTEGRATION.md)
