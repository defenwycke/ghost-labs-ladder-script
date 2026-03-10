# Ladder Script Glossary

Comprehensive glossary of Ladder Script terminology for Bitcoin Ghost. Terms are listed
in alphabetical order.

**Source files:** `src/rung/types.h`, `src/rung/evaluator.h`, `src/rung/conditions.h`,
`src/rung/sighash.h`, `src/rung/evaluator.cpp`.

---

### Adaptor Point

The second PUBKEY field (index 1) in an ADAPTOR_SIG block. A 32-byte x-only public key
representing a point on the secp256k1 curve. The adaptor point encodes a secret value
that is revealed when the adaptor signature is completed (adapted). Used in atomic swap
and PTLC protocols to link the completion of one transaction to the revelation of a
cryptographic secret.

### Adaptor Secret

The discrete logarithm of the adaptor point. Not stored on-chain. When the holder of
the adaptor secret completes (adapts) the partial signature into a full signature, the
secret can be extracted by comparing the partial and adapted signatures. This extraction
enables cross-chain atomic operations.

### Adaptor Signature

A partial Schnorr signature that cannot verify on its own but becomes a valid signature
once the adaptor secret is applied. In Ladder Script, the ADAPTOR_SIG block (0x0003)
expects the fully adapted signature in the witness; it verifies as a standard Schnorr
signature against the signing key. The adaptor point is committed in the conditions to
prove the protocol structure.

### Aggregate Signature

A single Schnorr signature produced by a MuSig2 or FROST threshold signing ceremony
that represents the combined authorisation of M-of-N signers. In Ladder Script, the
MUSIG_THRESHOLD block (0x0004) validates the aggregate signature against the aggregate
public key using standard Schnorr verification. The threshold ceremony is entirely
off-chain. On-chain, the spend is indistinguishable from a single-sig SIG block.

### AND Logic

The evaluation rule within a single rung. All blocks in a rung must independently
return SATISFIED for the rung to be satisfied. If any block returns UNSATISFIED or
ERROR, the entire rung fails. Defined in `EvalRung()`: the evaluator iterates blocks
sequentially and short-circuits on the first non-SATISFIED result.

### Attestation Mode

An enum (`RungAttestationMode`, `uint8_t`) describing how signatures are provided for
a given rung. Stored in the `RungCoil` structure. Three modes are defined:

- **INLINE (0x01):** Signatures are provided directly in the witness data, one per SIG
  or MULTISIG block. This is the default and most common mode.
- **AGGREGATE (0x02):** Signatures are aggregated at the block level. Multiple
  signature contributions are combined into a single aggregate signature.
- **DEFERRED (0x03):** Attestation is deferred via a template hash. The signature is
  not required at construction time but must be provided before broadcast.

### Block

See **RungBlock**.

### Block Type

See **RungBlockType**.

### Coil

The output terminal of a rung, represented by the `RungCoil` struct. In the PLC (ladder
diagram) analogy, the coil sits at the right end of a rung and determines what action
occurs when the rung is energised (all contacts/blocks are satisfied). Every
`LadderWitness` and `RungConditions` has exactly one coil.

The coil contains:
- `coil_type` (RungCoilType): the unlock semantics
- `attestation` (RungAttestationMode): how signatures are delivered
- `scheme` (RungScheme): default signature algorithm
- `address`: destination scriptPubKey bytes (may be empty)
- `conditions`: coil condition rungs (additional constraints on the output)

### Coil Type

An enum (`RungCoilType`, `uint8_t`) that determines the unlock semantics of a rung:

- **UNLOCK (0x01):** Standard unlock. The output is spent to an address with no
  additional constraints.
- **UNLOCK_TO (0x02):** Unlock to a specific destination. The output must go to the
  address specified in the coil.
- **COVENANT (0x03):** The coil constrains the spending transaction's output structure.
  Used with recursion and CTV blocks to enforce output conditions.

### Condition

A spending requirement embedded in a v4 output's scriptPubKey. Conditions are the
"locking" side of Ladder Script: they specify what must be satisfied to spend the
UTXO. Conditions contain only condition data types (PUBKEY, PUBKEY_COMMIT, HASH256,
HASH160, NUMERIC, SCHEME, SPEND_INDEX) and never contain witness-only types (SIGNATURE,
PREIMAGE). Serialised with the `RUNG_CONDITIONS_PREFIX` (0xc1) byte.

### Contact

In PLC (ladder diagram) notation, a contact is an input element on a rung that must be
closed (satisfied) for current to flow to the coil. In Ladder Script, each block in a
rung acts as a contact. Normally-open contacts pass when their condition is met;
normally-closed contacts (inverted blocks) pass when their condition is NOT met.

### Covenant

An output-constraining condition that restricts how a UTXO can be spent by imposing
requirements on the spending transaction itself (not just on who can sign). Covenant
blocks include CTV (template verification), VAULT_LOCK (two-path vault), AMOUNT_LOCK
(value range), and all recursion blocks (RECURSE_*). Covenants enable programmable
spending policies that persist across multiple transactions.

### Data Type

See **RungDataType**.

### Delta

The additive mutation amount in RECURSE_MODIFIED and RECURSE_DECAY blocks. Specifies
how a targeted NUMERIC field must change between input conditions and output conditions
in a covenant spend. The enforcement rule is:

- RECURSE_MODIFIED: `output_value = input_value + delta`
- RECURSE_DECAY: `output_value = input_value - delta` (deltas are negated internally)

Only NUMERIC fields may be targeted by delta mutations. All other fields must remain
identical between input and output conditions.

### Diff Witness

A witness that inherits its rung and relay structure from another input's witness within the same transaction, providing only field-level diffs and a fresh coil. Triggered when `n_rungs = 0` in the witness deserialisation. The witness-side counterpart to Template Inheritance.

### Energised

A rung or block that evaluates to SATISFIED. In PLC ladder diagram terminology, current
flows through the rung from the left power rail to the right power rail (coil), meaning
all contacts (blocks) are closed (satisfied). An energised rung activates its coil,
which determines the unlock action.

### EvalResult

The evaluation result enum returned by block and rung evaluators. Four values:

- **SATISFIED:** All conditions are met. The block or rung passes.
- **UNSATISFIED:** Conditions are valid but not met. The block or rung fails.
- **ERROR:** The block is malformed (missing required fields, invalid data). This is a
  consensus failure; the transaction is invalid.
- **UNKNOWN_BLOCK_TYPE:** The block type code is not recognised. Treated as UNSATISFIED
  for forward compatibility (allows future soft-fork activation of new block types).
  When inverted, UNKNOWN_BLOCK_TYPE becomes SATISFIED.

### Field

See **RungField**.

### First-Match

The OR evaluation strategy across rungs. The evaluator iterates rungs in order and
returns true as soon as one rung evaluates to SATISFIED. Remaining rungs are not
evaluated. This means the first satisfied rung determines the spend path. Defined in
`EvalLadder()`.

### Inversion

A boolean flag (`block.inverted`) on each RungBlock that flips the evaluation result.
When `inverted` is true:

- SATISFIED becomes UNSATISFIED
- UNSATISFIED becomes SATISFIED
- ERROR remains ERROR (errors never flip)
- UNKNOWN_BLOCK_TYPE becomes SATISFIED

Inversion is applied after the raw evaluation via `ApplyInversion()`. In PLC terms,
an inverted block acts as a normally-closed contact. The inverted flag is taken from
the conditions side (scriptPubKey), not from the witness.

### Ladder

The complete set of rungs that define the spending conditions for one input. A ladder
is represented by the `LadderWitness` struct, which contains a vector of `Rung` objects
and a `RungCoil`. Evaluation applies OR logic across rungs (first-match) and AND logic
within each rung (all blocks must pass).

### LadderSighash

The tagged hash used for Ladder Script signature commitment. Computed as
`TaggedHash("LadderSighash", ...)` following the BIP-340 tagged hash convention. The
sighash commits to:

- Epoch (0)
- Hash type
- Transaction version and locktime
- Prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY)
- Outputs hash (unless SIGHASH_NONE)
- Spend type (always 0 for ladder; no annex or extensions)
- Input-specific data (prevout or index)
- Conditions hash (SHA-256 of serialised rung conditions for `0xC1` outputs, or the
  conditions root directly for `0xC2` MLSC outputs)
- Output for SIGHASH_SINGLE

Similar to BIP-341 sighash but without annex, tapscript, or codeseparator extensions.
Defined in `src/rung/sighash.h`.

### LadderLeaf / LadderInternal

BIP-341-style tagged hash domain tags used in MLSC Merkle tree construction. A tagged
hash is computed as `SHA256(SHA256(tag) || SHA256(tag) || data)`, where the 64-byte
prefix of the doubled tag hash provides domain separation.

- **"LadderLeaf"** — Used for leaf nodes: rung leaves, coil leaf, relay leaves, and the
  empty padding leaf. Pre-computed as `LEAF_HASHER` in `conditions.cpp`.
- **"LadderInternal"** — Used for interior (branch) nodes. Takes `min(A,B) || max(A,B)`
  as data for canonical sorted construction. Pre-computed as `INTERNAL_HASHER`.

The domain separation ensures a valid leaf hash can never be mistaken for a valid interior
hash (and vice versa), preventing second preimage attacks. This follows the same pattern
as BIP-341's `"TapLeaf"` / `"TapBranch"` tags.

### LadderWitness

The witness data for a v4 (RUNG_TX) input. Contains:

- `rungs`: A vector of `Rung` objects, each containing blocks with witness data
  (signatures, preimages)
- `coil`: The output coil (per-output, not per-rung)

For `0xC1` (inline) outputs, the witness is merged with the conditions from the spent
output's scriptPubKey. For `0xC2` (MLSC) outputs, the witness additionally contains the
revealed rung conditions, Merkle proof, and coil data. In both cases, the merge combines
condition fields (locks) with witness fields (keys) into a unified structure that the
evaluator processes.

### Merkle Proof (MLSC)

The set of sibling hashes needed to reconstruct the conditions root from a revealed leaf.
For a tree with M leaves (padded to the next power of 2), the proof contains at most
`ceil(log2(M))` hashes — e.g., 0 hashes for a single-rung condition, 1 hash for 2 rungs,
4 hashes for 16 rungs. Each proof hash is 32 bytes. The verifier reconstructs the root
bottom-up using `TaggedHash("LadderInternal", min(A,B) || max(A,B))` at each level and
checks the result against the UTXO's conditions root.

### MLSC (Merkelised Ladder Script Conditions)

An output format (`0xC2` prefix) that stores only a 32-byte Merkle root instead of full
inline conditions. The complete conditions are revealed at spend time in the witness,
along with a Merkle proof. Key properties:

- **Fixed UTXO size:** 40 bytes per entry (value + root) regardless of script complexity
- **Data embedding resistance:** Fake conditions produce unspendable outputs; since they
  are never spent, the fake data is never published on-chain
- **MAST privacy:** Only the exercised spending path (one rung) is revealed; unused paths
  remain hidden behind opaque proof hashes
- **Tagged hash security:** Leaf nodes use `TaggedHash("LadderLeaf", ...)` and interior
  nodes use `TaggedHash("LadderInternal", ...)` following BIP-341 convention, preventing
  second preimage attacks between tree layers

Specified in `MERKLE-UTXO-SPEC.md`. Implemented in `src/rung/conditions.cpp`.

### Conditions Root

The 32-byte Merkle root stored in an MLSC (`0xC2`) output. Computed as a binary Merkle
tree over tagged leaf hashes of all rungs, relays, and the coil. Uses sorted interior
hashing for canonical construction. The root transitively commits to every field of every
block in every rung — changing any byte in any condition changes the root and invalidates
all signatures. Defined in `ComputeConditionsRoot()` in `src/rung/conditions.cpp`.

### MUSIG_THRESHOLD

A Signature family block type (0x0004) for MuSig2/FROST aggregate threshold signatures.
Conditions contain a PUBKEY_COMMIT (aggregate key hash) and two NUMERIC fields (threshold
M and group size N, for policy/display). The witness contains the aggregate PUBKEY and
aggregate SIGNATURE. On-chain, the spend is indistinguishable from a single-sig SIG
block (~131 bytes regardless of M or N). Schnorr-only; no post-quantum path.

### Latch

A PLC block implementing a bistable (set/reset) state element. Two complementary
blocks form a latch pair:

- **LATCH_SET (0x0621):** Activates when state == 0 (unset). Paired with
  RECURSE_MODIFIED to transition state from 0 to 1.
- **LATCH_RESET (0x0622):** Activates when state >= 1 (set). Paired with
  RECURSE_MODIFIED to transition state from 1 to 0.

Latches enable on-chain toggle switches and enable/disable logic across covenant spend
chains.

### OR Logic

The evaluation rule across rungs in a ladder. Rungs are evaluated in order, and the
first rung that returns SATISFIED causes the entire ladder to pass. If no rung is
satisfied, the ladder evaluation fails. Implemented as first-match semantics in
`EvalLadder()`.

### PLC

Programmable Logic Controller. An analogy from industrial automation that informs the
design vocabulary of Ladder Script. In a physical PLC, a ladder diagram consists of
horizontal rungs between vertical power rails. Each rung contains contacts (input
conditions) that must all close (AND logic) for current to reach the coil (output
action). Multiple rungs provide alternative paths (OR logic).

Ladder Script maps this directly: blocks are contacts, rungs are horizontal paths,
the coil is the output action, and the ladder is the complete program. The PLC family
of block types (0x06xx) implements specific PLC programming patterns: hysteresis bands,
timers, latches, counters, comparators, sequencers, and rate limiters.

### Power Rail

In a PLC ladder diagram, the two vertical lines on either side. The left rail represents
the power supply (input conditions to evaluate). The right rail represents the return
(evaluation complete, coil activated). In Ladder Script, the left rail is the entry
point for block evaluation, and the right rail is reached when all blocks in a rung
are SATISFIED, activating the coil.

### PUBKEY_COMMIT

A 32-byte SHA-256 hash commitment to a full public key, stored as RungDataType 0x02.
When present in a SIG block, the revealed PUBKEY in the witness must hash to this
commitment. This allows conditions to commit to a key without revealing it until spend
time, providing key privacy in the scriptPubKey.

Verification: `SHA256(PUBKEY.data) == PUBKEY_COMMIT.data`.

### Recursion

The family of covenant blocks (0x04xx) that enforce output condition continuity across
spends. When a UTXO with a recursion block is spent, the spending transaction's output
must carry forward the same (or specifically mutated) conditions, creating a chain of
constrained UTXOs. Six recursion blocks are defined:

- RECURSE_SAME: identical re-encumbrance
- RECURSE_MODIFIED: re-encumbrance with specified NUMERIC mutations
- RECURSE_UNTIL: re-encumbrance until a target block height
- RECURSE_COUNT: re-encumbrance with decrementing counter
- RECURSE_SPLIT: UTXO splitting with re-encumbrance
- RECURSE_DECAY: re-encumbrance with negated mutations (progressive relaxation)

### Register

A state value tracked across covenant spends via NUMERIC fields. Not a distinct
on-chain primitive but a conceptual term for the NUMERIC parameters within PLC blocks
that change over time through RECURSE_MODIFIED mutations. Examples include the
`accumulated` field in TIMER_CONTINUOUS, the `state` field in LATCH_SET/LATCH_RESET,
and the `current` field in COUNTER_UP/COUNTER_PRESET.

### Rung

A horizontal evaluation path in a ladder, represented by the `Rung` struct. Contains:

- `blocks`: A vector of `RungBlock` objects, all of which must be SATISFIED (AND logic)
  for the rung to pass.
- `rung_id`: A `uint8_t` identifier within the ladder.

Multiple rungs within a ladder are evaluated with OR logic (first-match). An empty rung
(no blocks) evaluates to ERROR.

### RungBlock

The fundamental evaluation unit within a rung. A typed function block that checks a
single spending condition. Represented by the `RungBlock` struct containing:

- `type`: The block type code (RungBlockType, uint16_t)
- `fields`: A vector of typed fields (RungField) providing parameters and witness data
- `inverted`: Boolean flag that flips SATISFIED and UNSATISFIED results

### RungBlockType

An enum (`uint16_t`) identifying the type of a block. Encoded as 2 bytes (little-endian)
in the wire format. 53 block types are defined across 9 families. The numeric ranges
partition the type space by family:

| Range | Family |
|-------|--------|
| 0x0001-0x00FF | Signature |
| 0x0100-0x01FF | Timelock |
| 0x0200-0x02FF | Hash |
| 0x0300-0x03FF | Covenant |
| 0x0400-0x04FF | Recursion |
| 0x0500-0x05FF | Anchor/L2 |
| 0x0600-0x06FF | PLC |
| 0x0700-0x07FF | Compound |
| 0x0800-0x08FF | Governance |

### RungConditions

The conditions embedded in a v4 output's scriptPubKey. Represented by the
`RungConditions` struct, which mirrors the `LadderWitness` structure but contains only
condition data types (no SIGNATURE or PREIMAGE). Serialised with the
`RUNG_CONDITIONS_PREFIX` (0xc1) byte as the first byte of the scriptPubKey.

Contains:
- `rungs`: Vector of `Rung` objects with condition-only fields
- `coil`: Output coil with attestation mode, scheme, address, and coil conditions

At spend time, conditions are deserialised from the spent output and merged with the
witness from the spending input before evaluation.

### RungDataType

An enum (`uint8_t`) specifying the type of data in a field. Every byte in a Ladder
Script witness belongs to one of these types; no arbitrary data pushes are possible.
Nine types are defined:

| Code | Name | Size Range | Description |
|------|------|------------|-------------|
| 0x01 | PUBKEY | 1-2048 B | Public key |
| 0x02 | PUBKEY_COMMIT | 32 B | Public key commitment |
| 0x03 | HASH256 | 32 B | SHA-256 hash |
| 0x04 | HASH160 | 20 B | HASH160 digest |
| 0x05 | PREIMAGE | 1-252 B | Hash preimage (witness only) |
| 0x06 | SIGNATURE | 1-50000 B | Signature (witness only) |
| 0x07 | SPEND_INDEX | 4 B | Spend index reference |
| 0x08 | NUMERIC | 1-4 B | Numeric value (little-endian) |
| 0x09 | SCHEME | 1 B | Signature scheme selector |

Formerly named `RungFieldType` in v1; the alias is retained for backward compatibility.

### RungField

A single typed data element within a block. Represented by the `RungField` struct:

- `type`: The data type (RungDataType)
- `data`: The raw byte vector

Fields are validated against the size constraints of their data type via
`FieldMinSize()` and `FieldMaxSize()`. Validation is performed by `RungField::IsValid()`.

### RUNG_TX

Transaction version 4, which signals that the transaction uses Ladder Script for input
validation instead of traditional Bitcoin Script. When a node encounters a v4
transaction, inputs are validated through the rung evaluator (`VerifyRungTx()`) rather
than the script interpreter.

### Scheme

The signature algorithm used for verification, represented by the `RungScheme` enum
(`uint8_t`). Six schemes are defined:

| Code | Name | Type |
|------|------|------|
| 0x01 | SCHNORR | Classical (BIP-340) |
| 0x02 | ECDSA | Classical (legacy) |
| 0x10 | FALCON512 | Post-quantum |
| 0x11 | FALCON1024 | Post-quantum |
| 0x12 | DILITHIUM3 | Post-quantum |
| 0x13 | SPHINCS_SHA | Post-quantum |

Classical schemes (codes < 0x10) are verified via the standard signature checker. Post-
quantum schemes (codes >= 0x10) are routed through `VerifyPQSignature()`. The scheme
may be specified explicitly via a SCHEME field in a SIG or MULTISIG block, or inferred
from signature size (64-65 bytes = Schnorr, 8-72 bytes = ECDSA).

### Sighash

The hash value that a signature commits to, derived from the transaction and spending
context. For Ladder Script, the sighash is computed by `SignatureHashLadder()` using
the `TaggedHash("LadderSighash")` construction. See **LadderSighash** for the full
commitment structure. Sighash types follow Bitcoin convention: SIGHASH_DEFAULT (0x00),
SIGHASH_ALL (0x01), SIGHASH_NONE (0x02), SIGHASH_SINGLE (0x03), with the
SIGHASH_ANYONECANPAY modifier (0x80).

### Spent

A rung that has been executed on-chain. Its conditions were satisfied in a confirmed
transaction. In the context of recursion blocks, "spent" refers to the input side of a
covenant chain: the input UTXO's conditions were satisfied, and the output UTXO
carries forward the (possibly mutated) conditions for the next spend.

### Wire Format

The serialised byte representation of Ladder Script structures. The wire format is used
for both scriptPubKey conditions (prefixed with 0xc1) and witness data. Key properties:

- Block types: 2 bytes, little-endian (uint16_t)
- Data types: 1 byte (uint8_t)
- Field data: length-prefixed (varint length followed by raw bytes)
- All data must belong to a known RungDataType; no arbitrary pushes
- Conditions and witness share the same serialisation format but differ in which data
  types are permitted

Serialization is handled by `src/rung/serialize.cpp`. Deserialisation validates field
sizes against type constraints and rejects unknown types.

### Witness Reference

The compact wire encoding for a diff witness: a source input index, a list of field-level diffs, and a fresh coil. Resolves at evaluation time by copying the source witness and applying diffs.
