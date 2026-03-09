# Ladder Script -- Frequently Asked Questions

---

## General

### 1. What is Ladder Script?

Ladder Script is a typed, structured transaction condition system for Bitcoin.
It replaces Bitcoin Script's stack-based opcode interpreter with a declarative
model where spending conditions are expressed as typed blocks organized into
rungs -- borrowing the visual and logical structure of Programmable Logic
Controller (PLC) ladder diagrams used in industrial automation.

Each output's scriptPubKey contains serialized *conditions* (the locking side),
and each input's witness contains serialized *attestations* (the unlocking side).
Both use the same wire format: rungs containing blocks containing typed fields.

### 2. Why not just use Bitcoin Script?

Bitcoin Script is a 15-year-old stack machine with known limitations:

- **No type safety.** Every value is an opaque byte vector. A pubkey and a hash
  preimage are indistinguishable at the script level.
- **Arbitrary data embedding.** OP_RETURN and witness pushes allow storing
  arbitrary data on-chain with no semantic constraint.
- **Limited composability.** Complex conditions require carefully sequenced
  stack operations that are difficult to analyze, audit, and compose.
- **No native covenant support.** Introspecting the spending transaction
  requires proposed (and contentious) new opcodes.

Ladder Script addresses all four by making every byte in a transaction
semantically typed, structurally bounded, and machine-verifiable.

### 3. What is the PLC analogy?

In industrial automation, a Programmable Logic Controller (PLC) runs a
continuous scan cycle over a *ladder diagram* -- a set of horizontal rungs
connecting a left power rail to a right power rail. Each rung contains
*contacts* (input conditions) in series, and terminates at a *coil* (output
action). Power flows left to right: if all contacts in a rung are closed,
the coil energizes.

Ladder Script maps this directly:

| PLC Concept | Ladder Script Equivalent |
|-------------|--------------------------|
| Rung | Rung (vector of blocks) |
| Contact | Block (SIG, CSV, HASH_PREIMAGE, etc.) |
| Coil | Coil (UNLOCK, UNLOCK_TO, COVENANT) |
| Power rail | Evaluation engine |
| Scan cycle | Transaction validation |
| AND logic | All blocks in a rung must be SATISFIED |
| OR logic | First satisfied rung wins |

### 4. Is this a hard fork or soft fork?

Ladder Script is designed as a soft fork. It uses transaction version 4 (v4)
and a new scriptPubKey prefix byte (`0xc1`) that does not conflict with any
existing opcode or witness version. Nodes that do not understand v4 transactions
treat them as anyone-can-spend under the soft fork activation rules, while
upgraded nodes enforce the full condition evaluation.

### 5. What transaction version does Ladder Script use?

Transaction version 4 (nVersion = 4). This version is currently unused in
Bitcoin consensus and is designated for RUNG_TX transactions. The version
number signals to upgraded nodes that the transaction should be validated
using the Ladder Script evaluator rather than the Bitcoin Script interpreter.

---

## Technical

### 6. How are conditions evaluated?

Evaluation follows two rules:

- **AND within a rung.** Every block in a rung must return SATISFIED for the
  rung to pass. If any block returns UNSATISFIED or ERROR, the entire rung fails.
- **OR across rungs.** Rungs are evaluated in order (R000, R001, ...). The first
  rung that passes wins, and the remaining rungs are not evaluated.

This two-level logic is equivalent to a disjunctive normal form (DNF):
`(A1 AND A2 AND A3) OR (B1 AND B2) OR (C1)`.

### 7. What is the inversion flag?

Every block has a boolean `inverted` field. When set to `true`, the evaluation
result is flipped: SATISFIED becomes UNSATISFIED, and UNSATISFIED becomes
SATISFIED. ERROR is never inverted (it always propagates as a consensus failure).

This allows constructing ceiling guards without dedicated block types. For
example, `COMPARE(GT, 1000000, inverted=true)` means "NOT (amount > 1,000,000)"
which is equivalent to "amount <= 1,000,000".

### 8. How does the sighash work?

Ladder Script uses a tagged hash: `TaggedHash("LadderSighash")`. The sighash
commits to:

- Epoch (currently 0)
- Hash type (SIGHASH_DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY)
- Transaction version and locktime
- Prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY)
- Outputs hash (unless SIGHASH_NONE)
- Spend type (always 0 -- no annex or extensions)
- Input-specific data (prevout or index)
- **Conditions hash**: SHA-256 of the serialized rung conditions from the spent
  output's scriptPubKey

The conditions hash is the key difference from BIP-341 Taproot sighash. It binds
the signature to the exact set of conditions being satisfied, preventing
condition substitution attacks.

### 9. What is the 0xc1 prefix?

The byte `0xc1` (hex) is the RUNG_CONDITIONS_PREFIX. It is the first byte of
every v4 output scriptPubKey that contains Ladder Script conditions. The
evaluator uses this prefix to quickly identify rung-encumbered outputs without
parsing the full script.

The value `0xc1` was chosen because it does not collide with any existing OP_
opcode prefix, witness version, or Taproot annex byte.

### 10. What are the size limits?

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Max rungs per ladder | 16 | Policy |
| Max blocks per rung | 8 | Policy |
| Max fields per block | 16 | Deserialization |
| Max ladder witness size | 10,000 bytes | Deserialization |
| Max PUBKEY size | 2,048 bytes | Field validation |
| Max SIGNATURE size | 5,000 bytes | Field validation |
| Max PREIMAGE size | 252 bytes | Field validation |
| HASH256 size | Exactly 32 bytes | Field validation |
| HASH160 size | Exactly 20 bytes | Field validation |
| NUMERIC size | 1-4 bytes | Field validation |
| SCHEME size | Exactly 1 byte | Field validation |
| PUBKEY_COMMIT size | Exactly 32 bytes | Field validation |
| SPEND_INDEX size | Exactly 4 bytes | Field validation |

### 11. How do coil types work?

Each output has a coil that determines what happens when a rung is satisfied:

- **UNLOCK** (0x01): Standard spend. The output is consumed and the value
  goes to the spending transaction's outputs without further constraint.
- **UNLOCK_TO** (0x02): Directed unlock. The output is sent to a specific
  destination address encoded in the coil.
- **COVENANT** (0x03): The spending transaction's outputs must satisfy
  additional conditions encoded in the coil. Used with recursion blocks.

### 12. What is the difference between conditions and witness?

**Conditions** are the locking side -- stored in the output's scriptPubKey
(prefixed with `0xc1`). They contain only *condition data types*: PUBKEY,
PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME, SPEND_INDEX. Witness-only
types (SIGNATURE, PREIMAGE) are forbidden in conditions.

The **witness** is the unlocking side -- stored in the transaction input's
witness field. It contains the attestations: signatures, preimages, and other
proof data needed to satisfy the conditions.

Both sides use the same serialization format (rungs, blocks, fields), but the
conditions side is strictly a subset -- it defines what must be proven, not the
proofs themselves.

### What is a diff witness and when should I use one?

A diff witness allows one input's witness to inherit its structure from another input in the same transaction. Instead of serializing a full witness for every input, you provide only the fields that differ (typically just signatures, since each input has a unique sighash). Use diff witnesses when a transaction spends multiple UTXOs with identical or similar conditions using the same keys — batch consolidation, covenant chain spends, and MULTISIG batches all benefit. The wire savings scale with witness complexity: a simple SIG witness saves ~28%, while a 3-of-5 MULTISIG witness saves ~60% per inherited input.

### Can diff witnesses be chained?

No. A diff witness can only reference a full (non-diff) witness. The source input must have a standard witness with `n_rungs > 0`. This prevents circular dependencies and keeps resolution to a single level of indirection. If you need three identical inputs, inputs 1 and 2 can both reference input 0, but input 2 cannot reference input 1 if input 1 is itself a diff witness.

---

## Covenants

### 13. How does RECURSE_SAME work?

`RECURSE_SAME` (0x0401) enforces that one of the spending transaction's outputs
has a scriptPubKey byte-identical to the input's scriptPubKey. This creates a
perpetual covenant: the UTXO re-encumbers itself with the exact same conditions
on every spend.

The block takes one NUMERIC field: `max_depth`. Each spend decrements the depth.
When depth reaches 0, the covenant expires and the block returns SATISFIED
without enforcing output structure, allowing free spending.

### 14. How does RECURSE_MODIFIED enforce mutations?

`RECURSE_MODIFIED` (0x0402) allows a covenant to re-encumber with controlled
mutations. The block specifies:

- **Target rung index**: which rung in the conditions to mutate
- **Target block index**: which block within that rung
- **Target parameter index**: which field within that block
- **Delta**: the exact signed change to apply

The evaluator verifies that the spending transaction's output conditions are
identical to the input conditions except for the specified field, which must
differ by exactly the specified delta. Multiple mutations can be specified in
a single block using the multi-mutation format.

### 15. Can covenants be infinite?

No. Every recursion block type includes a `max_depth` field (NUMERIC) that
limits the total number of recursive spends. This prevents unbounded covenant
chains that could create perpetual UTXO set obligations.

- `RECURSE_SAME`: depth decrements each spend; covenant expires at 0.
- `RECURSE_COUNT`: count decrements each spend; covenant expires at 0.
- `RECURSE_UNTIL`: covenant expires when block height reaches the target.
- `RECURSE_DECAY`: parameters decay toward zero; covenant expires when all
  decayed parameters reach their floor.

### 16. What is RECURSE_DECAY?

`RECURSE_DECAY` (0x0406) is a recursion block where specified parameters
decrease by a fixed amount on each spend. Unlike RECURSE_MODIFIED (which
applies an exact delta), RECURSE_DECAY is designed for constraints that
gradually relax over time.

Example: a COMPARE threshold that starts at 500,000 sats and decays by 50,000
per spend. After 10 spends, the threshold has relaxed to 0, effectively removing
the constraint. Multiple parameters can decay at different rates using the
multi-mutation format.

---

## Post-Quantum

### 17. Which PQ algorithms are supported?

Ladder Script supports three post-quantum signature schemes, identified by the
SCHEME data type:

| Scheme | Byte | Public Key Size | Signature Size |
|--------|------|-----------------|----------------|
| FALCON-512 | 0x10 | 897 bytes | ~690 bytes |
| FALCON-1024 | 0x11 | 1,793 bytes | ~1,330 bytes |
| Dilithium3 | 0x12 | 1,952 bytes | 3,293 bytes |

Classical schemes are also supported: Schnorr (0x01) and ECDSA (0x02).

### 18. What is PUBKEY_COMMIT?

PUBKEY_COMMIT (data type 0x02) is a 32-byte SHA-256 commitment to a public key.
Instead of storing the full PQ public key (e.g., 897 bytes for FALCON-512) in
the UTXO set, only the 32-byte hash is stored. The full public key is revealed
only at spend time in the witness.

The evaluator verifies the commitment by computing `SHA256(witness_pubkey)` and
comparing it to the PUBKEY_COMMIT value in the conditions. If they match,
signature verification proceeds using the full key from the witness.

UTXO savings for FALCON-512: 897 bytes reduced to 32 bytes (96% reduction).

### 19. What is the COSIGN anchor pattern?

The COSIGN anchor pattern provides post-quantum protection for multiple UTXOs
using a single perpetual PQ anchor:

1. **Anchor UTXO**: `SIG(FALCON512) + PUBKEY_COMMIT(hash) + RECURSE_SAME(depth=1000)`
   The anchor carries the PQ key commitment and re-encumbers itself on every spend.

2. **Child UTXOs**: `SIG(Schnorr) + COSIGN(SHA256(anchor_scriptPubKey))`
   Children use lightweight Schnorr signatures but cannot be spent unless the
   anchor is present as a co-input in the same transaction.

3. **Co-spend transaction**: Both anchor and child(ren) are inputs. The anchor
   provides the PQ signature; children provide Schnorr signatures. The COSIGN
   evaluator on each child scans all other inputs for a matching anchor.

The anchor's scriptPubKey hash never changes (RECURSE_SAME), so children created
at any future time can reference the same anchor hash.

### 20. How much space does PUBKEY_COMMIT save?

| Key Type | Full Key | With PUBKEY_COMMIT | Savings |
|----------|----------|-------------------|---------|
| FALCON-512 | 897 bytes | 32 bytes | 865 bytes (96%) |
| FALCON-1024 | 1,793 bytes | 32 bytes | 1,761 bytes (98%) |
| Dilithium3 | 1,952 bytes | 32 bytes | 1,920 bytes (98%) |

The savings apply per UTXO in the UTXO set. The full key must still be provided
in the witness at spend time, but witness data is prunable and does not
permanently burden the UTXO set.

---

## PLC Blocks

### 21. What are PLC blocks?

PLC (Programmable Logic Controller) blocks are block types in the 0x06xx range
that implement stateful industrial automation primitives: timers, counters,
latches, comparators, sequencers, and hysteresis bands. They carry state in
their NUMERIC fields and update that state across covenant spends.

PLC blocks enable complex, multi-step smart contracts without requiring an
external state machine. The UTXO itself is the state register, and each spend
is one scan cycle of the PLC program.

### 22. How do counters work across covenant spends?

Counter blocks (COUNTER_DOWN, COUNTER_UP, COUNTER_PRESET) store their current
count in a NUMERIC field. When combined with a recursion block (RECURSE_MODIFIED
or RECURSE_SAME), the counter state persists across spends:

- **COUNTER_DOWN** (0x0631): Starts at a count value. Returns SATISFIED while
  count > 0, allowing the rung to fire. At count == 0, returns UNSATISFIED.
  Used with RECURSE_MODIFIED to decrement on each spend.

- **COUNTER_UP** (0x0633): Starts at 0 and increments toward a target. Returns
  SATISFIED while current < target. At current >= target, returns UNSATISFIED.

- **COUNTER_PRESET** (0x0632): Like COUNTER_UP but with a preset threshold.
  Returns SATISFIED while current < preset; UNSATISFIED when the preset is
  reached or exceeded.

### 23. What is a latch?

LATCH_SET (0x0621) and LATCH_RESET (0x0622) implement bistable state elements.
A latch has a state field (NUMERIC): 0 = unset, nonzero = set.

- **LATCH_SET**: Returns SATISFIED when state == 0 (the latch can fire). Once
  the rung executes, the latch is considered "set" and a RECURSE_MODIFIED block
  would update its state to 1, preventing re-firing until reset.

- **LATCH_RESET**: Returns SATISFIED when state != 0. Resets the latch to 0.

Latches are used for one-time authorization, state machine gating, and
preventing double-execution of covenant logic.

### 24. What is HYSTERESIS_FEE for?

HYSTERESIS_FEE (0x0601) is a fee-rate band gate. It computes the spending
transaction's actual fee rate (in sat/vB) from `(sum_inputs - sum_outputs) / vsize`
and checks that it falls within a specified band `[low_sat_vb, high_sat_vb]`.

Use cases:

- **Prevent panic-spending** during fee spikes (reject transactions with
  fee rate > ceiling).
- **Prevent low-fee transactions** that might be vulnerable to replacement
  or fail to confirm (reject transactions with fee rate < floor).
- **Treasury governance**: ensure organizational funds are only spent during
  normal fee conditions.

---

## Security

### 25. Can arbitrary data be stored in Ladder Script?

No. Ladder Script's typed field system makes arbitrary data embedding
impractical. Every byte in a rung transaction must conform to a known data type
with strict size limits and semantic validation:

1. **RPC layer**: Unknown data types are rejected. Witness-only types (SIGNATURE,
   PREIMAGE) are blocked from conditions. Field sizes are validated against
   type-specific min/max bounds.
2. **Serialization**: Structure limits (max rungs, blocks, fields) are enforced
   during deserialization.
3. **Policy**: Output validation rejects oversized structures before mempool
   admission.
4. **Consensus**: Semantic validation at spend time rejects garbage operators,
   wrong preimages, and mismatched keys.
5. **Economic**: Even if structurally valid data gets into a UTXO (e.g., a
   PUBKEY field with non-key bytes), the funds are burned because no valid
   signature can be produced for a nonsense key. The attacker pays for storage
   they can never recover.

### 26. What happens with unknown block types?

Unknown block types return `UNKNOWN_BLOCK_TYPE` from `EvalBlock`, which is
treated as UNSATISFIED. This is a fail-closed design: if a node encounters a
block type it does not recognize, it cannot satisfy it, and the rung fails.

For forward compatibility with soft fork upgrades: a new block type can be
added in a future activation. Pre-upgrade nodes will treat the unknown type
as unsatisfied (making the output appear unspendable to them), while
post-upgrade nodes will evaluate it normally.

When the inversion flag is applied to an unknown block type, the result is
inverted from UNSATISFIED to SATISFIED, which allows opt-in forward
compatibility patterns.

### 27. How does fail-closed work?

Ladder Script follows the fail-closed principle throughout:

- Unknown block types: UNSATISFIED (not silently accepted).
- Unknown data types: rejected at deserialization (not passed through).
- Missing fields: ERROR (consensus failure, not silent acceptance).
- Deferred attestation: unconditionally returns false (`VerifyDeferredAttestation`
  is not yet supported and does not silently pass).
- Out-of-range field sizes: rejected at deserialization.

No ambiguous input can result in a transaction being accepted. Every path
through the evaluator either explicitly validates or explicitly rejects.

---

## Tooling

### 28. What is the Ladder Engine?

The Ladder Engine is a single-page React application for building, simulating,
and inspecting Ladder Script transactions. It is located at
`tools/ladder-engine/index.html` in the repository.

Features include:

- **Build Mode**: Drag blocks from a palette onto rungs, configure fields via
  a properties panel, define inputs/outputs, and generate `createrungtx` JSON.
- **Simulate Mode**: Step through rung evaluation visually. Power flows left
  to right through blocks. Click contacts to authorize them. Alt+click to
  force-toggle blocks. Coils fire when all contacts pass.
- **Watch Mode**: Mock UTXO monitoring with auto-incrementing block height
  and countdown timers for timelock blocks.
- **Examples Library**: 18 pre-built examples covering all major patterns.
- **Import/Export**: Load and save `createrungtx` JSON.

### 29. What RPCs are available?

| RPC | Purpose |
|-----|---------|
| `createrungtx` | Create a v4 RUNG_TX transaction from JSON conditions |
| `signrungtx` | Sign a v4 transaction (Schnorr, ECDSA, or PQ) |
| `decoderungtx` | Decode and display a v4 transaction's conditions and witness |
| `generatepqkeypair` | Generate a post-quantum keypair (FALCON512, etc.) |
| `pqpubkeycommit` | Compute SHA-256 commitment for a PQ public key |
| `extractadaptorsecret` | Extract adaptor secret from adapted/pre-signatures |
| `verifyadaptorpresig` | Verify an adaptor pre-signature |

### 30. How do I create a v4 transaction?

1. **Define conditions** as JSON with inputs, outputs, and per-output condition
   arrays. Each condition is a rung; each rung contains blocks; each block
   contains typed fields.

2. **Submit via RPC**: `ghost-cli createrungtx '<json>'`
   The node serializes the conditions, sets the scriptPubKey prefix to `0xc1`,
   and returns a hex-encoded raw transaction.

3. **Sign via RPC**: `ghost-cli signrungtx '<hex>' '<options>'`
   The node computes the LadderSighash and produces the appropriate signature
   type (Schnorr by default, or PQ if specified).

4. **Broadcast**: `ghost-cli sendrawtransaction '<signed_hex>'`

The Ladder Engine tool automates steps 1-2 by generating the `createrungtx`
JSON visually and displaying the resulting transaction structure.
