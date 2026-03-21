# Ladder Script: Frequently Asked Questions

---

## General

### 1. What is Ladder Script?

Ladder Script is a typed, structured transaction condition system for Bitcoin.
Spending conditions are expressed as typed blocks organised into rungs, borrowing
the visual and logical structure of Programmable Logic Controller (PLC) ladder
diagrams used in industrial automation.

Each output's scriptPubKey contains serialised *conditions* (the locking side),
and each input's witness contains serialised *attestations* (the unlocking side).
Both use the same wire format: rungs containing blocks containing typed fields.

### 2. What problems does Ladder Script solve?

Three:

- **Programmability.** 61 block types (59 active, 2 deprecated) across 10 families —signatures, timelocks,
  hash locks, covenants, recursion, PLC state machines, governance constraints,
  and more —that compose freely within rungs and ladders. Any combination of
  AND/OR spending logic, built declaratively.
- **Quantum hardening.** Four post-quantum signature schemes (FALCON-512,
  FALCON-1024, Dilithium3, SPHINCS+) are implemented, tested, and running on a
  live signet. Any block that takes a signature —SIG, MULTISIG, HTLC, vaults,
  covenants —can use PQ keys with zero structural changes.
- **Data abuse resistance.** Every byte in a transaction belongs to a declared
  data type with enforced size constraints. On the conditions side, the node
  computes all key and hash commitments —no arbitrary data enters the UTXO set.
  On the witness side, PUBKEY and SIGNATURE are cryptographically constrained,
  PREIMAGE and SCRIPT_BODY are capped (32 and 80 bytes) with a combined limit
  of 2 per witness, and data-embedding types are rejected in witness context for
  blocks without implicit witness layouts. Maximum embeddable data: ~40 bytes.

### 3. What is the PLC analogy?

In industrial automation, a Programmable Logic Controller (PLC) runs a
continuous scan cycle over a *ladder diagram*: a set of horizontal rungs
connecting a left power rail to a right power rail. Each rung contains
*contacts* (input conditions) in series, and terminates at a *coil* (output
action). Power flows left to right: if all contacts in a rung are closed,
the coil energises.

Ladder Script maps this directly:

| PLC Concept | Ladder Script Equivalent |
|-------------|--------------------------|
| Rung | Rung (vector of blocks) |
| Contact | Block (SIG, CSV, TAGGED_HASH, etc.) |
| Coil | Coil (UNLOCK, UNLOCK_TO, COVENANT) |
| Power rail | Evaluation engine |
| Scan cycle | Transaction validation |
| AND logic | All blocks in a rung must be SATISFIED |
| OR logic | First satisfied rung wins |

### 4. Is this a hard fork or soft fork?

Soft fork. Ladder Script uses transaction version 4 (v4) and the `0xC2`
scriptPubKey prefix byte for Merkelised conditions (MLSC). MLSC is the only
output format. Non-upgraded nodes treat v4 transactions as anyone-can-spend
under the standard soft fork activation rules. Upgraded nodes enforce the full
condition evaluation.

### 5. What transaction version does Ladder Script use?

Transaction version 4 (nVersion = 4). This version is currently unused in
Bitcoin consensus and is designated for RUNG_TX transactions. The version
number signals to upgraded nodes that the transaction should be validated
using the Ladder Script evaluator rather than the script interpreter.

---

## Technical

### 6. How are conditions evaluated?

Evaluation follows two rules:

- **AND within a rung.** Every block in a rung must return SATISFIED for the
  rung to pass. If any block returns UNSATISFIED or ERROR, the entire rung fails.
  The evaluator short-circuits on the first non-SATISFIED result.
- **OR across rungs.** Rungs are evaluated in order. The first rung that passes
  wins, and the remaining rungs are not evaluated.

This two-level logic is equivalent to a disjunctive normal form (DNF):
`(A1 AND A2 AND A3) OR (B1 AND B2) OR (C1)`.

### 7. What is the inversion flag?

Non-key-consuming blocks have a boolean `inverted` field. When set to `true`,
the evaluation result is flipped: SATISFIED becomes UNSATISFIED, and UNSATISFIED
becomes SATISFIED. ERROR is never inverted (it always propagates as a consensus
failure).

**Selective inversion:** Key-consuming blocks (SIG, MULTISIG, ADAPTOR_SIG,
MUSIG_THRESHOLD, KEY_REF_SIG, COSIGN, and all compound/legacy SIG types)
cannot be inverted. This is enforced at deserialization via
`IsInvertibleBlockType()`, a fail-closed allowlist. This prevents an attacker
from using a garbage pubkey with an inverted SIG block to embed arbitrary data.

This allows constructing ceiling guards without dedicated block types. For
example, `COMPARE(GT, 1000000, inverted=true)` means "NOT (amount > 1,000,000)"
which is equivalent to "amount <= 1,000,000".

### 8. How does the sighash work?

Ladder Script uses a tagged hash: `TaggedHash("LadderSighash")`. The sighash
commits to:

- Epoch (currently 0)
- Hash type (SIGHASH_DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY, ANYPREVOUT, ANYPREVOUTANYSCRIPT)
- Transaction version and locktime
- Prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY; prevouts skipped if ANYPREVOUT)
- Outputs hash (unless SIGHASH_NONE)
- Spend type (always 0; no annex or extensions)
- Input-specific data (prevout or index)
- **Conditions hash**: the conditions root directly from the `0xC2` MLSC output.
  Skipped if ANYPREVOUTANYSCRIPT.

The conditions hash binds the signature to the exact set of conditions being
satisfied, preventing condition substitution attacks. ANYPREVOUT (0x40) skips
prevouts commitment, enabling LN-Symmetry/eltoo. ANYPREVOUTANYSCRIPT (0xC0)
skips both prevouts and conditions commitments for fully rebindable signatures.

### 9. What is the output format?

Ladder Script uses a single output format:

- **`0xC2` (MLSC: Merkelised Ladder Script Conditions).** A 32-byte
  Merkle root follows the prefix byte (33 bytes standard, or 34-73 bytes
  with a DATA_RETURN payload appended). The actual conditions are revealed
  at spend time via a Merkle proof in the witness. This provides MAST-style
  privacy and keeps the UTXO set compact.

The `0xC2` prefix byte was chosen to avoid collision with any existing OP_
opcode, witness version, or Taproot annex byte. Inline conditions (`0xC1`)
have been removed; MLSC is the only output format.

### 10. What are the size limits?

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Max rungs per ladder | 16 | Consensus |
| Max blocks per rung | 8 | Consensus |
| Max fields per block | 16 | Deserialisation |
| Max ladder witness size | 100,000 bytes | Deserialisation |
| Max PUBKEY size | 2,048 bytes | Field validation |
| Max SIGNATURE size | 50,000 bytes | Field validation |
| Max PREIMAGE size | 32 bytes | Field validation |
| Max SCRIPT_BODY size | 80 bytes | Field validation |
| HASH256 size | Exactly 32 bytes | Field validation |
| HASH160 size | Exactly 20 bytes | Field validation |
| NUMERIC size | 1-4 bytes | Field validation |
| SCHEME size | Exactly 1 byte | Field validation |
| DATA size | 1-40 bytes | Field validation |

### 11. How do coil types work?

Each output has a coil that determines what happens when a rung is satisfied:

- **UNLOCK** (0x01): Standard spend. The output is consumed and the value
  goes to the spending transaction's outputs without further constraint.
- **UNLOCK_TO** (0x02): Directed unlock. The output must go to a specific
  destination address encoded in the coil.
- **COVENANT** (0x03): The spending transaction's outputs must satisfy
  additional conditions encoded in the coil. Used with recursion blocks.

### 12. What is the difference between conditions and witness?

**Conditions** are the locking side. For `0xC2` (MLSC) outputs, only a 32-byte
Merkle root is in the scriptPubKey; the actual conditions are revealed at spend
time via a Merkle proof. Conditions contain only *condition data types*:
HASH256, HASH160, NUMERIC, SCHEME, DATA. Witness-only types (PUBKEY, PREIMAGE,
SIGNATURE, SCRIPT_BODY) are forbidden in conditions. Public keys are not stored
in conditions at all —they are folded into the Merkle leaf hash (merkle_pub_key).

The **witness** is the unlocking side, stored in the transaction input's
witness field. It contains the attestations: signatures, preimages, and other
proof data needed to satisfy the conditions. For MLSC outputs, the witness
also includes the revealed conditions and their Merkle proof.

Both sides use the same serialisation format (rungs, blocks, fields), but the
conditions side is strictly a subset: it defines what must be proven, not the
proofs themselves.

### 12a. What is a diff witness and when should I use one?

A diff witness allows one input's witness to inherit its structure from another
input in the same transaction. Instead of serialising a full witness for every
input, you provide only the fields that differ (typically just signatures,
since each input has a unique sighash). Use diff witnesses when a transaction
spends multiple UTXOs with identical or similar conditions —batch
consolidation, covenant chain spends, and MULTISIG batches all benefit.

### 12b. Can diff witnesses be chained?

No. A diff witness can only reference a full (non-diff) witness. The source
input must have a standard witness with `n_rungs > 0`. This prevents circular
dependencies and keeps resolution to a single level of indirection. If you
need three identical inputs, inputs 1 and 2 can both reference input 0, but
input 2 cannot reference input 1 if input 1 is itself a diff witness.

### 12c. What are relays?

Relays are shared sub-condition blocks that are evaluated once and referenced
by multiple rungs via `relay_refs`. A relay contains blocks (like a rung) but
has no coil —it produces a boolean result that any rung can consume.

Relays are evaluated before any rungs. If a relay returns UNSATISFIED, every
rung that references it fails without evaluating its own blocks. This enables
AND composition across rungs without duplicating blocks, and in MLSC trees,
only the relays referenced by the exercised rung are revealed.

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

No. Every recursion block type includes a termination mechanism that limits the
total number of recursive spends. This prevents unbounded covenant chains that
could create perpetual UTXO set obligations.

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

### 16a. Why are covenants built in rather than requiring new opcodes?

Covenant semantics are encoded as block types with typed fields. RECURSE_SAME,
RECURSE_MODIFIED, CTV, VAULT_LOCK —each is a single block with explicit
parameters. The evaluator knows exactly what each block constrains. There is no
need to propose new opcodes, debate script semantics, or worry about
interactions with existing stack operations. A new covenant pattern is a new
block type with a defined evaluation function —not a new language primitive
that could conflict with existing ones.

---

## Post-Quantum

### 17. Which PQ algorithms are supported?

Four post-quantum signature schemes, all implemented and running on the live
signet:

| Scheme | Byte | Public Key Size | Signature Size |
|--------|------|-----------------|----------------|
| FALCON-512 | 0x10 | 897 bytes | ~690 bytes |
| FALCON-1024 | 0x11 | 1,793 bytes | ~1,330 bytes |
| Dilithium3 | 0x12 | 1,952 bytes | 3,293 bytes |
| SPHINCS+ | 0x13 | 32 bytes | ~7,856 bytes |

Classical schemes are also supported: Schnorr (0x01) and ECDSA (0x02).

### 18. What is merkle_pub_key and why does it matter?

merkle_pub_key is the scheme by which public keys are bound to conditions without
appearing in them. Instead of storing a key commitment field in the conditions,
the node folds all public keys consumed by a rung into the Merkle leaf hash:

```
leaf = TaggedHash("LadderLeaf", SerializeRung(rung) || pk1 || pk2 || ... || pkN)
```

Keys are appended in block order (left to right), with the count determined by
`PubkeyCountForBlock()` for each block type. The result is a single 32-byte leaf
with no writable surface —an attacker constructing a raw transaction has nowhere
to embed arbitrary data, because there is no key commitment field in the conditions
at all.

At spend time, the witness provides the public keys. The verifier recomputes the
leaf from the revealed conditions plus the witness keys. If the leaf does not match
the committed Merkle root, verification fails before signature checking begins.

For PQ keys, this also provides massive UTXO savings: a 1,952-byte Dilithium3 key
contributes only to the 32-byte Merkle leaf. The full key is revealed only at
spend time in the witness, which is prunable.

### 19. What is the COSIGN anchor pattern?

The COSIGN anchor pattern provides post-quantum protection for multiple UTXOs
using a single perpetual PQ anchor:

1. **Anchor UTXO**: `SIG(FALCON512) + RECURSE_SAME(depth=1000)`
   The anchor carries the PQ key (bound via merkle_pub_key) and re-encumbers itself on every spend.

2. **Child UTXOs**: `SIG(Schnorr) + COSIGN(SHA256(anchor_scriptPubKey))`
   Children use lightweight Schnorr signatures but cannot be spent unless the
   anchor is present as a co-input in the same transaction.

3. **Co-spend transaction**: Both anchor and child(ren) are inputs. The anchor
   provides the PQ signature; children provide Schnorr signatures. The COSIGN
   evaluator scans all other inputs for a matching scriptPubKey hash.

The anchor's scriptPubKey hash never changes (RECURSE_SAME), so children created
at any future time can reference the same anchor hash.

### 20. How much UTXO space does merkle_pub_key save?

| Key Type | Full Key | In UTXO (merkle_pub_key) | Savings |
|----------|----------|--------------------------|---------|
| FALCON-512 | 897 bytes | 0 bytes (folded into leaf) | 897 bytes (100%) |
| FALCON-1024 | 1,793 bytes | 0 bytes (folded into leaf) | 1,793 bytes (100%) |
| Dilithium3 | 1,952 bytes | 0 bytes (folded into leaf) | 1,952 bytes (100%) |

With merkle_pub_key, no public key data appears in the UTXO set at all. Keys are
folded into the 32-byte Merkle leaf hash. The full key is provided only at spend
time in the prunable witness.

### 20a. Can I migrate an existing Schnorr key to PQ without moving funds?

Not directly —the UTXO's conditions are fixed at creation. But the COSIGN
pattern (Q19) lets you add PQ protection to any existing spending pattern by
creating a PQ anchor and requiring it as a co-input. Your Schnorr UTXOs keep
their existing conditions; the PQ requirement is additive.

### 20b. Why not wait for a single PQ standard?

Because the threat is real and the migration takes time. Ladder Script ships
four schemes now. When the cryptographic community converges on a winner, that
scheme is already available. Meanwhile, SPHINCS+ (hash-based, 32-byte keys) is
considered the most conservative choice, and FALCON-512 offers the best
size/speed tradeoff. Users choose based on their own risk assessment —the
system supports all four today.

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

Latches are used for one-time authorisation, state machine gating, and
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

No. The typed field system eliminates arbitrary data embedding at multiple
layers:

1. **merkle_pub_key eliminates the writable surface.** Public keys are folded
   into the Merkle leaf hash —no key commitment field exists in conditions.
   There is no writable slot for an attacker to fill with arbitrary data.
2. **Type enforcement.** Every field must conform to a declared data type with
   strict size bounds. Unknown data types are rejected at deserialisation.
3. **Context separation.** Witness-only types (PUBKEY, PREIMAGE, SIGNATURE,
   SCRIPT_BODY) cannot appear in conditions. Data-embedding types (HASH256,
   HASH160, DATA) are rejected in witness context for blocks without implicit
   witness layouts.
4. **Selective inversion.** Key-consuming blocks cannot be inverted, preventing
   an attacker from using a garbage pubkey with an inverted SIG to embed data.
5. **Witness data limits.** PREIMAGE (max 32 bytes) and SCRIPT_BODY (max 80
   bytes) share a limit of 2 fields per witness
   (`MAX_PREIMAGE_FIELDS_PER_WITNESS = 2`). PUBKEY and SIGNATURE are cryptographically
   constrained —they must correspond to valid keys and signatures. Maximum
   embeddable data per witness: ~64 bytes.
6. **Build-time validation.** Public keys are checked for compressed key prefix
   (0x02/0x03 for 33-byte keys), SCHEME values are validated against the enum.
7. **Economic deterrent.** Even if structurally valid data gets into a UTXO
   (e.g., a PUBKEY field with non-key bytes), no valid signature can be produced.
   The attacker pays for storage they can never recover.

### 26. What happens with unknown block types?

Unknown block types are rejected at consensus during deserialization.
`IsKnownBlockType()` is checked in `DeserializeBlock()` —transactions
containing unrecognised block types cannot enter the mempool or be included in
blocks. This is a fail-closed design: no unknown type can reach the evaluator.

New block types require a code update and a soft fork activation to be
recognised. Pre-upgrade nodes reject transactions using the new types entirely
(they never reach evaluation), which is the standard soft fork security model.

### 27. How does fail-closed work?

Ladder Script follows the fail-closed principle throughout:

- Unknown block types: rejected at deserialisation (consensus failure).
- Unknown data types: rejected at deserialisation (not passed through).
- Missing fields: ERROR (consensus failure, not silent acceptance).
- Deferred attestation: unconditionally returns false (`VerifyDeferredAttestation`
  is not yet supported and does not silently pass).
- Out-of-range field sizes: rejected at deserialisation.
- Empty rungs (no blocks): ERROR.

No ambiguous input can result in a transaction being accepted. Every path
through the evaluator either explicitly validates or explicitly rejects.

### 27a. How does Ladder Script handle the inscription / data embedding problem?

By design, there is no writable surface for arbitrary data in conditions.
merkle_pub_key folds public keys into the Merkle leaf hash —no key commitment
field exists in conditions. Hash fields (HASH256, HASH160) are fixed-size.
NUMERIC fields are 1-4 bytes. SCHEME is 1 byte from a validated enum.
Witness-only types are blocked from conditions at both the RPC and consensus
layers. Key-consuming blocks cannot be inverted (selective inversion), closing
the garbage-pubkey-with-inverted-SIG vector.

MLSC outputs take this further: the UTXO stores only 33-73 bytes
(`0xC2` + 32-byte Merkle root, optionally with a DATA_RETURN payload). The
conditions are never in the UTXO set at all. An attacker could create a fake
`0xC2` output with a garbage root, but it would be unspendable —no valid
Merkle proof exists —so the fake data is never published on-chain. The
attacker burns their funds for nothing.

On the witness side, cryptographically constrained fields (PUBKEY, SIGNATURE)
leave no room for arbitrary data. PREIMAGE is capped at 32 bytes, SCRIPT_BODY
at 80 bytes, and `MAX_PREIMAGE_FIELDS_PER_WITNESS` limits each witness to 2
such fields total. Data-embedding types (HASH256, HASH160, DATA) are rejected
in witness context for blocks without implicit witness layouts. The maximum
embeddable data per witness is ~64 bytes —and only as valid hash preimages
or serialised Ladder Script conditions.

The Legacy family (0x0900) extends this to traditional transaction types. P2SH,
P2WSH, and taproot script-path —the primary inscription vectors today —are
wrapped as typed blocks where the inner script must be valid Ladder Script
conditions. Arbitrary bytes are rejected.

### 27b. What is the coil address_hash?

UNLOCK_TO coils store `SHA256(destination_scriptPubKey)` instead of the raw
destination address. The field is `address_hash`: 0 bytes (no destination) or
exactly 32 bytes (SHA256 hash). The raw address is never stored on-chain in
the coil data.

At evaluation time, the verifier computes `SHA256` of the spending transaction's
output `scriptPubKey` and compares it to the committed hash. This provides
destination binding without revealing the destination in the UTXO set.

### 27c. What are the exact anti-spam byte limits?

| Channel | Maximum | Enforcement |
|---------|---------|-------------|
| Output data (DATA_RETURN) | 40 bytes, 1/tx, zero-value | Consensus |
| Conditions writable surface | 0 bytes (merkle_pub_key) | Consensus |
| Witness PREIMAGE/SCRIPT_BODY | 2 fields, 32B + 80B max | Consensus |
| ACCUMULATOR proof fields | 10 HASH256 max | Consensus |
| Total embeddable per witness | ~64 bytes | Consensus |
| Total per 1-input tx | ~104 bytes | Combined |

For comparison, a single Bitcoin Taproot transaction can embed ~400,000 bytes
of arbitrary data via the script-path witness.

### 27d. What is leaf-centric covenant verification?

For MLSC outputs, covenant blocks (RECURSE_SAME, RECURSE_MODIFIED, etc.) use
the `MLSCVerifiedLeaves` structure rather than comparing full deserialized
conditions. The verifier:

1. Caches the input's verified leaf hashes from the Merkle proof.
2. Applies the declared mutation to the target leaf hash.
3. Rebuilds the Merkle root from the modified leaf array.
4. Compares against the output's committed root.

For cross-rung mutations (where the RECURSE_MODIFIED targets a different rung
than the one being exercised), the MLSC proof includes `revealed_mutation_targets`
with the target rung's condition blocks. This enables mutation verification
without revealing the entire ladder.

---

## Tooling

### 28. What is the Ladder Engine?

The Ladder Engine is a single-page web application (vanilla JS, no framework)
for building, simulating, and broadcasting Ladder Script transactions. Located
at `tools/ladder-engine/index.html` —runs entirely client-side with no build
step.

Features include:

- **Build Mode**: Drag blocks from a palette onto rungs, configure fields via
  a properties panel, define inputs/outputs, and generate `createrungtx` JSON.
- **Simulate Mode**: Step through rung evaluation visually. Power flows left
  to right through blocks. Click contacts to authorise them. Alt+click to
  force-toggle blocks. Coils fire when all contacts pass.
- **Send/Spend**: Fund outputs on the live signet and spend them —no local
  node required.
- **Examples Library**: Pre-built examples covering all major patterns.
- **Import/Export**: Load and save `createrungtx` JSON.

### 29. What RPCs are available?

| RPC | Purpose |
|-----|---------|
| `createrungtx` | Create a v4 RUNG_TX transaction from JSON conditions |
| `signrungtx` | Sign a v4 transaction (Schnorr, ECDSA, or PQ) |
| `decoderung` | Decode and display a v4 transaction's conditions and witness |
| `generatepqkeypair` | Generate a post-quantum keypair (FALCON512, etc.) |
| `pqpubkeycommit` | Compute SHA-256 commitment for a PQ public key |
| `extractadaptorsecret` | Extract adaptor secret from adapted/pre-signatures |
| `verifyadaptorpresig` | Verify an adaptor pre-signature |

### 30. How do I create a v4 transaction?

1. **Define conditions** as JSON with inputs, outputs, and per-output condition
   arrays. Each condition is a rung; each rung contains blocks; each block
   contains typed fields.

2. **Submit via RPC**: `ghost-cli createrungtx '<json>'`
   The node serialises the conditions, folds public keys into the Merkle leaf
   hash (merkle_pub_key), sets the scriptPubKey to `0xC2` (MLSC with Merkle
   root), and returns a hex-encoded raw transaction.

3. **Sign via RPC**: `ghost-cli signrungtx '<hex>' '<options>'`
   The RPC computes the LadderSighash and produces the appropriate signature
   type (Schnorr by default, or PQ if specified).

4. **Broadcast**: `ghost-cli sendrawtransaction '<signed_hex>'`

The Ladder Engine tool automates steps 1-2 visually and can fund and broadcast
directly on the signet.

---

## MLSC (Merkelised Ladder Script Conditions)

### 31. What is MLSC?

MLSC is the `0xC2` output format. Instead of storing full conditions inline,
the scriptPubKey contains `0xC2` + a 32-byte Merkle root (33 bytes standard,
or 34-73 bytes with a DATA_RETURN payload appended). The root is computed from
the ladder's rungs using BIP-341-style tagged hashing:

- **Leaf:** `TaggedHash("LadderLeaf", SerializeRung(rung[i]) || pk1 || ... || pkN)`
- **Internal:** `TaggedHash("LadderInternal", min(A,B) || max(A,B))`

Public keys consumed by blocks in the rung are appended to the leaf preimage
in block order (merkle_pub_key). This binds keys to conditions without storing
them in the UTXO set.

At spend time, the witness includes the revealed rung(s) and a Merkle proof.
Unrevealed rungs remain hidden, providing MAST-style privacy.

### 32. Why use MLSC instead of inline conditions?

Three reasons:

1. **Privacy.** Only the executed rung is revealed. Recovery paths, emergency
   keys, and alternative spending conditions stay hidden if never used.
2. **UTXO set efficiency.** Every MLSC scriptPubKey is 33 bytes (or 34-73
   with DATA_RETURN) regardless of how complex the conditions are. A 16-rung
   ladder with 8 blocks each takes the same UTXO space as a single SIG block.
3. **Spam resistance.** The UTXO set never contains conditions —only a Merkle
   root. There is no space for arbitrary data in the persistent state.

### 33. How does the sighash work for MLSC?

For `0xC2` outputs, the sighash commits to the `conditions_root` directly
(the 32-byte Merkle root from the scriptPubKey) rather than hashing the full
serialised conditions. This means the sighash is the same size regardless of
ladder complexity, and the signer does not need access to unrevealed rungs.

### 34. Can data be embedded in MLSC outputs?

The only data surface is DATA_RETURN: up to 40 bytes appended after the Merkle
root, making the output 34-73 bytes. DATA_RETURN outputs must be zero-value
(provably unspendable), are limited to 1 per transaction, and cost 4 WU per
byte —the same economics as OP_RETURN. This provides a structured, visible,
prunable channel for protocol metadata (timestamps, commitments, anchors).

Beyond DATA_RETURN, there is no writable surface. The Merkle root is
cryptographically bound to the conditions and keys. An attacker could create a
fake `0xC2` output with a garbage root, but it would be unspendable —no valid
Merkle proof exists —and the funds are permanently burned.

---

## Wire Format

### 35. What are micro-headers?

Micro-headers are a wire format optimisation. Instead of encoding a block's
type as a 2-byte `uint16_t`, all 61 block types are assigned a 1-byte slot
index (0x00 to 0x3D) in a compile-time lookup table. This saves 1 byte per
block.

For blocks not in the table (future types), escape bytes are used: `0x80`
followed by a 2-byte type code for non-inverted blocks, `0x81` followed by
a 2-byte type code for inverted blocks.

### 36. What are implicit fields?

When the deserialiser knows a block's field layout from its type (via the
implicit layout table), it can skip the field type byte during serialisation.
The field order is fixed by the block definition, so only the field *data* is
written. This saves 1 byte per field for all standard block types.

Additionally, fixed-size fields (HASH256 32B, HASH160 20B, SCHEME 1B) skip
the CompactSize length prefix entirely in implicit encoding —the deserialiser
knows the exact size from the layout definition.

### 37. How does context-aware serialisation work?

The wire format distinguishes between CONDITIONS context and WITNESS context.
In CONDITIONS context, witness-only data types (PUBKEY, SIGNATURE, PREIMAGE,
SCRIPT_BODY) are forbidden. In WITNESS context, condition-only types may be
omitted if they can be inferred from the corresponding conditions. This
eliminates redundant data in the witness without ambiguity.

---

## Compound Blocks

### 38. What are compound blocks?

Compound blocks combine two or more primitive operations into a single block
with a single header, saving wire bytes. There are 6 compound types:

| Compound Block | Replaces | Savings |
|----------------|----------|---------|
| HTLC (0x0702) | hash lock + CSV + SIG | ~16 bytes |
| TIMELOCKED_SIG (0x0701) | SIG + CSV | ~8 bytes |
| HASH_SIG (0x0703) | hash lock + SIG | ~8 bytes |
| PTLC (0x0704) | ADAPTOR_SIG + CSV | ~8 bytes |
| CLTV_SIG (0x0705) | SIG + CLTV | ~8 bytes |
| TIMELOCKED_MULTISIG (0x0706) | MULTISIG + CSV | ~8 bytes |

### 39. When should I use a compound block vs. separate blocks?

Use compound blocks when the pattern matches exactly. HTLC is always better
than separate hash + timelock + signature blocks for atomic swaps.
TIMELOCKED_SIG is always better than SIG + CSV for time-delayed authorisation.

Use separate blocks when you need different configuration (e.g., CSV on one
rung but CLTV on another), when you want to invert individual blocks, or
when the compound doesn't match your exact pattern.

---

## Governance Blocks

### 40. What are governance blocks?

Governance blocks (0x08xx family) constrain the *structure* of the spending
transaction rather than its *authorisation*. They enforce spending windows,
transaction size limits, I/O fanout bounds, and value ratios:

- **EPOCH_GATE** (0x0801): Only spendable during periodic windows (e.g.,
  first 144 blocks of every 2016-block epoch).
- **WEIGHT_LIMIT** (0x0802): Maximum transaction weight in weight units.
- **INPUT_COUNT** (0x0803): Min/max number of inputs.
- **OUTPUT_COUNT** (0x0804): Min/max number of outputs.
- **RELATIVE_VALUE** (0x0805): Output must be >= a ratio of the input value
  (anti-siphon protection).
- **ACCUMULATOR** (0x0806): Merkle set membership proof for allowlists.
- **OUTPUT_CHECK** (0x0807): Per-output value and script constraint.

### 41. How does ACCUMULATOR work?

ACCUMULATOR stores a Merkle root in the conditions. At spend time, the
witness provides a leaf value and a Merkle proof. The evaluator recomputes
the root from the proof and checks it matches. This enables allowlists,
blocklists, and set membership verification without storing the full set
on-chain.

---

## Anchor Blocks

### 42. What are anchor blocks?

Anchor blocks (0x05xx family) commit metadata to a UTXO via typed hash fields.
There are 7 anchor types:

- **ANCHOR** (0x0501): Generic 32-byte data commitment.
- **ANCHOR_CHANNEL** (0x0502): Lightning channel commitment binding.
- **ANCHOR_POOL** (0x0503): Pool / VTXO tree root.
- **ANCHOR_RESERVE** (0x0504): N-of-M guardian reserve set commitment.
- **ANCHOR_SEAL** (0x0505): Permanent, immutable data seal.
- **ANCHOR_ORACLE** (0x0506): Oracle attestation key binding.
- **DATA_RETURN** (0x0507): Prunable data carrier. Up to 40 bytes appended
  after the MLSC Merkle root (`0xC2 || root || data`). Zero-value, max 1 per
  transaction. Replaces OP_RETURN for v4 transactions.

Each anchor type validates its metadata fields and returns ERROR if required
fields are missing or malformed.

### 43. Why use anchor blocks instead of OP_RETURN?

Anchor blocks are semantically typed and structurally validated. An
ANCHOR_CHANNEL carries a 32-byte commitment that parsers can identify by
type code without guessing the data format. Anchor blocks also live inside
the conditions structure, so they benefit from the same size limits, type
validation, and MLSC privacy as all other blocks.

---

## Legacy Blocks

### 44. What is the Legacy family?

The Legacy family (0x0900-0x09FF) wraps traditional Bitcoin transaction types
as typed Ladder Script blocks. Seven block types cover the full range: P2PK,
P2PKH, P2SH, P2WPKH, P2WSH, P2TR (key-path), and P2TR_SCRIPT (script-path).

Each preserves the spending semantics of its original format but enforces typed
fields. P2SH, P2WSH, and P2TR_SCRIPT inner scripts must be valid Ladder Script
conditions —arbitrary bytes are rejected.

### 45. Why wrap legacy types as blocks?

Because the raw legacy formats have writable surfaces for arbitrary data. Taproot
script-path is the primary inscription vector today. By wrapping legacy semantics
in typed blocks, those surfaces are closed. Legacy blocks compose with all other
block types —you can put a P2PKH_LEGACY in a rung alongside a CSV timelock, a
COSIGN requirement, or a governance constraint. Legacy users get access to the
full Ladder Script composability without changing their spending semantics.

---

## Design Rationale

### 46. Why typed fields instead of a stack machine?

A stack machine processes opaque byte vectors. You push data, run opcodes, and
check the stack state. The machine cannot tell a public key from a preimage
from garbage without executing the full script. This means:

- You cannot validate a transaction without simulating execution.
- You cannot determine what conditions a UTXO requires by inspecting it.
- You cannot prevent arbitrary data from entering the stack.

Typed fields flip this. Every field declares its type. The node validates type
and size before evaluation begins. A PUBKEY is always a PUBKEY. A SIGNATURE is
always a SIGNATURE. Conditions can be machine-parsed without execution. And
since every byte is accounted for, there is no room for arbitrary data.

### 47. Why are conditions and witness structurally identical?

Because they are two views of the same data. Conditions say "this rung needs a
SIG block with SCHEME Schnorr." The witness says "here is PUBKEY Y and
SIGNATURE Z for that SIG block." Same rung index, same block index, same field
slots. The evaluator merges them and evaluates. The public key is bound to
conditions via merkle_pub_key (folded into the Merkle leaf), not stored as a
field in the conditions themselves.

This makes the system self-describing. You can look at a UTXO's conditions and
know exactly what the witness must provide —field by field, type by type. No
simulation required.

### 48. Why fold keys into the Merkle leaf instead of storing them in conditions?

Three reasons, all critical:

1. **Anti-spam.** merkle_pub_key eliminates every writable surface in conditions.
   There is no key commitment field for an attacker to fill with arbitrary data.
   The Merkle leaf is a cryptographic hash —it cannot be reverse-engineered
   to embed meaningful data.
2. **UTXO efficiency.** No public key data appears in the UTXO set at all. A
   1,952-byte Dilithium3 key contributes zero additional bytes —it is folded
   into the 32-byte leaf. The full key appears only at spend time in the
   prunable witness.
3. **Quantum stealth.** Until a UTXO is spent, the public key is hidden inside
   the Merkle leaf hash. A quantum attacker cannot derive the key from the hash,
   so they cannot forge signatures for unspent outputs.

### 49. Why AND-within-rung and OR-across-rungs?

Because it maps directly to how people think about spending policies:

- "Alice AND Bob must both sign" → one rung, two SIG blocks
- "Alice alone OR Bob alone" → two rungs, one SIG block each
- "Alice AND Bob, OR Carol after 30 days" → two rungs, one with two SIGs,
  one with a SIG and a CSV

This is disjunctive normal form (DNF). Every boolean spending condition can be
expressed in DNF. The two-level structure makes it trivial to read, compose, and
verify. No need to trace stack operations or reason about execution order.

### 50. Why is the evaluation model fail-closed?

Because the cost of a false positive is catastrophic —funds stolen. The cost of
a false negative is recoverable —funds temporarily unspendable, fixed by a
software upgrade.

Every unknown, ambiguous, or malformed input results in rejection. Unknown block
type? Rejected at deserialization. Missing field? ERROR. Wrong preimage?
UNSATISFIED. This is the only safe default for a consensus system that secures
real money.

### 51. What can Ladder Script do that Bitcoin Script cannot?

Several things that are either impossible or require contentious new opcodes:

- **Native covenants.** RECURSE_SAME, RECURSE_MODIFIED, CTV, VAULT_LOCK --
  all work today. No OP_CTV debate required.
- **Stateful contracts.** Counters, latches, timers, sequencers —UTXO state
  that updates across spends. Not possible in a stateless stack machine.
- **Transaction structure constraints.** INPUT_COUNT, OUTPUT_COUNT, WEIGHT_LIMIT,
  EPOCH_GATE —enforce rules about the spending transaction itself.
- **Fee-rate gates.** HYSTERESIS_FEE lets a UTXO reject spends during fee spikes.
  There is no way to inspect fee rates in Bitcoin Script.
- **Post-quantum signatures.** Drop-in PQ schemes across all block types. No
  new address format, no new script version, no migration ceremony.
- **Typed UTXO introspection.** Every field is machine-readable. Wallets,
  explorers, and policy engines can parse conditions without executing anything.

### 52. How does Ladder Script compare to Taproot?

Taproot provides MAST (hiding unused spending paths behind a Merkle root) and
Schnorr signatures. MLSC provides the same MAST privacy model with tagged hashing
and sorted interior nodes, extended to 61 block types including covenants, PLC
state machines, governance constraints, and PQ signatures.

Taproot script-path spends execute Bitcoin Script inside a revealed leaf. MLSC
reveals typed conditions —no script execution, no stack, no data embedding
surface.

### 53. Is the wire format efficient?

Yes. Two optimisations stack:

- **Micro-headers:** 1 byte per block type instead of 2 (all 61 types have slots).
- **Implicit fields:** Field type bytes omitted when the layout is known from the
  block type (saves 1 byte per field). Fixed-size fields skip the length prefix.

A single-sig MLSC output is 33 bytes regardless of condition complexity. Public
keys add zero bytes to conditions (merkle_pub_key folds them into the leaf).
Diff witnesses save further when spending multiple similar UTXOs in one
transaction.
