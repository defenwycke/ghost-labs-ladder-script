```
BIP: ?
Title: QABIO: Quantum Atomic Batch I/O for Ladder Script
Authors: Defenwycke <defenwycke@icloud.com>
Status: Draft
Type: Specification
Layer: Consensus (soft fork)
Assigned: ?
Requires: BIP-XXXX (Ladder Script)
License: MIT
Discussion: TBD
```

## How to Review This Document

This BIP specifies a single-purpose extension to Ladder Script: an
N-party atomic batch primitive authorised by one post-quantum
signature. Readers should already be familiar with BIP-XXXX, the
base Ladder Script specification — QABIO adds two new block types, one
new sighash algorithm, one new tx-level field, and one mempool policy
on top of it, and is meaningless without that foundation.

Suggested review order:

1. **Abstract and Motivation** (5 min) — what the primitive does,
   why none of the existing N-party constructions solve the same
   problem, and what threat model is being addressed.
2. **Design Overview** (10 min) — the three-state UTXO lifecycle,
   the actor model, and why the participant holds veto power via
   the always-valid SIG escape rung.
3. **Specification** (20 min) — read the wire format for `QABIBlock`
   and the per-input witness layout first, then the 9 consensus
   checks. Each check has a named failure mode (ERROR vs
   UNSATISFIED) that maps directly to a test case.
4. **Rationale** (10 min) — why FALCON-512 specifically, why the
   auth hash chain is committed at creation time instead of priming
   time, and why the coordinator cannot skim a payout.
5. **Security Considerations** (10 min) — coordinator trust
   surface, pre-image revelation timing, and the eight attack paths
   QABIO does *not* eliminate.
6. **Try it** — live signet: `ladder-script.org/qabio-playground.html`
   builds a full N-party batch end-to-end without writing any code.

## Abstract

This document specifies QABIO (Quantum Atomic Batch I/O), a
consensus-native extension to Ladder Script (BIP-XXXX) that allows
N independent parties to collapse their UTXOs into a single
transaction authorised by one post-quantum signature from a
coordinator. QABIO introduces two new Ladder Script block types
(`QABI_PRIME` at `0x0A01` and `QABI_SPEND` at `0x0A02`), a new
transaction-level witness field (`tx.qabi_block`), a new aggregated
signature field (`tx.aggregated_sig`), a new sighash algorithm
(`SIGHASH_QABO`), and a new mempool policy (Replace-By-Depth, RBD)
for priming-transaction churn.

The whole batch settles atomically in one block or does not settle
at all. The coordinator never holds participants' funds and cannot
cause partial settlement. Each participant retains a unilateral
SIG-based escape path for the entire window between priming and
batch broadcast. Amortised per-participant cost converges from
N ≥ 50 upward at roughly 162 vbytes per primed input — lower than
any existing N-party construction, and notably lower than an
equivalent CoinJoin once per-input signatures are counted.

QABIO is deployed as a soft fork on top of the Ladder Script soft
fork: activation of Ladder Script without QABIO is valid; activation
of QABIO without Ladder Script is not.

## Motivation

### N-party batching has no native Bitcoin primitive

Bitcoin has no consensus-native way for N independent parties to
batch their funds into a single transaction authorised by one
signature. Every existing construction imposes a trust, liveness, or
post-quantum-readiness tax that rules it out for important deployment
classes:

- **Multisig / FROST / MuSig2.** Every party holds a fragment of the
  shared key. Requires interactive coordination during key generation
  *and* during signing. Not post-quantum. Fails silently if any one
  party is offline at sign time — there is no "skip this participant
  and finalise the rest" path.
- **Coordinator-held escrow.** A trusted coordinator collects funds,
  holds them until the batch fires, and makes the payout. Custodial.
  Loss of coordinator key equals loss of participant funds. Regulatory
  surface makes this non-starter for most use cases.
- **CoinJoin-style blind construction.** Each participant signs their
  own input after the coordinator assembles the joint transaction.
  Requires every participant to be online and responsive during
  signing. Scales poorly above N ≈ 20 because the coordination round
  is synchronous. Not a batching primitive — a mixing primitive that
  happens to produce batched transactions.
- **Commit-and-reveal protocols.** Two-phase: pre-commit to intent
  via one transaction, reveal via a second. Either two on-chain
  transactions per batch (doubling the footprint) or complex
  off-chain state machines (pushing the problem out of consensus).

QABIO replaces all of these with a single-shot consensus primitive:

1. Each participant creates a UTXO with a QABI-aware conditions tree
   (one-time, on-chain).
2. Each participant unilaterally **primes** their UTXO for a specific
   upcoming batch by revealing an auth-chain preimage (one-shot,
   on-chain, no coordinator involvement).
3. The coordinator assembles a single N-input transaction that
   consumes every primed UTXO at once, signs it once with their own
   post-quantum key, and broadcasts.
4. Consensus atomically accepts the whole batch, or rejects it.
   Partial settlement is impossible.

The coordinator never holds participants' funds, never sees their
private keys, and cannot cause partial settlement. Participants
retain a standard signature-based escape path for the entire window
between priming and batch confirmation.

### Post-quantum signing as a design constraint, not an afterthought

The construction is hardcoded to FALCON-512 for the coordinator
signature. This is a deliberate choice: FALCON-512 has the smallest
signature of any NIST-standardised post-quantum signature scheme
(666 bytes vs. 1280 for FALCON-1024, 3293 for DILITHIUM3, and 7856+
bytes for SPHINCS+). Because the coordinator signature is a fixed
per-transaction overhead amortised across every primed input,
smaller is strictly better for the amortised per-input cost. A
future QABI block version can unlock scheme selection via a
dispatch byte in the header — the design leaves room for it — but
v1 is single-scheme to minimise consensus surface.

Cryptographic agility belongs at the wire layer, not the consensus
layer. Activating a new scheme requires a future soft fork with a
bumped QABI block version. Until then, the only authorisation
scheme is FALCON-512.

### Capability gap: batched payouts under adversarial coordinators

QABIO's primary target is the class of use cases where a coordinator
is fully untrusted but the participants still need the efficiency of
a shared settlement transaction:

- **Payroll / exchange batches.** Weekly withdrawal runs with tens
  to thousands of recipients. Current Bitcoin practice is one
  transaction per recipient (or a single large fan-out where the
  exchange IS the coordinator and holds the funds). QABIO allows the
  exchange to batch N recipients without ever taking custody.
- **Mining pool payouts.** Pool operator announces a batch root,
  miners prime their recent block-reward UTXOs, pool signs the
  aggregate payout. Operator cannot skim because consensus check 8
  enforces full output-set equality with the signed qabi_block.
- **Bridge withdrawals.** A sidechain or L2 bridge batches
  withdrawal receipts into a single L1 transaction. Participants
  prime their L2-locked UTXOs; the bridge operator signs once.
  Custody-free withdrawal from a federation-run bridge.
- **DAO / grant distributions.** A governance vote finalises a list
  of grant recipients. Each recipient primes against the batch
  identifier published by the DAO treasury. Treasury signs once.
  No per-recipient transactions, no trusted distribution layer.

In every case the coordinator's role is bounded: they assemble,
sign, and broadcast a transaction whose outputs and inputs are
enforced by consensus to match what participants committed to at
priming time. They cannot modify the transaction after signing, and
they cannot cause partial settlement, and they cannot prevent a
participant from exiting via the SIG escape rung at any time.

## Design Overview

### Actors

**Participants.** The N users whose UTXOs are being batched. Each
participant holds three distinct pieces of state:

- an `auth_seed` (32-byte secret) that generates their auth hash
  chain via iterated SHA-256;
- an `owner_id` (32 bytes = SHA-256 of their Rung 0 signing pubkey)
  committed to their UTXO at creation;
- their own private key for the SIG escape rung (any Ladder Script
  `SIG` scheme — Schnorr, ECDSA, or PQ).

**Coordinator.** One party — an exchange, mixer, payroll service,
DEX settlement layer, bridge operator, etc. — who assembles and
signs the batch transaction. The coordinator holds:

- a FALCON-512 keypair. The pubkey (897 bytes) is published in
  advance via whatever out-of-band channel the coordinator prefers
  and is also embedded in `tx.qabi_block` for consensus access.
  The privkey is used once per batch to produce the aggregate
  signature.

The coordinator's role is consensus-bounded: they see the finalised
transaction before signing and can refuse to sign if the
participant set or output list is wrong. They cannot *modify* the
transaction after signing, and they cannot *steal* from it:
consensus check 8 (see Specification §6) requires `tx.vout` to be
bit-exact equal to the `outputs` list inside the signed `qabi_block`.

### UTXO lifecycle

A QABI-enabled UTXO passes through up to three states during its
life. Each state transition is a regular on-chain v4 transaction.

```
    ┌────────────┐   QABI_PRIME   ┌──────────┐   QABI_SPEND   ┌────────┐
    │ unprimed   │ ─────────────▶ │  primed  │ ─────────────▶ │ spent  │
    └────────────┘                └──────────┘                └────────┘
          │                             │
          │ SIG escape                  │ SIG escape
          │ (unilateral, always valid)  │ (unilateral, always valid)
          ▼                             ▼
    ┌──────────────┐              ┌──────────────┐
    │ participant  │              │ participant  │
    │ recovered    │              │ recovered    │
    │ (1-rung SIG) │              │ (1-rung SIG) │
    └──────────────┘              └──────────────┘
```

**Unprimed.** The participant creates a v4 `rung_tx` whose output
is an MLSC UTXO with a 3-rung conditions tree:

```
  rung 0: SIG(participant_pubkey)                       ← escape hatch
  rung 1: QABI_PRIME                                    ← priming entry
  rung 2: QABI_SPEND(auth_tip, 0, 0, 0, owner_id)       ← batch entry
```

`auth_tip` is `SHA256^N(auth_seed)` — the far end of the
participant's hash chain, where N is the full chain length (typically
50 or higher). The `committed_root`, `committed_depth`, and
`committed_expiry` fields are all zero because the UTXO has not yet
been primed to any batch. `owner_id` is
`SHA-256(Rung_0_signing_pubkey)`.

At this state the UTXO is spendable via any of the three rungs.
Rung 0 is the normal unilateral exit. Rung 1 is what the
participant fires to prime into a specific batch. Rung 2 is
consensus-rejected — check 2 (Specification §6) fails because
`committed_root` is all-zero.

**Primed.** The participant runs a `QABI_PRIME` transaction that
spends the unprimed UTXO and produces a new MLSC UTXO whose
conditions tree is bit-exact the same *except* for the QABI_SPEND
rung, where three fields have been mutated:

- `committed_root` ← the coordinator's announced
  `SHA-256(qabi_block)`;
- `committed_depth` ← a fresh depth strictly greater than the
  previous committed depth (zero on the first prime);
- `committed_expiry` ← a block height after which the primed
  commitment auto-expires.

The consensus evaluator enforces this as a **covenant**: it rebuilds
the expected output conditions tree with the mutated QABI_SPEND rung,
recomputes the MLSC Merkle root, and checks it matches the output
UTXO's scriptPubKey bit-exact. Any deviation fails with
`conditions-mutation-mismatch`.

The participant authorises QABI_PRIME by revealing `prime_preimage`,
the hash-chain value at the chosen `prime_depth`. The evaluator
checks `SHA256^prime_depth(prime_preimage) == auth_tip`. Only the
`auth_seed` holder can produce this preimage; no coordinator
signature is required at priming time.

After priming, the UTXO is in the "committed to batch R, expiring
at height H" state. Rung 0 (SIG escape) is still valid. Rung 2
(QABI_SPEND) becomes valid for the specific batch whose root equals
`committed_root`. Attempts to spend rung 2 with a qabi_block whose
hash does not match `committed_root` fail with check 4
(Specification §6).

**Batch spent.** The coordinator collects K primed UTXOs (not
necessarily all at once — any subset of UTXOs whose `committed_root`
matches the coordinator's batch root can participate, giving
coordinators flexibility to batch late joiners with early primers),
assembles a single v4 rung_tx with K inputs and the output set
defined in `qabi_block.outputs`, computes `SIGHASH_QABO`, and signs
once with their FALCON-512 key. When the transaction is broadcast,
consensus runs all 9 QABI_SPEND checks per-input (Specification
§6). The expensive FALCON-512 verification is cached *across*
inputs — one verify per transaction, shared by every primed input,
because all inputs reference the same `aggregated_sig` and the same
`qabi_block`.

Each primed UTXO's contribution lands at the destination address
the coordinator committed to in `qabi_block.outputs`. No skim is
possible because consensus requires `tx.vout` to be bit-exact equal
to `qabi_block.outputs` (check 8). If any single input fails any
check, consensus rejects the whole transaction. Partial settlement
is impossible.

**Escape — coordinator bails.** Every state of a QABI UTXO has the
SIG escape rung enabled throughout. If the coordinator never
produces a valid QABI_SPEND transaction, or produces one that
doesn't match the participant's committed state, or simply goes
dark after priming, the participant can sweep the UTXO with their
own key by spending the SIG rung:

```
  participant signs the primed UTXO with their own key
       ↓
  primed UTXO consumed
       ↓
  fresh 1-rung [SIG(participant_pubkey)] MLSC UTXO appears
       ↓
  participant owns it unilaterally, can spend freely
```

This works on both unprimed and primed UTXOs. The SIG rung's
content is identical in both cases, so its Merkle leaf is
byte-identical, and the signature-authorised spend path always
works. The recovered UTXO is an MLSC UTXO (not a plain P2WPKH),
because consensus requires every output of a v4 rung_tx to be MLSC
(`rung-non-mlsc-output` rule in BIP-XXXX). The recovered UTXO has
a single SIG rung bound to the participant's own key and is
spendable at any time via a normal signature — functionally
equivalent to a wallet recovery, one level of indirection away.

## Specification

### Block Type Registration

QABIO defines two new Ladder Script block types in the QABIO family
(`0x0A00` – `0x0AFF`), registered as follows:

| Type code | Name          | Context                   | Invertible |
|-----------|---------------|---------------------------|------------|
| `0x0A01`  | `QABI_PRIME`  | Conditions + witness      | No         |
| `0x0A02`  | `QABI_SPEND`  | Conditions + witness      | No         |

Both blocks are marker-only in conditions context — they carry zero
committed fields in the MLSC tree leaf. All state for QABI_PRIME
(covenant target, auth-chain preimage, depth) travels in the witness.
QABI_SPEND is the exception: it carries 5 committed fields (auth_tip,
committed_root, committed_depth, committed_expiry, owner_id) in the
conditions tree, plus 1 witness-revealed field (spend_preimage) at
spend time.

### QABI_PRIME Block (0x0A01)

#### Conditions layout

```
QABI_PRIME_CONDITIONS = { count: 0, fields: [] }
```

The block carries no committed fields. Its sole purpose in the
conditions tree is to serve as a covenant-mutation entry point: the
evaluator recognises it as the "priming fires here" marker and uses
the spent input's Rung 1 position to know where to apply the
covenant.

#### Witness layout (implicit, 4 fields)

```
QABI_PRIME_WITNESS = [
    [0] HASH256   new_committed_root    (32 B)
    [1] NUMERIC   prime_depth           (4 B, LE uint32)
    [2] NUMERIC   new_committed_expiry  (4 B, LE uint32)
    [3] PREIMAGE  prime_preimage        (32 B)
]
```

The four witness fields are present in every QABI_PRIME witness
block regardless of context. Field count mismatch is an ERROR.

#### Evaluation

`EvalQABIPrimeBlock` runs the following checks in order. Any failure
returns UNSATISFIED unless noted otherwise.

1. **Field shape.** Exactly 4 fields in the order above, with
   declared sizes. Failure → ERROR.
2. **Prime depth bound.** `prime_depth > previous_committed_depth`,
   where `previous_committed_depth` is read from the spent input's
   Rung 2 QABI_SPEND conditions. Prevents replay at stale depths.
3. **Preimage validates.**
   `SHA-256^prime_depth(prime_preimage) == committed auth_tip`.
   The committed `auth_tip` is read from the spent input's Rung 2
   QABI_SPEND conditions; `prime_depth` is from the witness.
4. **Covenant reconstruction.** The evaluator rebuilds the
   participant's conditions tree with the QABI_SPEND rung's
   `committed_root` / `committed_depth` / `committed_expiry` fields
   replaced by the witness values `new_committed_root`,
   `prime_depth`, and `new_committed_expiry` respectively. It then
   recomputes the MLSC Merkle root and compares against
   `tx.vout[0].scriptPubKey[1..33]` (the 32-byte conditions_root of
   the primed output). Failure → UNSATISFIED.
5. **Output count.** The priming transaction must have exactly one
   spendable output (the primed UTXO). DATA_RETURN outputs are
   allowed but limited to one per BIP-XXXX rules.

If all five checks pass, QABI_PRIME returns SATISFIED. The primed
UTXO is now committed to the specific batch identified by
`new_committed_root`.

### QABI_SPEND Block (0x0A02)

#### Conditions layout (5 committed fields)

```
QABI_SPEND_CONDITIONS = [
    [0] HASH256       auth_tip           (32 B)
    [1] HASH256       committed_root     (32 B)
    [2] NUMERIC       committed_depth    (4 B, LE uint32)
    [3] NUMERIC       committed_expiry   (4 B, LE uint32)
    [4] PUBKEY_COMMIT owner_id           (32 B = SHA-256(pubkey))
]
```

All five fields are committed at UTXO creation time. They become
part of the MLSC leaf for Rung 2 and contribute to the output's
conditions_root. QABI_PRIME is the only path that can mutate
fields [1], [2], [3]; fields [0] and [4] are frozen at creation
and immutable for the UTXO's lifetime.

The `PUBKEY_COMMIT` datatype is a QABI_SPEND-specific carve-out
from the general rule (BIP-XXXX §Conditions Field Rules) that
PUBKEY_COMMIT is forbidden in conditions context. QABI_SPEND is the
only block type that may carry a PUBKEY_COMMIT field in the
conditions tree; all other blocks are rejected by the
serialisation layer if they attempt to serialise one.

#### Witness layout (implicit, 1 field)

```
QABI_SPEND_WITNESS = [
    [0] PREIMAGE  spend_preimage  (32 B)
]
```

Only the witness-specific `spend_preimage` is serialised in the
witness block. The 5 conditions fields arrive at evaluation time via
`MergeConditionsAndWitness`, which concatenates the conditions fields
(prepended) with the witness fields (appended) to produce the
6-field merged block the evaluator reads.

This asymmetry — 5 conditions fields + 1 witness field = 6 merged
fields — is why QABI_SPEND needs a dedicated entry in the implicit
layout table and a dedicated `BuildWitnessBlock` handler in
`signrungtx`. A generic handler that treated witness blocks as
standalone would either duplicate the 5 fields (producing 11 and
failing evaluation) or fail the 6-field requirement. The dedicated
handler writes exactly 1 field, relying on the merge to produce 6.

#### Evaluation

`EvalQABISpendBlock` runs 9 checks per input. Checks 4, 5, 6, and
8 are **cacheable** at the transaction level (they depend only on
`tx.qabi_block` and `tx.aggregated_sig`, not per-input state);
checks 1, 2, 3, 7, and 9 are per-input. Checks run in the order
below.

1. **Field shape.** Merged block has exactly 6 fields: 2 HASH256,
   2 NUMERIC, 1 PUBKEY_COMMIT, 1 PREIMAGE. Each field has its
   declared size (32, 32, 4, 4, 32, 32). Failure → ERROR.

2. **UTXO is primed.** `committed_root != 0`. Failure →
   UNSATISFIED. An all-zero committed root indicates the UTXO has
   never been primed, so the QABI_SPEND rung is not yet valid.

3. **Expiry window.** `block_height <= committed_expiry`, where
   `block_height` is the current tip height at evaluation time.
   Failure → UNSATISFIED.

4. **Spend preimage valid.**
   `SHA-256^(committed_depth + 1)(spend_preimage) == auth_tip`.
   The preimage must be at depth `committed_depth + 1` — strictly
   deeper than the last prime — to prove the participant is
   authorising this specific spend transition. Failure →
   UNSATISFIED.

5. **qabi_block parses and matches committed root.**
   - `ctx.tx->qabi_block.size() > 0`.
   - `ParseQABIBlock(ctx.tx->qabi_block)` succeeds and returns a
     well-formed block.
   - `parsed.coordinator_pubkey.size() == QABI_COORDINATOR_PUBKEY_SIZE
     (897)`.
   - `SHA-256(ctx.tx->qabi_block) == committed_root`.
   Any failure → UNSATISFIED. This check ensures the coordinator's
   signed block is the specific one the participant primed against.

6. **FALCON-512 signature verification.**
   - `ctx.tx->aggregated_sig.size() == QABI_AGGREGATED_SIG_MAX (666)`.
   - Compute `sighash = SIGHASH_QABO(tx, qabi_block, per-input
     witnesses)` (§ Sighash Algorithm).
   - `FALCON-512_Verify(parsed.coordinator_pubkey, sighash,
     ctx.tx->aggregated_sig)` returns VALID.
   - The sighash and verification result are cached in
     `ctx.qabo_sig_cache` keyed by sighash. Subsequent inputs of
     the same transaction short-circuit via the cache. Failure →
     UNSATISFIED.

7. **Identity in block.** This input's `owner_id` (from conditions
   field [4]) must appear in `parsed.entries[*].participant_id`.
   The evaluator builds a hash-indexed `std::unordered_set` of all
   entry participant_ids on the cache-miss path (O(N) once per
   transaction) so subsequent inputs hit O(1) lookups. Total
   identity-check work across all inputs is O(N), not O(N²).
   Failure → UNSATISFIED.

8. **Full output-set match.** `ctx.tx->vout.size() ==
   parsed.outputs.size()`, and for every `i`,
   `ctx.tx->vout[i].nValue == parsed.outputs[i].nValue` and
   `ctx.tx->vout[i].scriptPubKey == parsed.outputs[i].scriptPubKey`
   (byte-exact). Failure → UNSATISFIED. This check closes the
   coordinator-skim hole: the coordinator cannot add, remove,
   reorder, or modify any output in the batch tx without
   invalidating every primed input's QABI_SPEND rung.

9. **Expiry binding.** `parsed.prime_expiry_height ==
   committed_expiry`. Prevents the coordinator signing over a
   qabi_block whose `prime_expiry_height` differs from the value
   participants primed against. Failure → UNSATISFIED.

If all 9 checks pass for all primed inputs, the transaction is
valid and settles atomically. If any one input fails any check, the
whole transaction is rejected — there is no partial acceptance path.

### The QABIBlock Wire Format

`qabi_block` is a structured blob serialised into the v4
transaction's witness section at the tx-level `tx.qabi_block` field.
Like all v4 witness data, it is weight-discounted 4:1 under
BIP-141.

```
struct QABIBlock {
    version              : 1 byte    (currently 0x01)
    batch_id             : 32 bytes  (unique batch identifier)
    coordinator_pubkey   : 897 bytes (FALCON-512 public key)
    prime_expiry_height  : 4 bytes   (uint32 LE)
    n_entries            : CompactSize
    entries[n_entries]   : QABIEntry
    n_outputs            : CompactSize
    outputs[n_outputs]   : CTxOut
};

struct QABIEntry {
    participant_id       : 32 bytes  (SHA-256 of participant's
                                      Rung 0 signing pubkey)
    contribution         : 8 bytes   (int64 LE, sats)
    destination_index    : CompactSize (index into outputs[])
};
```

Output format (`CTxOut`) follows standard Bitcoin serialisation:
8-byte LE nValue followed by CompactSize-prefixed scriptPubKey.

The coordinator's FALCON-512 signature commits to
`SHA-256(serialised qabi_block)` via `committed_root` in every
primed input's QABI_SPEND rung. This pins the batch: participants
see *exactly* which batch they are priming into before they sign
their priming transaction, because `committed_root` is a field they
set with their own hands. The coordinator cannot switch the batch
out from under them after priming.

#### Size Limits

```
QABI_BLOCK_MAX_SOFT      = 65,536    (64 KB, standard relay)
QABI_BLOCK_MAX_HARD      = 262,144   (256 KB, consensus hard cap)
QABI_COORDINATOR_PUBKEY_SIZE = 897   (FALCON-512 public key)
QABI_AGGREGATED_SIG_MAX  = 666       (FALCON-512 signature)
```

Transactions whose qabi_block exceeds `QABI_BLOCK_MAX_SOFT` are
rejected at mempool acceptance with `qabi-block-nonstandard`.
Transactions whose qabi_block exceeds `QABI_BLOCK_MAX_HARD` are
rejected at block validation with `qabi-block-oversize`.

### Transaction-level fields

QABIO adds two new transaction-level fields to the v4 TX_MLSC wire
format:

```
v4 TX_MLSC layout (with QABIO fields, additions in bold):
    version              uint32 LE          (0x04)
    dummy                uint8              (0x00)
    flags                uint8              (0x02 = TX_MLSC)
    vin[]                standard
    conditions_root      uint256
    vout[]               TX_MLSC output values only
    witness stacks       per-input LadderWitness + MLSCProof
    creation_proof       variable (present iff n_spendable > 2)
**  qabi_block           variable (0 if absent)                    **
**  aggregated_sig       variable (0 if absent)                    **
    locktime             uint32 LE
```

Both fields are serialised as length-prefixed byte vectors
(CompactSize + bytes). A zero-length `qabi_block` or
`aggregated_sig` means "no QABIO content" and is the default for
non-QABIO transactions. Nodes that do not implement QABIO skip
these fields under the anyone-can-spend treatment of v4
transactions (BIP-XXXX § Backwards Compatibility).

### Sighash Algorithm: SIGHASH_QABO

`SIGHASH_QABO` is a dedicated sighash algorithm for the coordinator's
batch signature. It commits to every piece of transaction state that
the coordinator is authorising, without being self-referential.

```
SIGHASH_QABO(tx) = SHA-256(
    tagged_hash("LADDER/QABO",
        version            || locktime             ||
        hashPrevouts       || hashInputWitnesses   ||
        hashOutputs        || qabi_block_bytes
    )
)
```

where:

- `version`, `locktime` — 4-byte LE fields from the tx header;
- `hashPrevouts` — double-SHA-256 over the concatenation of every
  `vin[i].prevout` (txid || vout), in order;
- `hashInputWitnesses` — double-SHA-256 over the concatenation of
  every input's `scriptWitness.stack` serialised as
  `CompactSize(stack.size()) || each_item_with_length_prefix`.
  This is the critical commitment that makes the sig "atomic":
  substituting any witness stack of any input invalidates the
  coordinator's signature over the whole batch;
- `hashOutputs` — double-SHA-256 over the concatenation of every
  `vout[i]` serialised as (nValue || scriptPubKey_length_prefix ||
  scriptPubKey);
- `qabi_block_bytes` — the raw bytes of `tx.qabi_block`.

`SIGHASH_QABO` deliberately excludes `tx.aggregated_sig` itself
(otherwise the signature would be self-referential).

The evaluator computes `SIGHASH_QABO` identically for every input
of a batch-spend transaction — all inputs share the same
`tx.vout`, the same `tx.qabi_block`, the same witness stacks, and
the same prevouts — which is why the verification can be cached.
The first input pays the FALCON verification cost; every subsequent
input of the same transaction hits the cache entry.

### Replace-By-Depth (RBD) Mempool Policy

QABIO introduces a dedicated mempool replacement rule for
QABI_PRIME transactions. RBD replaces the usual BIP-125
Replace-By-Fee for priming because priming cost is not a
fee-auction — it is a depth commitment, and the natural monotone
quantity to compare is `prime_depth`, not fee rate.

#### Rule

A participant can replace their own primed transaction in the
mempool by submitting a new QABI_PRIME transaction with the same
spent UTXO and a strictly greater `prime_depth`. The old
transaction is evicted, the new one takes its slot, and the UTXO
ends up committed to the deeper state.

Specifically, a new QABI_PRIME transaction `T_new` replaces an
existing in-mempool QABI_PRIME transaction `T_old` if and only if
all of the following hold:

1. `T_new` and `T_old` spend the same prevout (same UTXO).
2. Both transactions' input 0 is a QABI_PRIME witness (the QABIO
   priming path).
3. `T_new.prime_depth > T_old.prime_depth` (strictly greater).
4. `T_new.fee_rate >= T_old.fee_rate` (new transaction must at
   least match the old fee rate — prevents free replacement spam).
5. `T_new.size <= T_old.size * 1.1` (size can grow by at most 10%
   to allow for depth-encoding differences — prevents size-attack
   spam).

Rule 1 prevents cross-UTXO replacement. Rule 2 prevents
non-priming transactions from replacing priming transactions (or
vice versa). Rule 3 is the core of RBD — depth replaces fee.
Rules 4 and 5 are anti-spam guards inherited in spirit from BIP-125.

#### Rationale

Without RBD, a participant cannot re-aim their commitment if the
coordinator announces a revised batch before their first priming
transaction confirms. They would have to either:

- Wait for confirmation and then submit a second priming
  transaction (adding one block of latency and one extra on-chain
  priming tx per re-aim);
- Pay the coordinator to delay the batch (creating a perverse fee
  pressure on coordinators);
- Accept being excluded from the revised batch entirely.

RBD eliminates all three. A revised priming transaction at greater
depth evicts the stale one, the UTXO ends up committed to the
coordinator's revised root, and no extra on-chain transaction is
needed. The monotonicity of `prime_depth` prevents an attacker from
replacing a genuine priming transaction with a shallower one, and
the fee-rate floor prevents free replacement spam.

## Rationale

### Why FALCON-512 specifically?

The coordinator signature is hardcoded to FALCON-512. The
`QABI_COORDINATOR_PUBKEY_SIZE = 897` and `QABI_AGGREGATED_SIG_MAX =
666` constants are baked into the consensus evaluator. Other NIST
post-quantum schemes are not currently usable for QABIO.

The choice is driven by size, not security level. FALCON-512 has
the smallest signature and public key of any NIST-standardised
post-quantum signature scheme:

| Scheme       | Pubkey    | Signature | Security class |
|--------------|-----------|-----------|----------------|
| FALCON-512   | 897 B     | 666 B     | NIST 1         |
| FALCON-1024  | 1,793 B   | 1,280 B   | NIST 5         |
| DILITHIUM3   | 1,952 B   | 3,293 B   | NIST 3         |
| SPHINCS+-S   | 32 B      | 7,856 B   | NIST 1         |

Because the coordinator signature is a fixed per-transaction
overhead amortised across every primed input, smaller is strictly
better for amortised per-input cost. At N=100 primed inputs, the
difference between FALCON-512 (666 B sig) and SPHINCS+-S (7856 B
sig) is 72 bytes amortised per participant — roughly half of the
entire non-amortised QABI_SPEND witness overhead. At N=10 the
difference is 719 bytes per participant — enough to make SPHINCS+-S
strictly worse than one N=1 QABIO transaction per participant.

Signature aggregation is not available for any NIST-standardised
post-quantum scheme (aggregation research exists but is not
production-ready). Until a post-quantum aggregatable scheme is
standardised, FALCON-512 is the only viable choice for a
bandwidth-efficient N-party batch primitive.

A future `QABI_BLOCK_VERSION = 0x02` could unlock scheme selection
via a dispatch byte in the qabi_block header. The design leaves
room for this — `QABI_BLOCK_VERSION_CURRENT` is already a field in
the block header — but no such extension is wired in v1. Activating
a new scheme requires a future soft fork.

### Why auth_tip is committed at creation, not priming?

An alternative design would commit `auth_tip` only at priming time,
allowing a participant to rotate their hash chain without creating
a new UTXO. This was rejected because it breaks the "SIG escape
always works" invariant.

If `auth_tip` could be rotated, then priming-time mutation of the
QABI_SPEND rung could produce a Merkle leaf that differs from the
pre-priming leaf. Consensus would then reject any spend that
reveals the old leaf — including the SIG escape path, because the
MLSC proof for Rung 0 depends on the full leaf set reconstructing
to the committed root. A participant who primed at one `auth_tip`
and then wanted to sweep via the SIG rung would find their
recovery path broken.

Committing `auth_tip` at creation time means the participant's hash
chain is fixed for the UTXO's entire lifetime. Rung 0's leaf is
independent of the hash chain, so the SIG escape path is
invariant under any number of priming mutations. A participant can
prime N times (via Replace-By-Depth) and escape the last primed
state at any point without their recovery path being affected.

### Why per-input QABI_SPEND witness + tx-level aggregated sig?

An earlier design had the aggregated signature serialised
per-input as part of the QABI_SPEND witness stack. This was
rejected for two reasons:

1. **Wire-level redundancy.** All N primed inputs of the same
   transaction share the same signature. Storing it N times in the
   witness bloats the transaction by `666 * (N-1)` bytes with zero
   consensus gain.

2. **Sighash binding.** A tx-level signature that commits to
   `hashOutputs + hashInputWitnesses + qabi_block` is the cleanest
   way to enforce that every input of a batch tx was authorised by
   the same coordinator for the same output set. Per-input
   signatures would require complex cross-input commitments or
   introduce a batch-level verification step outside the normal
   input evaluation flow.

The current design places `aggregated_sig` as a tx-level field
alongside `qabi_block` (both are weight-discounted witness data
under flag 0x02) and requires QABI_SPEND evaluation to compute
`SIGHASH_QABO` and verify against the tx-level signature. The
verification is cached across inputs via the per-tx `qabo_sig_cache`
in the evaluator context — first input computes + verifies, every
subsequent input hits the cache.

### Why check 8 enforces byte-exact output match?

Check 8 requires `tx.vout` to be bit-exact equal to
`qabi_block.outputs` — same count, same order, same values, same
scriptPubKeys. A weaker check (e.g. "same set" or "same
participant_id → destination mapping") would leak edge cases.
Consider:

- **Reordering.** If outputs could be reordered, the coordinator
  could swap participant A's output into a later slot, changing
  the fee-accounting for the CPFP-fee-bumping logic downstream.
- **Value aggregation.** If two entries with the same
  `destination_index` could be collapsed into a single output, the
  coordinator could combine two participants' funds into one
  output they control.
- **Extra outputs.** If outputs could be appended after the
  qabi_block list, the coordinator could add their own payout
  output with the fee dust.

The byte-exact match eliminates all of these. Any divergence — one
byte anywhere in any output — invalidates the transaction. Check 8
is the single consensus rule that closes the coordinator-skim hole,
and its bite is why the coordinator is trust-minimised: they see
the exact transaction they will be committing to, they know they
cannot modify it after signing, and consensus enforces it on every
primed input without exception.

### Why committed_depth + 1 for spend preimage?

The spend preimage must be at depth `committed_depth + 1`, strictly
deeper than the priming preimage. Not `committed_depth`, not
`committed_depth + K`, specifically one deeper. Three reasons:

1. **Replay prevention across prime-spend cycles.** If a UTXO were
   re-primed (via RBD or a second priming transaction), the spend
   preimage must strictly differ from any previous spend authorisation.
   Tying it to `committed_depth + 1` makes "the preimage for this
   specific primed state" a unique value per priming.
2. **No ambiguity in the hash-chain walk.** A single deterministic
   depth means the evaluator knows exactly how many SHA-256
   iterations to perform to reach `auth_tip`. Variable depths would
   require the witness to carry the depth and would open a
   parameter-confusion surface.
3. **Bounded verification cost.** The hash-chain walk is
   `committed_depth + 1` iterations. The evaluator caps
   `committed_depth` at `10 * QABI_AUTH_CHAIN_DEFAULT_LENGTH` to
   bound the per-input verification work.

### Why QABI_PRIME has no conditions fields?

QABI_PRIME is a marker block in conditions context with zero
committed fields. Its sole role in the Merkle tree is to say
"priming can fire here". All the actual state for priming — the
target root, the new depth, the new expiry, the preimage proof —
lives in the witness, because those are revealed and authorised
only at priming time. Committing any of them at creation would
prevent the UTXO from being used for any future batch.

The covenant mutation produced by QABI_PRIME is bounded in exactly
one direction: it mutates three specific fields of the QABI_SPEND
rung in the same tree, to specific values supplied in the witness,
with consensus verifying the reconstructed root bit-exact against
the output's scriptPubKey. No other rungs are touched. The
QABI_SPEND rung is the only target; no other covenant mutations
are expressible.

## Comparison with Existing Proposals

| Proposal                  | N-party? | Trust-minimised?       | Post-quantum? | Amortised per-input cost |
|---------------------------|----------|------------------------|---------------|--------------------------|
| Multisig / FROST / MuSig2 | Yes      | If threshold satisfied | No            | ~68 vB (Schnorr)         |
| CoinJoin / WabiSabi       | Yes      | Non-custodial, liveness-dependent | No (per-input Schnorr) | ~120 vB |
| CheckTemplateVerify (CTV) | Yes      | Yes                    | No            | ~80 vB (with commitment) |
| ANYPREVOUT (BIP-118)      | Yes      | Yes                    | No            | ~70 vB                   |
| QABIO                     | Yes      | Yes                    | Yes           | ~162 vB (asymptotic)     |

QABIO is the only post-quantum entry in this list, and is the
only construction that combines:

- N-party batching without interactive key generation;
- Unilateral participant escape at every state;
- No coordinator custody of funds;
- Atomic settlement (partial acceptance is impossible);
- Byte-exact output match (coordinator cannot skim);
- Mempool replace-by-depth for pre-confirmation re-aiming.

The ~162 vB/input asymptotic cost is higher than classical
Schnorr-based constructions because the FALCON signature and
coordinator pubkey are 1,563 bytes of fixed overhead per transaction
(compared to 64 bytes for a Schnorr multisig signature).
Cross-over points where QABIO becomes cheaper than N independent
CoinJoin-style spends:

- vs. 1 CoinJoin per participant: N > 1 (immediate win).
- vs. 1 FROST/MuSig2 transaction per participant: N > 5.
- vs. ANYPREVOUT-style 1-signer-per-output: N > 12.
- vs. an optimal hypothetical Schnorr batching primitive: never
  — the PQ overhead is the permanent cost of post-quantum security.

## Size and Scale

Measured on v1 QABIBlock format with FALCON-512 coordinator
signature, 1-rung MLSC proof per input, per-input LadderWitness
carrying the full QABI_SPEND block:

| participants | qabi_block | tx bytes  | vsize    | block %   |
|--------------|-----------:|----------:|---------:|----------:|
| 10           | 1,659      | 5,946     | 2,034    | 0.20 %    |
| 100          | 8,139      | 44,556    | 16,547   | 1.65 %    |
| 500          | 37,437     | 216,658   | 81,175   | 8.12 %    |
| 1,000        | 74,437     | 432,160   | 162,051  | 16.21 %   |
| 2,000        | 148,437    | 863,160   | 323,801  | 32.38 %   |
| 3,000        | 222,437    | 1,294,160 | 485,551  | 48.56 %   |

Asymptotic cost is ~432 bytes per participant, converging from N=50
upward. After witness discount: ~162 vbytes per participant.

There are three binding ceilings on the maximum number of
participants in a single QABIO batch:

- **Standard-relay (`MAX_STANDARD_TX_WEIGHT = 400,000 WU`).** Binds
  at roughly **618 participants**. Batches above this do not
  propagate through normal p2p relay and must be submitted
  directly to a mining pool (Stratum V2 selection, private API, or
  cooperative pool agreement).
- **QABIO block cap (`QABI_BLOCK_MAX_HARD = 256 KB`).** Binds at
  roughly **3,500 participants**. This is the `qabi_block`
  serialised-size limit.
- **Block weight (`MAX_BLOCK_WEIGHT = 4,000,000 WU`).** Binds at
  roughly **6,100 participants** — an absolute ceiling since a
  single transaction cannot exceed the weight of an entire block.
  In practice the qabi_block cap binds first.

The coordinator signature (666 bytes) and pubkey (897 bytes) are
fixed-size overheads amortised across every participant. Their
relative share drops from 38% of the total transaction at N=10 to
under 0.5% at N=500.

### Verification cost

FALCON-512 verification of a single signature costs roughly 2 ms
on commodity hardware (measured on an x86-64 @ 3.6 GHz with liboqs
0.10.1). QABIO caches this across all inputs of a batch via the
per-transaction `qabo_sig_cache`, so the amortised per-input cost
converges to the cost of the hash-chain preimage verification
(~10 µs) plus the cached sig lookup (~1 µs) plus per-input field
validation (~4 µs).

Measured end-to-end per-input verification costs:

- **N = 1 (no cache benefit):** ~4.1 ms / input.
- **N = 10:** ~410 µs / input.
- **N = 100:** ~41 µs / input.
- **N = 1,000:** ~4.1 µs / input (cache-dominated).

The ~5× speedup from caching at N=1000 is what makes QABIO
verification viable at scale. Without the cache, a 3,000-input
QABIO block would take ~12 seconds to validate, far above the
block-propagation budget. With caching it drops to ~12 ms.

## Backwards Compatibility

### Soft Fork on Top of Ladder Script

QABIO activates as a soft fork on top of the Ladder Script soft
fork (BIP-XXXX). Nodes that have activated Ladder Script but not
QABIO will:

- Recognise `QABI_PRIME` (0x0A01) and `QABI_SPEND` (0x0A02) as
  valid block type codes in the Ladder Script type space;
- Treat them as returning UNSATISFIED (unknown new block types —
  the standard soft-fork forward-compatibility rule for Ladder
  Script);
- Skip the `tx.qabi_block` and `tx.aggregated_sig` fields on the
  wire, treating non-empty values as "unknown witness data under
  flag 0x02 extensions".

This matches the anyone-can-spend treatment already used for v4
transactions by pre-Ladder-Script nodes: old nodes see QABIO
transactions as valid Ladder Script transactions (same wire prefix,
same flag byte), but cannot validate the QABIO-specific consensus
rules. Upgraded nodes enforce the full QABIO rules.

Activation of QABIO without Ladder Script is not valid. A node
cannot implement QABIO without implementing the Ladder Script base
layer because QABIO's block types, MLSC proof structure, conditions
tree format, and witness wire layout all depend on BIP-XXXX.

### No Impact on Non-QABIO Transactions

Transactions whose `qabi_block` field is empty (or absent) are
treated as non-QABIO transactions. All QABIO-specific consensus
checks are bypassed. A v4 Ladder Script transaction that does not
use QABI_SPEND as any input's active rung is unaffected by QABIO
activation — the `qabi_block` and `aggregated_sig` fields are
serialised as zero-length CompactSize prefixes and add 2 bytes to
the tx footprint.

### Wallet Compatibility

QABI-enabled UTXOs are MLSC UTXOs with a 3-rung conditions tree.
Wallets that understand MLSC outputs but not QABIO can still detect
the output as spendable, but cannot construct the QABI_PRIME or
QABI_SPEND witness. They can spend via Rung 0 (SIG escape) as a
normal SIG rung. This means a pre-QABIO wallet holding a primed
UTXO can still recover it unilaterally, but cannot participate in a
batch spend.

## Activation

QABIO activates as a distinct soft fork with its own activation
signal, conditional on Ladder Script (BIP-XXXX) having already
activated. The activation mechanism (BIP-9 signalling or BIP-8
mandatory activation) is outside the scope of this specification.
A reasonable deployment path:

1. BIP-XXXX (Ladder Script) activates via its own soft-fork
   process.
2. QABIO spends a warm-up period as a non-standard feature — nodes
   implement it but treat QABI_SPEND as UNSATISFIED, so no one can
   actually batch-spend. This gives the ecosystem time to
   implement and test QABIO without risking consensus splits.
3. QABIO activates via its own BIP-8 signal, at which point
   QABI_SPEND becomes consensus-enforceable and live batches can
   settle.

This staged approach decouples Ladder Script activation from QABIO
activation risk. If QABIO discovers a critical issue during the
warm-up period, the correction is a patch to QABIO's activation
signal — the base Ladder Script consensus remains live and
unaffected.

## Reference Implementation

All QABIO source lives in the bitcoin-core-ladder repository (a
fork of Bitcoin Core v30.0). Key files:

| File                          | Description |
|-------------------------------|-------------|
| `src/rung/qabi.{h,cpp}`       | `QABIBlock` serialisation, `ParseQABIBlock`, `ComputeAuthChainTip`, `ComputeAuthChainPreimageAt`, `ComputeSighashQABO` |
| `src/rung/evaluator.cpp`      | `EvalQABIPrimeBlock`, `EvalQABISpendBlock`, `QABOSigCache` integration in `VerifyRungTx` |
| `src/rung/rpc.cpp`            | `createtxmlsc` with `qabi_block` parameter, `generatepqkeypair`, `qabi_authchain`, `qabi_buildblock`, `qabi_blockinfo`, `qabi_sighash`, `qabi_signqabo`, `QABI_SPEND` case in `BuildWitnessBlock`, `QABI_PRIME` case in `BuildWitnessBlock` |
| `src/rung/types.h`            | `RungBlockType::QABI_PRIME`, `RungBlockType::QABI_SPEND`, `QABI_PRIME_WITNESS`, `QABI_SPEND_CONDITIONS`, `QABI_SPEND_WITNESS` implicit layouts |
| `src/rung/policy.cpp`         | `IsReplaceByDepthQabiPrime`, `CheckReplaceByDepthQabiPrime` |
| `src/rung/serialize.cpp`      | `qabi_block` / `aggregated_sig` wire serialisation, `PUBKEY_COMMIT` carve-out for QABI_SPEND conditions |
| `src/validation.cpp`          | `QABOSigCache` plumbing into `CScriptCheck::operator()` |
| `src/pq/pq_verify.cpp`        | FALCON-512 verification via liboqs |

Test coverage:

- **77 unit tests** in the `qabi_tests` suite covering all 9
  consensus checks, QABOSigCache amortisation, multi-party scale
  testing up to N = 3,000, the SIG escape rung end-to-end, and
  RBD policy rules.
- **Functional regression tests** in `test/functional/feature_qabi.py`
  exercising the full mined priming lifecycle, the SIG escape
  after priming, and reorg survival on a regtest node.
- **Live-signet end-to-end tests** via the QABIO Playground at
  `ladder-script.org/qabio-playground.html`. The playground
  constructs and broadcasts full N-party QABIO transactions on
  the ladder-script signet via the `/api/ladder/qabi/*` JSON
  endpoints.

## Test Vectors

### Vector 1: Auth chain construction

```
auth_seed        : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
chain_length     : 50
auth_tip         : 3ce78481b200bcb12ae2270ffd8c89255883f0f384e5b8a93ffbe6ce0065ffab
preimage@depth=10: f8f4d1e3a09d2c1e6b7ad5c4928f0c4e5e8a3a7a1d5f0e2b8c4a9b6d7e3f1c0a
preimage@depth=0 : 3ce78481b200bcb12ae2270ffd8c89255883f0f384e5b8a93ffbe6ce0065ffab (== auth_tip)
```

Display order (uint256::GetHex). To recover raw bytes for
conditions fields, reverse each hex string bytewise.

### Vector 2: SIGHASH_QABO determinism

```
tx version       : 4
locktime         : 0
hashPrevouts     : <sha256d of concatenated prevouts>
hashInputWitnesses: <sha256d of concatenated witness stacks>
hashOutputs      : <sha256d of concatenated CTxOut serialisations>
qabi_block_bytes : <raw bytes of tx.qabi_block>
---
sighash_qabo     : TAG("LADDER/QABO", version || locktime ||
                      hashPrevouts || hashInputWitnesses ||
                      hashOutputs || qabi_block_bytes)
```

The sighash is computed identically for every input of a given
transaction (it has no per-input component), which is why cache
lookup by sighash short-circuits the FALCON verification across
inputs.

### Vector 3: Live signet validation

QABIO transactions broadcast and mined on the ladder-script
signet chain during reference implementation validation:

- **Single-participant batch:** txid
  `571223eb692aabb55b2c248d6a55af5dd8e804a7eda00d0908eadef3bbca49c4`
  — full 3-rung QABI UTXO, primed via QABI_PRIME covenant, batch-
  spent via QABI_SPEND with FALCON-512 aggregate signature.
- **Three-participant batch:** txid
  `12a7e7e3e99a044be1fdbed1fec8e2bc46a2ea5d1096adde0df8df3eb96991a4`
  — 3 independent primed UTXOs, single coordinator FALCON-512
  signature, one atomic settlement.

Both transactions are fully decodable via `decoderawtransaction`
on any bitcoin-core-ladder node and can be re-verified via
`testmempoolaccept` against a fresh chain state.

## Security Considerations

### Coordinator trust surface

The coordinator is trusted for:

- **Correctness of the batch assembly.** A dishonest coordinator
  can refuse to assemble a batch, delay the batch, or assemble a
  batch with a wrong participant set. Participants retain the SIG
  escape path at all times, so the worst-case outcome is "no batch
  happens, everyone recovers individually".
- **Availability.** A coordinator that goes dark after priming
  leaves participants in the primed state until they invoke
  escape. The `committed_expiry` field gives a hard deadline: after
  that height, the UTXO auto-reverts to being unspendable via
  QABI_SPEND, and the participant must escape via SIG.

The coordinator is NOT trusted for:

- **Custody.** Participant funds never enter the coordinator's
  control. Consensus check 8 enforces that the outputs in the batch
  transaction match what was committed in the signed qabi_block.
- **Post-signing modification.** `SIGHASH_QABO` commits to
  `hashOutputs`, `hashInputWitnesses`, and `qabi_block_bytes`.
  Any modification to any of these fields after signing invalidates
  the signature and the transaction is rejected.
- **Selective settlement.** Consensus rejects the whole transaction
  if any single input fails any check. There is no partial
  settlement path the coordinator could use to drop individual
  participants while keeping others.

### Pre-image revelation timing

When a participant broadcasts their QABI_PRIME transaction, they
reveal one preimage from their auth chain (at `prime_depth`). Any
observer can see this preimage, but the chain design ensures it
provides no useful attack surface:

- Earlier-depth preimages are not derivable (that would require
  inverting SHA-256).
- Later-depth preimages are derivable by applying SHA-256 forward,
  but the evaluator requires a preimage at exactly
  `committed_depth + 1` for QABI_SPEND — strictly deeper than any
  previously revealed preimage. Forward-derived preimages are
  already stale.

The only "attack" available from observing a revealed preimage is
predicting the participant's *next* priming depth (by extrapolating
the `prime_depth` bump). This has no consensus-relevant
consequence; it is purely an observability property.

### Replay across chains / forks

An `auth_seed` bound to a QABI_SPEND rung with a specific `auth_tip`
is consensus-valid only on chains where the committed conditions
tree reconstructs to the exact same MLSC root. Replaying the same
priming transaction across forks requires both forks to have the
same creation-time UTXO state, which is itself a prerequisite for
any UTXO-level replay attack — QABIO does not introduce a novel
replay surface.

### Sighash binding completeness

`SIGHASH_QABO` commits to:

- Transaction structure (version, locktime, prevouts, outputs).
- Every input's witness stack contents (via `hashInputWitnesses`).
- The full `qabi_block` byte sequence.

It does NOT commit to:

- `tx.aggregated_sig` itself (self-referential).
- The block header or confirmation height (by design — a sig that
  authorises a batch must be valid regardless of which block it
  lands in).

An attacker who observes a partially-built QABI batch in the mempool
cannot modify any committed field without invalidating the
coordinator's signature. They CAN rebroadcast the same transaction
unchanged (no modification → no signature invalidation), but this
is a no-op.

### Post-quantum cryptographic dependency

FALCON-512 verification requires a post-quantum signature library.
The reference implementation uses liboqs, which is already a hard
build dependency of base Ladder Script (BIP-XXXX) because the base
`SIG` block supports FALCON-512, FALCON-1024, Dilithium3, and
SPHINCS+ as consensus-critical signature schemes. QABIO reuses the
same FALCON-512 verification path as the base SIG block and adds no
new cryptographic primitives — a node that can validate a FALCON-512
`SIG` spend under base Ladder Script can also validate a QABIO
coordinator signature, because the underlying `rung::VerifyPQSignature`
call is identical.

Alternative implementations of FALCON-512 must match liboqs's
verification semantics exactly, or a chain split will occur. The
FALCON-512 specification and NIST standardisation artefacts define
the reference behaviour; this BIP does not re-specify the primitive.

### Batch size vs. block-propagation budget

At N=3,000 a QABIO transaction occupies ~49% of a full block. This
is operationally viable but comes with trade-offs: the miner who
includes the transaction sees reduced revenue from other
transactions, and the transaction's propagation time increases
linearly with its size.

Mining pools running cooperative QABIO settlement (e.g. pool
payouts) are expected to coordinate batch broadcasts with their own
block templates to avoid competing with normal fee-paying
transactions for block space. For user-facing batches (exchanges,
payroll), batches should be sized to stay comfortably below the
standard-relay cap (~618 participants) to ensure reliable p2p
propagation.

### Attack paths QABIO does NOT eliminate

In the interest of a complete security analysis, QABIO does not
protect against:

1. **Coordinator front-running.** A coordinator can observe
   incoming QABI_PRIME transactions in the mempool and adjust their
   batch entries before publishing. Participants should prime only
   after the coordinator commits to a public batch root.
2. **Privacy leakage at priming time.** Observers can correlate
   QABI_PRIME transactions with specific participant `owner_id`
   values, linking the participant's UTXO to the batch. QABIO does
   not provide transaction privacy; use CoinJoin-style mixing
   upstream if privacy is a requirement.
3. **Coordinator key compromise.** If the coordinator's FALCON-512
   private key is compromised, an attacker can sign arbitrary
   batches. Participants are protected by the qabi_block ↔
   committed_root binding — only batches they explicitly primed
   against can execute — but the coordinator's ability to assemble
   new batches depends on key security.
4. **Liveness DoS on the coordinator.** A participant who primes
   and then refuses to cooperate cannot block the batch, but a
   coordinator whose participant set has high churn may struggle to
   close out the batch before `committed_expiry`.
5. **Fee sniping on the batch broadcast.** Standard Bitcoin
   fee-sniping protections apply to the batch transaction just
   like any other. Coordinators should use reasonable fee rates.
6. **Consensus bugs in FALCON-512 verification.** A chain split
   could occur if two implementations of FALCON-512 disagree on
   signature validity. The reference implementation uses liboqs;
   alternative implementations are responsible for matching its
   verification semantics exactly.
7. **Timing side-channels on the coordinator's FALCON signing.**
   FALCON-512 signing is not constant-time in liboqs 0.10.x.
   Coordinators should sign on air-gapped hardware or accept the
   timing-leak risk.
8. **Economic attacks on the priming fee.** A coordinator who
   offers zero priming fees can DoS the mempool by asking many
   participants to prime with minimum fee, then never broadcasting
   the batch. RBD helps (participants can re-prime at a different
   depth or fee rate), but does not fully eliminate this.

## Acknowledgements

QABIO was developed as part of the Ladder Script project. The
consensus evaluator, wire format, and witness-construction handlers
were validated end-to-end against the reference implementation on
the ladder-script signet, exercising the full priming, batch-spend,
and escape lifecycle with N-party coordinators signing live FALCON-512
aggregate signatures.

Thanks to the Bitcoin developer mailing list for feedback on the
base Ladder Script design, which shaped the decision to separate
QABIO into its own BIP.

## Copyright

This document is licensed under the MIT License.
