# BIP-YYYY Hostile Review — Anticipated Questions and Answers

Pre-submission review prep for BIP-YYYY (QABIO). Each entry is framed
as a question a skeptical reviewer is likely to ask, followed by the
strongest answer we can give today. Entries are grouped by severity:
Blockers, Major concerns, and Nits.

## Blockers

### 1. SIGHASH_QABO does not commit to network magic, chain ID, or fork point — cross-chain replay risk
The sighash preimage lists `version || locktime || hashPrevouts ||
hashInputWitnesses || hashOutputs || qabi_block_bytes` and nothing
else. There is no chain-id, no genesis-hash binding, and no
deployment-magic binding. Two chains that share Ladder Script and
QABIO activation (e.g. mainnet, testnet, signet, plus any future
hard-fork descendants) will produce identical sighashes for
identical UTXO topologies. Section "Replay across chains / forks"
hand-waves this by saying replay requires the same UTXO state on
both forks, but the entire point of replay protection is to harden
the case where someone deliberately reproduces equivalent state.
Bitcoin learned this lesson in 2017 with BCH and BIP-143's SIGHASH_FORKID.
**Answer.** The argument the BIP currently makes — that UTXO state
must match for a replay to land — is sound for naturally diverged
chains, but it is not sound when an attacker can deliberately
construct equivalent UTXO state on a hostile fork (e.g. by holding
the original UTXO before the fork point, or by replaying creation
transactions). The safest fix is to bind the tagged hash to a
chain-distinguishing constant. We can do this without breaking the
cache: the tag string already differentiates ("LADDER/QABO") but
should additionally be bound to a 32-byte chain magic the network
sets at activation. Concretely: include `chain_magic` (the
genesis-block hash, as is standard practice) inside the tagged-hash
preimage, ahead of `version`. This costs nothing per-input,
preserves the cache (chain magic is constant per chain), and gives
us strict cross-chain replay protection that survives an attacker
deliberately reproducing UTXO state.
**BIP change needed:** Add `chain_magic` (32 B, genesis hash) as the
first field inside the tagged-hash preimage in the SIGHASH_QABO
definition. Update test vector 2 to show the new ordering. Add a
sentence in "Replay across chains / forks" explaining that
`chain_magic` provides defence-in-depth even when an attacker
deliberately reproduces equivalent UTXO state.

### 2. The 9 consensus checks reference state that is not formally defined before they are used
Check 5 reads `parsed.coordinator_pubkey`. Check 7 reads
`parsed.entries[*].participant_id`. Check 8 reads `parsed.outputs`.
Check 9 reads `parsed.prime_expiry_height`. All four come from the
output of `ParseQABIBlock(ctx.tx->qabi_block)`, but `ParseQABIBlock`
is referenced as a function whose semantics live in the reference
implementation — it is not defined in the BIP itself. The wire
format struct is given, but the parser's failure modes (oversize,
truncated, version mismatch, malformed CompactSize, duplicate
participant_id, destination_index out of range) are not. A second
implementation that parses defensively could disagree with liboqs
on, e.g., a malformed CompactSize at offset 38 — and that
disagreement is a chain split.
**Answer.** This is a real specification gap. Two independent
implementations will agree on `FALCON-512_Verify`, but they will
not necessarily agree on what counts as "well-formed" for
QABIBlock unless we enumerate every parser failure mode and assign
each one to ERROR or UNSATISFIED. We need a dedicated
"QABIBlock parsing" subsection that lists, in order: (a) version
byte must equal `QABI_BLOCK_VERSION_CURRENT` (0x01) → UNSATISFIED;
(b) every CompactSize must be canonical (shortest encoding) →
ERROR; (c) `n_entries` and `n_outputs` bounded by qabi_block size
budget → ERROR; (d) every `destination_index` in
`[0, n_outputs)` → ERROR; (e) `participant_id` set must be unique
(no duplicate within one block) → ERROR; (f) sum of `contribution`
fields must not overflow int64 → ERROR; (g) trailing bytes after
final field → ERROR. Without this enumeration, any of the 9 checks
that reads from `parsed.*` is implicitly ill-defined.
**BIP change needed:** Add a "QABIBlock Parsing" subsection between
"The QABIBlock Wire Format" and "Size Limits" that enumerates every
parser failure mode and its ERROR/UNSATISFIED classification. Move
the field-shape, ordering, and canonicality requirements from the
implementation into the spec.

### 3. Check 8 enforces output equality but does NOT enforce input equality — coordinator can stuff free inputs
Check 8 says `tx.vout` must be byte-exact equal to
`qabi_block.outputs`. There is no equivalent check that
`tx.vin` is byte-exact equal to a list inside the qabi_block. The
qabi_block carries `entries[]` with `participant_id` and
`contribution`, and check 7 verifies that each spent input's
`owner_id` appears in the entry list — but there is no check that
every entry corresponds to a spent input, and no check that no
extra inputs exist beyond those entries. The coordinator can append
arbitrary additional inputs to the transaction (their own UTXOs,
or someone else's UTXOs they have authority to spend) without
invalidating SIGHASH_QABO, because hashPrevouts and
hashInputWitnesses are committed and the coordinator simply
includes those extra inputs in their signature. The extra inputs
contribute their value to the transaction's input total, and check
8 only enforces output equality — there is no value-conservation
check that ties total input value to total output value at the
QABIO layer. The coordinator can therefore (a) sneak in their own
input to fund a fee bump, which is benign, but also (b) drain a
coerced input from a wallet they have non-QABIO authority over
into a QABIO batch where the participant set looks legitimate.
More subtly, since check 7 only asks "does this owner_id appear
in entries[]", a coordinator could add a second input with the
same owner_id — duplicating one participant — and consensus would
let it pass, double-counting one participant against one entry.
**Answer.** This is a real hole and we need to plug it. Two
additions: (1) add a check that the multiset of spent inputs'
owner_ids equals the multiset of entries[].participant_id —
currently the BIP only checks subset-membership in one direction;
(2) add a check that every QABI_SPEND-rung input's contribution
matches a unique entries[] slot, with no entry consumed twice.
This eliminates double-counting and ensures the coordinator cannot
add inputs not committed to in the qabi_block. Note that
non-QABIO inputs (e.g. a coordinator-owned plain SIG input used to
top up the fee) are not necessarily problematic, but they should
be opt-in via an explicit `coordinator_inputs[]` list in the
qabi_block, not silently allowed.
**BIP change needed:** Add a 10th consensus check that asserts
multiset equality between `{vin[i].owner_id : vin[i] uses
QABI_SPEND rung}` and `{entries[j].participant_id}`. Add an 11th
check that asserts every entry is consumed by exactly one input.
Document explicitly that non-QABI_SPEND inputs in the same tx are
either forbidden or constrained to a separate `coordinator_inputs[]`
list. Update §6 ordering so the new checks run before
sig verification.

### 4. Replace-By-Depth interacts badly with package relay and BIP-125 RBF
RBD allows a participant to evict their own QABI_PRIME tx by
submitting a deeper-prime version. But what about CPFP children?
A participant could prime, then a third party could attach a
fee-bumping child (legitimate CPFP), then the participant could
RBD-replace the parent — orphaning the child without a fee refund
to the third party. Worse: what if a tx is BOTH a QABI_PRIME (for
its rung 1 input) AND has descendants that RBF themselves under
BIP-125? Two replacement policies now apply to overlapping txs in
the mempool, and the BIP does not specify which wins. Package
relay (BIP-331) makes this worse: a package containing a
QABI_PRIME parent and a non-RBF child would have to be evaluated
under both RBD (for parent eviction) and the package's own
replacement rules (for total package fee).
**Answer.** RBD as currently specified is mempool-only and applies
strictly to QABI_PRIME→QABI_PRIME replacement of the same prevout.
We need to: (a) explicitly state that RBD does not apply to a
QABI_PRIME tx that has any in-mempool descendants — replacement is
refused if descendants exist, just like BIP-125 rule 2; (b) state
that RBD is mutually exclusive with BIP-125 RBF on the same tx —
a QABI_PRIME tx is RBD-eligible and not RBF-eligible (or vice
versa, but not both); (c) state that a package containing a
QABI_PRIME parent inherits the parent's RBD-or-RBF disposition for
the whole package; (d) require the QABI_PRIME tx to be a leaf in
its mempool subtree at replacement time. This is conservative and
loses some flexibility (CPFP fee-bumping primings becomes
impossible), but it eliminates the cross-policy ambiguity that
would otherwise be a footgun for wallet implementers.
**BIP change needed:** Add a subsection "RBD interaction with
BIP-125 and BIP-331" specifying the four constraints above. Add an
explicit rule 6 to the RBD list: `T_old` must have no in-mempool
descendants. Update the rationale to acknowledge the loss of CPFP
flexibility and explain why predictability matters more than
flexibility for priming churn.

### 5. The covenant rebuild in check 4 is not deterministic across implementations
Check 4 of QABI_PRIME says: rebuild the conditions tree with
`committed_root`, `committed_depth`, `committed_expiry` mutated to
witness values, recompute the MLSC Merkle root, compare against
`tx.vout[0].scriptPubKey[1..33]`. The rebuild requires
re-serialising the QABI_SPEND rung's 5 conditions fields including
`PUBKEY_COMMIT` (which is a 32-byte hash, OK) and two NUMERIC
fields (4 bytes each, LE). NUMERIC encoding rules in BIP-XXXX have
historically had ambiguities around variable-width encoding (does
a 4-byte NUMERIC always serialise as 4 bytes LE, or does it
minimal-encode to fewer bytes for values < 2^16?). If two
implementations differ on this — or on any leaf-hash domain
separator, or on tree-padding for non-power-of-two leaf counts —
the recomputed Merkle root will not match, and consensus will
split.
**Answer.** This is a fair concern and the spec needs to nail it
down. Three things must be specified explicitly: (a) NUMERIC
encoding for QABI_SPEND fields is fixed-width 4-byte LE with no
minimal-encoding — the field declares its size and the size is
authoritative; (b) the leaf-hash domain separator for the Merkle
tree is the same one BIP-XXXX uses for MLSC leaves (cite the exact
constant); (c) tree padding for non-power-of-two leaf counts
follows BIP-XXXX's MLSC convention exactly (likely
duplicate-last-leaf, but cite the rule). All three must be
test-vectorised. The BIP currently relies on BIP-XXXX defining
these correctly; if they are well-defined upstream, the fix is
just a normative reference. If they are not well-defined upstream,
they need to be fixed in BIP-XXXX before QABIO can be reviewed.
**BIP change needed:** Add a paragraph in "QABI_PRIME §Evaluation"
that normatively references the BIP-XXXX section defining
NUMERIC fixed-width encoding, leaf-hash domain separator, and
tree padding. Add a test vector showing the byte-exact rebuild for
a small QABI UTXO from raw fields to recomputed conditions_root.

### 6. The "atomic settlement or nothing" claim has a race window between priming and broadcast
Section "Design Overview" claims: "The whole batch settles
atomically in one block or does not settle at all." Section
"Coordinator trust surface" says the coordinator is not trusted
for "selective settlement". But there is a race window:
participant A primes; the coordinator collects A's primed
commitment along with B's, C's, ..., N's; the coordinator signs
the batch; before the coordinator's batch tx mines, A submits a
SIG-rung escape transaction spending the same primed UTXO.
Now the coordinator's signed batch tx is invalid (one of its
inputs is gone). The other N-1 participants are still in their
primed state but have no way to replace input A — they must wait
for the coordinator to re-sign without A. Meanwhile, the
coordinator's signature is now a public artefact authorising a
slightly-different transaction that will never confirm. This is
not technically "partial settlement" (the batch did not partially
settle — it failed entirely), but it is an important liveness
weakness that can be weaponised: any single participant can DoS
the entire batch by escaping at the right moment. The BIP
acknowledges this in passing under "Liveness DoS on the
coordinator" but the framing understates the issue.
**Answer.** This is a real liveness limitation and we should be
explicit about it. The defensive answers are: (a) the coordinator
holds the signed tx privately and broadcasts it as a sealed
package, so the window between sign-and-broadcast is small;
(b) the SIG escape revokes the participant's place in the batch
permanently, so a malicious escape costs the participant their
batch slot — they cannot re-prime into the same batch root
afterwards (`prime_depth` is monotone, so they could re-prime at
a deeper depth, but the coordinator's existing signature would
still be invalidated); (c) the coordinator can simply re-sign
without A and rebroadcast — the cost is one extra FALCON sign,
no new round-trip with participants. None of these eliminate the
race, but together they bound the damage to "one extra coordinator
sign per griefing escape". We should document this explicitly in
Security Considerations and remove the "atomic settlement" framing
from places where it implies liveness rather than just safety.
**BIP change needed:** Add a paragraph in "Coordinator trust
surface" explaining the prime→sign→broadcast race window and the
griefing bound. Soften "atomic settlement or nothing" in the
Abstract to "atomic settlement or no-op" or similar. Add a
specific item to the "Attack paths QABIO does NOT eliminate" list
covering the sign-then-escape griefing pattern.

### 7. Verification cost numbers are not reproducible — no methodology, no hardware spec, no scripts
Section "Verification cost" claims ~4.1 ms uncached, ~4.1 µs
cached at N=1000, with a 5x speedup at scale. The numbers come
from "x86-64 @ 3.6 GHz with liboqs 0.10.1" and that is the entire
methodology. Reviewers will ask: single-threaded? With turbo? With
SMT? Cache cold or warm? What N for the warm-up? What was being
measured — just `EvalQABISpendBlock` or full block validation
including header processing? Was the FALCON-512 verify the
constant-time variant or the speed variant in liboqs? These
numbers are load-bearing for the BIP's scale story (N=3,000 in 12
ms is the headline) and any reviewer who has been burned by
synthetic benchmarks before will insist on reproducibility.
**Answer.** The numbers are real, measured on commodity hardware
during reference-implementation validation, but the BIP currently
publishes them in "trust me" form. We need to: (a) publish the
benchmark script under the reference-implementation tree and
reference it from the BIP; (b) document hardware (CPU model,
clock, SMT on/off, turbo on/off, RAM, OS); (c) document liboqs
version, build flags, and which FALCON variant is compiled in;
(d) document the test methodology (cache cold vs warm, N values
benchmarked, statistics aggregated — mean, p50, p99); (e) measure
on at least two different microarchitectures (Intel + AMD or Intel
+ ARM) to detect microarch-dependent regressions. Without this
the numbers are unfalsifiable and reviewers will discount them.
**BIP change needed:** Replace the "Verification cost" subsection
with reproducible numbers including hardware spec, liboqs build
config, methodology paragraph, and a link to the benchmark script
in the reference implementation. Add p50/p99 in addition to the
mean. Add a sentence on whether the reference implementation uses
the constant-time or speed-optimised FALCON variant.

## Major concerns

### 8. The coordinator pubkey is announced "via whatever out-of-band channel the coordinator prefers" — that is a trust assumption
Section "Actors" says the coordinator's FALCON-512 pubkey is
"published in advance via whatever out-of-band channel the
coordinator prefers". This is stated as a feature of the design's
flexibility but it is actually a trust assumption being smuggled
into the protocol. If a participant primes against the wrong
coordinator pubkey (because the coordinator's website was MITMed,
or because the coordinator advertised one key and signed with a
different one), the participant's primed UTXO is locked until
expiry and can only be recovered via SIG escape. The BIP's
coordinator-trust enumeration ("trusted for: correctness,
availability; not trusted for: custody, modification, selective
settlement") quietly skips "trusted for: pubkey distribution".
**Answer.** The mitigation already exists in the design — the
coordinator pubkey is also embedded in `tx.qabi_block`, and the
participant primes against `committed_root = SHA-256(qabi_block)`,
so the pubkey is implicitly committed by the prime step. A
participant who reconstructs the qabi_block from a coordinator's
publication can verify the pubkey before priming. We should make
this explicit: the coordinator pubkey is not actually OOB-trusted
once priming has happened, because it is bound into the same hash
the participant signs over with their own auth-chain preimage.
The OOB channel only matters for the convenience of fetching the
qabi_block before priming; if the channel is hostile, the worst
outcome is the participant primes against a hostile qabi_block
they thought was the legitimate one — and in that case SIG escape
is still available. We should document this clearly.
**BIP change needed:** Rewrite the "coordinator pubkey is
published in advance via whatever out-of-band channel" sentence to
state explicitly that the pubkey is bound into `committed_root` at
prime time and the OOB channel is convenience, not trust. Add a
paragraph in "Coordinator trust surface" explicitly listing
"pubkey distribution" as a non-trust dependency, with the
rationale.

### 9. The size caps (64 KB soft, 256 KB hard) are not justified
Section "Size Limits" gives `QABI_BLOCK_MAX_SOFT = 65,536` and
`QABI_BLOCK_MAX_HARD = 262,144`. There is zero rationale for why
these specific numbers. Why not 32 KB / 128 KB (more conservative,
binds at ~1750 participants — still above realistic exchange
batch sizes)? Why not 128 KB / 512 KB (more headroom)? The
numbers look like power-of-two constants chosen for aesthetic
reasons, not derived from any analysis. Reviewers will flag this
because consensus constants must always have a defended provenance.
**Answer.** The numbers were chosen to (a) keep the standard-relay
soft cap below MAX_STANDARD_TX_WEIGHT/4 so a QABIO tx can never
single-handedly fill standard-relay budgets, (b) keep the
consensus hard cap at exactly 1/16 of MAX_BLOCK_WEIGHT (256 KB ≈
1 MWU at 4:1 discount), giving a comfortable headroom for the
non-qabi_block portion of the tx, and (c) align with power-of-two
sizes for memory-allocation friendliness in the parser. We should
document this. We should also explicitly note that the hard cap
is not the binding ceiling on participant count in practice — the
standard-relay-weight cap binds first, at ~618 participants, well
below the 3,500 the qabi_block hard cap allows. The hard cap
exists as a defence-in-depth bound, not as the primary ceiling.
**BIP change needed:** Add a "Rationale for size constants" inset
in §Size Limits that explains the four numbers (soft, hard,
pubkey, sig) and which ceiling binds in practice. Add a sentence
noting that the hard cap is defensive, not operational.

### 10. The privacy analysis is one paragraph and incomplete
Section "Pre-image revelation timing" mentions that observers can
correlate priming with participant identity, but the analysis is
shallow. Let me enumerate what an observer learns at each step:
(a) at UTXO creation, the auth_tip is committed to the conditions
tree as a HASH256 — observable and unique per participant; (b) at
priming, the participant reveals `prime_preimage`, links it to the
auth_tip via the chain, and reveals `prime_depth`, `committed_root`,
and `committed_expiry` in the witness — all observable; (c) at
batch spend, the spend_preimage is revealed plus the entire
qabi_block including all entries[] participant_ids and outputs;
(d) the SIG escape, if used, reveals the participant's signing
pubkey via the standard signature path. The result is that any
observer can correlate (creation, priming, batch spend) into a
single linked transaction graph for every participant in every
QABIO batch, including total contribution and final destination
address. This is worse than a CoinJoin because it has no
indistinguishability set.
**Answer.** This is correct and the BIP should be honest about it.
QABIO is not a privacy primitive — it is a settlement primitive,
and the design intentionally trades privacy for trust-minimised
batch authorisation. The privacy story should be: "use QABIO for
non-sensitive batch settlement (payroll, exchange withdrawals,
mining payouts) where the participants are already known to the
coordinator. Use CoinJoin upstream if you need transaction-graph
privacy on the inputs, or downstream if you need to obfuscate
outputs." The current Security Considerations section says "QABIO
does not provide transaction privacy; use CoinJoin-style mixing
upstream if privacy is a requirement", which is correct but
buried. We should expand it into a numbered list of what an
observer learns at each step, so reviewers cannot accuse us of
hand-waving.
**BIP change needed:** Replace "Privacy leakage at priming time"
in the "Attack paths QABIO does NOT eliminate" list with a fuller
"Observable leakage by lifecycle step" subsection in Security
Considerations, enumerating creation, priming, batch spend, and
SIG escape leakage. State explicitly that QABIO is not a privacy
primitive and link to CoinJoin/WabiSabi as the appropriate
complementary tool.

### 11. FALCON-512 at NIST 1 is sufficient for "billions in flight"? Show the work
The BIP justifies FALCON-512 on size grounds (smallest signature
of any NIST-standardised PQ scheme) and asserts NIST 1 security
class without further argument. NIST 1 is "256 classical / 128
quantum" security — broadly equivalent to AES-128. For a
consensus-layer signature that may end up authorising
multi-million-dollar settlement batches, reviewers will want a
defended security argument. Why not FALCON-1024 (NIST 5, ~AES-256
equivalent)? The size delta is 614 bytes per signature plus 896
bytes per pubkey — at amortised cost across N=100, that is
roughly 15 vbytes per participant, a 9% increase in per-input cost
in exchange for a 128-bit-quantum bump.
**Answer.** This is a defensible call but we need to show the
work. NIST 1 (~128-bit quantum security) is the same level as
the BIP-XXXX base SIG block accepts for FALCON-512, so QABIO is
not introducing a weaker primitive than already exists in the
parent BIP. The argument "NIST 1 is sufficient for consensus
signatures" reduces to "NIST 1 is sufficient for any Bitcoin
signature", and that is a Ladder-Script-wide question, not a
QABIO-specific question. We should state explicitly: (a) FALCON-512
is at the same security level as the base SIG block's FALCON-512
mode, so QABIO does not lower the cryptographic floor of Ladder
Script; (b) a future QABI_BLOCK_VERSION = 0x02 can introduce
FALCON-1024 via dispatch byte (the design already mentions this);
(c) the choice is bandwidth-driven, and bandwidth matters because
amortised cost dominates the BIP's value proposition. We should
also cite the FALCON specification's security reduction, which is
based on NTRU lattice problems and has been studied since 2008.
**BIP change needed:** Add a "Security level rationale" paragraph
in "Why FALCON-512 specifically?" with the three points above. Add
a normative reference to the FALCON v1.2 spec's security analysis.
Note explicitly that QABIO inherits the security floor from the
base BIP-XXXX SIG block.

### 12. What if BIP-XXXX activates and BIP-YYYY does not? Are participants stranded?
Section "Backwards Compatibility" addresses the soft-fork-on-soft-fork
case but does not discuss the user-experience consequences of
asymmetric activation. Suppose BIP-XXXX activates, a user creates
a QABI-aware UTXO with the 3-rung conditions tree
[SIG, QABI_PRIME, QABI_SPEND], and then BIP-YYYY does not
activate (or activates much later, or fails activation). Without
QABIO, QABI_PRIME and QABI_SPEND return UNSATISFIED on every
node, so the UTXO is spendable only via Rung 0 (SIG escape). That
is functionally fine — the user is not stuck — but they are
holding a UTXO with two dead rungs and have wasted the conditions
tree space. More importantly, a wallet that does not understand
QABIO will see the UTXO as having "weird unknown rungs" and may
warn the user not to spend it. The BIP should address this case
explicitly so wallet implementers know what to do.
**Answer.** The fact that SIG escape always works is the
participant's safety net for exactly this scenario. The BIP needs
to make three things clearer: (a) creating a QABI UTXO before
QABIO activation is safe — Rung 0 is always spendable, so the
user is never stranded; (b) wallets that recognise the MLSC
output but not QABIO should treat unknown rungs as
non-blocking — they should still be able to construct a Rung 0
spend; (c) explicitly state that QABI UTXOs created pre-activation
become full-featured at activation without any user action — the
conditions tree does not change, only the consensus interpretation
of the rungs. This is a strong feature of the design and we
should highlight it rather than gloss over it.
**BIP change needed:** Expand "Wallet Compatibility" to address
pre-activation QABI UTXO creation. Add a sentence stating that
SIG escape via Rung 0 is the unconditional safety net even if
QABIO never activates. Add a recommendation to wallet implementers
that unknown rungs in MLSC trees should not block Rung 0 spends.

### 13. The aggregated_sig is excluded from SIGHASH_QABO — why exactly, and does that open a malleability surface?
Section "Sighash Algorithm" says SIGHASH_QABO "deliberately
excludes `tx.aggregated_sig` itself (otherwise the signature
would be self-referential)". This is the standard reason. But
excluding the signature from its own sighash is exactly what
creates ECDSA-style signature malleability in pre-segwit
transactions. FALCON-512 is not ECDSA, but the question still
matters: can an attacker take a valid `(qabi_block, aggregated_sig)`
pair and substitute a different `aggregated_sig'` that also
verifies under the same coordinator pubkey for the same sighash?
For FALCON-512 the answer is "not easily" because FALCON
signatures are tightly bound to the message via the trapdoor
sampler, but reviewers will ask the question and we should answer
it explicitly rather than relying on "it is self-referential" to
close the topic.
**Answer.** FALCON-512 signatures are not deterministic (they
use randomness during signing) but they are uniquely verifiable —
a given `(pubkey, message)` pair has many valid signatures, but
producing a new valid signature requires knowing the private key.
An attacker who observes `(qabi_block, sig1)` cannot construct
`(qabi_block, sig2)` without the private key, so signature
substitution is not a practical attack. However, the *txid* of
the QABIO transaction depends on `aggregated_sig` (it is part of
the witness data, weight-discounted), so a coordinator who signs
twice with different randomness produces two different txids for
the same logical transaction. This is wtxid malleability, not
txid malleability (since aggregated_sig is in the witness), and
it is the same property segwit already has for ECDSA signatures.
We should document this explicitly: the wtxid is malleable by the
coordinator (who is the only party that can produce valid
signatures), but the txid is not. CPFP children depend on txid
and are therefore unaffected.
**BIP change needed:** Add a paragraph in "Sighash binding
completeness" explicitly addressing FALCON-512 signature
non-determinism and the wtxid-vs-txid malleability split. State
that the coordinator can produce multiple valid signatures for
the same logical batch but only one will mine, and that this is
benign because txid is stable across signature variants.

### 14. liboqs is now mandatory for BIP-XXXX too — does QABIO still need its own BIP?
The BIP currently leans on "QABIO requires liboqs as a dependency"
as part of its motivation, but Section "Post-quantum cryptographic
dependency" admits that liboqs is already a hard build dependency
of base Ladder Script (BIP-XXXX) for the FALCON-512 mode of the
SIG block. So the dependency argument cuts no weight — QABIO is
not adding a new dependency, it is just adding a new use of an
existing one. The reviewer's natural follow-up is: "If QABIO is
just a new use of an existing primitive, why does it need its own
BIP and its own soft-fork activation? Why isn't this just a new
block type added in a future BIP-XXXX revision?"
**Answer.** Three reasons QABIO deserves a separate BIP: (a)
QABIO introduces consensus-level state that the base Ladder Script
spec does not contemplate — the per-tx aggregated_sig field, the
SIGHASH_QABO algorithm, the Replace-By-Depth mempool policy, and
the tx-level qabi_block field are all additions to the v4 wire
format and to the validator's per-tx state, not just new block
types within an existing dispatch table; (b) the soft-fork
activation of QABIO is meaningfully separable from the base
Ladder Script activation — it lets the ecosystem stage the rollout,
catch QABIO-specific bugs without endangering the base layer, and
hold QABIO in reserve if implementation experience reveals
issues; (c) the use case (N-party batching with a trust-minimised
coordinator) is a self-contained capability with a self-contained
threat model, and conflating it with the base Ladder Script BIP
would make both BIPs harder to review. The "shared dependency"
argument is the weakest reason to merge — the strong reasons to
keep them separate are wire-format additions, separable activation,
and reviewability.
**BIP change needed:** Rewrite "Post-quantum cryptographic
dependency" to lead with "QABIO reuses the same liboqs FALCON-512
verification path as the base SIG block" rather than treating it
as a new dependency. Add a paragraph in Motivation explaining
why QABIO is its own BIP despite sharing a primitive with the
base layer.

### 15. The N-party batch use case — is the demand real, or speculative?
The BIP cites payroll, exchanges, mining pools, bridges, and DAOs
as use cases. None of these citations come with concrete demand
signals. The reviewer's question: "Is this actually solving a
problem people are asking to be solved, or is it speculative
infrastructure looking for users?" Several proposals in this
space (CTV, ANYPREVOUT, the various covenant proposals) have
similar use cases and have been debated for years without
activation, partly because the demand has not materialised in a
form that compels consensus changes.
**Answer.** The honest answer is that demand is real for some of
the use cases and speculative for others. Mining pool payouts are
a concrete, ongoing operational problem — pools today either run
custodial payouts (regulatory burden) or fan-out transactions
(per-payout fees), and a trust-minimised batch primitive would
strictly improve both. Exchange withdrawal batches are similar —
exchanges currently take temporary custody of withdrawal funds
during batching, and a non-custodial primitive would reduce
regulatory exposure for jurisdictions that distinguish custody
from settlement. Payroll is more speculative — there is no
existing on-chain payroll service the BIP could point to. Bridge
withdrawals and DAO distributions are even more speculative. We
should be honest in the Motivation: lead with the concrete use
cases (mining pools, exchange withdrawals) and frame the rest as
"the primitive enables these cases without claiming current
demand". This is also a stronger framing than "we have eight use
cases" because it focuses reviewers on the strongest one.
**BIP change needed:** Reorder the use case list in "Capability
gap: batched payouts under adversarial coordinators" to lead with
mining pool payouts and exchange withdrawals (the strongest
cases). Add a sentence acknowledging that payroll, bridges, and
DAOs are enabled-but-not-currently-demanded uses. Optionally cite
a pool operator or exchange that has expressed interest, if such
a citation can be obtained pre-submission.

### 16. The QABI_SPEND PUBKEY_COMMIT carve-out is a special case in the type system
The BIP introduces a "QABI_SPEND-specific carve-out from the
general rule that PUBKEY_COMMIT is forbidden in conditions
context" (section "QABI_SPEND Block §Conditions layout"). This is
an exception in the Ladder Script type system that exists solely
for QABIO. Reviewers who care about minimal consensus surface will
ask: why? Why not commit `owner_id` via a different field type
(say, HASH256) that does not require a carve-out? The answer is
presumably that PUBKEY_COMMIT carries semantic meaning (it is a
hash-of-pubkey, not just any 32-byte value) and that meaning
matters for downstream tooling, but the BIP does not say that
explicitly.
**Answer.** Two reasons for keeping PUBKEY_COMMIT as the field
type: (a) semantic clarity — `owner_id` is conceptually a "hashed
pubkey commitment", and using PUBKEY_COMMIT signals that to
parsers, RPC tools, and analytics; using HASH256 would lose that
type information; (b) consistency with how owner_ids are
constructed elsewhere in Ladder Script. The carve-out is small
(it is one rule exception, not a broad relaxation of the type
system) and is well-bounded — only QABI_SPEND can carry
PUBKEY_COMMIT in conditions context, and the serialiser enforces
this. We should document the reason for the carve-out explicitly
in the BIP. An alternative that avoids the carve-out is to use
HASH256 instead and lose the semantic tag; this is a minor
trade-off but worth raising as a design alternative.
**BIP change needed:** Add a paragraph in QABI_SPEND §Conditions
layout explaining why PUBKEY_COMMIT is used despite requiring a
carve-out, and noting the HASH256 alternative for completeness.
Acknowledge in Rationale that the carve-out is a deliberate
exception with a well-bounded scope.

### 17. The committed_expiry field is a uint32 block height — Y2106 problem and reorg considerations
`committed_expiry` is a 4-byte LE uint32 representing a block
height. At the current rate of ~52,560 blocks/year, uint32 covers
~81,700 years — so the Y2106 problem does not bite for block
heights, only for unix timestamps. But there is a different issue:
the field is interpreted as an absolute block height, not a
relative one. A coordinator who announces a batch with
`prime_expiry_height = current_tip + 100` is committing
participants to a 100-block deadline. If the chain reorgs by, say,
30 blocks while the priming transactions are confirming, the
effective deadline shifts. The BIP does not specify whether
`committed_expiry` is checked against the chain tip at the time
of the QABI_SPEND tx (which is what check 3 implies) or at the
time the QABI_SPEND tx mines (which would be reorg-stable).
**Answer.** Check 3 reads "block_height <= committed_expiry, where
block_height is the current tip height at evaluation time".
"Evaluation time" should be normatively pinned to "the height at
which the spending transaction is included in a block" — not the
mempool acceptance time, not the tip when the tx was first seen.
This makes the check reorg-stable: a tx that was valid at height
H stays valid at any height H' ≤ committed_expiry, and a reorg
that re-mines the same tx at height H ≤ committed_expiry remains
valid. We should also document the chosen reasoning around relative
vs absolute heights: relative heights would be reorg-stable by
construction but require participants to know the prime tx's
inclusion height before they can use it, which is awkward. Absolute
heights are simpler and reorg-stable as long as the check is
pinned to the inclusion height of the spending tx.
**BIP change needed:** Clarify check 3 to read "block_height is the
height at which the QABI_SPEND transaction is mined". Add a
paragraph in Rationale or Security Considerations explaining the
choice of absolute heights and the reorg-stability argument.

### 18. The auth chain length cap (`10 * QABI_AUTH_CHAIN_DEFAULT_LENGTH`) is mentioned in passing without definition
Section "Why committed_depth + 1 for spend preimage?" mentions
that "the evaluator caps `committed_depth` at `10 *
QABI_AUTH_CHAIN_DEFAULT_LENGTH` to bound the per-input verification
work". `QABI_AUTH_CHAIN_DEFAULT_LENGTH` is not defined anywhere
else in the BIP. Auth chain construction in test vector 1 uses
length 50, so presumably the default is 50 and the cap is 500,
but reviewers should not have to infer consensus constants from
test vectors. This is also load-bearing for the verification cost
analysis — if the default is 50 then verification is ~50 SHA-256
ops per input, which is negligible; if the cap is reached
(`committed_depth = 500`) then it is 500 ops, which is still
negligible but should be explicit.
**Answer.** This is a documentation gap. We should define
`QABI_AUTH_CHAIN_DEFAULT_LENGTH = 50` in the Constants section
alongside the size limits, and define the cap as a separate
constant `QABI_AUTH_CHAIN_MAX_DEPTH = 500`. Both should be cited
in the verification cost analysis to make the per-input cost
fully derivable from spec constants. The "10x" multiplier in the
cap exists to allow Replace-By-Depth churn during a long priming
window without exceeding the cap; if a participant primes once
they consume depth 1, but if they re-prime via RBD many times
they could consume hundreds of depth slots.
**BIP change needed:** Add `QABI_AUTH_CHAIN_DEFAULT_LENGTH = 50`
and `QABI_AUTH_CHAIN_MAX_DEPTH = 500` to the Size Limits
subsection (or rename it to Constants). Reference both in the
spend-preimage rationale and the verification cost analysis.

## Nits

### 19. "Asymptotic cost converges from N ≥ 50 upward" — show the convergence curve
The Size and Scale table shows N=10, 100, 500, 1000, 2000, 3000.
The text says convergence happens from N=50, but N=50 is not in
the table. A reviewer trying to verify the convergence claim has
to interpolate. Adding N=25 and N=50 to the table would make the
convergence visible.
**Answer.** Trivial fix; add the rows.
**BIP change needed:** Add N=25 and N=50 rows to the size table.

### 20. Test vector 1's `preimage@depth=10` value looks suspect
The test vector lists `preimage@depth=10:
f8f4d1e3a09d2c1e6b7ad5c4928f0c4e5e8a3a7a1d5f0e2b8c4a9b6d7e3f1c0a`
which is 62 hex chars (31 bytes), not 64 hex chars (32 bytes).
This is either a typo in the BIP or a real bug in the test
vector generation. Either way, reviewers will spot it instantly.
**Answer.** It is a typo — the value should be 32 bytes (64 hex
chars). Regenerate the test vector from the reference
implementation and paste the correct hex.
**BIP change needed:** Regenerate Test Vector 1 from the
reference implementation, ensuring all hex strings are 64
characters. Cross-check against the qabi_authchain RPC output.

### 21. "Live signet" txids in test vector 3 should be reproducible from a published block
Test vector 3 cites two signet txids as evidence of live
validation, but does not say which signet (the BIP-XXXX signet?
A QABIO-specific signet?), at what block height, or with what
genesis. A reviewer who wants to verify the test vector cannot
do so without that context.
**Answer.** The txids are from the ladder-script signet
(genesis hash and configuration documented in the
bitcoin-core-ladder repository). We should cite the exact signet
configuration, the block heights at which the two txids confirmed,
and the URL of a public block explorer that indexes that signet.
**BIP change needed:** Expand Test Vector 3 with signet name,
signet genesis hash, block heights for both citations, and a
block-explorer URL. Add a "How to reproduce" sentence pointing at
the playground or RPC commands.

### 22. The Replace-By-Depth section uses "1.1 * old size" for the size growth rule — why 1.1 specifically?
RBD rule 5 says `T_new.size <= T_old.size * 1.1`. Why 1.1? Why
not 1.0 (no growth at all) or 1.2 (more headroom)? A 10% size
growth allowance is fine but should be defended; the only reason
in the rationale is "depth-encoding differences", which seems
optimistic — `prime_depth` is a fixed-width 4-byte field, so
encoding it differently does not change the size at all.
**Answer.** The 10% bound was chosen to allow for fee-bumping at
the wire level (slightly higher fees may need slightly larger
witnesses if signatures grow, e.g. when re-signing under a
different escape rung) and to give wallets room to repack RBD
replacements without hitting the wire-size cap. In practice,
wallet-built QABI_PRIME txs are very close to fixed-size, so the
1.1 factor is generous slack rather than a meaningful constraint.
We could tighten it to 1.0 if wallets confirm they do not need
the slack, but the safer default is to keep some headroom.
**BIP change needed:** Either tighten to 1.0 (preferred) or
defend the 1.1 in the rationale paragraph for RBD.

### 23. "DATA_RETURN outputs are allowed but limited to one per BIP-XXXX rules" — cite the rule
QABI_PRIME §Evaluation check 5 says exactly one spendable output
plus optional DATA_RETURN. The DATA_RETURN limit is presumably a
BIP-XXXX rule but the BIP-YYYY draft does not cite the section.
A reviewer should not have to grep BIP-XXXX for the rule.
**Answer.** Add a normative reference. The BIP-XXXX section that
limits DATA_RETURN outputs (one per tx) should be named explicitly
in the cite.
**BIP change needed:** Replace "limited to one per BIP-XXXX
rules" with the section name from BIP-XXXX.

### 24. The Rationale section "Why per-input QABI_SPEND witness + tx-level aggregated sig?" mentions an "earlier design" without dating it
This is a minor stylistic point: BIP rationales often cite earlier
designs to show the reasoning trail. Saying "an earlier design" is
fine but a reviewer who wants to understand the design history
will look for a reference. If there is a public discussion thread
or design doc, link it. If there is not, "an earlier design we
considered and rejected" is fine but should be slightly more
explicit ("during reference implementation development we
initially built per-input signatures and...").
**Answer.** Trivial wording improvement.
**BIP change needed:** Slightly expand the "an earlier design"
phrasing to make clear it was an internal iteration rather than a
public competing proposal.
