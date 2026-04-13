# BIP-XXXX Hostile Review — Anticipated Questions and Answers

Pre-submission review prep. Each entry is framed as a question a
skeptical bitcoin-dev reviewer is likely to ask, followed by the
strongest answer we can give today. Entries are grouped by severity:
questions that could sink the proposal, questions that will require
substantial revision, and nits.

The reviewer voice in each question is intentionally adversarial. The
goal is not to defend Ladder Script but to surface every objection a
serious reader will raise so we can either (a) preempt them in the BIP
text or (b) have a crisp answer ready on the mailing list.

## Blockers

### 1. Why is this not several BIPs?

You are proposing 61 new typed primitives, a new transaction
serialization (`nVersion=4`, `0x02` flag, `0xDF` scriptPubKey prefix), a
new Merkle commitment scheme (MLSC), a new sighash algorithm
(`LadderSighash`), a new descriptor language, a new wire format
(micro-headers + implicit layouts), a new anti-spam regime, a hard
dependency on liboqs, six recursion primitives, fourteen stateful PLC
primitives, seven legacy wrappers, and seven governance constraints —
all activating atomically as a single soft fork. The BIP itself
acknowledges this is "a large system" in the very first review-guide
sentence. The historical pattern in Bitcoin (segwit, taproot, even
those are considered large) is to separate the *transaction format*
change from the *script semantics* change from the *cryptographic
agility* change. What is the argument against splitting, and why
should the network accept all of this in one activation event?

**Answer.** The atomicity argument is in the Activation section: the
block families are interdependent. Compound blocks (Family 0x07) are
literally defined as the AND of signature, hash, and timelock blocks;
recursion blocks (Family 0x04) reference the MLSC leaf computation
and would not work without it; PLC blocks (Family 0x06) drive their
state transitions through `RECURSE_MODIFIED`. We cannot ship "Ladder
Script without recursion" because then half of the PLC family is
inert, and we cannot ship "Ladder Script without compounds" because
the size and analysis arguments collapse — the whole motivation for
typed blocks over generic primitives (Rationale §"Why 61 types
instead of fewer generic primitives?") is that compounds reduce
witness size and failure modes. Splitting would introduce
intermediate consensus states that no application would target.

That said, the BIP currently buries this argument under the
Activation section in two sentences. It needs to be hoisted to a
top-level Rationale subsection titled "Why one BIP and one
activation?" so it is the first thing a reviewer sees on this
question.

**BIP change needed:** Add a Rationale subsection "Why one BIP and
one activation?" that explicitly enumerates the cross-family
dependencies (compounds → signature+timelock+hash, recursion → MLSC,
PLC → recursion, governance → coil/output_index, legacy → recursion
depth limits) and states that a phased rollout would leave 30+ of
the 61 types non-functional in any partial state.

### 2. The 112-byte residual claim is doing a lot of work and is not derived in the spec.

The Anti-Spam Properties section asserts a "residual embeddable
surface of 112 bytes per transaction (flat)" and the Security
Considerations section repeats it. Neither section actually proves
this number. The breakdown table lists DATA_RETURN (40) + PREIMAGE
(64) + nLockTime+nSequence (8) = 112, but: (a) `nSequence` is a
*per-input* field and a 1-of-N spend with N inputs has 4N bytes of
nSequence, not 4 (Bitcoin convention is one nSequence per input);
(b) the breakdown ignores `address_hash` (32 bytes per coil and a
per-rung-destination 32-byte hash; the BIP says these are SHA256
hashes of the address but does not actually require the preimage be
known to the verifier — an attacker can choose the 32 bytes
freely); (c) the breakdown ignores the `value_commitment` (32 bytes
per rung leaf, which the spec says is "a SHA256 output, not
attacker-chosen data" — but the *inputs* to that SHA256 include
field values the attacker controls, so the 32-byte digest is a
funder-controlled write surface even if it requires hashing); (d)
SIGNATURE fields up to 50,000 bytes are validated against a
committed pubkey, but a malformed PQ signature that fails
verification is still 49KB of data the attacker put on chain; (e)
the COIL_ADDRESS_HASH_SIZE = 32 line in the consensus limits table
is never explained.

**Answer.** Each of (a)–(e) needs an explicit rebuttal in the spec,
not in tribal knowledge:

- **(a) nSequence per-input**: this is correct. The "8 bytes" line
  in the residual table is wrong as written; it should be "8 bytes
  flat (4 nLockTime + 4 first-input nSequence)" and we need a
  separate row for additional inputs at "4 bytes per additional
  input". The 112-byte claim should be restated as "112 bytes for
  a 1-input transaction; 112 + 4(N-1) bytes for an N-input
  transaction." Or alternatively, since nSequence is a standard
  Bitcoin field that exists today and is not a Ladder Script
  innovation, exclude it from the table entirely and claim "104
  bytes of new attacker-chosen surface introduced by Ladder
  Script."

- **(b) address_hash**: the coil's `address_hash` is SHA256 of an
  address the spender chooses. The fact that it is a hash does not
  make it un-attacker-chosen — an attacker can grind preimages or,
  more cheaply, just commit to a 32-byte string they want to embed
  and never produce a preimage (the BIP does not require a preimage
  reveal). This needs to be addressed: either (i) require the coil
  address_hash be derivable from a structurally validated source
  (e.g. an output scriptPubKey hash), (ii) require the preimage be
  revealed at spend time, or (iii) honestly add it to the residual
  surface as 32 bytes per coil + 32 bytes per rung_destination. The
  same critique applies to the per-rung_destination address_hash.

- **(c) value_commitment**: the spec's claim that `value_commitment`
  is "not attacker-chosen data" is technically true (it is a SHA256
  output) but reviewers will point out that a 32-byte SHA256 digest
  of attacker-controlled inputs is *exactly* how every existing
  inscription channel works (Ordinals' envelope, rune commitments,
  etc. all hide attacker data behind validated structures). The
  defence here is that the digest costs ~2^32 hashing work to grind
  to anything specific (e.g. embedding a 4-byte ASCII tag), so it
  is not a *practical* high-bandwidth channel — but the BIP needs
  to *say* this and quantify the grinding cost.

- **(d) malformed PQ signatures**: a SIGNATURE field is bounded by
  the SCHEME byte committed in the leaf. A spend that fails
  signature verification is rejected before block inclusion, so
  there is no on-chain residue. This needs to be made explicit:
  "Failed-verification witnesses do not enter the chain because
  they are rejected at block validation; only successfully-verified
  signatures contribute to on-chain bytes."

- **(e) COIL_ADDRESS_HASH_SIZE**: undocumented constant. Either
  delete it from the consensus limits table or explain it.

**BIP change needed:** Rewrite the Anti-Spam Properties residual
table with a per-input/per-output decomposition; add a row for
coil and rung_destination address_hashes (with the choice of
scheme above); add explicit text on `value_commitment` grinding
cost; add explicit text on rejected-signature non-residue; document
COIL_ADDRESS_HASH_SIZE.

### 3. The MLSC creation proof is not specified.

Step 6 of `VerifyRungTx` says "Verify the Merkle proof against the
UTXO's `conditions_root`" and the wire layout has a
`[creation_proof: bytes]` blob between the witnesses and nLockTime
that is "validated at block acceptance to confirm the Merkle tree
structure." Nowhere does the BIP specify (a) the format of the
creation proof, (b) the consensus rules for accepting or rejecting
it, (c) what happens if it disagrees with the on-wire reveal, (d)
why a creation proof is needed at *spend* time (creation proofs are
normally bound to *funding* time), (e) whether all inputs share one
creation proof or each input carries its own, (f) the size bounds.
The Security Considerations section says the conditions_root is
"protocol-derived (triple-hashed from validated structure via the
creation proof)" — *triple-hashed* appears nowhere else in the spec.
This is a consensus-critical gap.

**Answer.** This is the single most important spec gap. The
creation proof is the mechanism that prevents an attacker from
constructing a fake Merkle tree where the revealed leaf is
attacker-controlled but other unrevealed leaves contain arbitrary
data. Without a creation proof spec, every claim in Anti-Spam
Properties about non-attacker-chosen `conditions_root` is
unverifiable.

The reference implementation's `VerifyCreationProof` (in
`conditions.cpp`) is the source of truth, but the BIP must include
a Specification subsection titled "Creation Proof" with at minimum:
the wire format (probably a list of `(leaf_template_hash,
value_commitment_preimage_summary)` per leaf), the validation
algorithm (rebuild the tree, check against `conditions_root`), the
relationship to the on-wire MLSC proof (the creation proof covers
*all* leaves, the MLSC proof reveals one), and explicit statement
of what fails consensus. The "triple-hashed" phrase in Security
Considerations should either be defined or removed.

The BIP also needs to clarify whether the creation proof is one
blob per transaction or per input. The wire layout shows it after
all witness stacks but before nLockTime, which suggests
per-transaction — but if so, how does it cover N inputs that may
spend N different conditions_roots? Each input has its own UTXO
with its own root. This needs an answer.

**BIP change needed:** Add a Specification subsection "Creation
Proof" with wire format, validation algorithm, scope (per-tx vs
per-input), size bounds, and consensus failure modes. Define
"triple-hashed" or remove it. Add a test vector that exhibits a
creation proof and a malformed creation proof that must be rejected.

### 4. The sighash algorithm is described informally and has unspecified edge cases.

The `SignatureHashLadder` pseudocode lists fields but is not a
byte-exact algorithm. Specifically: (a) the order in which the
"skip if X" clauses apply when multiple hash-type bits are set is
not defined (e.g. ANYPREVOUTANYSCRIPT = `0xC0` = ANYPREVOUT |
something — does it skip `prevouts_hash` AND `conditions_hash`, or
just `conditions_hash`?); (b) `<input-specific data>` is left as
prose — what bytes does it cover? (c) `single_output` is described
as "only for SIGHASH_SINGLE" but the spec does not say what
happens when the input index exceeds the output count under
SIGHASH_SINGLE (in BIP-143 this is the famous "1" bug); (d)
`amounts_hash` is listed but not defined — sum of amounts? hash of
concatenation? in what order? (e) the table lists ANYPREVOUT as
`0x40` and ANYONECANPAY as `0x80`, but the valid combinations
table omits `0x40` itself — only `0x40-0x43` is listed, implying
0x40 is valid but the prose doesn't say what `0x40 | 0x00` means
versus `0x40 | 0x01`; (f) there is no test vector exercising any
non-default hash type.

**Answer.** Sighash is consensus-critical and historically the
source of more soft-fork bugs than any other component (BIP-143
was an emergency fix for SegWit's sighash; BIP-341 went through
multiple revisions to nail down the byte layout). The BIP currently
treats sighash as a footnote — one half-page section with a
pseudocode block — when it should be the most rigorously specified
section in the document.

What we need to do:

- Replace the pseudocode with byte-exact serialization rules,
  one bullet per byte range, in the same style as BIP-341 §
  "Common signature message".
- Define every helper hash (`prevouts_hash`, `amounts_hash`,
  `sequences_hash`, `outputs_hash`, `conditions_hash`) by exact
  preimage.
- Specify the `<input-specific data>` block: at minimum it should
  include input_index, the spending input's scriptSig length (must
  be 0 — restate the consensus rule), and the `coil_hash` of the
  satisfying coil.
- Define the SIGHASH_SINGLE-out-of-range behavior. Prefer
  hard-fail (consensus error) over the BIP-143 "uint256(1)" hack;
  the BIP can do this because it's a new format.
- Add at least three sighash test vectors: ALL, SINGLE on a
  multi-output tx, and ANYPREVOUTANYSCRIPT.
- Clarify the meaning of the bare `0x40` (ANYPREVOUT alone, no base
  hash type): is it valid, and if so, does it commit to outputs?
  The current table is ambiguous.

**BIP change needed:** Rewrite the Sighash Algorithm section to be
byte-exact. Add helper-hash definitions. Add SIGHASH_SINGLE
overflow rule. Add three sighash test vectors. Disambiguate
`0x40` standalone semantics.

### 5. "Unknown block type → UNSATISFIED" is not actually a universal forward-compat rule.

The BIP states that unknown block types return `UNKNOWN_BLOCK_TYPE`,
which is "treated as UNSATISFIED" for forward compatibility — this
is the soft-fork-friendly behavior because old nodes will reject
spends that depend on new block types as failing-spends rather than
invalid-blocks. But there are at least three contexts where this
rule does not (or cannot) hold:

- **Inverted unknown blocks**: the inversion rules say
  "`UNKNOWN_BLOCK_TYPE` inverted becomes `ERROR`". `ERROR` is a
  consensus failure, not a valid failure. So an attacker on the
  *new* network can construct a witness that, on an old node,
  would silently succeed (unknown block → unsatisfied → inverted
  → satisfied), but on the new network is rejected as ERROR. This
  is a chain split.

- **Unknown blocks inside compound dispatch**: if a future BIP
  adds a new compound block type (say `0x0707`) that has its own
  implicit field layout, an old node will reject the field bytes
  during *deserialization* (no implicit layout known), causing
  the *transaction* to fail to deserialize entirely — not the
  block to return UNSATISFIED. Failed deserialization is a block
  consensus failure on old nodes, an evaluation-time
  UNKNOWN_BLOCK_TYPE on new nodes. Chain split.

- **Unknown blocks inside `RECURSE_MODIFIED` mutation targets**:
  the recursion family rebuilds the Merkle tree from mutated
  leaves. If a mutation targets a block field of a type the old
  node doesn't know, the rebuilt root will diverge from the new
  node's root.

How does the BIP handle this?

**Answer.** The first concern is the most serious because it's a
*current* spec rule, not a hypothetical future one. The inversion
rule "unknown inverted → ERROR" is correct as a *post-activation*
rule (so that on the new network, you can't use an unknown block
to get free SATISFIED), but it's exactly what an attacker would
exploit to cause a chain split between activated and
yet-to-be-activated nodes during the activation window.

The mitigation is that activation is single-event (BIP-9 / BIP-8),
not staggered — once nodes activate they all enforce the same
rules. But the BIP needs to *say* this, and it should clarify that
during the signaling window, nodes that have not yet activated
treat *all* `nVersion=4` transactions as anyone-can-spend (per
Backwards Compatibility), so the rule is "old nodes accept any v4
tx, new nodes enforce all rules" — which means the chain-split
risk only exists if a node *partially* activates. The BIP should
state that partial activation is not supported.

For the second and third concerns, the answer is: *future* BIPs
that add new block types must not add new implicit field layouts,
because that breaks deserialization on old nodes. New block types
must use the explicit field encoding (escape byte + n_fields + per
field type+len+data), which old nodes can deserialize as
"unknown-type block with N fields" and then evaluate to
UNKNOWN_BLOCK_TYPE → UNSATISFIED. This is a constraint on future
BIPs that the current BIP must document.

**BIP change needed:** Add a Specification subsection "Forward
Compatibility for Future Block Types" that states: (1) future
block types MUST be added via the escape byte and explicit
encoding; future BIPs MUST NOT extend the micro-header table or
the implicit layout table without a new soft fork that bumps the
version flag; (2) the inversion rule "UNKNOWN_BLOCK_TYPE inverted
→ ERROR" is post-activation only and does not affect pre-activation
nodes because they treat v4 as anyone-can-spend; (3) future block
types added inside compound or recursion contexts have additional
constraints; (4) partial activation is explicitly unsupported.

### 6. Recursion + PLC + Merkle rebuild is the worst-case evaluation cost, and the BIP doesn't bound it.

`RECURSE_MODIFIED` and `RECURSE_DECAY` evaluation says: "Apply
parameterized mutations ... recompute the MLSC Merkle root from the
mutated leaf array, and compare against the output's root." This
means evaluation of *one block* can require rebuilding the entire
Merkle tree, which is O(MAX_RUNGS + MAX_RELAYS) leaves = up to 25
leaves, padded to 32, with 5 levels of TaggedHash. That's ~57 SHA256
computations per RECURSE_MODIFIED evaluation. Each rung can have
MAX_BLOCKS_PER_RUNG = 8 blocks, MAX_RUNGS = 16, so a worst-case
witness can contain 16 × 8 = 128 RECURSE_MODIFIED blocks, all
firing tree rebuilds. That's ~7,300 SHA256 ops just for recursion
verification per input. Multiply by MAX_LADDER_WITNESS_SIZE / typical
input weight, multiply by inputs per block. The BIP gives no
worst-case-cost analysis, no SigOps-equivalent budget, no
benchmark numbers. CTV (BIP-119) was scrutinized for *one*
template-hash computation per input; this proposal allows hundreds.

**Answer.** This is a fair concern and the BIP needs to address it
head-on with concrete numbers. The defenses are:

- A single rung is evaluated until the first satisfied rung;
  remaining rungs are skipped. So the worst case is "the satisfying
  rung contains 8 RECURSE_MODIFIED blocks", not "all 128 blocks".
- RECURSE_MODIFIED across multiple blocks in the same rung is
  redundant (they all check the same output root against the same
  rebuilt tree). Implementations cache the rebuilt root.
- The leaf count is bounded by MAX_RUNGS + MAX_RELAYS + 1 (coil) =
  25, padded to 32. The rebuild is ~57 SHA256 per call, ~456 ops in
  the absolute worst case (8 distinct mutations in one rung), which
  is comparable to a few BIP-119 verifications.
- PLC blocks do *not* trigger Merkle rebuilds; only the recursion
  family does. The BIP should state this explicitly.

What we need to do is publish actual numbers: worst-case SHA256
ops per input, worst-case ECDSA-equivalents per block, a SigOps
budget analogous to BIP-141. Without numbers, reviewers will
extrapolate from the worst-case algebra and reject the proposal.

**BIP change needed:** Add a Security Considerations subsection
"Worst-Case Evaluation Cost" with: (a) maximum SHA256 ops per
input (recursion rebuild + leaf hashing + sighash); (b)
maximum signature verifications per input (across all schemes);
(c) a SigOps-equivalent budget proposal; (d) a benchmark from the
reference implementation showing actual µs per worst-case input;
(e) explicit statement that PLC blocks are O(1) and only
recursion blocks trigger O(leaves) work.

### 7. The post-quantum dependency is mandatory and the BIP under-justifies it.

The BIP says liboqs is a hard build dependency and frames this as
"the honest choice — analogous to how secp256k1 is a hard
dependency of Bitcoin Core today." This analogy is weak: secp256k1
is a single-curve ~10kLoC library that the Bitcoin Core team
audited and forked into the project; liboqs is a 100kLoC C library
covering ~20 algorithms, several of which (including FALCON's
Gaussian sampling) have a history of side-channel and
implementation bugs and are still under active research. Reviewers
will ask: (a) why are FOUR PQ schemes required at activation
instead of one; (b) what audit work has been done on liboqs in a
consensus context; (c) if a future liboqs version produces a
different validity result than the current version (because of a
bug fix or spec clarification), how does Bitcoin handle the chain
split; (d) why not defer PQ to a separate BIP that activates after
NIST's PQ standards are widely deployed and audited; (e) why not
make PQ a *standardness* rule instead of a consensus rule, so
nodes can validate PQ inputs as policy without being a chain-split
risk.

**Answer.** The strongest steelman is:

- **One scheme vs four**: at the time of writing, none of FALCON,
  Dilithium, or SPHINCS+ alone covers every use case. FALCON is
  small but signing requires constant-time Gaussian sampling that
  nobody has shipped a portable safe implementation of. Dilithium
  is the NIST primary recommendation but signatures are ~2.4KB.
  SPHINCS+ is hash-based with no number-theoretic assumptions but
  signatures are ~50KB. Picking only one forces every wallet to
  accept its tradeoff. BUT — this is a *wallet* concern, not a
  *consensus* concern. The BIP could activate with only one
  consensus-supported scheme (say Dilithium3, the NIST primary)
  and add the others in subsequent soft forks via additional
  SCHEME byte values.

- **liboqs audit**: the honest answer is "we have done the
  integration but no formal audit." This needs to be stated.

- **Version skew**: this is the killer concern. If liboqs v0.10
  accepts a signature that liboqs v0.11 rejects (or vice versa),
  every node running the old version forks off. Bitcoin Core's
  approach with secp256k1 is to *vendor* the library and freeze
  the version, accepting upstream changes only after audit. The
  BIP needs to state this approach: "Ladder Script vendors a
  specific liboqs commit hash; consensus is defined relative to
  *that commit*, not to liboqs in general." This is in fact the
  only safe approach for any external crypto dependency.

- **Defer PQ**: this is the most likely reviewer outcome. The
  current BIP framing makes PQ feel central, but actually
  Ladder Script works completely without it (Schnorr and ECDSA
  cover ~all current use cases). The defensible answer is: the
  SCHEME byte is the *extension point*; activating Ladder Script
  reserves the byte and the wire format, but the consensus rules
  for PQ schemes can be specified in a follow-up BIP. The first
  activation can ship with SCHEME values 0x01 (Schnorr) and 0x02
  (ECDSA) as consensus-mandatory, and 0x10–0x13 reserved as
  unknown-scheme → UNSATISFIED. This makes liboqs a *future*
  dependency, not a *current* one, and addresses the audit/version
  concern by deferring it.

The BIP currently does not consider the "reserve the SCHEME byte
without activating PQ schemes" option, which is the obvious
compromise position. Reviewers *will* propose this and the BIP
should preempt it.

**BIP change needed:** Add a Rationale subsection "Why mandatory
PQ at activation?" that either (a) accepts the deferral and
restructures the BIP to make PQ schemes "reserved" with a clear
activation path, OR (b) explicitly defends the four-schemes-at-once
choice with a vendoring + audit policy and a version-pinning
commitment. Document the liboqs commit hash that defines consensus
in either case.

### 8. The conditions_root is shared across all outputs, which breaks single-output MLSC privacy.

TX_MLSC has one shared `conditions_root` per *transaction*, and
each rung's coil declares its `output_index`. The BIP frames this
as a savings (one root vs N roots) and references the "PLC model".
But the consequence is that revealing *one* spending path on input
A reveals the structural template of the *entire* condition tree
that governs all outputs — including outputs that have not yet been
spent. An adversary watching the chain can look at the spend of
output 0 and learn the structural skeletons (block types, inverted
flags, output_indexes) of every other rung in the same tree, even
the ones governing output 5 that no one has touched. This is
materially worse than Taproot, where each output has its own tapleaf
tree that is independent.

**Answer.** This is true and the BIP does not currently disclose
it. The mitigations are:

- **Structural templates only**: the revealed tree leaks block
  *types*, not block *values*. An attacker learns "output 5 has a
  rung with HTLC + RATE_LIMIT" but not the keys, hashes, amounts,
  or counterparties. The MLSC proof reveals the satisfied rung's
  full data plus *only Merkle proof hashes* for unrevealed leaves.

- **Per-tx granularity is fine for batch payments**: if all outputs
  in a tx are "sig(@k)" the leak is irrelevant. The leak only
  matters for heterogeneous output trees, which are an advanced
  use case.

- **Privacy-sensitive users can use single-output transactions**:
  in which case the shared root is identical to a per-output root.

- **Workaround**: applications that need cross-output structural
  privacy can use distinct transactions instead of batching.

But none of this is in the BIP. Reviewers will compare to Taproot's
per-output script trees and conclude TX_MLSC is a privacy
*regression*, not just a savings. The BIP needs to state this
tradeoff explicitly and explain when shared roots are appropriate.

**BIP change needed:** Add a Privacy Considerations section (the
BIP currently has none) that documents: (a) shared
`conditions_root` leaks the structural templates (not values) of
all outputs in a tx when any one output is spent; (b) this is a
deliberate tradeoff for batch payment efficiency; (c) users who
need per-output structural privacy should not batch sensitive
outputs into one tx; (d) compare explicitly to Taproot's
per-output tapleaf trees.

### 9. The diff witness mode is a footgun that the BIP doesn't justify.

The "Diff Witness Mode" in §Serialization Format says: "When
`n_rungs = 0`, the witness uses diff encoding: it inherits rungs
and relays from a prior input (`input_index < current`), overriding
specific fields via `(rung_index, block_index, field_index,
data_type, data)` tuples." This is a complex feature that:

- Adds a stateful coupling between inputs (input N's witness
  depends on input M's witness for M < N), which breaks the
  per-input independence that simplifies validation in Bitcoin
  Core today.
- Creates an attack surface for malformed-diff cases (what if the
  diff references a `(rung_index, block_index, field_index)` that
  doesn't exist in input M? error or unsatisfied?).
- Is justified by exactly zero text in the Rationale section.
- Has no test vector in Appendix B.
- Adds language ("diff pointing to diff is prohibited", "Coil
  fields are always fresh") that suggests there were earlier bugs.

What is the use case that justifies this complexity?

**Answer.** The honest answer is: diff witness mode is a witness-
size optimization for transactions that spend many inputs with
identical condition trees (e.g., a user consolidating 50 UTXOs that
all have the same vault structure, or an exchange batch-settling
many similar outputs). Without diff mode, each input carries its
own LadderWitness with the full rung structure, which is
duplicative. With diff mode, input 0 carries the full witness and
inputs 1..N carry only their distinguishing signatures and pubkeys.

But:

- The BIP doesn't explain this anywhere.
- The savings only matter for batched-similar-input transactions,
  which is a narrow case.
- The complexity cost is real: an extra deserialization mode, an
  extra state coupling, an extra error class.
- It might be cleaner to *remove* diff mode from this BIP and add
  it later as a separate optimization once the base format is
  stable.

If we keep diff mode, the BIP must:

- Add a Rationale subsection "Why diff witness mode?"
- Specify the consensus failure modes for malformed diffs.
- Add at least one test vector exercising diff mode.
- Document the edge cases (diff on input 0 must error; diff
  referencing forward inputs must error; diff-of-diff must error).
- State the per-input witness validation order (must be 0..N-1
  sequential, can't parallelize).

If we drop it, this becomes much simpler.

**BIP change needed:** Either remove diff witness mode from this
BIP and defer to a follow-up (preferred), or add: a Rationale
subsection, explicit failure modes, a test vector, and a statement
that input validation order is sequential 0..N-1. The current text
is not enough to implement against.

### 10. The inversion allowlist is consensus-critical and is defined by reference to a header file.

§"Inversion Rules" says inversion is "restricted to the
`IsInvertibleBlockType` allowlist (fail-closed: new block types
default to non-invertible). Key-consuming blocks are never
invertible." The Anti-Spam Properties section lists *some*
key-consuming blocks (SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD,
KEY_REF_SIG, compound signature types, legacy key types,
ANCHOR_CHANNEL, ANCHOR_ORACLE, VAULT_LOCK, LATCH_SET, LATCH_RESET,
COUNTER_DOWN, COUNTER_UP) but says "etc." in spirit — the
authoritative list is in `src/rung/types.h`. For a consensus-level
spec, the authoritative list cannot live in a header file. A
reviewer can't tell whether `RATE_LIMIT` is invertible or not, or
whether `OUTPUT_CHECK` is invertible. Different implementations
reading this BIP will produce different allowlists.

**Answer.** This is correct and easy to fix: the BIP needs an
explicit table mapping all 61 block types to (invertible: yes/no).
The table can live in an appendix. Without it, two
implementations will disagree on which inversions are valid, which
is a guaranteed chain split.

**BIP change needed:** Add an appendix table "Block Type Inversion
Allowlist" that lists all 61 block types with an explicit
invertible/non-invertible marker. State that this table is
normative and any future block type's invertibility must be
declared in the BIP that introduces it.

## Major concerns

### 11. The micro-header table is also defined by reference to a header file.

§"Micro-Header Table" says "Slots `0x00` through `0x3E` are
assigned to the 61 block types (in the order listed in the Block
Type Families section above, starting with SIG at `0x00`). Slots
`0x07` and `0x08` are reserved. ... The complete table is defined
in `src/rung/types.h` (`kMicroHeaderSlots`)." This has the same
problem as the inversion allowlist: the authoritative mapping
lives in a header file, not in the BIP. Two reviewers who try to
implement Ladder Script from this BIP alone will disagree on which
slot index corresponds to which block type. The "in the order
listed in the Block Type Families section" rule is ambiguous
because the families are listed in section order but slots 0x07
and 0x08 are reserved — does that mean SIG=0x00, MULTISIG=0x01,
ADAPTOR_SIG=0x02, MUSIG_THRESHOLD=0x03, KEY_REF_SIG=0x04,
CSV=0x05, CSV_TIME=0x06, [reserved], [reserved], CLTV=0x09? Or
does the reservation create a hole that pushes everything down by
2? The BIP doesn't say.

**Answer.** Add the explicit mapping. There are 61 entries; it's
one table.

**BIP change needed:** Add a Specification subsection "Micro-Header
Slot Assignment" with an explicit table mapping each of the 61
block types to a slot index 0x00–0x3E. Mark 0x07 and 0x08 as
reserved with rationale (or remove the reservation if it's not
needed). Make the table normative.

### 12. "61 block types verified on signet" is not a substitute for test vectors.

The BIP claims 480 unit tests + 60 functional tests + 10 TLA+ specs
+ 61/61 block types verified on signet, but Appendix B contains
exactly 5 test vectors:

1. Vector 1: parseladder for a SIG ladder
2. Vector 2: parseladder for a vault
3. Vector 3: formatladder roundtrip
4. Vector 4: SIG fund+spend (just txids)
5. Vector 5: HTLC fund+spend (just txids)

A txid is not a test vector. A reviewer can't verify a txid
without running a Ladder Script signet node. The two
parseladder vectors don't include witness bytes, sighash inputs,
or signature data. Vector 3 is a roundtrip of the same data as
Vector 1.

For a 61-type spec, this is very thin. CTV (BIP-119) has more
test vectors than this and it specifies one opcode.

**Answer.** The reference implementation has 480 unit tests; many
of them are effectively test vectors (input bytes → expected
output). We need to extract a representative subset and include
them inline. At minimum:

- One vector per family (10 vectors)
- One Merkle proof construction vector (showing leaf hashes,
  interior hashes, and root)
- One sighash vector for each non-default hash type (3 vectors)
- One vector demonstrating each anti-spam rejection path (4–5
  vectors)
- One vector showing inversion (showing the inverted-flag bit on
  the wire and the resulting evaluation flip)
- One creation-proof vector
- One diff-witness vector (if diff mode is kept)

That's ~25 vectors instead of 5. Without these, the BIP is not
implementable without reading the reference C++ code.

**BIP change needed:** Expand Appendix B to ~25 inline test
vectors with full byte serializations. Include at least one
vector per block type family, full Merkle tree construction,
sighash construction for each hash type variant, and explicit
anti-spam rejection cases. Move signet txids to an external
file (`tests/vectors/signet_spends.json` is already
referenced).

### 13. The CTV block (0x0301) is named CTV but the BIP doesn't say whether it's BIP-119 byte-compatible.

The Covenant Family section says "CTV: OP_CHECKTEMPLATEVERIFY
covenant (BIP-119)". Appendix A says "Compute the BIP-119 template
hash for the spending transaction at the current input index.
Compare against the HASH256 field." But BIP-119's template hash
includes nVersion, nLockTime, scriptSig hash, input count,
sequences hash, output count, outputs hash, and current input
index. Bitcoin's nVersion=2 transactions and Ladder Script's
nVersion=4 transactions have different serializations (different
output format, different witness format, etc.). A "BIP-119
template hash" computed on a v4 transaction is *not* the same
hash as one computed on a v2 transaction. If a user constructs a
CTV commitment intending it to lock a v2 spend chain, then later
realizes Ladder Script's CTV block hashes the v4 wire format,
their commitment is unspendable.

**Answer.** This is a genuine spec ambiguity. The choices are:

- **Option A**: CTV in Ladder Script computes the template hash
  over the v4 wire format. This is consistent with the rest of
  the BIP but means CTV commitments are not portable between v2
  and v4. The block should arguably be renamed `CTV_LADDER` or
  `TEMPLATE_HASH` to avoid implying BIP-119 compatibility.

- **Option B**: CTV in Ladder Script computes the template hash
  over an emulated v2 serialization of the v4 transaction (filling
  in the output scriptPubKeys from the conditions_root, etc.).
  This preserves BIP-119 byte compatibility but requires a
  serialization shim and is fragile.

Either way the BIP must say which choice was made. Currently it
says "BIP-119" without specifying whether the input to the
template hash is the v2 or v4 wire format.

**BIP change needed:** Specify which transaction serialization
the CTV block hashes (recommend Option A: native v4 wire format).
If Option A, rename the block to disambiguate or add a
prominent note that "BIP-119" refers to the algorithm, not byte
compatibility with v2 CTV commitments.

### 14. The comparison table is unfair to the alternatives.

The "Comparison with Existing Proposals" table has multiple cells
that overstate Ladder Script's advantages or understate the
alternatives:

- "OP_CAT (BIP-420): Composability via stack composition" is true,
  but the cell "Stateful contracts: Via composition" implies parity
  when actually OP_CAT can express stateful contracts more
  succinctly than Ladder Script's PLC family for many cases (e.g.,
  Mike Schmidt's BitVM-style constructions).
- "BIP-119 (CTV): Recursion: Via template chain" understates CTV's
  recursive expressiveness: a CTV chain is unbounded in the same
  sense Ladder Script's RECURSE_SAME is unbounded.
- "BIP-118 (APO): Composability: Sighash flags" is misleading —
  APO provides composability via signature pre-commitment, not via
  sighash flags. The cell oversimplifies a complex design.
- "BIP-345 (OP_VAULT): Vaults: Native; Recursion: Unvaulting only"
  is fair, but the cell "Composability: Vault-specific" is a
  pejorative framing — OP_VAULT was deliberately scope-limited.
- "Static analysis: Full (typed blocks) vs Partial (single
  opcode)" for CTV is technically correct but misses that CTV's
  single-opcode model is *easier* to formally analyze than 61
  typed blocks, not harder.
- "Formal specification: 10 TLA+ specs vs None" is unfair — APO
  and CTV both have informal proofs and review documents, even if
  not in TLA+.
- "Anti-spam enforcement: 7 mechanisms vs None (opcodes)" frames
  the alternatives as having zero anti-spam, which is technically
  true but elides that they don't *introduce* new spam surfaces
  beyond existing Bitcoin Script.

The table as written reads as advocacy, not analysis. Reviewers
will notice this and discount the entire BIP.

**Answer.** Rewrite the table for fairness:

- Add a "Scope" row to the top: Ladder Script (61 block types,
  full type system, new tx format) vs CTV (1 opcode) vs APO (2
  sighash flags) vs OP_VAULT (3 opcodes) vs OP_CAT (1 opcode).
  This sets honest expectations.
- Replace pejorative cells ("Vault-specific", "Unbounded risk")
  with neutral descriptions.
- Remove or qualify "Anti-spam: 7 mechanisms vs None" — the
  alternatives don't introduce spam, they just don't add
  defenses for problems they don't create.
- Acknowledge OP_CAT's expressive power explicitly. CAT is the
  closest thing to a competitor for Ladder Script's covenant
  capabilities and the BIP currently dismisses it.
- Add a row "Activation history" showing each proposal's status
  on the road to activation (CTV has been discussed since 2019,
  APO since 2018, OP_VAULT since 2022, OP_CAT since 2013/2024,
  Ladder Script is brand new). This is honest and self-aware.

**BIP change needed:** Rewrite the comparison table for fairness.
Add a Scope row. Replace pejorative cells. Acknowledge OP_CAT's
expressiveness. Add an Activation history row.

### 15. "This is the final upgrade to Bitcoin's spending condition model" will torpedo the proposal.

This sentence appears in the Motivation section and is exactly the
kind of absolutist language that bitcoin-dev reviewers react badly
to. Bitcoin has had multiple "final" upgrades that turned out not
to be (P2SH was supposed to be enough; SegWit was supposed to be
enough; Taproot was supposed to be enough). The history of Bitcoin
soft forks is one of incremental, humble improvements with explicit
acknowledgment that future changes may be needed. Calling Ladder
Script "the final upgrade" reads as marketing and primes reviewers
to find reasons to disagree.

The same paragraph also says "After activation, no further Script
changes are needed. The type system is fixed." This is also a red
flag — the BIP itself defines a SCHEME byte specifically for
*future* extensibility, defines a `0x0A00+` family range for
*future* extensions, and dedicates a whole subsection to forward
compatibility for *future* block types. So the type system is
explicitly *not* fixed; it's extensible. Saying it is fixed is
both contradictory and bad framing.

**Answer.** Delete the absolutist language. Rewrite as: "Ladder
Script provides a foundation for future extensions via reserved
SCHEME values and family ranges. The base layer specified in this
BIP is intended to be stable; extensions are deferred to follow-up
BIPs."

**BIP change needed:** Delete the sentences "This is the final
upgrade to Bitcoin's spending condition model" and "After
activation, no further Script changes are needed. The type system
is fixed." Replace with humble framing that acknowledges the
extension points.

### 16. "Composable conditions" is presented as a Ladder Script invention but Tapscript already composes.

The Motivation section says compounds (vault + rate-limit + heir
clause in one UTXO) are "impossible" in current Script and that
"Each proposed opcode (CTV, APO, OP_VAULT) addresses one use case.
They were not designed to compose." This is overstated:

- Tapscript already supports composition via the script tree:
  Alice can put a vault path in one tapleaf and a rate-limit path
  in another. A spender chooses the satisfying tapleaf. This is
  the same OR-of-AND structure Ladder Script provides, just with
  raw Script inside each leaf instead of typed blocks.
- The "impossible" examples in the Motivation are mostly things
  that Tapscript *can* do today (HTLCs, multisig with timelock
  recovery, etc.) — what current Script can't do is the
  *specific* features (rate limiting, recursive covenants,
  amount introspection). The Motivation conflates "can't compose"
  with "can't introspect", and these are different problems.

**Answer.** Tighten the Motivation. The honest framing is:

- Bitcoin Script today lacks *introspection* (output amounts,
  spending rates, weight limits) — this is the real motivation
  for new primitives.
- Bitcoin Script today *can* compose existing primitives via
  Tapscript trees, but composition is *unwieldy* because each
  leaf is a custom hand-rolled script with no static-analysis
  guarantees.
- Ladder Script's contribution is (a) typed introspection
  primitives that Script lacks, and (b) a typed composition
  language that replaces ad-hoc Tapscript leaves with structured
  blocks.

The "impossible" framing is wrong on the composition axis.
Reviewers will catch this and discount the entire Motivation.

**BIP change needed:** Rewrite the Motivation bullets to
distinguish "introspection capabilities Script lacks" from
"typed composition Script does ad-hoc". Remove the claim that
existing opcodes "were not designed to compose" — Tapscript was
explicitly designed for this.

### 17. PLC blocks have hidden state coupling that the BIP doesn't model.

The PLC family contains 14 stateful primitives: counters, latches,
timers, hysteresis bands, sequencers, etc. Appendix A says:

- LATCH_SET: "pubkey-authenticated state activation"
- COUNTER_DOWN: "decrement on signed event; SATISFIED at zero"
- RATE_LIMIT: "spending rate cap: max_per_block, accumulation_cap,
  refill_blocks"

Where does the *state* live? A counter has a current value; a
latch has a set/unset bit; a rate limiter has accumulated history.
Bitcoin's UTXO model is stateless — each output has fixed
conditions at creation and is consumed in one spend. PLC blocks
imply state that persists across spends, which means the state
must live in *something*: either the conditions of the next output
(via RECURSE_MODIFIED, which is what the BIP says: "stateful
contract primitives driven by RECURSE_MODIFIED state transitions")
or in some external register.

The BIP doesn't actually walk through how state flows for a single
PLC primitive. A reviewer reading the spec cannot tell:

- How does COUNTER_DOWN's current count get into the next output?
- How does RATE_LIMIT's accumulation_cap track historical spends?
- What happens if two parallel inputs both try to advance the
  same counter?
- Are PLC blocks *ever* satisfied without a recursion block?

**Answer.** The intended model is: PLC blocks read parameters
from the current rung's NUMERIC fields. State updates happen via
RECURSE_MODIFIED, which mutates the relevant NUMERIC fields and
re-encumbers the output with the mutated conditions. So
COUNTER_DOWN at value 5 in input becomes COUNTER_DOWN at value 4
in the output, via a RECURSE_MODIFIED that targets the counter
field. RATE_LIMIT tracks the per-block cap as a NUMERIC; the
accumulation parameter is updated via RECURSE_MODIFIED based on
the spend amount. Concurrent spends are impossible because each
output is single-use (UTXO model).

But this is not in the BIP. A reviewer reading the PLC family
section will not understand the state model without reading the
reference implementation. We need a Specification subsection
"Stateful Contract Primitives: State Flow" that walks through
COUNTER_DOWN, LATCH_SET, and RATE_LIMIT end-to-end with concrete
examples showing the input rung, the witness, the output rung,
and the RECURSE_MODIFIED block that mutates state.

**BIP change needed:** Add a Specification subsection "PLC State
Flow" with worked examples for at least three PLC blocks (one
counter, one latch, one rate limiter). Show the input conditions,
the spending witness, and the output conditions. Make explicit
that PLC state lives in NUMERIC fields and is mutated only via
RECURSE_MODIFIED.

### 18. The KEY_REF_SIG block leaks key material across rungs in a non-obvious way.

KEY_REF_SIG is described as "Signature using key commitment from a
relay block" and Appendix A says it resolves a PUBKEY_COMMIT from a
relay via `relay_refs`, then verifies the signature against the
referenced key. This is presented as a DRY optimization: define a
key once in a relay, reference it from multiple rungs.

But: the relay is a leaf in the MLSC Merkle tree, and relays are
revealed when a rung that references them is spent. So spending a
rung that uses KEY_REF_SIG forces the relay to be revealed, which
discloses the PUBKEY_COMMIT. If multiple rungs reference the same
relay, spending *any one* of them reveals the shared key
commitment, which weakens privacy across all the dependent rungs.

Worse: PUBKEY_COMMIT is in the *condition* context of the relay,
not the witness context. But the BIP's Anti-Spam Properties section
says PUBKEY_COMMIT is a witness-only type. So either KEY_REF_SIG
violates the type rules, or the relay carries something other than
a real PUBKEY_COMMIT (maybe just a HASH256 that aliases as a key
commitment), or the spec is internally inconsistent.

**Answer.** Looking at the spec more carefully: §"Data Types" says
"PUBKEY, PUBKEY_COMMIT, SIGNATURE, PREIMAGE, and SCRIPT_BODY are
witness-only and rejected in the conditions context." But
KEY_REF_SIG is described as "resolve PUBKEY_COMMIT from a relay
block via relay_refs". A relay is in the conditions context (it's
part of the MLSC tree). So KEY_REF_SIG's relay can't carry a
PUBKEY_COMMIT — there's an inconsistency.

The probable resolution is that the relay carries a HASH256 (32
bytes, allowed in conditions) which is interpreted as a hashed
public key by KEY_REF_SIG. The BIP needs to clarify this: the
relay carries `HASH256(pubkey)`, the witness provides the pubkey,
KEY_REF_SIG verifies the hash matches and the signature verifies
under the pubkey. This is a *different* mechanism from
`merkle_pub_key` and the BIP should explain why both exist.

**BIP change needed:** Clarify the KEY_REF_SIG mechanism: which
data type is in the relay, what the witness provides, how the
hash check works. Resolve the apparent type inconsistency
(PUBKEY_COMMIT in conditions vs witness-only). Explain why
KEY_REF_SIG exists alongside `merkle_pub_key` — what use case
needs key reuse across rungs that `merkle_pub_key` doesn't
already cover?

### 19. ANYPREVOUTANYSCRIPT is dangerous and the BIP does not warn users.

The BIP includes ANYPREVOUTANYSCRIPT (`0xC0`) as a sighash flag,
analogous to BIP-118. BIP-118 itself includes extensive warnings
about the danger of signing without committing to the script — a
signature signed with ANYPREVOUTANYSCRIPT can be replayed against
*any* output that the same key+sighash flags can spend, including
outputs the signer never intended to authorize. This is why BIP-118
restricts ANYPREVOUTANYSCRIPT to specific deployment contexts
(Lightning channel updates, primarily).

Ladder Script's BIP says only "ANYPREVOUTANYSCRIPT (`0xC0`) skip
prevout and conditions commitment" with no warning, no usage
restriction, and no description of safe-use patterns.

**Answer.** Add the warning. ANYPREVOUTANYSCRIPT must be presented
with the same caveats BIP-118 provides: signers must understand
that the signature is replayable against any condition set; this
flag is intended for protocols (e.g., eltoo channel updates) where
the signer explicitly wants this property; default wallet behavior
should never produce ANYPREVOUTANYSCRIPT signatures without an
explicit user confirmation.

**BIP change needed:** Add a Security Considerations subsection
"ANYPREVOUTANYSCRIPT Replay Risk" that mirrors the BIP-118 warnings.
State that this flag is intended for protocol use, not interactive
spending. Recommend that wallets gate this flag behind an explicit
user confirmation.

### 20. The 50,000-byte SIGNATURE field is a DoS amplifier.

The Data Types table says SIGNATURE max is 50,000 bytes "to
accommodate SPHINCS+-SHA2-256f (~49,216 bytes)". Verifying a 49KB
SPHINCS+ signature is ~5ms on a modern CPU. A worst-case witness
can carry MAX_BLOCKS_PER_RUNG = 8 signature blocks per rung,
with up to 50KB each — that's 400KB of signature data per input.
At 8 signatures × 5ms = 40ms verification time per input. A block
with 1000 inputs of this shape would take 40 seconds to verify.
The BIP gives no analysis of worst-case signature verification
cost, no SigOps budget for PQ schemes, and no per-block-type
multiplier (a SPHINCS+ verification is several orders of magnitude
more expensive than a Schnorr verification).

**Answer.** Bitcoin currently uses a SigOps limit (BIP-141, ~80k
sigops per block) to bound signature verification cost. Ladder
Script needs an analogous limit that accounts for the wide cost
spread between schemes. Proposed:

- Schnorr verify: 1 sigop
- ECDSA verify: 1 sigop
- Dilithium3 verify: ~10 sigops
- FALCON-512 verify: ~5 sigops
- FALCON-1024 verify: ~10 sigops
- SPHINCS+ verify: ~100 sigops

Block sigops budget remains ~80k. A worst-case SPHINCS+ block
contains ~800 verifications instead of ~80,000 Schnorr.

The BIP currently has no sigops accounting for PQ schemes. This
is a consensus-relevant gap.

**BIP change needed:** Add a Specification subsection "Signature
Operations Budget" with per-scheme sigops weights and a block-
level sigops cap. Justify the weights with reference benchmarks.
This is also a place where deferring PQ to a follow-up BIP
(per #7) simplifies the work: the base activation only needs
sigops for Schnorr+ECDSA, which are well-understood.

### 21. The 80-byte SCRIPT_BODY for legacy wrappers is too small for real legacy scripts.

The Data Types table says SCRIPT_BODY max is 80 bytes. But:

- A typical P2WSH inner script for a 2-of-3 multisig is ~71 bytes,
  fits.
- A 3-of-5 multisig is ~104 bytes, doesn't fit.
- A typical Lightning HTLC script is ~120 bytes, doesn't fit.
- A typical Lightning revocation script is ~80 bytes, *just*
  fits.
- A complex P2SH script (e.g., a 2-of-3 with timelock recovery
  arms) is ~150 bytes, doesn't fit.

If the goal of the Legacy Family is "migration without re-keying"
(per Backwards Compatibility), then 80 bytes excludes most
real-world legacy P2SH/P2WSH scripts that anyone would want to
migrate. The user has to either (a) re-key into a Ladder Script
native primitive (defeating the purpose) or (b) leave their
funds in legacy form (defeating activation incentives).

**Answer.** The 80-byte limit is too small. Either raise it
(to 520 bytes to match Bitcoin's MAX_SCRIPT_ELEMENT_SIZE, or to
3,600 bytes to match BIP-141's MAX_SCRIPT_SIZE for SegWit
witness scripts) or document explicitly that the Legacy Family
is intended for *small* legacy scripts only and recommend that
users with larger legacy scripts re-key.

The 80-byte choice is presumably driven by anti-spam concerns
(SCRIPT_BODY counts against the PREIMAGE field budget per
§"Anti-Spam Properties"). A larger limit means more attacker-
chosen bytes per witness. The BIP needs to justify the 80-byte
choice on this tradeoff and either accept the migration limit
or change the limit.

**BIP change needed:** Either raise SCRIPT_BODY max to ~520 bytes
(P2WSH compatibility) and update the residual surface analysis,
or document the 80-byte limit as a deliberate restriction with
guidance to migrate small scripts only and re-key for larger
scripts.

### 22. Activation mechanism: deferring to SOFT_FORK_GUIDE.md is not acceptable.

The Activation section says: "The activation mechanism (BIP-9
signaling or BIP-8 mandatory activation) is outside the scope of
this specification. See `SOFT_FORK_GUIDE.md` for a phased
deployment approach." Reviewers will reject this. Every
recently-activated soft fork (BIP-148, BIP-91, BIP-341) had to
make a recommendation in the BIP itself, and the activation
mechanism was the most contentious part of every one of them.
Saying "see another doc" is treating activation as a footnote.

**Answer.** Make a recommendation in the BIP. Either:

- **BIP-9 with a 1-year signaling window**, on grounds that
  signaling-based activation is the precedent set by Taproot and
  is less contentious than mandatory activation. This is the
  conservative choice.
- **BIP-8 with mandatory activation after 2 years**, on grounds
  that signaling can be jammed by hostile miners (segwit
  experience) and a guaranteed activation date prevents
  indefinite delay.

Either way the BIP needs to take a position. SOFT_FORK_GUIDE.md
can contain the implementation details, but the *recommendation*
must be in the BIP.

Reviewers will *also* push for:

- A specific signal bit assignment.
- A specific signaling start height and timeout height.
- A specific activation height (or signaling threshold).
- A specific testnet/signet deployment timeline.

These can be left to the eventual deployment BIP, but the BIP
should at least propose a reasonable starting set so the
discussion has somewhere to start.

**BIP change needed:** Replace the deferred activation paragraph
with an explicit recommendation (BIP-9 or BIP-8), a rationale,
and proposed signal bit / window parameters. Move implementation
details to SOFT_FORK_GUIDE.md but keep the recommendation in the
BIP.

### 23. The BIP claims 10 TLA+ specs but doesn't describe what they cover or how to verify them.

The Reference Implementation section and the Test Vectors section
both reference "10 TLA+ specifications" covering "evaluation
semantics, anti-spam, and Merkle proofs." This is a significant
claim — TLA+ verification is rare in Bitcoin BIPs and a strong
positive signal. But the BIP doesn't:

- Name the 10 specifications.
- Describe what each one models.
- State which model checker was used (TLC? Apalache? PlusCal
  translation?).
- State the state space size (a TLA+ spec that finishes in a few
  thousand states is much weaker than one that explores millions).
- Provide a path or link to the spec files.
- State which properties were proven (safety only? liveness?
  refinement?).

A reviewer who doesn't read TLA+ will skim past the claim. A
reviewer who *does* read TLA+ will want to verify it and will be
frustrated by the lack of pointers.

Worse, the user's own session memory (from project context) notes
"NEVER run tla2tools.jar, OOM-kills WSL2" — this raises a real
question of whether the TLA+ specs have been *checked* recently or
whether they're aspirational artifacts. The BIP needs to make
clear what state of model checking has actually been performed.

**Answer.** Add a Reference Implementation subsection or Appendix
"Formal Specifications" that lists each of the 10 TLA+ specs by
name, describes what it models, states which checker was used,
states the maximum state space explored, lists the safety/liveness
properties proved, and provides a path to the file
(`spec/tlaplus/<name>.tla` or similar). Be honest about what's
been checked vs what's been written.

If the specs have not been re-checked recently (per the project
memory note), the BIP should say "TLA+ specifications are
provided as documentation; reviewers are encouraged to re-run
checking" rather than implying the proofs are current.

**BIP change needed:** Add an appendix "Formal Specifications"
listing all 10 TLA+ specs with name, scope, model checker,
state space size, properties proved, and file path. Be honest
about the verification status.

### 24. "60 functional tests" for 61 block types is suspiciously round, and the coverage gap matters.

480 unit tests + 60 functional tests = approximately 1 functional
test per block type, with 8 unit tests per block type. For a
consensus spec, this is light. Compare to Bitcoin Core's
`script_tests.cpp` which contains ~thousands of test vectors for
the existing opcode set. A reviewer will ask:

- Which functional tests cover which block types? Is there a
  matrix?
- Are there any block types with *only* unit test coverage and no
  end-to-end coverage?
- Are negative tests counted? (e.g., "this malformed witness must
  be rejected")
- What's the line coverage of the reference implementation?
- How many of the tests are derived from the TLA+ specs vs
  hand-written?

**Answer.** Add a coverage matrix to the appendix or the test
vectors section. The reference implementation should report line/
branch coverage. Explicitly call out any block types whose
coverage is below the average so reviewers can focus there.

The 60 functional tests are presumably the integration tests in
the reference implementation; the unit tests are the per-evaluator
tests. State this clearly. State which negative cases are covered.

**BIP change needed:** Add a Reference Implementation subsection
or appendix table mapping block types to test files. State line
coverage. Identify gaps. Distinguish positive from negative tests.

## Nits

### 25. "ladder-script.org/ladder-engine.html" in the review guide.

The "How to Review This Document" section says step 6 is "Try it —
live signet: `ladder-script.org/ladder-engine.html`". A live demo
URL is great, but the BIP should mention that this is a third-
party-hosted resource, the activation status, and what happens if
the URL goes offline. Reviewers shouldn't have to depend on
infrastructure outside the BIP to understand the spec.

**BIP change needed:** Move the demo URL to a "Resources" appendix
with a note that the live signet is a project-maintained service
and is not normative.

### 26. "PREIMAGE min=1" rationale is buried.

The Rationale section explains why PREIMAGE has min=1 (because
P2SH/P2WSH inner scripts can be shorter than 32 bytes). But the
Data Types table just lists "PREIMAGE: 1 to 32" with no inline
note. A reviewer will flag this as "32-byte preimages with a
1-byte min looks like a bug" before they read the rationale.

**BIP change needed:** Add a footnote or a parenthetical to the
PREIMAGE row of the Data Types table: "Min 1 byte; see Rationale
'Why PREIMAGE min=1?' for the legacy-wrapper justification."

### 27. The DATA_RETURN block's `nValue == 0` overlap with output_count rules.

§"Output Format" says "An output with `nValue == 0` is a
DATA_RETURN output." But §"Consensus Limits" says
"MIN_RUNG_OUTPUT_VALUE = 546" (the dust threshold). A
DATA_RETURN at nValue=0 is below the dust threshold — is the
dust rule waived for DATA_RETURN, or are DATA_RETURN outputs
specifically excluded from the rule? The BIP is silent.

**BIP change needed:** Add a sentence to §"Consensus Limits" or
§"Output Format" stating that MIN_RUNG_OUTPUT_VALUE applies to
non-DATA_RETURN outputs only.

### 28. "Must provide a witness stack of exactly 2 elements" — what about empty witnesses for unspendable outputs?

§"Transaction Format" says "All inputs MUST provide a witness
stack of exactly 2 elements". This is fine for spending a v4
output. But are there legitimate v4 transactions where some
inputs spend non-Ladder outputs (e.g., a v4 transaction spending
a mix of v4 and v3 inputs)? The BIP doesn't say whether v4
transactions can have mixed input types.

**BIP change needed:** Clarify whether v4 transactions can mix
v4 (Ladder) and non-v4 inputs. If yes, specify witness rules for
the non-v4 inputs. If no, state explicitly that all inputs of a
v4 transaction must spend v4 outputs.

### 29. Vector 5's spend txid looks fake.

Appendix B Vector 5 lists:
```
Fund txid:  40094685bdf2b3db55eb0e84cc21e3a1fc3b3ed6db00cb499bce973413f8cef4
Spend txid: c7d4ed9f9d61b8c3adc6e0dbf93b8f07f1a9e3c42a7b1d5e6f8094a3b2c1d0e5
```

The spend txid `c7d4ed9f...c1d0e5` has a suspiciously sequential
ASCII-like ending (`...c1d0e5` looks crafted). If this is a real
signet txid, fine, but reviewers will assume it's a placeholder
and ask. Compare against Vector 4's spend txid which looks like
genuine random hash output.

**BIP change needed:** Verify Vector 5's spend txid is real and
queryable on the live signet. If it's a placeholder, replace with
the actual txid before publication.

### 30. The "Discussion" header at the top of the BIP cites a March 2026 mailing list post.

The header says "Discussion: 2026-03-16:
https://groups.google.com/g/bitcoindev/c/0jEHXaQaeZw". Reviewers
will follow this link. Make sure the linked thread is actually a
discussion of *this* BIP draft (not an earlier Ladder Script
draft) and that the contents are consistent with the current
spec. If the mailing list discussion predates significant
revisions, link to the most recent thread instead.

**BIP change needed:** Verify the mailing list link points to a
current discussion of this version. Update if the spec has
materially changed since the linked post.

### 31. "Single Output" SIGHASH_SINGLE bug context missing.

§"Sighash Algorithm" lists SIGHASH_SINGLE without explaining the
historical context. Bitcoin's SIGHASH_SINGLE has had several
historical bugs (the famous "SIGHASH_SINGLE bug" where signing
input N when there are fewer than N+1 outputs returns a uint256
of 1). The BIP should state explicitly how Ladder Script handles
this case — and given that this is a new sighash, it should
*not* repeat the BIP-143 hack of returning uint256(1). Best
practice: SIGHASH_SINGLE with input_index >= output_count is a
consensus failure (ERROR), not a valid signing context.

**BIP change needed:** Add a sentence to the Sighash Algorithm
section: "If `hash_type & 0x03 == 0x03` (SIGHASH_SINGLE) and
`input_index >= output_count`, sighash computation fails with
ERROR. Implementations MUST NOT return a placeholder value."

### 32. The "10 family purposes" referenced in the review guide are not labelled as such.

§"How to Review This Document" step 3 says "understand the 10
family purposes". The Block Type Families section has 10 family
headers, each with a brief sentence, but they're not numbered
"1/10, 2/10, ..." and the readability tip in step 3 is not
matched by visual structure. Minor readability fix.

**BIP change needed:** Number the family subsection headers
explicitly (e.g., "Signature Family (1/10)") so reviewers
following the guide can track progress.

### 33. The "merkle_pub_key" vs "merkle pub key" vs "merkle pubkey" inconsistency.

The BIP uses `merkle_pub_key` (with underscore) in the Design
Overview and Rationale, but uses "Pubkeys are appended in
positional order via `PubkeyCountForBlock()` (the
`merkle_pub_key` commitment)" in the Leaf Computation section.
The descriptor language doesn't expose the term at all. Pick one
spelling and use it consistently.

**BIP change needed:** Standardize on `merkle_pub_key`
(underscore) throughout. Add a glossary entry if the term isn't
otherwise defined inline.

### 34. The Reference Implementation table cites file paths that bind the BIP to a specific tree layout.

The Reference Implementation section table maps section topics to
files like `src/rung/types.h`, `src/rung/evaluator.cpp`, etc. If
the reference implementation tree is reorganized (e.g., merged
into Bitcoin Core's `src/script/` tree under
`src/script/ladder/`), every file path in the BIP becomes stale.

**BIP change needed:** Either (a) make the file paths advisory
("In the reference implementation as of this writing, ...") or
(b) commit to keeping the file layout stable and document this
commitment.

### 35. "Ladder Script transactions use version 4" but version 3 was just standardized.

The Abstract says "Ladder Script transactions use version 4
(`nVersion = 4`)." Bitcoin Core recently standardized v3
transactions for TRUC (Topologically Restricted Until
Confirmed) policy. Reviewers will ask: is v4 chosen because v3 is
taken, and is there any conflict? The BIP should note that v4 is
chosen because v3 is in use for TRUC, and v4 is the next available
version number.

The user's session memory (project context) explicitly notes
"RUNG_TX_VERSION = 4 (not 3 — BIP 431 claims v3)". This
confirms the choice but is not in the BIP.

**BIP change needed:** Add a one-sentence footnote to the
Abstract or Transaction Format section: "Version 4 is used
because version 3 is reserved for TRUC transactions per BIP-431."

---

## Summary: where the BIP needs the most work

The blockers cluster around three themes:

1. **Consensus surface gaps**: creation proof unspecified (#3),
   sighash informal (#4), inversion allowlist by-reference (#10),
   micro-header table by-reference (#11), forward compatibility
   half-defined (#5). Any one of these is enough to block
   activation review. All five together mean the spec cannot be
   independently implemented today.

2. **Anti-spam claims unsubstantiated**: the "112 bytes residual"
   number is not derived (#2), worst-case evaluation cost is not
   bounded (#6), DoS via PQ signatures is not analysed (#20).
   The BIP makes strong claims it cannot back up with current text.

3. **Framing and scope issues**: absolutist "final upgrade"
   language (#15), unfair comparison table (#14), mandatory PQ
   without justification (#7), activation mechanism deferred (#22).
   These are not technical bugs but they will dominate the
   mailing-list discussion and prevent the technical content from
   being heard.

The major concerns are mostly clarification debt: the spec exists
in the head of the implementer and in the C++ source, but not in
the BIP text. Test vectors (#12), state flow (#17), KEY_REF_SIG
mechanism (#18), CTV byte-compatibility (#13), TLA+ coverage (#23),
and test coverage matrix (#24) all need to be lifted from the
reference implementation into the spec.

The nits are mostly editorial polish that can be done in a single
revision pass once the structural issues are resolved.

**Recommended order of operations:**

1. Fix #3 (creation proof spec) and #4 (sighash spec) first — these
   are the consensus-critical gaps that block any implementation.
2. Add the missing tables: #10 (inversion), #11 (micro-header).
3. Add the missing test vectors: #12 (Appendix B expansion).
4. Restructure the residual surface analysis: #2.
5. Address the framing issues in one editorial pass: #14, #15,
   #16, #22.
6. Decide on PQ scope (#7) — if deferred, restructure §
   Post-Quantum and the SCHEME byte sections accordingly.
7. Add the worst-case cost analysis: #6, #20.
8. Address the remaining major concerns and nits.

After this work, the BIP will be defensible against the questions
above. The current draft will not survive serious review.
