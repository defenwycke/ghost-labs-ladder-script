--------------------------- MODULE LadderEval ---------------------------
(***************************************************************************)
(* Formal specification of Ladder Script evaluation semantics.             *)
(*                                                                         *)
(* Models:                                                                 *)
(*   - AND logic within rungs (all blocks must SATISFY)                    *)
(*   - OR logic across rungs (first satisfied rung wins)                   *)
(*   - Selective inversion (SATISFIED <-> UNSATISFIED, ERROR unchanged)    *)
(*   - Relay evaluation (forward-only DAG, cached results)                 *)
(*   - Block evaluation dispatch and result types                          *)
(*   - Anti-spam: non-invertible blocks cannot be inverted                 *)
(*   - Recursion termination (RECURSE_* bounded by depth/count/height)     *)
(*                                                                         *)
(* This spec is independent of the C++ implementation and can be           *)
(* model-checked with TLC to verify structural properties.                 *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    BlockTypes,          \* Set of all block type identifiers
    InvertibleTypes,     \* Subset of BlockTypes that can be inverted
    KeyConsumingTypes,   \* Subset that consume pubkeys (never invertible)
    MaxRungs,            \* Maximum rungs per ladder (16)
    MaxBlocksPerRung,    \* Maximum blocks per rung (8)
    MaxRelays,           \* Maximum relays per ladder (8)
    MaxRelayDepth,       \* Maximum relay chain depth (4)
    MaxRecurseDepth      \* Maximum recursion depth for RECURSE_* blocks

(***************************************************************************)
(* Evaluation results                                                      *)
(***************************************************************************)

EvalResults == {"SATISFIED", "UNSATISFIED", "ERROR", "UNKNOWN_BLOCK_TYPE"}

(***************************************************************************)
(* Block structure                                                         *)
(***************************************************************************)

\* A block has a type, an inverted flag, and an intrinsic eval result
\* (the result before inversion is applied)
Block == [type : BlockTypes, inverted : BOOLEAN, intrinsicResult : EvalResults]

\* A rung is a sequence of blocks with relay references
Rung == [blocks : Seq(Block), relayRefs : SUBSET (0..MaxRelays-1)]

\* A relay is a sequence of blocks with relay references (forward-only)
Relay == [blocks : Seq(Block), relayRefs : SUBSET (0..MaxRelays-1)]

\* A ladder is a sequence of rungs, a sequence of relays, and a coil
Ladder == [rungs : Seq(Rung), relays : Seq(Relay)]

(***************************************************************************)
(* Inversion logic                                                         *)
(***************************************************************************)

ApplyInversion(result, inverted) ==
    IF ~inverted THEN result
    ELSE
        CASE result = "SATISFIED"        -> "UNSATISFIED"
          [] result = "UNSATISFIED"      -> "SATISFIED"
          [] result = "ERROR"            -> "ERROR"
          [] result = "UNKNOWN_BLOCK_TYPE" -> "SATISFIED"

(***************************************************************************)
(* Block evaluation                                                        *)
(***************************************************************************)

\* Evaluate a single block: check inversion validity, then apply inversion
EvalBlock(block) ==
    \* Defense in depth: inverted non-invertible blocks return ERROR
    IF block.inverted /\ block.type \notin InvertibleTypes
    THEN "ERROR"
    ELSE ApplyInversion(block.intrinsicResult, block.inverted)

(***************************************************************************)
(* Rung evaluation (AND logic)                                             *)
(***************************************************************************)

\* Evaluate a rung: all blocks must return SATISFIED
\* If any block returns ERROR, the whole rung is ERROR
\* If any block returns UNSATISFIED (and no ERROR), rung is UNSATISFIED
EvalRung(rung, relayResults) ==
    LET n == Len(rung.blocks)
    IN IF n = 0 THEN "ERROR"
       ELSE
         \* Check relay prerequisites
         LET relaysMet ==
             \A ref \in rung.relayRefs :
                 ref < Len(relayResults) /\ relayResults[ref+1] = "SATISFIED"
         IN
         IF ~relaysMet THEN "UNSATISFIED"
         ELSE
           \* Evaluate blocks left-to-right (AND logic)
           LET blockResults == [i \in 1..n |-> EvalBlock(rung.blocks[i])]
           IN
             IF \E i \in 1..n : blockResults[i] = "ERROR"
             THEN "ERROR"
             ELSE IF \A i \in 1..n : blockResults[i] = "SATISFIED"
             THEN "SATISFIED"
             ELSE "UNSATISFIED"

(***************************************************************************)
(* Relay evaluation (forward-only DAG)                                     *)
(***************************************************************************)

\* Evaluate relays in order, caching results
\* Each relay can only reference relays with lower indices (no cycles)
RECURSIVE EvalRelaysHelper(_, _, _)
EvalRelaysHelper(relays, results, idx) ==
    IF idx > Len(relays) THEN results
    ELSE
        LET relay == relays[idx]
            \* Check relay_refs: all must be satisfied
            refsMet == \A ref \in relay.relayRefs :
                           ref < idx - 1 /\ results[ref+1] = "SATISFIED"
        IN
        IF ~refsMet THEN
            EvalRelaysHelper(relays, Append(results, "UNSATISFIED"), idx + 1)
        ELSE IF Len(relay.blocks) = 0 THEN
            \* Empty relay is an error that aborts all evaluation
            Append(results, "ERROR")
        ELSE
            LET blockResults == [i \in 1..Len(relay.blocks) |->
                                    EvalBlock(relay.blocks[i])]
                relayResult ==
                    IF \E i \in 1..Len(relay.blocks) : blockResults[i] = "ERROR"
                    THEN "ERROR"
                    ELSE IF \A i \in 1..Len(relay.blocks) : blockResults[i] = "SATISFIED"
                    THEN "SATISFIED"
                    ELSE "UNSATISFIED"
            IN
            IF relayResult = "ERROR" THEN
                Append(results, "ERROR")  \* Abort: relay ERROR fails everything
            ELSE
                EvalRelaysHelper(relays, Append(results, relayResult), idx + 1)

EvalRelays(relays) == EvalRelaysHelper(relays, <<>>, 1)

(***************************************************************************)
(* Ladder evaluation (OR logic across rungs)                               *)
(***************************************************************************)

\* Evaluate a complete ladder: first satisfied rung wins
\* Returns [result |-> "SATISFIED"/"UNSATISFIED"/"ERROR", rungIndex |-> Nat]
RECURSIVE EvalLadderHelper(_, _, _, _)
EvalLadderHelper(rungs, relayResults, idx, hasError) ==
    IF idx > Len(rungs) THEN
        IF hasError THEN [result |-> "ERROR", rungIndex |-> 0]
        ELSE [result |-> "UNSATISFIED", rungIndex |-> 0]
    ELSE
        LET rungResult == EvalRung(rungs[idx], relayResults)
        IN
        CASE rungResult = "SATISFIED" ->
                [result |-> "SATISFIED", rungIndex |-> idx]
          [] rungResult = "ERROR" ->
                \* ERROR in any rung fails the entire ladder
                [result |-> "ERROR", rungIndex |-> 0]
          [] OTHER ->
                EvalLadderHelper(rungs, relayResults, idx + 1, hasError)

EvalLadder(ladder) ==
    IF Len(ladder.rungs) = 0 THEN [result |-> "UNSATISFIED", rungIndex |-> 0]
    ELSE
        LET relayResults ==
                IF Len(ladder.relays) = 0 THEN <<>>
                ELSE EvalRelays(ladder.relays)
            \* Check if any relay returned ERROR (aborts everything)
            relayError == \E i \in 1..Len(relayResults) :
                              relayResults[i] = "ERROR"
        IN
        IF relayError THEN [result |-> "ERROR", rungIndex |-> 0]
        ELSE EvalLadderHelper(ladder.rungs, relayResults, 1, FALSE)

(***************************************************************************)
(* Safety properties (invariants)                                          *)
(***************************************************************************)

\* PROPERTY 1: Key-consuming blocks are never invertible
\* (prevents garbage-pubkey data embedding via inversion)
KeyConsumingNeverInvertible ==
    KeyConsumingTypes \cap InvertibleTypes = {}

\* PROPERTY 2: Inversion preserves ERROR
\* ERROR results are never flipped by inversion
InversionPreservesError ==
    \A inv \in BOOLEAN :
        ApplyInversion("ERROR", inv) = "ERROR"

\* PROPERTY 3: Double inversion is identity
\* Inverting twice returns the original result
DoubleInversionIdentity ==
    \A result \in EvalResults :
        ApplyInversion(ApplyInversion(result, TRUE), TRUE) = result

\* PROPERTY 4: Empty rung is always ERROR
EmptyRungError ==
    \A relayResults \in Seq(EvalResults) :
        EvalRung([blocks |-> <<>>, relayRefs |-> {}], relayResults) = "ERROR"

\* PROPERTY 5: Empty ladder never satisfies
EmptyLadderNeverSatisfied ==
    EvalLadder([rungs |-> <<>>, relays |-> <<>>]).result # "SATISFIED"

\* PROPERTY 6: A rung with all SATISFIED blocks is SATISFIED
\*             (assuming relay prerequisites met)
AllSatisfiedRungSatisfied ==
    \A n \in 1..MaxBlocksPerRung :
        LET blocks == [i \in 1..n |->
                [type |-> CHOOSE t \in BlockTypes : TRUE,
                 inverted |-> FALSE,
                 intrinsicResult |-> "SATISFIED"]]
            rung == [blocks |-> blocks, relayRefs |-> {}]
        IN EvalRung(rung, <<>>) = "SATISFIED"

\* PROPERTY 7: A single ERROR block makes the rung ERROR
SingleErrorBlockMakesRungError ==
    \A t \in BlockTypes :
        LET block == [type |-> t, inverted |-> FALSE, intrinsicResult |-> "ERROR"]
            rung == [blocks |-> <<block>>, relayRefs |-> {}]
        IN EvalRung(rung, <<>>) = "ERROR"

\* PROPERTY 8: Inverted non-invertible block always ERROR
InvertedNonInvertibleAlwaysError ==
    \A t \in BlockTypes \ InvertibleTypes :
        \A r \in EvalResults :
            LET block == [type |-> t, inverted |-> TRUE, intrinsicResult |-> r]
            IN EvalBlock(block) = "ERROR"

(***************************************************************************)
(* Recursion termination model                                             *)
(***************************************************************************)

\* Model recursion depth as a decreasing natural number
\* RECURSE_SAME: depth decreases by 1 each hop
\* RECURSE_COUNT: counter decreases by 1 each hop
\* RECURSE_UNTIL: terminates when height >= target
\* RECURSE_SPLIT: max_splits decreases
\* RECURSE_DECAY: parameter decreases toward zero

VARIABLES recurseDepth

RecurseInit == recurseDepth = MaxRecurseDepth

\* A recursion step is valid iff depth > 0
RecurseStep == recurseDepth > 0 /\ recurseDepth' = recurseDepth - 1

\* Termination: depth reaches 0
RecurseTerminated == recurseDepth = 0

\* PROPERTY 9: Recursion always terminates
\* (depth is a natural number that strictly decreases)
RecurseTerminates ==
    recurseDepth \in 0..MaxRecurseDepth /\
    (recurseDepth > 0 => recurseDepth' < recurseDepth)

RecurseSpec == RecurseInit /\ [][RecurseStep]_recurseDepth

(***************************************************************************)
(* Anti-spam properties                                                    *)
(***************************************************************************)

\* PROPERTY 10: No block type allows arbitrary data embedding
\* Key-consuming blocks bind pubkeys to Merkle leaves (merkle_pub_key).
\* Non-key blocks use implicit field layouts with fixed types.
\* PREIMAGE fields are capped at MAX_PREIMAGE_FIELDS_PER_WITNESS = 2.
\* DATA type is restricted to DATA_RETURN blocks only.
\*
\* This property is structural (enforced by deserialization) and cannot
\* be fully modeled in TLA+ without the wire format. We assert the
\* key invariant: key-consuming blocks cannot be inverted.
AntiSpamKeyInvariant == KeyConsumingNeverInvertible

(***************************************************************************)
(* Relay DAG properties                                                    *)
(***************************************************************************)

\* PROPERTY 11: Relay references are forward-only (no cycles)
\* relay N can only reference relays 0..N-1
RelayForwardOnly(relays) ==
    \A i \in 1..Len(relays) :
        \A ref \in relays[i].relayRefs :
            ref < i - 1

\* PROPERTY 12: Relay chain depth is bounded
\* The longest chain of relay-requires-relay is at most MaxRelayDepth
RECURSIVE RelayDepth(_, _, _)
RelayDepth(relays, idx, depths) ==
    IF idx > Len(relays) THEN depths
    ELSE
        LET maxRefDepth ==
                IF relays[idx].relayRefs = {} THEN 0
                ELSE LET refDepths == {depths[ref+1] : ref \in relays[idx].relayRefs}
                     IN CHOOSE d \in refDepths : \A d2 \in refDepths : d >= d2
            depth == maxRefDepth + 1
        IN RelayDepth(relays, idx + 1, Append(depths, depth))

RelayDepthBounded(relays) ==
    LET depths == RelayDepth(relays, 1, <<>>)
    IN \A i \in 1..Len(depths) : depths[i] <= MaxRelayDepth

(***************************************************************************)
(* OR-across-rungs: first-wins semantics                                   *)
(***************************************************************************)

\* PROPERTY 13: If rung K is satisfied, earlier rungs don't affect outcome
\* (first-wins: the ladder result is determined by the first satisfied rung)
FirstWinsSemantic ==
    \A ladder \in Ladder :
        LET eval == EvalLadder(ladder)
        IN eval.result = "SATISFIED" =>
            \* The rungIndex is the FIRST satisfied rung
            \A i \in 1..(eval.rungIndex - 1) :
                LET relayResults ==
                    IF Len(ladder.relays) = 0 THEN <<>>
                    ELSE EvalRelays(ladder.relays)
                IN EvalRung(ladder.rungs[i], relayResults) # "SATISFIED"

=============================================================================
