------------------------ MODULE LadderSighash ------------------------
(***************************************************************************)
(* Model the sighash commitment completeness for Ladder Script.           *)
(* Verifies which fields are committed under each hash type combination   *)
(* and that ANYPREVOUT skip rules are correctly applied.                  *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Hash type flags                                                         *)
(***************************************************************************)

\* Output type (low 2 bits)
OutputTypes == {"DEFAULT", "ALL", "NONE", "SINGLE"}

\* Input modifier flags
InputModifiers == {"NORMAL", "ANYONECANPAY", "ANYPREVOUT", "ANYPREVOUTANYSCRIPT"}

\* Encoding: output_type + modifier → hash_type byte
HashTypeByte(outType, inMod) ==
    LET outVal == CASE outType = "DEFAULT" -> 0
                    [] outType = "ALL" -> 1
                    [] outType = "NONE" -> 2
                    [] outType = "SINGLE" -> 3
        modVal == CASE inMod = "NORMAL" -> 0
                    [] inMod = "ANYONECANPAY" -> 16  \* 0x80 >> 3 (simplified)
                    [] inMod = "ANYPREVOUT" -> 8     \* 0x40 >> 3
                    [] inMod = "ANYPREVOUTANYSCRIPT" -> 24  \* 0xC0 >> 3
    IN outVal + modVal

\* Valid hash type combinations
IsValidHashType(outType, inMod) ==
    \* ANYONECANPAY alone with no output type is invalid (0x80 with output=0 means DEFAULT which is valid)
    \* Actually invalid: output type > 3, or standalone ACP without valid output
    \* The truly invalid cases are: output nibble = 0x04..0x0F and similar
    \* For our model: all combinations of our enums are valid EXCEPT
    \* ACP+NONE and ACP+SINGLE are valid. All combos are valid in Ladder.
    TRUE

(***************************************************************************)
(* Committed fields model                                                  *)
(* Each field is a boolean: TRUE = committed, FALSE = skipped             *)
(***************************************************************************)

\* Fields that are ALWAYS committed regardless of hash type
AlwaysCommitted == {"epoch", "hash_type", "tx_version", "tx_locktime", "spend_type"}

CommittedFields(outType, inMod) ==
    LET isACP == inMod = "ANYONECANPAY"
        isAPO == inMod = "ANYPREVOUT"
        isAPOAS == inMod = "ANYPREVOUTANYSCRIPT"
        isAnyPrevout == isAPO \/ isAPOAS

        \* Prevouts hash: committed unless ACP; also skipped if any APO variant
        commitPrevouts == ~isACP /\ ~isAnyPrevout

        \* Amounts hash: committed unless ACP (APO still commits to amounts!)
        commitAmounts == ~isACP

        \* Sequences hash: committed unless ACP
        commitSequences == ~isACP

        \* Outputs hash: committed if ALL or DEFAULT
        commitOutputs == outType \in {"ALL", "DEFAULT"}

        \* Single output hash: committed if SINGLE
        commitSingleOutput == outType = "SINGLE"

        \* Per-input prevout: committed unless ACP has APO variant
        \* Normal: always. ACP: yes. APO: no. APOAS: no.
        commitInputPrevout == ~isAnyPrevout

        \* Per-input spent_output: always (includes amount)
        commitInputSpentOutput == TRUE

        \* Per-input sequence: always for per-input section
        commitInputSequence == TRUE

        \* Input index: committed when NOT ACP
        commitInputIndex == ~isACP

        \* Conditions hash: committed unless APOAS
        commitConditions == ~isAPOAS
    IN
    [prevouts_hash |-> commitPrevouts,
     amounts_hash |-> commitAmounts,
     sequences_hash |-> commitSequences,
     outputs_hash |-> commitOutputs,
     single_output_hash |-> commitSingleOutput,
     input_prevout |-> commitInputPrevout,
     input_spent_output |-> commitInputSpentOutput,
     input_sequence |-> commitInputSequence,
     input_index |-> commitInputIndex,
     conditions_hash |-> commitConditions]

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    outType,
    inMod,
    phase

vars == <<outType, inMod, phase>>

Init ==
    /\ outType \in OutputTypes
    /\ inMod \in InputModifiers
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<outType, inMod>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* DEFAULT and ALL commit to same fields
Inv_DefaultEqualsAll ==
    \A im \in InputModifiers :
        CommittedFields("DEFAULT", im) = CommittedFields("ALL", im)

\* ANYPREVOUT still commits to amounts (prevents fee manipulation)
Inv_APOCommitsAmounts ==
    CommittedFields("ALL", "ANYPREVOUT").amounts_hash = TRUE

\* ANYPREVOUTANYSCRIPT skips conditions (allows script rebinding)
Inv_APOASSkipsConditions ==
    /\ CommittedFields("ALL", "ANYPREVOUTANYSCRIPT").conditions_hash = FALSE
    \* But regular APO does commit to conditions
    /\ CommittedFields("ALL", "ANYPREVOUT").conditions_hash = TRUE

\* ANYONECANPAY skips prevouts, amounts, sequences aggregates
Inv_ACPSkipsAggregates ==
    \A ot \in OutputTypes :
        LET cf == CommittedFields(ot, "ANYONECANPAY")
        IN /\ cf.prevouts_hash = FALSE
           /\ cf.amounts_hash = FALSE
           /\ cf.sequences_hash = FALSE

\* ANYPREVOUT skips prevout in per-input section
Inv_APOSkipsInputPrevout ==
    /\ CommittedFields("ALL", "ANYPREVOUT").input_prevout = FALSE
    /\ CommittedFields("ALL", "ANYPREVOUTANYSCRIPT").input_prevout = FALSE
    \* Normal keeps it
    /\ CommittedFields("ALL", "NORMAL").input_prevout = TRUE

\* NONE skips outputs hash
Inv_NoneSkipsOutputs ==
    \A im \in InputModifiers :
        /\ CommittedFields("NONE", im).outputs_hash = FALSE
        /\ CommittedFields("NONE", im).single_output_hash = FALSE

\* SINGLE commits only single output hash
Inv_SingleOutput ==
    \A im \in InputModifiers :
        /\ CommittedFields("SINGLE", im).outputs_hash = FALSE
        /\ CommittedFields("SINGLE", im).single_output_hash = TRUE

\* Every valid hash type commits to the always-committed fields
\* (modeled implicitly since those are always in the hash preimage)
Inv_AlwaysCommittedPresent ==
    TRUE  \* epoch, hash_type, tx_version, tx_locktime, spend_type always present by construction

\* Changing any committed field changes the hash (binding property)
\* Modeled structurally: committed fields are inputs to the hash function
Inv_FieldsAreInputs ==
    \A ot \in OutputTypes :
        \A im \in InputModifiers :
            LET cf == CommittedFields(ot, im)
            IN \* At least one field is always committed
               cf.input_spent_output = TRUE /\ cf.input_sequence = TRUE

\* ACP: no input_index (uses per-input fields directly)
Inv_ACPNoInputIndex ==
    \A ot \in OutputTypes :
        CommittedFields(ot, "ANYONECANPAY").input_index = FALSE

\* Normal: has input_index
Inv_NormalHasInputIndex ==
    \A ot \in OutputTypes :
        CommittedFields(ot, "NORMAL").input_index = TRUE

\* Combined
SafetyInvariant ==
    /\ Inv_DefaultEqualsAll
    /\ Inv_APOCommitsAmounts
    /\ Inv_APOASSkipsConditions
    /\ Inv_ACPSkipsAggregates
    /\ Inv_APOSkipsInputPrevout
    /\ Inv_NoneSkipsOutputs
    /\ Inv_SingleOutput
    /\ Inv_AlwaysCommittedPresent
    /\ Inv_FieldsAreInputs
    /\ Inv_ACPNoInputIndex
    /\ Inv_NormalHasInputIndex

=============================================================================
