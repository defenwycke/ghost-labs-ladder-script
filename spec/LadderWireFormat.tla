------------------------ MODULE LadderWireFormat ------------------------
(***************************************************************************)
(* Model the micro-header encoding/decoding for Ladder Script wire format.*)
(* Covers roundtrip correctness, rejection of deprecated/unused types,    *)
(* inverted non-invertible rejection, and implicit vs explicit parsing.   *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* Constants                                                               *)
(***************************************************************************)

\* Representative block type IDs (small integers for tractability)
\* We model type IDs 0..7 mapped to micro-header slots 0..7
\* Plus escape codes at slots 8 (0x80) and 9 (0x81)
NumSlots == 8
EscapeNormal == 8
EscapeInverted == 9

\* Block types
ValidTypes == 0..5
DeprecatedTypes == {6}    \* e.g. HASH_PREIMAGE
UnusedSlots == {7}        \* 0xFFFF equivalent

\* Invertible block types
InvertibleTypes == {0, 1, 2}    \* e.g. CSV, CLTV, AMOUNT_LOCK
NonInvertibleTypes == {3, 4, 5} \* e.g. SIG, MULTISIG, etc.

\* Whether a block type has an implicit layout
TypesWithLayout == {0, 1, 2, 3, 4}
TypesWithoutLayout == {5}

DecodeResults == {"OK", "REJECT_UNUSED", "REJECT_DEPRECATED",
                  "REJECT_INVERTED_NON_INVERTIBLE"}

(***************************************************************************)
(* Encoding: block → wire bytes                                            *)
(* Returns [slot, typeId, inverted, useEscape]                             *)
(***************************************************************************)

\* Lookup: type → micro-header slot (inverse of the table)
\* If type is in slots 0..5, use direct micro-header
\* Otherwise use escape
HasMicroHeader(typeId) == typeId \in 0..(NumSlots - 1)

Encode(typeId, inverted) ==
    IF HasMicroHeader(typeId) /\ ~inverted
    THEN [slot |-> typeId, useEscape |-> FALSE, typeId |-> typeId, inverted |-> FALSE]
    ELSE IF inverted
    THEN [slot |-> EscapeInverted, useEscape |-> TRUE, typeId |-> typeId, inverted |-> TRUE]
    ELSE [slot |-> EscapeNormal, useEscape |-> TRUE, typeId |-> typeId, inverted |-> FALSE]

(***************************************************************************)
(* Decoding: wire bytes → block (or rejection)                             *)
(***************************************************************************)

Decode(slot, typeId, inverted) ==
    \* Non-escape slot: look up in table
    IF slot < NumSlots THEN
        IF slot \in UnusedSlots THEN [result |-> "REJECT_UNUSED", typeId |-> -1, inverted |-> FALSE]
        ELSE IF slot \in DeprecatedTypes THEN [result |-> "REJECT_DEPRECATED", typeId |-> -1, inverted |-> FALSE]
        ELSE [result |-> "OK", typeId |-> slot, inverted |-> FALSE]
    \* Escape normal
    ELSE IF slot = EscapeNormal THEN
        IF typeId \in DeprecatedTypes THEN [result |-> "REJECT_DEPRECATED", typeId |-> -1, inverted |-> FALSE]
        ELSE [result |-> "OK", typeId |-> typeId, inverted |-> FALSE]
    \* Escape inverted
    ELSE IF slot = EscapeInverted THEN
        IF typeId \in DeprecatedTypes THEN [result |-> "REJECT_DEPRECATED", typeId |-> -1, inverted |-> FALSE]
        ELSE IF typeId \in NonInvertibleTypes THEN [result |-> "REJECT_INVERTED_NON_INVERTIBLE", typeId |-> -1, inverted |-> FALSE]
        ELSE [result |-> "OK", typeId |-> typeId, inverted |-> TRUE]
    ELSE [result |-> "REJECT_UNUSED", typeId |-> -1, inverted |-> FALSE]

(***************************************************************************)
(* Parsing mode determination                                              *)
(***************************************************************************)

ParsingMode(slot, typeId) ==
    IF slot < NumSlots /\ slot \in TypesWithLayout THEN "IMPLICIT"
    ELSE IF slot < NumSlots /\ slot \notin TypesWithLayout THEN "EXPLICIT"
    ELSE IF slot \in {EscapeNormal, EscapeInverted} /\ typeId \in TypesWithLayout THEN "IMPLICIT"
    ELSE "EXPLICIT"

(***************************************************************************)
(* State machine                                                           *)
(***************************************************************************)

VARIABLES
    encTypeId,
    encInverted,
    decSlot,
    decTypeId,
    phase

vars == <<encTypeId, encInverted, decSlot, decTypeId, phase>>

Init ==
    /\ encTypeId \in ValidTypes
    /\ encInverted \in BOOLEAN
    /\ decSlot \in 0..9
    /\ decTypeId \in ValidTypes \cup DeprecatedTypes \cup UnusedSlots
    /\ phase = "check"

Next ==
    \/ /\ phase = "check"
       /\ phase' = "done"
       /\ UNCHANGED <<encTypeId, encInverted, decSlot, decTypeId>>
    \/ /\ phase = "done"
       /\ UNCHANGED vars

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

\* Roundtrip: Decode(Encode(block)) == block for valid non-deprecated types
Inv_Roundtrip ==
    \A tid \in ValidTypes :
        \A inv \in BOOLEAN :
            \* Skip inverted non-invertible (rejected by design)
            (~inv \/ tid \in InvertibleTypes) =>
                LET enc == Encode(tid, inv)
                    dec == Decode(enc.slot, enc.typeId, enc.inverted)
                IN /\ dec.result = "OK"
                   /\ dec.typeId = tid
                   /\ dec.inverted = inv

\* Unused micro-header slots → rejection
Inv_UnusedRejected ==
    \A s \in UnusedSlots :
        Decode(s, 0, FALSE).result = "REJECT_UNUSED"

\* Deprecated block types → rejection (direct slot)
Inv_DeprecatedRejectedDirect ==
    \A d \in DeprecatedTypes :
        Decode(d, 0, FALSE).result = "REJECT_DEPRECATED"

\* Deprecated block types → rejection (via escape)
Inv_DeprecatedRejectedEscape ==
    \A d \in DeprecatedTypes :
        /\ Decode(EscapeNormal, d, FALSE).result = "REJECT_DEPRECATED"
        /\ Decode(EscapeInverted, d, FALSE).result = "REJECT_DEPRECATED"

\* Inverted non-invertible → rejection
Inv_InvertedNonInvertibleRejected ==
    \A tid \in NonInvertibleTypes :
        Decode(EscapeInverted, tid, TRUE).result = "REJECT_INVERTED_NON_INVERTIBLE"

\* Micro-header + implicit layout → IMPLICIT parsing
Inv_ImplicitParsing ==
    \A s \in TypesWithLayout :
        s < NumSlots => ParsingMode(s, s) = "IMPLICIT"

\* Escape + no layout → EXPLICIT parsing
Inv_ExplicitParsing ==
    \A tid \in TypesWithoutLayout :
        /\ ParsingMode(EscapeNormal, tid) = "EXPLICIT"
        /\ ParsingMode(EscapeInverted, tid) = "EXPLICIT"

\* Escape + layout → IMPLICIT parsing
Inv_EscapeImplicitParsing ==
    \A tid \in TypesWithLayout :
        /\ ParsingMode(EscapeNormal, tid) = "IMPLICIT"
        /\ ParsingMode(EscapeInverted, tid) = "IMPLICIT"

\* Combined
SafetyInvariant ==
    /\ Inv_Roundtrip
    /\ Inv_UnusedRejected
    /\ Inv_DeprecatedRejectedDirect
    /\ Inv_DeprecatedRejectedEscape
    /\ Inv_InvertedNonInvertibleRejected
    /\ Inv_ImplicitParsing
    /\ Inv_ExplicitParsing
    /\ Inv_EscapeImplicitParsing

=============================================================================
