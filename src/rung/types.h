// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_TYPES_H
#define BITCOIN_RUNG_TYPES_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rung {

/** Block types for Ladder Script function blocks.
 *  Each block evaluates a single spending condition within a rung.
 *  Encoded as uint16_t in the wire format (little-endian 2 bytes).
 *
 *  Ranges (10 families, 60 block types):
 *    0x0001-0x00FF  Signature family (SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG)
 *    0x0100-0x01FF  Timelock family (CSV, CSV_TIME, CLTV, CLTV_TIME)
 *    0x0200-0x02FF  Hash family (HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH)
 *    0x0300-0x03FF  Covenant family (CTV, VAULT_LOCK, AMOUNT_LOCK)
 *    0x0400-0x04FF  Recursion family (RECURSE_SAME, _MODIFIED, _UNTIL, _COUNT, _SPLIT, _DECAY)
 *    0x0500-0x05FF  Anchor family (ANCHOR, _CHANNEL, _POOL, _RESERVE, _SEAL, _ORACLE)
 *    0x0600-0x06FF  PLC family (HYSTERESIS_*, TIMER_*, LATCH_*, COUNTER_*, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN)
 *    0x0700-0x07FF  Compound family (TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG)
 *    0x0800-0x08FF  Governance family (EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR)
 *    0x0900-0x09FF  Legacy family (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2TR_SCRIPT) */
enum class RungBlockType : uint16_t {
    // Signature family
    SIG              = 0x0001, //!< Single signature verification
    MULTISIG         = 0x0002, //!< M-of-N threshold signature
    ADAPTOR_SIG      = 0x0003, //!< Adaptor signature verification
    MUSIG_THRESHOLD  = 0x0004, //!< MuSig2/FROST aggregate threshold signature
    KEY_REF_SIG      = 0x0005, //!< Signature using key commitment from a relay block

    // Timelock family
    CSV              = 0x0101, //!< Relative timelock — block-height (BIP68 sequence)
    CSV_TIME         = 0x0102, //!< Relative timelock — median-time-past
    CLTV             = 0x0103, //!< Absolute timelock — block-height (nLockTime)
    CLTV_TIME        = 0x0104, //!< Absolute timelock — median-time-past

    // Hash family
    HASH_PREIMAGE    = 0x0201, //!< SHA-256 hash preimage reveal
    HASH160_PREIMAGE = 0x0202, //!< HASH160 preimage reveal
    TAGGED_HASH      = 0x0203, //!< BIP-340 tagged hash verification

    // Covenant family
    CTV              = 0x0301, //!< OP_CHECKTEMPLATEVERIFY covenant
    VAULT_LOCK       = 0x0302, //!< Vault timelock covenant
    AMOUNT_LOCK      = 0x0303, //!< Output amount range check

    // Recursion family
    RECURSE_SAME     = 0x0401, //!< Recursive re-encumber with identical conditions
    RECURSE_MODIFIED = 0x0402, //!< Recursive re-encumber with single mutation
    RECURSE_UNTIL    = 0x0403, //!< Recursive until block height
    RECURSE_COUNT    = 0x0404, //!< Recursive countdown
    RECURSE_SPLIT    = 0x0405, //!< Recursive output splitting
    RECURSE_DECAY    = 0x0406, //!< Recursive parameter decay

    // Anchor/L2 family
    ANCHOR           = 0x0501, //!< Generic anchor
    ANCHOR_CHANNEL   = 0x0502, //!< Lightning channel anchor
    ANCHOR_POOL      = 0x0503, //!< Pool anchor
    ANCHOR_RESERVE   = 0x0504, //!< Reserve anchor (guardian set)
    ANCHOR_SEAL      = 0x0505, //!< Seal anchor
    ANCHOR_ORACLE    = 0x0506, //!< Oracle anchor

    // Compound family (collapsed multi-block patterns)
    TIMELOCKED_SIG   = 0x0701, //!< SIG + CSV combined: pubkey + sig + block-height timelock
    HTLC             = 0x0702, //!< Hash + Timelock + Sig: atomic swap / Lightning HTLC
    HASH_SIG         = 0x0703, //!< HASH_PREIMAGE + SIG combined: atomic swap claim
    PTLC             = 0x0704, //!< ADAPTOR_SIG + CSV combined: point-locked payment channel
    CLTV_SIG         = 0x0705, //!< SIG + CLTV combined: absolute-time locked payment
    TIMELOCKED_MULTISIG = 0x0706, //!< MULTISIG + CSV combined: time-delayed M-of-N

    // Governance family (transaction-level constraints)
    EPOCH_GATE       = 0x0801, //!< Periodic spending window: spendable only in specific block epochs
    WEIGHT_LIMIT     = 0x0802, //!< Maximum transaction weight limit
    INPUT_COUNT      = 0x0803, //!< Input count bounds (min/max inputs in spending tx)
    OUTPUT_COUNT     = 0x0804, //!< Output count bounds (min/max outputs in spending tx)
    RELATIVE_VALUE   = 0x0805, //!< Output value as ratio of input (numerator/denominator)
    ACCUMULATOR      = 0x0806, //!< Merkle accumulator: set membership proof with root update

    // Legacy family (wrapped Bitcoin transaction types)
    P2PK_LEGACY          = 0x0901, //!< P2PK wrapped: PUBKEY_COMMIT + SCHEME → PUBKEY + SIGNATURE
    P2PKH_LEGACY         = 0x0902, //!< P2PKH wrapped: HASH160 → PUBKEY + SIGNATURE
    P2SH_LEGACY          = 0x0903, //!< P2SH wrapped: HASH160 → PREIMAGE (inner conditions) + inner witness
    P2WPKH_LEGACY        = 0x0904, //!< P2WPKH wrapped: HASH160 → PUBKEY + SIGNATURE (delegates to P2PKH)
    P2WSH_LEGACY         = 0x0905, //!< P2WSH wrapped: HASH256 → PREIMAGE (inner conditions) + inner witness
    P2TR_LEGACY          = 0x0906, //!< P2TR key-path wrapped: PUBKEY_COMMIT + SCHEME → PUBKEY + SIGNATURE
    P2TR_SCRIPT_LEGACY   = 0x0907, //!< P2TR script-path wrapped: HASH256 + PUBKEY_COMMIT → PREIMAGE (inner) + inner witness

    // PLC family
    HYSTERESIS_FEE   = 0x0601, //!< Fee hysteresis band
    HYSTERESIS_VALUE = 0x0602, //!< Value hysteresis band
    TIMER_CONTINUOUS = 0x0611, //!< Continuous timer (consecutive blocks)
    TIMER_OFF_DELAY  = 0x0612, //!< Off-delay timer (hold after trigger)
    LATCH_SET        = 0x0621, //!< Latch set (state activation)
    LATCH_RESET      = 0x0622, //!< Latch reset (state deactivation)
    COUNTER_DOWN     = 0x0631, //!< Down counter (decrement on event)
    COUNTER_PRESET   = 0x0632, //!< Preset counter (approval accumulator)
    COUNTER_UP       = 0x0633, //!< Up counter (increment on event)
    COMPARE          = 0x0641, //!< Comparator (amount vs thresholds)
    SEQUENCER        = 0x0651, //!< Step sequencer
    ONE_SHOT         = 0x0661, //!< One-shot activation window
    RATE_LIMIT       = 0x0671, //!< Rate limiter
    COSIGN           = 0x0681, //!< Co-spend constraint: requires another input with matching conditions hash
};

/** Data types for typed parameters within blocks.
 *  Every byte in a Ladder Script witness must belong to one of these types.
 *  No arbitrary data pushes are possible.
 *  (Renamed from RungFieldType in v1.) */
enum class RungDataType : uint8_t {
    PUBKEY        = 0x01, //!< Public key: 1-2048 bytes (witness-only; conditions use PUBKEY_COMMIT)
    PUBKEY_COMMIT = 0x02, //!< Public key commitment: exactly 32 bytes
    HASH256       = 0x03, //!< SHA-256 hash: exactly 32 bytes
    HASH160       = 0x04, //!< RIPEMD160(SHA256()) hash: exactly 20 bytes
    PREIMAGE      = 0x05, //!< Hash preimage: 1-252 bytes
    SIGNATURE     = 0x06, //!< Signature: 1-50000 bytes (Schnorr 64-65, ECDSA 8-72, PQ up to 49216)
    SPEND_INDEX   = 0x07, //!< Spend index reference: 4 bytes
    NUMERIC       = 0x08, //!< Numeric value (threshold, locktime, etc.): 1-4 bytes
    SCHEME        = 0x09, //!< Signature scheme selector: 1 byte
    SCRIPT_BODY   = 0x0A, //!< Serialized inner conditions: 1-10000 bytes (witness-only; node computes hash for conditions)
};

// Backward-compatible alias
using RungFieldType = RungDataType;

/** Returns true if the uint16_t is a known RungBlockType. */
inline bool IsKnownBlockType(uint16_t b)
{
    switch (static_cast<RungBlockType>(b)) {
    // Signature
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::KEY_REF_SIG:
    // Timelock
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    // Hash
    case RungBlockType::HASH_PREIMAGE:
    case RungBlockType::HASH160_PREIMAGE:
    case RungBlockType::TAGGED_HASH:
    // Covenant
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::AMOUNT_LOCK:
    // Anchor
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
    // Recursion
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    // PLC
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COUNTER_UP:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    case RungBlockType::COSIGN:
    // Compound family
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::TIMELOCKED_MULTISIG:
    // Governance family
    case RungBlockType::EPOCH_GATE:
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::RELATIVE_VALUE:
    case RungBlockType::ACCUMULATOR:
    // Legacy family
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
        return true;
    }
    return false;
}

/** Returns true if the byte is a known RungDataType. */
inline bool IsKnownDataType(uint8_t b)
{
    return b >= 0x01 && b <= 0x0A;
}

// Backward-compatible alias
inline bool IsKnownFieldType(uint8_t b) { return IsKnownDataType(b); }

/** Minimum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMinSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 1;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 1;
    case RungDataType::SCRIPT_BODY:   return 1;
    case RungDataType::SIGNATURE:     return 1;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 1;
    case RungDataType::SCHEME:        return 1;
    }
    return 0;
}

/** Maximum allowed size for a given data type. Returns 0 for unknown types. */
inline size_t FieldMaxSize(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return 2048;
    case RungDataType::PUBKEY_COMMIT: return 32;
    case RungDataType::HASH256:       return 32;
    case RungDataType::HASH160:       return 20;
    case RungDataType::PREIMAGE:      return 252;
    case RungDataType::SCRIPT_BODY:   return 10000;
    case RungDataType::SIGNATURE:     return 50000;
    case RungDataType::SPEND_INDEX:   return 4;
    case RungDataType::NUMERIC:       return 4;
    case RungDataType::SCHEME:        return 1;
    }
    return 0;
}

/** Returns a human-readable name for a block type. */
inline std::string BlockTypeName(RungBlockType type)
{
    switch (type) {
    case RungBlockType::SIG:              return "SIG";
    case RungBlockType::MULTISIG:         return "MULTISIG";
    case RungBlockType::ADAPTOR_SIG:      return "ADAPTOR_SIG";
    case RungBlockType::MUSIG_THRESHOLD:  return "MUSIG_THRESHOLD";
    case RungBlockType::KEY_REF_SIG:      return "KEY_REF_SIG";
    case RungBlockType::CSV:              return "CSV";
    case RungBlockType::CSV_TIME:         return "CSV_TIME";
    case RungBlockType::CLTV:             return "CLTV";
    case RungBlockType::CLTV_TIME:        return "CLTV_TIME";
    case RungBlockType::HASH_PREIMAGE:    return "HASH_PREIMAGE";
    case RungBlockType::HASH160_PREIMAGE: return "HASH160_PREIMAGE";
    case RungBlockType::TAGGED_HASH:      return "TAGGED_HASH";
    case RungBlockType::CTV:              return "CTV";
    case RungBlockType::VAULT_LOCK:       return "VAULT_LOCK";
    case RungBlockType::AMOUNT_LOCK:      return "AMOUNT_LOCK";
    case RungBlockType::RECURSE_SAME:     return "RECURSE_SAME";
    case RungBlockType::RECURSE_MODIFIED: return "RECURSE_MODIFIED";
    case RungBlockType::RECURSE_UNTIL:    return "RECURSE_UNTIL";
    case RungBlockType::RECURSE_COUNT:    return "RECURSE_COUNT";
    case RungBlockType::RECURSE_SPLIT:    return "RECURSE_SPLIT";
    case RungBlockType::RECURSE_DECAY:    return "RECURSE_DECAY";
    case RungBlockType::ANCHOR:           return "ANCHOR";
    case RungBlockType::ANCHOR_CHANNEL:   return "ANCHOR_CHANNEL";
    case RungBlockType::ANCHOR_POOL:      return "ANCHOR_POOL";
    case RungBlockType::ANCHOR_RESERVE:   return "ANCHOR_RESERVE";
    case RungBlockType::ANCHOR_SEAL:      return "ANCHOR_SEAL";
    case RungBlockType::ANCHOR_ORACLE:    return "ANCHOR_ORACLE";
    case RungBlockType::HYSTERESIS_FEE:   return "HYSTERESIS_FEE";
    case RungBlockType::HYSTERESIS_VALUE: return "HYSTERESIS_VALUE";
    case RungBlockType::TIMER_CONTINUOUS: return "TIMER_CONTINUOUS";
    case RungBlockType::TIMER_OFF_DELAY:  return "TIMER_OFF_DELAY";
    case RungBlockType::LATCH_SET:        return "LATCH_SET";
    case RungBlockType::LATCH_RESET:      return "LATCH_RESET";
    case RungBlockType::COUNTER_DOWN:     return "COUNTER_DOWN";
    case RungBlockType::COUNTER_PRESET:   return "COUNTER_PRESET";
    case RungBlockType::COUNTER_UP:       return "COUNTER_UP";
    case RungBlockType::COMPARE:          return "COMPARE";
    case RungBlockType::SEQUENCER:        return "SEQUENCER";
    case RungBlockType::ONE_SHOT:         return "ONE_SHOT";
    case RungBlockType::RATE_LIMIT:       return "RATE_LIMIT";
    case RungBlockType::COSIGN:           return "COSIGN";
    case RungBlockType::TIMELOCKED_SIG:   return "TIMELOCKED_SIG";
    case RungBlockType::HTLC:             return "HTLC";
    case RungBlockType::HASH_SIG:         return "HASH_SIG";
    case RungBlockType::PTLC:             return "PTLC";
    case RungBlockType::CLTV_SIG:         return "CLTV_SIG";
    case RungBlockType::TIMELOCKED_MULTISIG: return "TIMELOCKED_MULTISIG";
    case RungBlockType::EPOCH_GATE:       return "EPOCH_GATE";
    case RungBlockType::WEIGHT_LIMIT:     return "WEIGHT_LIMIT";
    case RungBlockType::INPUT_COUNT:      return "INPUT_COUNT";
    case RungBlockType::OUTPUT_COUNT:     return "OUTPUT_COUNT";
    case RungBlockType::RELATIVE_VALUE:   return "RELATIVE_VALUE";
    case RungBlockType::ACCUMULATOR:      return "ACCUMULATOR";
    case RungBlockType::P2PK_LEGACY:      return "P2PK_LEGACY";
    case RungBlockType::P2PKH_LEGACY:     return "P2PKH_LEGACY";
    case RungBlockType::P2SH_LEGACY:      return "P2SH_LEGACY";
    case RungBlockType::P2WPKH_LEGACY:    return "P2WPKH_LEGACY";
    case RungBlockType::P2WSH_LEGACY:     return "P2WSH_LEGACY";
    case RungBlockType::P2TR_LEGACY:      return "P2TR_LEGACY";
    case RungBlockType::P2TR_SCRIPT_LEGACY: return "P2TR_SCRIPT_LEGACY";
    }
    return "UNKNOWN";
}

/** Returns a human-readable name for a data type. */
inline std::string DataTypeName(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:        return "PUBKEY";
    case RungDataType::PUBKEY_COMMIT: return "PUBKEY_COMMIT";
    case RungDataType::HASH256:       return "HASH256";
    case RungDataType::HASH160:       return "HASH160";
    case RungDataType::PREIMAGE:      return "PREIMAGE";
    case RungDataType::SCRIPT_BODY:   return "SCRIPT_BODY";
    case RungDataType::SIGNATURE:     return "SIGNATURE";
    case RungDataType::SPEND_INDEX:   return "SPEND_INDEX";
    case RungDataType::NUMERIC:       return "NUMERIC";
    case RungDataType::SCHEME:        return "SCHEME";
    }
    return "UNKNOWN";
}

// Backward-compatible alias
inline std::string FieldTypeName(RungDataType type) { return DataTypeName(type); }

/** Coil type — determines what this rung unlocks. */
enum class RungCoilType : uint8_t {
    UNLOCK    = 0x01, //!< Standard unlock — spend the output
    UNLOCK_TO = 0x02, //!< Unlock to a specific destination
    COVENANT  = 0x03, //!< Covenant — constrains the spending transaction
};

/** Attestation mode for signatures in this rung. */
enum class RungAttestationMode : uint8_t {
    INLINE    = 0x01, //!< Signatures inline in witness
    AGGREGATE = 0x02, //!< Aggregated signature (block-level aggregate)
    DEFERRED  = 0x03, //!< Deferred attestation (template hash)
};

/** Signature scheme for this rung. */
enum class RungScheme : uint8_t {
    SCHNORR     = 0x01, //!< BIP-340 Schnorr
    ECDSA       = 0x02, //!< ECDSA (legacy compat)
    FALCON512   = 0x10, //!< FALCON-512 post-quantum
    FALCON1024  = 0x11, //!< FALCON-1024 post-quantum
    DILITHIUM3  = 0x12, //!< Dilithium3 post-quantum
    SPHINCS_SHA = 0x13, //!< SPHINCS+-SHA2-256f post-quantum
};

/** Returns true if the scheme is a known value. */
inline bool IsKnownScheme(uint8_t s)
{
    switch (static_cast<RungScheme>(s)) {
    case RungScheme::SCHNORR:
    case RungScheme::ECDSA:
    case RungScheme::FALCON512:
    case RungScheme::FALCON1024:
    case RungScheme::DILITHIUM3:
    case RungScheme::SPHINCS_SHA:
        return true;
    }
    return false;
}

/** Returns true if the scheme is a post-quantum scheme. */
inline bool IsPQScheme(RungScheme s)
{
    return static_cast<uint8_t>(s) >= 0x10;
}

/** Coil metadata — attached to each output (LadderWitness), determines unlock semantics.
 *  UNLOCK:    Standard spend to an address.
 *  UNLOCK_TO: Send to an address, but recipient must also satisfy coil conditions.
 *  COVENANT:  Constrains the spending transaction structure via coil conditions. */
struct RungCoil {
    RungCoilType coil_type{RungCoilType::UNLOCK};
    RungAttestationMode attestation{RungAttestationMode::INLINE};
    RungScheme scheme{RungScheme::SCHNORR};
    std::vector<uint8_t> address;              //!< Destination address (raw scriptPubKey bytes), empty if none
    std::vector<struct Rung> conditions;        //!< Coil condition rungs (AND within rung, OR across rungs)
};

/** A single typed field within a block. Type constrains the allowed data size. */
struct RungField {
    RungDataType type;
    std::vector<uint8_t> data;

    /** Validate that data size conforms to the field type constraints.
     *  Returns false with reason populated on failure. */
    bool IsValid(std::string& reason) const;
};

/** A function block within a rung. Contains typed fields that the evaluator checks. */
struct RungBlock {
    RungBlockType type;
    std::vector<RungField> fields;
    bool inverted{false}; //!< If true, evaluation result is inverted (SATISFIED↔UNSATISFIED)
};

/** Compact rung types — efficient encodings for common single-block patterns.
 *  Triggered by n_blocks == 0 sentinel within a rung.
 *  See COMPACT_RUNG_PLAN.md for design rationale. */
enum class CompactRungType : uint8_t {
    COMPACT_SIG = 0x01,  //!< Single SIG with explicit PUBKEY_COMMIT + SCHEME
};

/** Returns true if the byte is a known CompactRungType. */
inline bool IsKnownCompactRungType(uint8_t b)
{
    return b == 0x01;
}

/** Compact rung data — stored in Rung when compact is set.
 *  COMPACT_SIG: pubkey_commit (32 bytes) + scheme.
 *  Resolves to an equivalent SIG block at evaluation time. */
struct CompactRungData {
    CompactRungType type;
    std::vector<uint8_t> pubkey_commit;  //!< 32-byte SHA-256(pubkey)
    RungScheme scheme{RungScheme::SCHNORR};
};

/** A single rung in a ladder. All blocks must be satisfied (AND logic).
 *  When compact is set, the rung has no blocks — it encodes a single
 *  condition compactly (e.g., COMPACT_SIG = SIG with inline PUBKEY_COMMIT). */
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};                //!< Rung identifier within the ladder
    std::vector<uint16_t> relay_refs;    //!< Indices into relay array that must be satisfied
    std::optional<CompactRungData> compact; //!< Compact rung encoding (n_blocks == 0 on wire)

    bool IsCompact() const { return compact.has_value(); }
};

/** A relay definition: blocks evaluated for cross-referencing, not tied to an output.
 *  Relays enable AND composition across rungs and DRY condition reuse.
 *  Forward-only indexing: relay N can only require relays 0..N-1 (no cycles). */
struct Relay {
    std::vector<RungBlock> blocks;
    std::vector<uint16_t> relay_refs;    //!< Indices of other relays (must be < own index)
};

/** A single field-level diff in a witness reference. */
struct WitnessDiff {
    uint16_t rung_index;   //!< Which rung in the inherited witness
    uint16_t block_index;  //!< Which block within that rung
    uint16_t field_index;  //!< Which field within that block
    RungField new_field;   //!< Replacement field data
};

/** Witness reference: rungs/relays inherited from another input's witness with diffs.
 *  Coil is always provided fresh (never inherited — inheriting destination
 *  addresses would be a dangerous footgun). */
struct WitnessReference {
    uint32_t input_index;               //!< Which input's witness to inherit rungs/relays from
    std::vector<WitnessDiff> diffs;     //!< Field-level patches to apply after inheritance
};

/** The complete ladder witness for one output.
 *  Rungs define input conditions (OR logic — first satisfied rung wins).
 *  Coil defines output semantics (destination, constraints).
 *  Relays are shared condition sets referenced via requires (AND composition).
 *
 *  When witness_ref is set (n_rungs == 0 on wire), rungs and relays are
 *  inherited from the referenced input's witness. Only diffs and a fresh
 *  coil are provided. Resolution happens in VerifyRungTx. */
struct LadderWitness {
    std::vector<Rung> rungs;     //!< Input condition rungs
    RungCoil coil;               //!< Output coil (per-output, not per-rung)
    std::vector<Relay> relays;   //!< Relay definitions (shared across outputs)
    std::optional<WitnessReference> witness_ref; //!< Witness inheritance reference

    bool IsEmpty() const { return rungs.empty() && !witness_ref.has_value(); }
    bool IsWitnessRef() const { return witness_ref.has_value(); }
};

// ============================================================================
// Micro-header lookup table (Phase 2: encoding optimization)
// ============================================================================

/** Number of micro-header slots (0x00-0x7F). */
static constexpr size_t MICRO_HEADER_SLOTS = 128;
/** Escape byte: full header follows (not inverted). */
static constexpr uint8_t MICRO_HEADER_ESCAPE = 0x80;
/** Escape byte: full header follows (inverted). */
static constexpr uint8_t MICRO_HEADER_ESCAPE_INV = 0x81;

/** Micro-header lookup table: maps slot index → RungBlockType.
 *  Value 0xFFFF means the slot is unused. */
inline constexpr uint16_t MICRO_HEADER_TABLE[MICRO_HEADER_SLOTS] = {
    // Slot 0-2: Signature family
    0x0001, // 0x00: SIG
    0x0002, // 0x01: MULTISIG
    0x0003, // 0x02: ADAPTOR_SIG
    // Slot 3-6: Timelock family
    0x0101, // 0x03: CSV
    0x0102, // 0x04: CSV_TIME
    0x0103, // 0x05: CLTV
    0x0104, // 0x06: CLTV_TIME
    // Slot 7-9: Hash family
    0x0201, // 0x07: HASH_PREIMAGE
    0x0202, // 0x08: HASH160_PREIMAGE
    0x0203, // 0x09: TAGGED_HASH
    // Slot 10-12: Covenant family
    0x0301, // 0x0A: CTV
    0x0302, // 0x0B: VAULT_LOCK
    0x0303, // 0x0C: AMOUNT_LOCK
    // Slot 13-18: Recursion family
    0x0401, // 0x0D: RECURSE_SAME
    0x0402, // 0x0E: RECURSE_MODIFIED
    0x0403, // 0x0F: RECURSE_UNTIL
    0x0404, // 0x10: RECURSE_COUNT
    0x0405, // 0x11: RECURSE_SPLIT
    0x0406, // 0x12: RECURSE_DECAY
    // Slot 19-24: Anchor family
    0x0501, // 0x13: ANCHOR
    0x0502, // 0x14: ANCHOR_CHANNEL
    0x0503, // 0x15: ANCHOR_POOL
    0x0504, // 0x16: ANCHOR_RESERVE
    0x0505, // 0x17: ANCHOR_SEAL
    0x0506, // 0x18: ANCHOR_ORACLE
    // Slot 25-38: PLC family
    0x0601, // 0x19: HYSTERESIS_FEE
    0x0602, // 0x1A: HYSTERESIS_VALUE
    0x0611, // 0x1B: TIMER_CONTINUOUS
    0x0612, // 0x1C: TIMER_OFF_DELAY
    0x0621, // 0x1D: LATCH_SET
    0x0622, // 0x1E: LATCH_RESET
    0x0631, // 0x1F: COUNTER_DOWN
    0x0632, // 0x20: COUNTER_PRESET
    0x0633, // 0x21: COUNTER_UP
    0x0641, // 0x22: COMPARE
    0x0651, // 0x23: SEQUENCER
    0x0661, // 0x24: ONE_SHOT
    0x0671, // 0x25: RATE_LIMIT
    0x0681, // 0x26: COSIGN
    // Slot 39-44: Compound family
    0x0701, // 0x27: TIMELOCKED_SIG
    0x0702, // 0x28: HTLC
    0x0703, // 0x29: HASH_SIG
    0x0704, // 0x2A: PTLC
    0x0705, // 0x2B: CLTV_SIG
    0x0706, // 0x2C: TIMELOCKED_MULTISIG
    // Slot 45-50: Governance family
    0x0801, // 0x2D: EPOCH_GATE
    0x0802, // 0x2E: WEIGHT_LIMIT
    0x0803, // 0x2F: INPUT_COUNT
    0x0804, // 0x30: OUTPUT_COUNT
    0x0805, // 0x31: RELATIVE_VALUE
    0x0806, // 0x32: ACCUMULATOR
    // Slot 51-52: Late-added Signature family
    0x0004, // 0x33: MUSIG_THRESHOLD
    0x0005, // 0x34: KEY_REF_SIG
    // Slot 53-59: Legacy family
    0x0901, // 0x35: P2PK_LEGACY
    0x0902, // 0x36: P2PKH_LEGACY
    0x0903, // 0x37: P2SH_LEGACY
    0x0904, // 0x38: P2WPKH_LEGACY
    0x0905, // 0x39: P2WSH_LEGACY
    0x0906, // 0x3A: P2TR_LEGACY
    0x0907, // 0x3B: P2TR_SCRIPT_LEGACY
    // Remaining slots unused
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x3C-0x3F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x40-0x47
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x48-0x4F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x50-0x57
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x58-0x5F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x60-0x67
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x68-0x6F
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x70-0x77
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, // 0x78-0x7F
};

/** Reverse lookup: find micro-header slot index for a block type.
 *  Returns -1 if the block type has no micro-header slot. */
inline int MicroHeaderSlot(RungBlockType type)
{
    uint16_t val = static_cast<uint16_t>(type);
    for (size_t i = 0; i < MICRO_HEADER_SLOTS; ++i) {
        if (MICRO_HEADER_TABLE[i] == val) return static_cast<int>(i);
    }
    return -1;
}

// ============================================================================
// Implicit field tables (Phase 2: per-block-type fixed field layouts)
// ============================================================================

/** An entry in an implicit field table: data type + fixed size (0 = variable). */
struct ImplicitFieldEntry {
    RungDataType type;
    uint16_t fixed_size; //!< 0 means variable-length (CompactSize prefix present)
};

/** Maximum implicit fields per block type per context. */
static constexpr size_t MAX_IMPLICIT_FIELDS = 8;

/** An implicit field layout for a block type in a given context. */
struct ImplicitFieldLayout {
    uint8_t count;                                  //!< Number of implicit fields (0 = no implicit table)
    ImplicitFieldEntry fields[MAX_IMPLICIT_FIELDS]; //!< Field entries
};

/** Empty layout — no implicit fields, use explicit encoding. */
inline constexpr ImplicitFieldLayout NO_IMPLICIT = {0, {}};

// -- Conditions context implicit field layouts --

/** SIG conditions: [PUBKEY_COMMIT(32), SCHEME(1)] */
inline constexpr ImplicitFieldLayout SIG_CONDITIONS = {2, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::SCHEME, 1},
}};

/** CSV conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_CONDITIONS = {1, {
    {RungDataType::NUMERIC, 0}, // varint encoding, variable
}};

/** CSV_TIME conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_TIME_CONDITIONS = CSV_CONDITIONS;

/** CLTV conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_CONDITIONS = CSV_CONDITIONS;

/** CLTV_TIME conditions: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_TIME_CONDITIONS = CSV_CONDITIONS;

/** HASH_PREIMAGE conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout HASH_PREIMAGE_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** HASH160_PREIMAGE conditions: [HASH160(20)] */
inline constexpr ImplicitFieldLayout HASH160_PREIMAGE_CONDITIONS = {1, {
    {RungDataType::HASH160, 20},
}};

/** TAGGED_HASH conditions: [HASH256(32), HASH256(32)] */
inline constexpr ImplicitFieldLayout TAGGED_HASH_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::HASH256, 32},
}};

/** CTV conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout CTV_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** AMOUNT_LOCK conditions: [NUMERIC(varint), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout AMOUNT_LOCK_CONDITIONS = {2, {
    {RungDataType::NUMERIC, 0},
    {RungDataType::NUMERIC, 0},
}};

/** COSIGN conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout COSIGN_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** TIMELOCKED_SIG conditions: [PUBKEY_COMMIT(32), SCHEME(1), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout TIMELOCKED_SIG_CONDITIONS = {3, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::SCHEME, 1},
    {RungDataType::NUMERIC, 0},
}};

/** HTLC conditions: [PUBKEY_COMMIT(32), PUBKEY_COMMIT(32), HASH256(32), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout HTLC_CONDITIONS = {4, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::HASH256, 32},
    {RungDataType::NUMERIC, 0},
}};

/** HASH_SIG conditions: [PUBKEY_COMMIT(32), HASH256(32), SCHEME(1)] */
inline constexpr ImplicitFieldLayout HASH_SIG_CONDITIONS = {3, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::HASH256, 32},
    {RungDataType::SCHEME, 1},
}};

/** CLTV_SIG conditions: [PUBKEY_COMMIT(32), SCHEME(1), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_SIG_CONDITIONS = TIMELOCKED_SIG_CONDITIONS;

/** EPOCH_GATE conditions: [NUMERIC(varint), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout EPOCH_GATE_CONDITIONS = AMOUNT_LOCK_CONDITIONS;

/** MUSIG_THRESHOLD conditions: [PUBKEY_COMMIT(32), NUMERIC(varint M), NUMERIC(varint N)] */
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_CONDITIONS = {3, {
    {RungDataType::PUBKEY_COMMIT, 32},
    {RungDataType::NUMERIC, 0},  // threshold M
    {RungDataType::NUMERIC, 0},  // group size N
}};

/** ANCHOR_SEAL conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout ANCHOR_SEAL_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** P2PKH_LEGACY / P2WPKH_LEGACY conditions: [HASH160(20)] */
inline constexpr ImplicitFieldLayout P2PKH_LEGACY_CONDITIONS = {1, {
    {RungDataType::HASH160, 20},
}};

/** P2WSH_LEGACY conditions: [HASH256(32)] */
inline constexpr ImplicitFieldLayout P2WSH_LEGACY_CONDITIONS = {1, {
    {RungDataType::HASH256, 32},
}};

/** P2TR_SCRIPT_LEGACY conditions: [HASH256(32), PUBKEY_COMMIT(32)] */
inline constexpr ImplicitFieldLayout P2TR_SCRIPT_LEGACY_CONDITIONS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::PUBKEY_COMMIT, 32},
}};

// -- Witness context implicit field layouts --

/** SIG witness: [PUBKEY(var), SIGNATURE(var)] */
inline constexpr ImplicitFieldLayout SIG_WITNESS = {2, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
}};

/** CSV witness: [NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CSV_WITNESS = CSV_CONDITIONS;

/** HASH_PREIMAGE witness: [HASH256(32), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout HASH_PREIMAGE_WITNESS = {2, {
    {RungDataType::HASH256, 32},
    {RungDataType::PREIMAGE, 0},
}};

/** HASH160_PREIMAGE witness: [HASH160(20), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout HASH160_PREIMAGE_WITNESS = {2, {
    {RungDataType::HASH160, 20},
    {RungDataType::PREIMAGE, 0},
}};

/** TAGGED_HASH witness: [HASH256(32), HASH256(32), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout TAGGED_HASH_WITNESS = {3, {
    {RungDataType::HASH256, 32},
    {RungDataType::HASH256, 32},
    {RungDataType::PREIMAGE, 0},
}};

/** CTV witness: [HASH256(32)] */
inline constexpr ImplicitFieldLayout CTV_WITNESS = CTV_CONDITIONS;

/** COSIGN witness: [HASH256(32)] */
inline constexpr ImplicitFieldLayout COSIGN_WITNESS = COSIGN_CONDITIONS;

/** TIMELOCKED_SIG witness: [PUBKEY(var), SIGNATURE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout TIMELOCKED_SIG_WITNESS = {3, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::NUMERIC, 0},
}};

/** HTLC witness: [PUBKEY(var), SIGNATURE(var), PREIMAGE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout HTLC_WITNESS = {4, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::PREIMAGE, 0},
    {RungDataType::NUMERIC, 0},
}};

/** HASH_SIG witness: [PUBKEY(var), SIGNATURE(var), PREIMAGE(var)] */
inline constexpr ImplicitFieldLayout HASH_SIG_WITNESS = {3, {
    {RungDataType::PUBKEY, 0},
    {RungDataType::SIGNATURE, 0},
    {RungDataType::PREIMAGE, 0},
}};

/** MUSIG_THRESHOLD witness: [PUBKEY(var), SIGNATURE(var)] */
inline constexpr ImplicitFieldLayout MUSIG_THRESHOLD_WITNESS = SIG_WITNESS;

/** CLTV_SIG witness: [PUBKEY(var), SIGNATURE(var), NUMERIC(varint)] */
inline constexpr ImplicitFieldLayout CLTV_SIG_WITNESS = TIMELOCKED_SIG_WITNESS;

/** Lookup implicit field layout for a block type and serialization context.
 *  Returns NO_IMPLICIT if no implicit table exists. */
inline const ImplicitFieldLayout& GetImplicitLayout(RungBlockType type, uint8_t ctx)
{
    // ctx: 0 = WITNESS, 1 = CONDITIONS
    if (ctx == 1) {
        // CONDITIONS context
        switch (type) {
        case RungBlockType::SIG:              return SIG_CONDITIONS;
        case RungBlockType::MUSIG_THRESHOLD:  return MUSIG_THRESHOLD_CONDITIONS;
        case RungBlockType::CSV:              return CSV_CONDITIONS;
        case RungBlockType::CSV_TIME:         return CSV_TIME_CONDITIONS;
        case RungBlockType::CLTV:             return CLTV_CONDITIONS;
        case RungBlockType::CLTV_TIME:        return CLTV_TIME_CONDITIONS;
        case RungBlockType::HASH_PREIMAGE:    return HASH_PREIMAGE_CONDITIONS;
        case RungBlockType::HASH160_PREIMAGE: return HASH160_PREIMAGE_CONDITIONS;
        case RungBlockType::TAGGED_HASH:      return TAGGED_HASH_CONDITIONS;
        case RungBlockType::CTV:              return CTV_CONDITIONS;
        case RungBlockType::AMOUNT_LOCK:      return AMOUNT_LOCK_CONDITIONS;
        case RungBlockType::COSIGN:           return COSIGN_CONDITIONS;
        case RungBlockType::TIMELOCKED_SIG:   return TIMELOCKED_SIG_CONDITIONS;
        case RungBlockType::HTLC:             return HTLC_CONDITIONS;
        case RungBlockType::HASH_SIG:         return HASH_SIG_CONDITIONS;
        case RungBlockType::CLTV_SIG:         return CLTV_SIG_CONDITIONS;
        case RungBlockType::EPOCH_GATE:       return EPOCH_GATE_CONDITIONS;
        case RungBlockType::ANCHOR_SEAL:      return ANCHOR_SEAL_CONDITIONS;
        // Legacy family
        case RungBlockType::P2PK_LEGACY:      return SIG_CONDITIONS;
        case RungBlockType::P2PKH_LEGACY:     return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2SH_LEGACY:      return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2WPKH_LEGACY:    return P2PKH_LEGACY_CONDITIONS;
        case RungBlockType::P2WSH_LEGACY:     return P2WSH_LEGACY_CONDITIONS;
        case RungBlockType::P2TR_LEGACY:      return SIG_CONDITIONS;
        case RungBlockType::P2TR_SCRIPT_LEGACY: return P2TR_SCRIPT_LEGACY_CONDITIONS;
        default: return NO_IMPLICIT;
        }
    } else {
        // WITNESS context
        switch (type) {
        case RungBlockType::SIG:              return SIG_WITNESS;
        case RungBlockType::MUSIG_THRESHOLD:  return MUSIG_THRESHOLD_WITNESS;
        case RungBlockType::CSV:              return CSV_WITNESS;
        case RungBlockType::CSV_TIME:         return CSV_WITNESS;
        case RungBlockType::CLTV:             return CSV_WITNESS;
        case RungBlockType::CLTV_TIME:        return CSV_WITNESS;
        case RungBlockType::HASH_PREIMAGE:    return HASH_PREIMAGE_WITNESS;
        case RungBlockType::HASH160_PREIMAGE: return HASH160_PREIMAGE_WITNESS;
        case RungBlockType::TAGGED_HASH:      return TAGGED_HASH_WITNESS;
        case RungBlockType::CTV:              return CTV_WITNESS;
        case RungBlockType::COSIGN:           return COSIGN_WITNESS;
        case RungBlockType::TIMELOCKED_SIG:   return TIMELOCKED_SIG_WITNESS;
        case RungBlockType::HTLC:             return HTLC_WITNESS;
        case RungBlockType::HASH_SIG:         return HASH_SIG_WITNESS;
        case RungBlockType::CLTV_SIG:         return CLTV_SIG_WITNESS;
        // Legacy family
        case RungBlockType::P2PK_LEGACY:      return SIG_WITNESS;
        case RungBlockType::P2PKH_LEGACY:     return SIG_WITNESS;
        case RungBlockType::P2WPKH_LEGACY:    return SIG_WITNESS;
        case RungBlockType::P2TR_LEGACY:      return SIG_WITNESS;
        // P2SH, P2WSH, P2TR_SCRIPT: no implicit witness (variable inner conditions)
        default: return NO_IMPLICIT;
        }
    }
}

/** Check whether a block's fields match its implicit layout exactly.
 *  Returns true if the block can use implicit encoding (field count and types omitted). */
inline bool MatchesImplicitLayout(const RungBlock& block, const ImplicitFieldLayout& layout)
{
    if (layout.count == 0) return false;
    if (block.fields.size() != layout.count) return false;
    for (uint8_t i = 0; i < layout.count; ++i) {
        if (block.fields[i].type != layout.fields[i].type) return false;
    }
    return true;
}

/** Runtime check that every block type with a CONDITIONS implicit layout also
 *  has a WITNESS implicit layout (or the block is one of the explicitly-listed
 *  types that intentionally have no implicit witness: P2SH, P2WSH, P2TR_SCRIPT,
 *  EPOCH_GATE, ANCHOR_SEAL, AMOUNT_LOCK, CTV).
 *  Call once at init to catch layout pairing mistakes early. */
inline bool VerifyImplicitLayoutPairing()
{
    // Block types that intentionally have conditions-only implicit layouts
    static constexpr RungBlockType conditions_only[] = {
        RungBlockType::P2SH_LEGACY, RungBlockType::P2WSH_LEGACY,
        RungBlockType::P2TR_SCRIPT_LEGACY,
        RungBlockType::EPOCH_GATE, RungBlockType::ANCHOR_SEAL,
        RungBlockType::AMOUNT_LOCK, RungBlockType::CTV,
    };

    for (uint32_t code = 0; code <= 0x0FFF; ++code) {
        uint16_t tc = static_cast<uint16_t>(code);
        if (!IsKnownBlockType(tc)) continue;
        auto bt = static_cast<RungBlockType>(tc);
        const auto& cond_layout = GetImplicitLayout(bt, 1);
        const auto& wit_layout = GetImplicitLayout(bt, 0);
        if (cond_layout.count > 0 && wit_layout.count == 0) {
            // Must be in the conditions_only whitelist
            bool whitelisted = false;
            for (auto exempt : conditions_only) {
                if (bt == exempt) { whitelisted = true; break; }
            }
            if (!whitelisted) return false;
        }
    }
    return true;
}

} // namespace rung

#endif // BITCOIN_RUNG_TYPES_H

