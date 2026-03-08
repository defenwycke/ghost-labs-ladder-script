// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_TYPES_H
#define BITCOIN_RUNG_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace rung {

/** Block types for Ladder Script function blocks.
 *  Each block evaluates a single spending condition within a rung.
 *  Encoded as uint16_t in the wire format (little-endian 2 bytes).
 *
 *  Ranges:
 *    0x0001-0x00FF  Signature family
 *    0x0100-0x01FF  Timelock family
 *    0x0200-0x02FF  Hash family
 *    0x0300-0x03FF  Covenant family
 *    0x0400-0x04FF  Recursion family
 *    0x0500-0x05FF  Anchor/L2 family
 *    0x0600-0x06FF  PLC family */
enum class RungBlockType : uint16_t {
    // Signature family
    SIG              = 0x0001, //!< Single signature verification
    MULTISIG         = 0x0002, //!< M-of-N threshold signature
    ADAPTOR_SIG      = 0x0003, //!< Adaptor signature verification

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
    COSIGN           = 0x0681, //!< Co-spend contact: requires another input with matching conditions hash
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
        return true;
    }
    return false;
}

/** Returns true if the byte is a known RungDataType. */
inline bool IsKnownDataType(uint8_t b)
{
    return b >= 0x01 && b <= 0x09;
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

/** A single rung in a ladder. All blocks must be satisfied (AND logic). */
struct Rung {
    std::vector<RungBlock> blocks;
    uint8_t rung_id{0};                //!< Rung identifier within the ladder
    std::vector<uint16_t> relay_refs;    //!< Indices into relay array that must be satisfied
};

/** A relay definition: blocks evaluated for cross-referencing, not tied to an output.
 *  Relays enable AND composition across rungs and DRY condition reuse.
 *  Forward-only indexing: relay N can only require relays 0..N-1 (no cycles). */
struct Relay {
    std::vector<RungBlock> blocks;
    std::vector<uint16_t> relay_refs;    //!< Indices of other relays (must be < own index)
};

/** The complete ladder witness for one output.
 *  Rungs define input conditions (OR logic — first satisfied rung wins).
 *  Coil defines output semantics (destination, constraints).
 *  Relays are shared condition sets referenced via requires (AND composition). */
struct LadderWitness {
    std::vector<Rung> rungs;     //!< Input condition rungs
    RungCoil coil;               //!< Output coil (per-output, not per-rung)
    std::vector<Relay> relays;   //!< Relay definitions (shared across outputs)

    bool IsEmpty() const { return rungs.empty(); }
};

} // namespace rung

#endif // BITCOIN_RUNG_TYPES_H
