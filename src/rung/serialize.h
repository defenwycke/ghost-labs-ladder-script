// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_SERIALIZE_H
#define BITCOIN_RUNG_SERIALIZE_H

#include <rung/types.h>
#include <serialize.h>
#include <span.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rung {

/** Maximum number of rungs per ladder witness (policy, not consensus). */
static constexpr size_t MAX_RUNGS = 16;
/** Maximum number of blocks per rung (policy, not consensus). */
static constexpr size_t MAX_BLOCKS_PER_RUNG = 8;
/** Maximum number of fields per block. */
static constexpr size_t MAX_FIELDS_PER_BLOCK = 16;
/** Maximum total ladder witness size in bytes (must accommodate PQ signatures). */
static constexpr size_t MAX_LADDER_WITNESS_SIZE = 100000;
/** Maximum number of preimage-bearing blocks (HASH_PREIMAGE, HASH160_PREIMAGE,
 *  TAGGED_HASH) per ladder witness. Limits user-chosen data to ~504 bytes
 *  (2 * 252 bytes PREIMAGE max) while covering all legitimate use cases. */
static constexpr size_t MAX_PREIMAGE_BLOCKS_PER_WITNESS = 2;
/** Maximum number of relays per ladder witness. */
static constexpr size_t MAX_RELAYS = 8;
/** Maximum number of relay requirements per rung or relay. */
static constexpr size_t MAX_REQUIRES = 8;
/** Maximum transitive relay chain depth (relay requiring relay requiring relay...). */
static constexpr size_t MAX_RELAY_DEPTH = 4;

/** Serialization context — determines which implicit field table to use. */
enum class SerializationContext : uint8_t {
    WITNESS,     //!< Witness (spending) side — SIGNATURE, PREIMAGE allowed
    CONDITIONS,  //!< Conditions (locking) side — only condition data types
};

/** Deserialize a LadderWitness from raw witness bytes.
 *  Performs full type and size validation during deserialization.
 *  Returns false with error message on any malformed data.
 *
 *  Wire format (v3 — micro-header + varint NUMERIC + implicit fields):
 *    [n_rungs: varint]
 *    for each rung:
 *      [n_blocks: varint]
 *      for each block:
 *        [micro_header: uint8_t]    -- 0x00-0x7F = lookup table index
 *                                   -- 0x80 = escape (full header follows, not inverted)
 *                                   -- 0x81 = escape (full header follows, inverted)
 *        if escape: [block_type: uint16_t LE]
 *        if micro-header with implicit field table for context:
 *          -- field count and type bytes omitted
 *          for each implicit field:
 *            if NUMERIC: [value: CompactSize]
 *            else: [data_len: CompactSize] [data: bytes]
 *        else:
 *          [n_fields: varint]
 *          for each field:
 *            [data_type: uint8_t]
 *            if NUMERIC: [value: CompactSize]
 *            else: [data_len: CompactSize] [data: bytes]
 *    [coil_type: uint8_t]
 *    [attestation: uint8_t]
 *    [scheme: uint8_t]
 *    [address_len: varint]
 *    [address: bytes]              (raw scriptPubKey, 0 len = no address)
 *    [n_coil_conditions: varint]   (0 = no coil conditions)
 *    for each coil condition rung:
 *      [n_blocks: varint]
 *      for each block: (same format as input blocks)
 */
bool DeserializeLadderWitness(const std::vector<uint8_t>& witness_bytes,
                              LadderWitness& ladder_out,
                              std::string& error,
                              SerializationContext ctx = SerializationContext::WITNESS);

/** Serialize a LadderWitness to raw bytes. */
std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder,
                                             SerializationContext ctx = SerializationContext::WITNESS);

/** Serialize a single rung's blocks + relay_refs to bytes (for MLSC Merkle leaf computation).
 *  Format: CompactSize(n_blocks) + blocks + CompactSize(n_relay_refs) + relay_ref indices.
 *  Uses the standard wire format (micro-headers + implicit fields) in the given context. */
std::vector<uint8_t> SerializeRungBlocks(const Rung& rung, SerializationContext ctx);

/** Serialize coil metadata to bytes (for MLSC Merkle leaf computation).
 *  Format: coil_type(1) + attestation(1) + scheme(1) + address_len(varint) + address +
 *          n_conditions(varint) + condition_rungs. */
std::vector<uint8_t> SerializeCoilData(const RungCoil& coil);

/** Serialize a relay's blocks + relay_refs to bytes (for MLSC Merkle leaf computation).
 *  Format: CompactSize(n_blocks) + blocks + CompactSize(n_relay_refs) + relay_ref indices. */
std::vector<uint8_t> SerializeRelayBlocks(const Relay& relay, SerializationContext ctx);

} // namespace rung

#endif // BITCOIN_RUNG_SERIALIZE_H
