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

/** Deserialize a LadderWitness from raw witness bytes.
 *  Performs full type and size validation during deserialization.
 *  Returns false with error message on any malformed data.
 *
 *  Wire format (v2):
 *    [n_rungs: varint]
 *    for each rung:
 *      [n_blocks: varint]
 *      for each block:
 *        [block_type: uint16_t LE]
 *        [inverted: uint8_t (0x00 or 0x01)]
 *        [n_fields: varint]
 *        for each field:
 *          [data_type: uint8_t]
 *          [data_len: varint]
 *          [data: bytes]
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
                              std::string& error);

/** Serialize a LadderWitness to raw bytes. */
std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder);

} // namespace rung

#endif // BITCOIN_RUNG_SERIALIZE_H
