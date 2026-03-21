// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_DESCRIPTOR_H
#define BITCOIN_RUNG_DESCRIPTOR_H

#include <rung/conditions.h>
#include <rung/types.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace rung {

/** Parse a Ladder Script descriptor into conditions and pubkeys.
 *
 *  Grammar:
 *    ladder(or(rung1, rung2, ...))
 *    rung = block | and(block, block, ...)
 *    block = sig(@alias) | sig(@alias, scheme)
 *           | csv(N) | csv_time(N) | cltv(N) | cltv_time(N)
 *           | multisig(M, @pk1, @pk2, ...) | multisig(M, @pk1, @pk2, ..., scheme)
 *           | hash_guarded(hex) | tagged_hash(hex1, hex2)
 *           | ctv(hex) | amount_lock(min, max)
 *           | timelocked_sig(@alias, N) | htlc(@alias1, @alias2, hex, N)
 *           | hash_sig(@alias, hex) | cltv_sig(@alias, N)
 *           | output_check(idx, min, max, hex)
 *           | !block  (inverted)
 *
 *  Scheme names: schnorr, ecdsa, falcon512, falcon1024, dilithium3, sphincs_sha
 *
 *  @param[in]  desc     Descriptor string
 *  @param[in]  keys     Map of alias → pubkey bytes (e.g., {"alice" → {0x02, ...}})
 *  @param[out] out      Parsed rung conditions
 *  @param[out] pubkeys  Per-rung pubkey lists (for merkle_pub_key)
 *  @param[out] error    Error message on failure
 *  @return true on success */
bool ParseDescriptor(const std::string& desc,
                     const std::map<std::string, std::vector<uint8_t>>& keys,
                     RungConditions& out,
                     std::vector<std::vector<std::vector<uint8_t>>>& pubkeys,
                     std::string& error);

/** Format rung conditions as a descriptor string.
 *  @param[in]  conditions  The conditions to format
 *  @param[in]  pubkeys     Per-rung pubkey lists (for alias resolution, optional)
 *  @param[in]  aliases     Reverse map: pubkey hex → alias name (optional)
 *  @return descriptor string */
std::string FormatDescriptor(const RungConditions& conditions,
                             const std::vector<std::vector<std::vector<uint8_t>>>& pubkeys = {},
                             const std::map<std::string, std::string>& aliases = {});

} // namespace rung

#endif // BITCOIN_RUNG_DESCRIPTOR_H
