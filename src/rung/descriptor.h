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
 *  Grammar (all 61 active block types):
 *    ladder(or(rung1, rung2, ...))
 *    rung = block | and(block, block, ...)
 *    block = !block  (inverted)
 *
 *  Signature family:
 *    sig(@alias) | sig(@alias, scheme)
 *    multisig(M, @pk1, @pk2, ...)
 *    adaptor_sig(@signer, @adaptor_point) | adaptor_sig(@s, @p, scheme)
 *    musig_threshold(M, @pk1, @pk2, ...)
 *    key_ref_sig(relay_idx, block_idx)
 *
 *  Timelock family:
 *    csv(N) | csv_time(N) | cltv(N) | cltv_time(N)
 *
 *  Hash family:
 *    tagged_hash(tag_hex, expected_hex)
 *    hash_guarded(hash_hex)
 *
 *  Covenant family:
 *    ctv(template_hash_hex)
 *    vault_lock(@recovery, @hot, delay)
 *    amount_lock(min, max)
 *
 *  Recursion family:
 *    recurse_same(max_depth) | recurse_until(height) | recurse_count(count)
 *    recurse_split(max_splits, min_sats)
 *    recurse_modified(max_depth, block_idx, param_idx, delta)
 *    recurse_decay(max_depth, block_idx, param_idx, decay)
 *
 *  Anchor family:
 *    anchor() | anchor_channel() | anchor_pool()
 *    anchor_reserve() | anchor_seal() | anchor_oracle()
 *    data_return(hex)
 *
 *  PLC family:
 *    hysteresis_fee(N, N) | hysteresis_value(N, N)
 *    timer_continuous(N) | timer_off_delay(N, N)
 *    latch_set(@pk, N) | latch_reset(@pk, N)
 *    counter_down(@pk, N) | counter_preset(@pk, N) | counter_up(@pk, N)
 *    compare(op, value_b) | compare(op, value_b, value_c)
 *    sequencer(N) | one_shot(@pk, N) | rate_limit(N, N, N)
 *    cosign(conditions_hash_hex)
 *
 *  Compound family:
 *    timelocked_sig(@pk, csv_blocks) | cltv_sig(@pk, height)
 *    htlc(@sender, @receiver, preimage_hex, csv_blocks)
 *    hash_sig(@pk, preimage_hex)
 *    ptlc(@pk, @adaptor_point, csv_blocks)
 *    timelocked_multisig(M, @pk1, @pk2, ..., csv_blocks)
 *
 *  Governance family:
 *    epoch_gate(epoch_size, window_size) | weight_limit(max_weight)
 *    input_count(min, max) | output_count(min, max)
 *    relative_value(numerator, denominator) | accumulator(root_hex)
 *    output_check(idx, min, max, script_hash_hex)
 *
 *  Legacy family:
 *    p2pk(@pk) | p2pkh(@pk) | p2wpkh(@pk) | p2tr(@pk)
 *    p2sh(inner_hex) | p2wsh(inner_hex) | p2tr_script(inner_hex)
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
