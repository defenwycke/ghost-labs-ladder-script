// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_POLICY_H
#define BITCOIN_RUNG_POLICY_H

#include <primitives/transaction.h>
#include <script/script.h>

#include <string>

namespace rung {

/** Check whether a uint16_t block type is Phase 1 (policy-standard).
 *  Phase 2/3 blocks are consensus-valid but policy-non-standard. */
bool IsPhase1BlockType(uint16_t block_type);

/** Check whether a uint16_t block type is Phase 2 (covenant + anchor). */
bool IsPhase2BlockType(uint16_t block_type);

/** Check whether a uint16_t block type is Phase 3 (recursion + PLC). */
bool IsPhase3BlockType(uint16_t block_type);

/** Check whether a v3 RUNG_TX transaction conforms to mempool policy.
 *  Validates:
 *    - Max 16 rungs per input witness
 *    - Max 8 blocks per rung
 *    - All data types known and correctly sized
 *    - Only Phase 1 block types (Phase 2/3 are non-standard)
 *  Returns false with reason populated on policy violation. */
bool IsStandardRungTx(const CTransaction& tx, std::string& reason);

/** Check whether a v3 output scriptPubKey is a valid rung conditions script. */
bool IsStandardRungOutput(const CScript& scriptPubKey, std::string& reason);

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
