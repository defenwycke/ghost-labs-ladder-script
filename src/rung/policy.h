// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_POLICY_H
#define BITCOIN_RUNG_POLICY_H

#include <primitives/transaction.h>
#include <script/script.h>

#include <string>

namespace rung {

/** Check whether a block type is a base block (signature, timelock, hash, compound). */
bool IsBaseBlockType(uint16_t block_type);

/** Check whether a block type is a covenant, anchor, or governance block. */
bool IsCovenantBlockType(uint16_t block_type);

/** Check whether a block type is a recursion or PLC block. */
bool IsStatefulBlockType(uint16_t block_type);

/** Check whether a v3 RUNG_TX transaction conforms to mempool policy.
 *  Validates:
 *    - Max 16 rungs per input witness
 *    - Max 8 blocks per rung
 *    - All data types known and correctly sized
 *    - All known block types
 *  Returns false with reason populated on policy violation. */
bool IsStandardRungTx(const CTransaction& tx, std::string& reason);

/** Check whether a v3 output scriptPubKey is a valid rung conditions script. */
bool IsStandardRungOutput(const CScript& scriptPubKey, std::string& reason);

} // namespace rung

#endif // BITCOIN_RUNG_POLICY_H
