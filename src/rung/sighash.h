// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_SIGHASH_H
#define BITCOIN_RUNG_SIGHASH_H

#include <rung/conditions.h>
#include <script/interpreter.h>

#include <cstdint>

class CTransaction;
class CMutableTransaction;
class uint256;

namespace rung {

/** Tagged hash writer for LadderSighash, pre-fed with the tag. */
extern const HashWriter HASHER_LADDERSIGHASH;

/** Compute the signature hash for a v3 RUNG_TX input.
 *
 *  Similar to BIP341 sighash but without annex/tapscript/codeseparator extensions.
 *  Uses tagged hash: TaggedHash("LadderSighash").
 *
 *  Commits to:
 *    - epoch (0)
 *    - hash_type
 *    - tx version, locktime
 *    - prevouts hash, amounts hash, sequences hash (unless ANYONECANPAY)
 *    - outputs hash (unless NONE)
 *    - spend_type (always 0 for ladder — no annex, no extensions)
 *    - input-specific data (prevout or index)
 *    - conditions hash (SHA256 of serialized rung conditions from spent output)
 *    - output for SIGHASH_SINGLE
 *
 *  @param[in]  cache       Precomputed transaction data (must have m_ladder_ready set)
 *  @param[in]  tx          The transaction being signed
 *  @param[in]  nIn         Input index being signed
 *  @param[in]  hash_type   Sighash type (SIGHASH_DEFAULT=0, ALL=1, NONE=2, SINGLE=3, ANYONECANPAY=0x80)
 *  @param[in]  conditions  Rung conditions from the spent output
 *  @param[out] hash_out    The computed sighash
 *  @return true on success, false if hash_type is invalid or data is missing
 */
template <class T>
bool SignatureHashLadder(const PrecomputedTransactionData& cache,
                         const T& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const RungConditions& conditions,
                         uint256& hash_out);

} // namespace rung

#endif // BITCOIN_RUNG_SIGHASH_H
