// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_AGGREGATE_H
#define BITCOIN_RUNG_AGGREGATE_H

#include <rung/types.h>

#include <cstdint>
#include <uint256.h>
#include <vector>

namespace rung {

/** Block-level aggregate proof — a single aggregate signature covering all
 *  AGGREGATE-mode spends in one block. */
struct AggregateProof {
    std::vector<uint256> pubkey_commits;  //!< One per AGGREGATE spend
    std::vector<uint8_t> aggregate_sig;   //!< Single aggregate signature
    RungScheme scheme{RungScheme::SCHNORR}; //!< All spends must use same scheme
    bool verified{false}; //!< Set true after aggregate sig is verified at block level
};

/** Per-transaction aggregate context for AGGREGATE attestation mode.
 *  Collects sighashes and pubkeys from all AGGREGATE-mode inputs.
 *  After all inputs pass evaluation, VerifyTxAggregate verifies the
 *  aggregate signature over the entire batch. */
struct TxAggregateContext {
    RungScheme scheme{RungScheme::SCHNORR};  //!< All inputs must use same scheme
    std::vector<uint256> sighashes;           //!< One per AGGREGATE input
    std::vector<std::vector<uint8_t>> pubkeys; //!< One per AGGREGATE input
};

/** Verify that a spend_index + pubkey_commit pair is covered by the aggregate proof.
 *  @param proof       The block-level aggregate proof
 *  @param spend_index Index of this spend within the proof
 *  @param pubkey_commit Expected pubkey commitment (32 bytes)
 *  @return true if the spend is covered by the proof */
bool VerifyAggregateSpend(const AggregateProof& proof,
                           uint32_t spend_index,
                           const uint256& pubkey_commit);

/** Verify a deferred attestation template hash.
 *  @param template_hash The 32-byte template hash from witness
 *  @return false — deferred attestation is not yet supported (fail closed) */
bool VerifyDeferredAttestation(const uint256& template_hash);

} // namespace rung

#endif // BITCOIN_RUNG_AGGREGATE_H
