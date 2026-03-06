// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/aggregate.h>

namespace rung {

bool VerifyAggregateSpend(const AggregateProof& proof,
                           uint32_t spend_index,
                           const uint256& pubkey_commit)
{
    // Verify: spend_index is within range and pubkey_commit matches
    if (spend_index >= proof.pubkey_commits.size()) {
        return false;
    }
    if (proof.pubkey_commits[spend_index] != pubkey_commit) {
        return false;
    }
    // The aggregate signature itself is verified at the block level,
    // not per-spend. Individual spend verification just checks inclusion.
    return true;
}

bool VerifyDeferredAttestation(const uint256& /*template_hash*/)
{
    // Deferred attestation is not yet supported. Fail closed to prevent
    // any code path from silently accepting unverified attestations.
    return false;
}

} // namespace rung
