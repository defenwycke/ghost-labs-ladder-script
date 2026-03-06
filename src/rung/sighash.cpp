// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/sighash.h>
#include <rung/serialize.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

namespace rung {

const HashWriter HASHER_LADDERSIGHASH{TaggedHash("LadderSighash")};

/** Compute SHA256 of serialized rung conditions. */
static uint256 HashRungConditions(const RungConditions& conditions)
{
    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder);

    HashWriter ss{};
    ss.write(MakeByteSpan(bytes));
    return ss.GetSHA256();
}

template <class T>
bool SignatureHashLadder(const PrecomputedTransactionData& cache,
                         const T& tx,
                         unsigned int nIn,
                         uint8_t hash_type,
                         const RungConditions& conditions,
                         uint256& hash_out)
{
    assert(nIn < tx.vin.size());

    // Validate hash_type (same range as BIP341)
    if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))) {
        return false;
    }

    // Require ladder caches to be initialized
    if (!cache.m_ladder_ready || !cache.m_spent_outputs_ready) {
        return false;
    }

    const uint8_t output_type = (hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type & SIGHASH_OUTPUT_MASK);
    const uint8_t input_type = hash_type & SIGHASH_INPUT_MASK;

    HashWriter ss{HASHER_LADDERSIGHASH};

    // Epoch
    static constexpr uint8_t EPOCH = 0;
    ss << EPOCH;

    // Hash type
    ss << hash_type;

    // Transaction level data
    ss << tx.version;
    ss << tx.nLockTime;

    if (input_type != SIGHASH_ANYONECANPAY) {
        ss << cache.m_prevouts_single_hash;
        ss << cache.m_spent_amounts_single_hash;
        ss << cache.m_sequences_single_hash;
    }
    if (output_type == SIGHASH_ALL) {
        ss << cache.m_outputs_single_hash;
    }

    // Spend type: always 0 for ladder (no annex, no extensions)
    static constexpr uint8_t SPEND_TYPE = 0;
    ss << SPEND_TYPE;

    // Input-specific data
    if (input_type == SIGHASH_ANYONECANPAY) {
        ss << tx.vin[nIn].prevout;
        ss << cache.m_spent_outputs[nIn];
        ss << tx.vin[nIn].nSequence;
    } else {
        ss << nIn;
    }

    // Output for SIGHASH_SINGLE
    if (output_type == SIGHASH_SINGLE) {
        if (nIn >= tx.vout.size()) return false;
        HashWriter sha_single_output{};
        sha_single_output << tx.vout[nIn];
        ss << sha_single_output.GetSHA256();
    }

    // Conditions hash — commit to the locking conditions from the spent output
    ss << HashRungConditions(conditions);

    hash_out = ss.GetSHA256();
    return true;
}

// Explicit template instantiations
template bool SignatureHashLadder<CTransaction>(
    const PrecomputedTransactionData& cache,
    const CTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    const RungConditions& conditions,
    uint256& hash_out);

template bool SignatureHashLadder<CMutableTransaction>(
    const PrecomputedTransactionData& cache,
    const CMutableTransaction& tx,
    unsigned int nIn,
    uint8_t hash_type,
    const RungConditions& conditions,
    uint256& hash_out);

} // namespace rung
