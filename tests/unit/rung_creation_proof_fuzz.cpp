// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/types.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cstring>
#include <vector>

/**
 * Fuzz target: TX_MLSC creation proof deserialization and validation.
 *
 * Tests that arbitrary byte sequences either:
 * 1. Fail to deserialize (rejected early)
 * 2. Deserialize but fail validation (wrong root, bad types, etc.)
 * 3. Deserialize AND validate (only for well-formed proofs)
 *
 * No crash, no assert failure, no undefined behavior for any input.
 */

FUZZ_TARGET(rung_creation_proof)
{
    FuzzedDataProvider fuzzed_data(buffer.data(), buffer.size());

    // Try to deserialize as a creation proof
    std::vector<uint8_t> proof_bytes(buffer.begin(), buffer.end());
    rung::CreationProof proof;
    std::string error;

    bool deser_ok = rung::DeserializeCreationProof(proof_bytes, proof, error);

    if (deser_ok) {
        // Round-trip: serialize and re-deserialize should produce same root
        auto reserialized = rung::SerializeCreationProof(proof);
        rung::CreationProof proof2;
        std::string error2;
        bool deser2_ok = rung::DeserializeCreationProof(reserialized, proof2, error2);

        if (deser2_ok) {
            // Roots must match after round-trip
            uint256 root1 = rung::ComputeTxMLSCRoot(proof);
            uint256 root2 = rung::ComputeTxMLSCRoot(proof2);
            assert(root1 == root2);
        }

        // Try validation with various output counts
        uint256 root = rung::ComputeTxMLSCRoot(proof);
        for (size_t n_out = 0; n_out <= proof.rungs.size() + 1; ++n_out) {
            std::string val_error;
            rung::ValidateCreationProof(proof, root, n_out, val_error);
            // Must not crash — result doesn't matter
        }

        // Try validation with wrong root — must reject
        uint256 wrong_root;
        wrong_root.SetNull();
        if (!proof.rungs.empty()) {
            std::string val_error;
            bool valid = rung::ValidateCreationProof(proof, wrong_root, 1, val_error);
            // Should be rejected (wrong root)
            assert(!valid || wrong_root == root);
        }

        // Compute individual leaves — must not crash
        for (const auto& rung : proof.rungs) {
            rung::ComputeTxMLSCLeaf(rung);
        }

        // Serialize structural templates — must not crash
        for (const auto& rung : proof.rungs) {
            rung::SerializeStructuralTemplate(rung);
        }
    }

    // Also fuzz the structural template serialization directly
    if (fuzzed_data.remaining_bytes() >= 10) {
        rung::CreationProofRung cp_rung;
        uint8_t n_blocks = fuzzed_data.ConsumeIntegral<uint8_t>() % 9; // 0-8
        for (uint8_t i = 0; i < n_blocks; ++i) {
            uint16_t block_type = fuzzed_data.ConsumeIntegral<uint16_t>();
            uint8_t inverted = fuzzed_data.ConsumeIntegral<uint8_t>() & 1;
            cp_rung.blocks.push_back({block_type, inverted});
        }
        cp_rung.coil.output_index = fuzzed_data.ConsumeIntegral<uint8_t>();
        if (fuzzed_data.remaining_bytes() >= 32) {
            auto vc_bytes = fuzzed_data.ConsumeBytes<uint8_t>(32);
            memcpy(cp_rung.value_commitment.data(), vc_bytes.data(), 32);
        }

        // These must not crash for any input
        rung::SerializeStructuralTemplate(cp_rung);
        rung::ComputeTxMLSCLeaf(cp_rung);
    }
}
