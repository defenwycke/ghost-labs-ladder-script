// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/serialize.h>
#include <rung/types.h>
#include <rung/evaluator.h>
#include <script/interpreter.h>

#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(rung_deserialize)
{
    rung::LadderWitness ladder;
    std::string error;

    // Convert span to vector for DeserializeLadderWitness interface.
    // This must never crash, assert, or invoke undefined behavior.
    std::vector<uint8_t> data(buffer.begin(), buffer.end());
    bool ok = rung::DeserializeLadderWitness(data, ladder, error);

    if (ok) {
        // If deserialization succeeded, verify invariants:

        // 1. At least one rung
        assert(!ladder.rungs.empty());

        // 2. Rung count within limits
        assert(ladder.rungs.size() <= rung::MAX_RUNGS);

        // 3. Each rung has blocks within limits
        for (const auto& r : ladder.rungs) {
            assert(!r.blocks.empty());
            assert(r.blocks.size() <= rung::MAX_BLOCKS_PER_RUNG);

            for (const auto& b : r.blocks) {
                // Block type is known
                assert(rung::IsKnownBlockType(static_cast<uint16_t>(b.type)));

                // Field count within limits
                assert(b.fields.size() <= rung::MAX_FIELDS_PER_BLOCK);

                // Each field is valid
                for (const auto& f : b.fields) {
                    std::string reason;
                    assert(f.IsValid(reason));
                }
            }
        }

        // 4. Roundtrip: serialize then deserialize should produce identical ladder
        auto reserialized = rung::SerializeLadderWitness(ladder);
        rung::LadderWitness ladder2;
        std::string error2;
        bool ok2 = rung::DeserializeLadderWitness(reserialized, ladder2, error2);
        assert(ok2);
        assert(ladder2.rungs.size() == ladder.rungs.size());

        // 5. Coil condition rungs also within limits
        assert(ladder.coil.conditions.size() <= rung::MAX_RUNGS);
    } else {
        // If deserialization failed, error message should be non-empty
        assert(!error.empty());
    }
}
