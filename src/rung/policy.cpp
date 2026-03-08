// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/policy.h>
#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>

namespace rung {

bool IsPhase1BlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    case RungBlockType::HASH_PREIMAGE:
    case RungBlockType::HASH160_PREIMAGE:
    case RungBlockType::TAGGED_HASH:
        return true;
    default:
        return false;
    }
}

bool IsPhase2BlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::CTV:
    case RungBlockType::VAULT_LOCK:
    case RungBlockType::AMOUNT_LOCK:
    case RungBlockType::ANCHOR:
    case RungBlockType::ANCHOR_CHANNEL:
    case RungBlockType::ANCHOR_POOL:
    case RungBlockType::ANCHOR_RESERVE:
    case RungBlockType::ANCHOR_SEAL:
    case RungBlockType::ANCHOR_ORACLE:
        return true;
    default:
        return false;
    }
}

bool IsPhase3BlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::RECURSE_SAME:
    case RungBlockType::RECURSE_MODIFIED:
    case RungBlockType::RECURSE_UNTIL:
    case RungBlockType::RECURSE_COUNT:
    case RungBlockType::RECURSE_SPLIT:
    case RungBlockType::RECURSE_DECAY:
    case RungBlockType::HYSTERESIS_FEE:
    case RungBlockType::HYSTERESIS_VALUE:
    case RungBlockType::TIMER_CONTINUOUS:
    case RungBlockType::TIMER_OFF_DELAY:
    case RungBlockType::LATCH_SET:
    case RungBlockType::LATCH_RESET:
    case RungBlockType::COUNTER_DOWN:
    case RungBlockType::COUNTER_PRESET:
    case RungBlockType::COUNTER_UP:
    case RungBlockType::COMPARE:
    case RungBlockType::SEQUENCER:
    case RungBlockType::ONE_SHOT:
    case RungBlockType::RATE_LIMIT:
    case RungBlockType::COSIGN:
        return true;
    default:
        return false;
    }
}

bool IsStandardRungTx(const CTransaction& tx, std::string& reason)
{
    // Validate v3 output scriptPubKeys as rung conditions
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto& scriptPubKey = tx.vout[i].scriptPubKey;
        // Allow OP_RETURN data outputs
        if (scriptPubKey.size() > 0 && scriptPubKey[0] == OP_RETURN) {
            continue;
        }
        // All rung conditions outputs must pass policy
        if (IsRungConditionsScript(scriptPubKey)) {
            std::string output_reason;
            if (!IsStandardRungOutput(scriptPubKey, output_reason)) {
                reason = output_reason;
                return false;
            }
        }
        // Allow non-conditions outputs (e.g., standard P2TR for change) during bootstrap
    }

    // Validate each input's witness as a ladder witness
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto& witness = tx.vin[i].scriptWitness;
        if (witness.stack.empty()) {
            reason = "rung-missing-witness";
            return false;
        }

        const auto& witness_bytes = witness.stack[0];
        LadderWitness ladder;
        std::string deser_error;
        if (!DeserializeLadderWitness(witness_bytes, ladder, deser_error)) {
            reason = "rung-invalid-witness: " + deser_error;
            return false;
        }

        if (ladder.rungs.size() > MAX_RUNGS) {
            reason = "rung-too-many-rungs";
            return false;
        }

        size_t preimage_block_count = 0;
        for (const auto& rung : ladder.rungs) {
            if (rung.blocks.size() > MAX_BLOCKS_PER_RUNG) {
                reason = "rung-too-many-blocks";
                return false;
            }

            for (const auto& block : rung.blocks) {
                uint16_t btype = static_cast<uint16_t>(block.type);
                // Policy: all known block types are standard
                if (!IsKnownBlockType(btype)) {
                    reason = "rung-unknown-block-type: " + BlockTypeName(block.type);
                    return false;
                }

                // Count preimage-bearing blocks (spam surface limit)
                if (block.type == RungBlockType::HASH_PREIMAGE ||
                    block.type == RungBlockType::HASH160_PREIMAGE ||
                    block.type == RungBlockType::TAGGED_HASH) {
                    preimage_block_count++;
                }

                for (const auto& field : block.fields) {
                    std::string field_reason;
                    if (!field.IsValid(field_reason)) {
                        reason = "rung-invalid-field: " + field_reason;
                        return false;
                    }
                }
            }
        }

        if (preimage_block_count > MAX_PREIMAGE_BLOCKS_PER_WITNESS) {
            reason = "rung-too-many-preimage-blocks: " + std::to_string(preimage_block_count);
            return false;
        }
    }

    return true;
}

bool IsStandardRungOutput(const CScript& scriptPubKey, std::string& reason)
{
    RungConditions conditions;
    std::string error;
    if (!DeserializeRungConditions(scriptPubKey, conditions, error)) {
        reason = "rung-invalid-output: " + error;
        return false;
    }

    if (conditions.rungs.size() > MAX_RUNGS) {
        reason = "rung-output-too-many-rungs";
        return false;
    }

    for (const auto& rung : conditions.rungs) {
        if (rung.blocks.size() > MAX_BLOCKS_PER_RUNG) {
            reason = "rung-output-too-many-blocks";
            return false;
        }

        for (const auto& block : rung.blocks) {
            uint16_t btype = static_cast<uint16_t>(block.type);
            if (!IsKnownBlockType(btype)) {
                reason = "rung-output-unknown-block-type: " + BlockTypeName(block.type);
                return false;
            }
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    reason = "rung-output-witness-only-field: " + DataTypeName(field.type);
                    return false;
                }
                std::string field_reason;
                if (!field.IsValid(field_reason)) {
                    reason = "rung-output-invalid-field: " + field_reason;
                    return false;
                }
            }
        }
    }

    return true;
}

} // namespace rung
