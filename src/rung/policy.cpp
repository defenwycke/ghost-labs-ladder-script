// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/policy.h>
#include <rung/conditions.h>
#include <rung/serialize.h>
#include <rung/types.h>

#include <algorithm>

namespace rung {

bool IsBaseBlockType(uint16_t block_type)
{
    switch (static_cast<RungBlockType>(block_type)) {
    case RungBlockType::SIG:
    case RungBlockType::MULTISIG:
    case RungBlockType::ADAPTOR_SIG:
    case RungBlockType::MUSIG_THRESHOLD:
    case RungBlockType::KEY_REF_SIG:
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
    case RungBlockType::HASH_PREIMAGE:
    case RungBlockType::HASH160_PREIMAGE:
    case RungBlockType::TAGGED_HASH:
    // Compound family (collapsed multi-block patterns)
    case RungBlockType::TIMELOCKED_SIG:
    case RungBlockType::HTLC:
    case RungBlockType::HASH_SIG:
    case RungBlockType::PTLC:
    case RungBlockType::CLTV_SIG:
    case RungBlockType::TIMELOCKED_MULTISIG:
    // Legacy family (wrapped Bitcoin transaction types)
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2SH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY:
    case RungBlockType::P2WSH_LEGACY:
    case RungBlockType::P2TR_LEGACY:
    case RungBlockType::P2TR_SCRIPT_LEGACY:
        return true;
    default:
        return false;
    }
}

bool IsCovenantBlockType(uint16_t block_type)
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
    // Governance family (transaction-level constraints)
    case RungBlockType::EPOCH_GATE:
    case RungBlockType::WEIGHT_LIMIT:
    case RungBlockType::INPUT_COUNT:
    case RungBlockType::OUTPUT_COUNT:
    case RungBlockType::RELATIVE_VALUE:
    case RungBlockType::ACCUMULATOR:
        return true;
    default:
        return false;
    }
}

bool IsStatefulBlockType(uint16_t block_type)
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
    // Validate v4 output scriptPubKeys as rung conditions
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
        // MLSC outputs (0xC2 + 32-byte root) are always standard
        if (IsMLSCScript(scriptPubKey)) {
            continue;
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

        // Diff witness: deserialization already validates field types and limits.
        // Forward-only and no-chaining are consensus rules enforced at evaluation time.
        if (ladder.IsWitnessRef()) {
            continue;
        }

        if (ladder.rungs.size() > MAX_RUNGS) {
            reason = "rung-too-many-rungs";
            return false;
        }

        size_t preimage_block_count = 0;
        for (const auto& rung : ladder.rungs) {
            // Compact rungs: validate compact data, skip block iteration
            if (rung.IsCompact()) {
                if (!IsKnownCompactRungType(static_cast<uint8_t>(rung.compact->type))) {
                    reason = "rung-unknown-compact-type";
                    return false;
                }
                if (rung.compact->type == CompactRungType::COMPACT_SIG) {
                    if (rung.compact->pubkey_commit.size() != 32) {
                        reason = "rung-compact-sig-bad-commit-size";
                        return false;
                    }
                    if (!IsKnownScheme(static_cast<uint8_t>(rung.compact->scheme))) {
                        reason = "rung-compact-sig-unknown-scheme";
                        return false;
                    }
                }
                if (!rung.relay_refs.empty()) {
                    reason = "rung-compact-has-relay-refs";
                    return false;
                }
                continue;
            }

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

        // Validate relay limits
        if (ladder.relays.size() > MAX_RELAYS) {
            reason = "rung-too-many-relays: " + std::to_string(ladder.relays.size());
            return false;
        }

        for (size_t rl = 0; rl < ladder.relays.size(); ++rl) {
            const auto& relay = ladder.relays[rl];
            if (relay.blocks.empty()) {
                reason = "rung-relay-empty-blocks";
                return false;
            }
            if (relay.blocks.size() > MAX_BLOCKS_PER_RUNG) {
                reason = "rung-relay-too-many-blocks";
                return false;
            }
            if (relay.relay_refs.size() > MAX_REQUIRES) {
                reason = "rung-relay-too-many-requires";
                return false;
            }
            for (uint16_t req : relay.relay_refs) {
                if (req >= rl) {
                    reason = "rung-relay-forward-reference";
                    return false;
                }
            }
            for (const auto& block : relay.blocks) {
                uint16_t btype = static_cast<uint16_t>(block.type);
                if (!IsKnownBlockType(btype)) {
                    reason = "rung-relay-unknown-block-type";
                    return false;
                }
                // Count preimage blocks in relays too
                if (block.type == RungBlockType::HASH_PREIMAGE ||
                    block.type == RungBlockType::HASH160_PREIMAGE ||
                    block.type == RungBlockType::TAGGED_HASH) {
                    preimage_block_count++;
                }
                for (const auto& field : block.fields) {
                    std::string field_reason;
                    if (!field.IsValid(field_reason)) {
                        reason = "rung-relay-invalid-field: " + field_reason;
                        return false;
                    }
                }
            }
        }

        // Validate rung relay_refs
        for (const auto& rung : ladder.rungs) {
            if (rung.relay_refs.size() > MAX_REQUIRES) {
                reason = "rung-too-many-requires";
                return false;
            }
            for (uint16_t req : rung.relay_refs) {
                if (req >= ladder.relays.size()) {
                    reason = "rung-requires-invalid-relay-index";
                    return false;
                }
            }
        }

        // Validate relay chain depth
        if (!ladder.relays.empty()) {
            // Compute transitive depth for each relay
            std::vector<size_t> depths(ladder.relays.size(), 0);
            for (size_t rl = 0; rl < ladder.relays.size(); ++rl) {
                for (uint16_t req : ladder.relays[rl].relay_refs) {
                    depths[rl] = std::max(depths[rl], depths[req] + 1);
                }
                if (depths[rl] > MAX_RELAY_DEPTH) {
                    reason = "rung-relay-depth-exceeded: " + std::to_string(depths[rl]);
                    return false;
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
        // Compact rungs: validate and skip
        if (rung.IsCompact()) {
            if (!IsKnownCompactRungType(static_cast<uint8_t>(rung.compact->type))) {
                reason = "rung-output-unknown-compact-type";
                return false;
            }
            if (rung.compact->type == CompactRungType::COMPACT_SIG) {
                if (rung.compact->pubkey_commit.size() != 32) {
                    reason = "rung-output-compact-sig-bad-commit-size";
                    return false;
                }
                if (!IsKnownScheme(static_cast<uint8_t>(rung.compact->scheme))) {
                    reason = "rung-output-compact-sig-unknown-scheme";
                    return false;
                }
            }
            if (!rung.relay_refs.empty()) {
                reason = "rung-output-compact-has-relay-refs";
                return false;
            }
            continue;
        }

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

        // Validate rung relay_refs
        if (rung.relay_refs.size() > MAX_REQUIRES) {
            reason = "rung-output-too-many-requires";
            return false;
        }
        for (uint16_t req : rung.relay_refs) {
            if (req >= conditions.relays.size()) {
                reason = "rung-output-requires-invalid-relay-index";
                return false;
            }
        }
    }

    // Validate relays in conditions output
    if (conditions.relays.size() > MAX_RELAYS) {
        reason = "rung-output-too-many-relays";
        return false;
    }
    for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
        const auto& relay = conditions.relays[rl];
        if (relay.blocks.empty()) {
            reason = "rung-output-relay-empty-blocks";
            return false;
        }
        if (relay.blocks.size() > MAX_BLOCKS_PER_RUNG) {
            reason = "rung-output-relay-too-many-blocks";
            return false;
        }
        if (relay.relay_refs.size() > MAX_REQUIRES) {
            reason = "rung-output-relay-too-many-requires";
            return false;
        }
        for (uint16_t req : relay.relay_refs) {
            if (req >= rl) {
                reason = "rung-output-relay-forward-reference";
                return false;
            }
        }
        for (const auto& block : relay.blocks) {
            uint16_t btype = static_cast<uint16_t>(block.type);
            if (!IsKnownBlockType(btype)) {
                reason = "rung-output-relay-unknown-block-type";
                return false;
            }
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    reason = "rung-output-relay-witness-only-field: " + DataTypeName(field.type);
                    return false;
                }
                std::string field_reason;
                if (!field.IsValid(field_reason)) {
                    reason = "rung-output-relay-invalid-field: " + field_reason;
                    return false;
                }
            }
        }
    }

    // Validate relay chain depth
    if (!conditions.relays.empty()) {
        std::vector<size_t> depths(conditions.relays.size(), 0);
        for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
            for (uint16_t req : conditions.relays[rl].relay_refs) {
                depths[rl] = std::max(depths[rl], depths[req] + 1);
            }
            if (depths[rl] > MAX_RELAY_DEPTH) {
                reason = "rung-output-relay-depth-exceeded";
                return false;
            }
        }
    }

    return true;
}

} // namespace rung
