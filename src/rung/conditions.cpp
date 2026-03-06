// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/serialize.h>

#include <streams.h>
#include <util/strencodings.h>

namespace rung {

bool IsConditionDataType(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY:
    case RungDataType::PUBKEY_COMMIT:
    case RungDataType::HASH256:
    case RungDataType::HASH160:
    case RungDataType::NUMERIC:
    case RungDataType::SCHEME:
    case RungDataType::SPEND_INDEX:
        return true;
    case RungDataType::SIGNATURE:
    case RungDataType::PREIMAGE:
        return false;
    }
    return false;
}

bool IsRungConditionsScript(const CScript& scriptPubKey)
{
    return scriptPubKey.size() >= 2 && scriptPubKey[0] == RUNG_CONDITIONS_PREFIX;
}

bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error)
{
    if (!IsRungConditionsScript(scriptPubKey)) {
        error = "not a rung conditions script";
        return false;
    }

    // Strip the prefix byte and deserialize the rest as a ladder witness
    std::vector<uint8_t> data(scriptPubKey.begin() + 1, scriptPubKey.end());

    LadderWitness ladder;
    if (!DeserializeLadderWitness(data, ladder, error)) {
        return false;
    }

    // Validate: no witness-only fields (SIGNATURE, PREIMAGE) in conditions
    for (const auto& rung : ladder.rungs) {
        for (const auto& block : rung.blocks) {
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    error = "conditions contain witness-only data type: " + DataTypeName(field.type);
                    return false;
                }
            }
        }
    }

    out.rungs = std::move(ladder.rungs);
    out.coil = std::move(ladder.coil);
    return true;
}

CScript SerializeRungConditions(const RungConditions& conditions)
{
    // Serialize the conditions as a ladder witness
    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    ladder.coil = conditions.coil;
    auto bytes = SerializeLadderWitness(ladder);

    // Prepend the conditions prefix
    CScript result;
    result.push_back(RUNG_CONDITIONS_PREFIX);
    result.insert(result.end(), bytes.begin(), bytes.end());
    return result;
}

} // namespace rung
