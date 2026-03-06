// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/adaptor.h>
#include <rung/conditions.h>
#include <rung/evaluator.h>
#include <rung/policy.h>
#include <rung/pq_verify.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>

#include <core_io.h>
#include <crypto/sha256.h>
#include <key.h>
#include <key_io.h>
#include <random.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <util/strencodings.h>

#include <univalue.h>

#include <cstring>

using rung::RungBlockType;
using rung::RungDataType;
using rung::RungConditions;
using rung::LadderWitness;
using rung::RungBlock;
using rung::RungField;
using rung::Rung;
using rung::RungCoil;
using rung::RungCoilType;
using rung::RungAttestationMode;
using rung::RungScheme;

/** Convert blocks to JSON array (shared between input rungs and coil condition rungs). */
static UniValue BlocksToJSON(const std::vector<RungBlock>& blocks)
{
    UniValue arr(UniValue::VARR);
    for (const auto& block : blocks) {
        UniValue block_obj(UniValue::VOBJ);
        block_obj.pushKV("type", rung::BlockTypeName(block.type));
        uint16_t btype = static_cast<uint16_t>(block.type);
        std::vector<uint8_t> type_bytes = {static_cast<uint8_t>(btype & 0xFF), static_cast<uint8_t>((btype >> 8) & 0xFF)};
        block_obj.pushKV("type_hex", HexStr(type_bytes));
        block_obj.pushKV("inverted", block.inverted);

        UniValue fields_arr(UniValue::VARR);
        for (const auto& field : block.fields) {
            UniValue field_obj(UniValue::VOBJ);
            field_obj.pushKV("type", rung::DataTypeName(field.type));
            field_obj.pushKV("size", static_cast<int>(field.data.size()));
            field_obj.pushKV("hex", HexStr(field.data));
            fields_arr.push_back(field_obj);
        }
        block_obj.pushKV("fields", fields_arr);
        arr.push_back(block_obj);
    }
    return arr;
}

/** Convert a coil to JSON. */
static UniValue CoilToJSON(const RungCoil& coil)
{
    UniValue obj(UniValue::VOBJ);
    switch (coil.coil_type) {
    case RungCoilType::UNLOCK:    obj.pushKV("type", "UNLOCK"); break;
    case RungCoilType::UNLOCK_TO: obj.pushKV("type", "UNLOCK_TO"); break;
    case RungCoilType::COVENANT:  obj.pushKV("type", "COVENANT"); break;
    default: obj.pushKV("type", "UNKNOWN"); break;
    }
    switch (coil.attestation) {
    case RungAttestationMode::INLINE:    obj.pushKV("attestation", "INLINE"); break;
    case RungAttestationMode::AGGREGATE: obj.pushKV("attestation", "AGGREGATE"); break;
    case RungAttestationMode::DEFERRED:  obj.pushKV("attestation", "DEFERRED"); break;
    default: obj.pushKV("attestation", "UNKNOWN"); break;
    }
    switch (coil.scheme) {
    case RungScheme::SCHNORR:     obj.pushKV("scheme", "SCHNORR"); break;
    case RungScheme::ECDSA:       obj.pushKV("scheme", "ECDSA"); break;
    case RungScheme::FALCON512:   obj.pushKV("scheme", "FALCON512"); break;
    case RungScheme::FALCON1024:  obj.pushKV("scheme", "FALCON1024"); break;
    case RungScheme::DILITHIUM3:  obj.pushKV("scheme", "DILITHIUM3"); break;
    case RungScheme::SPHINCS_SHA: obj.pushKV("scheme", "SPHINCS_SHA"); break;
    default: obj.pushKV("scheme", "UNKNOWN"); break;
    }
    if (!coil.address.empty()) {
        obj.pushKV("address", HexStr(coil.address));
    }
    if (!coil.conditions.empty()) {
        UniValue cond_arr(UniValue::VARR);
        for (const auto& crung : coil.conditions) {
            UniValue crung_obj(UniValue::VOBJ);
            crung_obj.pushKV("blocks", BlocksToJSON(crung.blocks));
            cond_arr.push_back(crung_obj);
        }
        obj.pushKV("conditions", cond_arr);
    }
    return obj;
}

/** Convert a LadderWitness to JSON for RPC display.
 *  Returns an object with "rungs" array and "coil" object. */
static UniValue LadderWitnessToJSON(const LadderWitness& ladder)
{
    UniValue result(UniValue::VOBJ);

    UniValue rungs_arr(UniValue::VARR);
    for (size_t r = 0; r < ladder.rungs.size(); ++r) {
        UniValue rung_obj(UniValue::VOBJ);
        rung_obj.pushKV("rung_index", static_cast<int>(r));
        rung_obj.pushKV("blocks", BlocksToJSON(ladder.rungs[r].blocks));
        rungs_arr.push_back(rung_obj);
    }
    result.pushKV("rungs", rungs_arr);
    result.pushKV("coil", CoilToJSON(ladder.coil));

    return result;
}

/** Parse a block type string to enum. Returns false on unknown type. */
static bool ParseBlockType(const std::string& name, RungBlockType& out)
{
    // Phase 1 — Signature
    if (name == "SIG")              { out = RungBlockType::SIG; return true; }
    if (name == "MULTISIG")         { out = RungBlockType::MULTISIG; return true; }
    if (name == "ADAPTOR_SIG")      { out = RungBlockType::ADAPTOR_SIG; return true; }
    // Phase 1 — Timelock
    if (name == "CSV")              { out = RungBlockType::CSV; return true; }
    if (name == "CSV_TIME")         { out = RungBlockType::CSV_TIME; return true; }
    if (name == "CLTV")             { out = RungBlockType::CLTV; return true; }
    if (name == "CLTV_TIME")        { out = RungBlockType::CLTV_TIME; return true; }
    // Phase 1 — Hash
    if (name == "HASH_PREIMAGE")    { out = RungBlockType::HASH_PREIMAGE; return true; }
    if (name == "HASH160_PREIMAGE") { out = RungBlockType::HASH160_PREIMAGE; return true; }
    if (name == "TAGGED_HASH")      { out = RungBlockType::TAGGED_HASH; return true; }
    // Phase 2 — Covenant
    if (name == "CTV")              { out = RungBlockType::CTV; return true; }
    if (name == "VAULT_LOCK")       { out = RungBlockType::VAULT_LOCK; return true; }
    if (name == "AMOUNT_LOCK")      { out = RungBlockType::AMOUNT_LOCK; return true; }
    // Phase 2 — Anchor
    if (name == "ANCHOR")           { out = RungBlockType::ANCHOR; return true; }
    if (name == "ANCHOR_CHANNEL")   { out = RungBlockType::ANCHOR_CHANNEL; return true; }
    if (name == "ANCHOR_POOL")      { out = RungBlockType::ANCHOR_POOL; return true; }
    if (name == "ANCHOR_RESERVE")   { out = RungBlockType::ANCHOR_RESERVE; return true; }
    if (name == "ANCHOR_SEAL")      { out = RungBlockType::ANCHOR_SEAL; return true; }
    if (name == "ANCHOR_ORACLE")    { out = RungBlockType::ANCHOR_ORACLE; return true; }
    // Phase 3 — Recursion
    if (name == "RECURSE_SAME")     { out = RungBlockType::RECURSE_SAME; return true; }
    if (name == "RECURSE_MODIFIED") { out = RungBlockType::RECURSE_MODIFIED; return true; }
    if (name == "RECURSE_UNTIL")    { out = RungBlockType::RECURSE_UNTIL; return true; }
    if (name == "RECURSE_COUNT")    { out = RungBlockType::RECURSE_COUNT; return true; }
    if (name == "RECURSE_SPLIT")    { out = RungBlockType::RECURSE_SPLIT; return true; }
    if (name == "RECURSE_DECAY")    { out = RungBlockType::RECURSE_DECAY; return true; }
    // Phase 3 — PLC
    if (name == "HYSTERESIS_FEE")   { out = RungBlockType::HYSTERESIS_FEE; return true; }
    if (name == "HYSTERESIS_VALUE") { out = RungBlockType::HYSTERESIS_VALUE; return true; }
    if (name == "TIMER_CONTINUOUS") { out = RungBlockType::TIMER_CONTINUOUS; return true; }
    if (name == "TIMER_OFF_DELAY")  { out = RungBlockType::TIMER_OFF_DELAY; return true; }
    if (name == "LATCH_SET")        { out = RungBlockType::LATCH_SET; return true; }
    if (name == "LATCH_RESET")      { out = RungBlockType::LATCH_RESET; return true; }
    if (name == "COUNTER_DOWN")     { out = RungBlockType::COUNTER_DOWN; return true; }
    if (name == "COUNTER_PRESET")   { out = RungBlockType::COUNTER_PRESET; return true; }
    if (name == "COUNTER_UP")       { out = RungBlockType::COUNTER_UP; return true; }
    if (name == "COMPARE")          { out = RungBlockType::COMPARE; return true; }
    if (name == "SEQUENCER")        { out = RungBlockType::SEQUENCER; return true; }
    if (name == "ONE_SHOT")         { out = RungBlockType::ONE_SHOT; return true; }
    if (name == "RATE_LIMIT")       { out = RungBlockType::RATE_LIMIT; return true; }
    if (name == "COSIGN")           { out = RungBlockType::COSIGN; return true; }
    // Backward compat aliases
    if (name == "HASHLOCK")         { out = RungBlockType::HASH_PREIMAGE; return true; }
    if (name == "ANCHOR_BOND")      { out = RungBlockType::ANCHOR_SEAL; return true; }
    if (name == "ANCHOR_ESCROW")    { out = RungBlockType::ANCHOR_ORACLE; return true; }
    if (name == "RECURSE_COLLECT")  { out = RungBlockType::RECURSE_COUNT; return true; }
    if (name == "RECURSE_MERGE")    { out = RungBlockType::RECURSE_SPLIT; return true; }
    if (name == "RECURSE_SWEEP")    { out = RungBlockType::RECURSE_DECAY; return true; }
    return false;
}

/** Parse a data type string to enum. Returns false on unknown type. */
static bool ParseDataType(const std::string& name, RungDataType& out)
{
    if (name == "PUBKEY")        { out = RungDataType::PUBKEY; return true; }
    if (name == "PUBKEY_COMMIT") { out = RungDataType::PUBKEY_COMMIT; return true; }
    if (name == "HASH256")       { out = RungDataType::HASH256; return true; }
    if (name == "HASH160")       { out = RungDataType::HASH160; return true; }
    if (name == "PREIMAGE")      { out = RungDataType::PREIMAGE; return true; }
    if (name == "SIGNATURE")     { out = RungDataType::SIGNATURE; return true; }
    if (name == "SPEND_INDEX")   { out = RungDataType::SPEND_INDEX; return true; }
    if (name == "NUMERIC")       { out = RungDataType::NUMERIC; return true; }
    if (name == "SCHEME")        { out = RungDataType::SCHEME; return true; }
    // Backward compat: accept old name LOCKTIME as alias for NUMERIC
    if (name == "LOCKTIME")      { out = RungDataType::NUMERIC; return true; }
    return false;
}

/** Parse a block spec from JSON (shared between input and coil conditions). */
static RungBlock ParseBlockSpec(const UniValue& block_obj, bool conditions_only)
{
    RungBlock block;
    std::string type_str = block_obj["type"].get_str();
    if (!ParseBlockType(type_str, block.type)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown block type: " + type_str);
    }
    if (block_obj.exists("inverted") && block_obj["inverted"].get_bool()) {
        block.inverted = true;
    }
    const UniValue& fields_arr = block_obj["fields"].get_array();
    for (size_t f = 0; f < fields_arr.size(); ++f) {
        const UniValue& field_obj = fields_arr[f];
        RungField field;
        std::string ftype_str = field_obj["type"].get_str();
        if (!ParseDataType(ftype_str, field.type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown data type: " + ftype_str);
        }
        if (conditions_only && !rung::IsConditionDataType(field.type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Data type " + ftype_str + " not allowed in conditions (witness-only)");
        }
        std::string hex_data = field_obj["hex"].get_str();
        field.data = ParseHex(hex_data);
        std::string reason;
        if (!field.IsValid(reason)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid field: " + reason);
        }
        block.fields.push_back(std::move(field));
    }
    return block;
}

/** Parse coil from JSON. Defaults to UNLOCK/INLINE/SCHNORR. */
static RungCoil ParseCoil(const UniValue& obj)
{
    RungCoil coil;
    if (obj.isNull() || !obj.isObject()) return coil;

    if (obj.exists("type")) {
        std::string t = obj["type"].get_str();
        if (t == "UNLOCK")    coil.coil_type = RungCoilType::UNLOCK;
        else if (t == "UNLOCK_TO") coil.coil_type = RungCoilType::UNLOCK_TO;
        else if (t == "COVENANT")  coil.coil_type = RungCoilType::COVENANT;
    }
    if (obj.exists("attestation")) {
        std::string a = obj["attestation"].get_str();
        if (a == "INLINE")     coil.attestation = RungAttestationMode::INLINE;
        else if (a == "AGGREGATE") coil.attestation = RungAttestationMode::AGGREGATE;
        else if (a == "DEFERRED")  coil.attestation = RungAttestationMode::DEFERRED;
    }
    if (obj.exists("scheme")) {
        std::string s = obj["scheme"].get_str();
        if (s == "SCHNORR") coil.scheme = RungScheme::SCHNORR;
        else if (s == "ECDSA") coil.scheme = RungScheme::ECDSA;
        else if (s == "FALCON512") coil.scheme = RungScheme::FALCON512;
        else if (s == "FALCON1024") coil.scheme = RungScheme::FALCON1024;
        else if (s == "DILITHIUM3") coil.scheme = RungScheme::DILITHIUM3;
        else if (s == "SPHINCS_SHA") coil.scheme = RungScheme::SPHINCS_SHA;
    }
    if (obj.exists("address")) {
        coil.address = ParseHex(obj["address"].get_str());
    }
    if (obj.exists("conditions")) {
        const UniValue& cond_arr = obj["conditions"].get_array();
        for (size_t i = 0; i < cond_arr.size(); ++i) {
            const UniValue& crung_obj = cond_arr[i];
            Rung crung;
            const UniValue& cblocks_arr = crung_obj["blocks"].get_array();
            for (size_t b = 0; b < cblocks_arr.size(); ++b) {
                crung.blocks.push_back(ParseBlockSpec(cblocks_arr[b], false));
            }
            coil.conditions.push_back(std::move(crung));
        }
    }
    return coil;
}

static RPCHelpMan decoderung()
{
    return RPCHelpMan{
        "decoderung",
        "Decode a ladder witness from hex and display its typed structure.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The ladder witness in hex."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "num_rungs", "Number of rungs in the ladder"},
            {RPCResult::Type::ARR, "rungs", "The rungs",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "rung_index", "Rung index"},
                        {RPCResult::Type::ARR, "blocks", "Function blocks in this rung",
                            {
                                {RPCResult::Type::OBJ, "", "", {
                                    {RPCResult::Type::STR, "type", "Block type name"},
                                    {RPCResult::Type::STR_HEX, "type_hex", "Block type (2 bytes LE)"},
                                    {RPCResult::Type::BOOL, "inverted", "Whether block is inverted"},
                                    {RPCResult::Type::ARR, "fields", "Typed fields",
                                        {
                                            {RPCResult::Type::OBJ, "", "", {
                                                {RPCResult::Type::STR, "type", "Data type name"},
                                                {RPCResult::Type::NUM, "size", "Field data size"},
                                                {RPCResult::Type::STR_HEX, "hex", "Field data hex"},
                                            }},
                                        }},
                                }},
                            }},
                    }},
                }},
            {RPCResult::Type::OBJ, "coil", "Coil metadata (per-output)",
                {
                    {RPCResult::Type::STR, "type", "Coil type"},
                    {RPCResult::Type::STR, "attestation", "Attestation mode"},
                    {RPCResult::Type::STR, "scheme", "Signature scheme"},
                    {RPCResult::Type::STR_HEX, "address", /*optional=*/ true, "Destination scriptPubKey hex"},
                    {RPCResult::Type::ARR, "conditions", /*optional=*/ true, "Coil condition rungs (same block format as input rungs)",
                        {
                            {RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::ARR, "blocks", "Function blocks",
                                    {
                                        {RPCResult::Type::OBJ, "", "", {
                                            {RPCResult::Type::STR, "type", "Block type name"},
                                            {RPCResult::Type::BOOL, "inverted", "Whether block is inverted"},
                                        }},
                                    }},
                            }},
                        }},
                }},
        }},
        RPCExamples{
            HelpExampleCli("decoderung", "010101012103abcdef...0240deadbeef...")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    auto witness_bytes = ParseHex(hex_str);
    if (witness_bytes.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex string");
    }

    LadderWitness ladder;
    std::string error;
    if (!rung::DeserializeLadderWitness(witness_bytes, ladder, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode ladder witness: " + error);
    }

    UniValue result = LadderWitnessToJSON(ladder);
    result.pushKV("num_rungs", static_cast<int>(ladder.rungs.size()));
    return result;
},
    };
}

static RPCHelpMan createrung()
{
    return RPCHelpMan{
        "createrung",
        "Create a ladder witness from a JSON specification.\n"
        "Returns the serialized ladder witness as hex.\n",
        {
            {"rungs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of rung specifications",
                {
                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A single rung",
                        {
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of block specifications",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A function block",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"inverted", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Invert evaluation result (default false)"},
                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Typed fields for this block",
                                                {
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A typed field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data in hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            {"coil", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Coil metadata (default UNLOCK/INLINE/SCHNORR). For UNLOCK_TO/COVENANT, conditions array uses same block format as input rungs.",
                {
                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UNLOCK, UNLOCK_TO, or COVENANT"},
                    {"attestation", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "INLINE, AGGREGATE, or DEFERRED"},
                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SCHNORR or ECDSA"},
                    {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Destination scriptPubKey hex"},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The serialized ladder witness hex"},
            {RPCResult::Type::NUM, "size", "Size in bytes"},
        }},
        RPCExamples{
            HelpExampleCli("createrung", "'[{\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"PUBKEY\",\"hex\":\"03...\"},{\"type\":\"SIGNATURE\",\"hex\":\"...\"}]}]}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& rungs_arr = request.params[0].get_array();
    LadderWitness ladder;

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;

        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/false));
        }

        ladder.rungs.push_back(std::move(rung));
    }

    // Parse optional coil (per-ladder, not per-rung)
    if (!request.params[1].isNull()) {
        ladder.coil = ParseCoil(request.params[1]);
    }

    auto serialized = rung::SerializeLadderWitness(ladder);
    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", HexStr(serialized));
    result.pushKV("size", static_cast<int>(serialized.size()));
    return result;
},
    };
}

static RPCHelpMan validateladder()
{
    return RPCHelpMan{
        "validateladder",
        "Validate a raw v3 RUNG_TX transaction's ladder witnesses.\n"
        "Checks that all input witnesses are valid ladder witnesses\n"
        "and pass policy rules.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw transaction hex."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether all ladder witnesses are valid"},
            {RPCResult::Type::STR, "error", /*optional=*/ true, "Error message if invalid"},
            {RPCResult::Type::NUM, "version", "Transaction version"},
            {RPCResult::Type::NUM, "num_inputs", "Number of inputs"},
            {RPCResult::Type::ARR, "inputs", "Per-input validation results",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "index", "Input index"},
                        {RPCResult::Type::BOOL, "valid", "Whether this input's ladder witness is valid"},
                        {RPCResult::Type::STR, "error", /*optional=*/ true, "Error if invalid"},
                        {RPCResult::Type::NUM, "num_rungs", /*optional=*/ true, "Number of rungs"},
                    }},
                }},
        }},
        RPCExamples{
            HelpExampleCli("validateladder", "0300000001...")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex_str)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction");
    }

    CTransaction tx(mtx);

    UniValue result(UniValue::VOBJ);
    result.pushKV("version", static_cast<int>(tx.version));
    result.pushKV("num_inputs", static_cast<int>(tx.vin.size()));

    if (tx.version != CTransaction::RUNG_TX_VERSION) {
        result.pushKV("valid", false);
        result.pushKV("error", "Not a v3 RUNG_TX (version=" + std::to_string(tx.version) + ")");
        result.pushKV("inputs", UniValue(UniValue::VARR));
        return result;
    }

    // Check policy
    std::string policy_reason;
    bool policy_ok = rung::IsStandardRungTx(tx, policy_reason);

    UniValue inputs_arr(UniValue::VARR);
    bool all_valid = true;

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        UniValue input_obj(UniValue::VOBJ);
        input_obj.pushKV("index", static_cast<int>(i));

        const auto& witness = tx.vin[i].scriptWitness;
        if (witness.stack.empty()) {
            input_obj.pushKV("valid", false);
            input_obj.pushKV("error", "missing witness");
            all_valid = false;
        } else {
            LadderWitness ladder;
            std::string error;
            if (!rung::DeserializeLadderWitness(witness.stack[0], ladder, error)) {
                input_obj.pushKV("valid", false);
                input_obj.pushKV("error", error);
                all_valid = false;
            } else {
                input_obj.pushKV("valid", true);
                input_obj.pushKV("num_rungs", static_cast<int>(ladder.rungs.size()));
            }
        }
        inputs_arr.push_back(input_obj);
    }

    result.pushKV("valid", all_valid && policy_ok);
    if (!policy_ok) {
        result.pushKV("error", policy_reason);
    }
    result.pushKV("inputs", inputs_arr);
    return result;
},
    };
}

/** Helper: parse a conditions JSON spec into a RungConditions struct.
 *  rungs_arr is the array of rung specs; coil_obj is the optional coil spec (per-output). */
static RungConditions ParseConditionsSpec(const UniValue& rungs_arr, const UniValue& coil_obj = UniValue())
{
    RungConditions conditions;

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;

        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true));
        }

        conditions.rungs.push_back(std::move(rung));
    }

    // Parse coil at output level (not per-rung)
    if (!coil_obj.isNull() && coil_obj.isObject()) {
        conditions.coil = ParseCoil(coil_obj);
    }

    return conditions;
}

static RPCHelpMan createrungtx()
{
    return RPCHelpMan{
        "createrungtx",
        "Create an unsigned v3 RUNG_TX transaction with rung condition outputs.\n"
        "Inputs are outpoints to spend. Outputs specify rung conditions and amounts.\n",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Transaction inputs",
                {
                    {"input", RPCArg::Type::OBJ, RPCArg::Optional::NO, "An input",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output index"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "nSequence value (default 0xfffffffe). Set for CSV spends."},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Transaction outputs",
                {
                    {"output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "An output",
                        {
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in BTC"},
                            {"conditions", RPCArg::Type::ARR, RPCArg::Optional::NO, "Rung conditions spec",
                                {
                                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A rung spec",
                                        {
                                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Block specs",
                                                {
                                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                                            {"inverted", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Invert evaluation"},
                                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Fields",
                                                                {
                                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A field",
                                                                        {
                                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type"},
                                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Field data hex"},
                                                                        },
                                                                    },
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {"coil", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Coil metadata (per-output, default UNLOCK/INLINE/SCHNORR). For UNLOCK_TO/COVENANT, conditions uses same block format as input rungs.",
                                {
                                    {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UNLOCK, UNLOCK_TO, or COVENANT"},
                                    {"attestation", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "INLINE, AGGREGATE, or DEFERRED"},
                                    {"scheme", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SCHNORR or ECDSA"},
                                    {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Destination scriptPubKey hex"},
                                },
                            },
                        },
                    },
                },
            },
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Transaction nLockTime (default 0). Set for CLTV spends."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The unsigned transaction hex"},
        }},
        RPCExamples{
            HelpExampleCli("createrungtx", "'[{\"txid\":\"...\",\"vout\":0}]' '[{\"amount\":0.001,\"conditions\":[{\"blocks\":[{\"type\":\"SIG\",\"fields\":[{\"type\":\"PUBKEY\",\"hex\":\"02...\"}]}]}]}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const UniValue& inputs_arr = request.params[0].get_array();
    const UniValue& outputs_arr = request.params[1].get_array();

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    // Optional locktime (3rd param)
    if (!request.params[2].isNull()) {
        mtx.nLockTime = request.params[2].getInt<uint32_t>();
    }

    // Parse inputs
    for (size_t i = 0; i < inputs_arr.size(); ++i) {
        const UniValue& inp = inputs_arr[i];
        CTxIn txin;
        auto hash = uint256::FromHex(inp["txid"].get_str());
        if (!hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txid: " + inp["txid"].get_str());
        }
        txin.prevout.hash = Txid::FromUint256(*hash);
        txin.prevout.n = inp["vout"].getInt<uint32_t>();
        if (inp.exists("sequence")) {
            txin.nSequence = inp["sequence"].getInt<uint32_t>();
        } else {
            txin.nSequence = CTxIn::MAX_SEQUENCE_NONFINAL;
        }
        mtx.vin.push_back(txin);
    }

    // Parse outputs
    for (size_t i = 0; i < outputs_arr.size(); ++i) {
        const UniValue& outp = outputs_arr[i];
        CAmount amount = AmountFromValue(outp["amount"]);

        const UniValue& cond_arr = outp["conditions"].get_array();
        UniValue coil_val = outp.exists("coil") ? outp["coil"] : UniValue();
        RungConditions conditions = ParseConditionsSpec(cond_arr, coil_val);

        CTxOut txout;
        txout.nValue = amount;
        txout.scriptPubKey = rung::SerializeRungConditions(conditions);
        mtx.vout.push_back(txout);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    return result;
},
    };
}

/** Build a witness block for a single signing spec entry. */
static RungBlock BuildWitnessBlock(const UniValue& block_spec,
                                   const CMutableTransaction& mtx,
                                   unsigned int input_idx,
                                   const PrecomputedTransactionData& txdata,
                                   const RungConditions& conditions)
{
    std::string type_str = block_spec["type"].get_str();
    RungBlockType btype;
    if (!ParseBlockType(type_str, btype)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown block type: " + type_str);
    }

    RungBlock block;
    block.type = btype;

    switch (btype) {
    case RungBlockType::SIG: {
        // Check for PQ scheme
        if (block_spec.exists("scheme") && block_spec.exists("pq_privkey")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (scheme_str == "FALCON512") scheme = RungScheme::FALCON512;
            else if (scheme_str == "FALCON1024") scheme = RungScheme::FALCON1024;
            else if (scheme_str == "DILITHIUM3") scheme = RungScheme::DILITHIUM3;
            else if (scheme_str == "SPHINCS_SHA") scheme = RungScheme::SPHINCS_SHA;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown PQ scheme: " + scheme_str);

            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ signing requires liboqs support");
            }

            auto pq_privkey = ParseHex(block_spec["pq_privkey"].get_str());
            if (pq_privkey.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty pq_privkey");
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }

            std::vector<uint8_t> pq_sig;
            std::span<const uint8_t> msg{sighash.begin(), 32};
            if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ signing failed");
            }

            // If conditions use PUBKEY_COMMIT, push full pubkey into witness for verification
            if (block_spec.exists("pq_pubkey")) {
                auto pubkey_bytes = ParseHex(block_spec["pq_pubkey"].get_str());
                if (pubkey_bytes.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty pq_pubkey");
                }
                block.fields.push_back({RungDataType::PUBKEY, std::move(pubkey_bytes)});
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::move(pq_sig)});
            break;
        }

        std::string wif = block_spec["privkey"].get_str();
        CKey privkey = DecodeSecret(wif);
        if (!privkey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
        }

        unsigned char sig_buf[64];
        uint256 aux_rand = GetRandHash();
        if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed");
        }

        block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        break;
    }
    case RungBlockType::MULTISIG: {
        // Check for PQ scheme
        if (block_spec.exists("scheme") && block_spec.exists("pq_privkeys")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (scheme_str == "FALCON512") scheme = RungScheme::FALCON512;
            else if (scheme_str == "FALCON1024") scheme = RungScheme::FALCON1024;
            else if (scheme_str == "DILITHIUM3") scheme = RungScheme::DILITHIUM3;
            else if (scheme_str == "SPHINCS_SHA") scheme = RungScheme::SPHINCS_SHA;
            else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown PQ scheme: " + scheme_str);

            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ signing requires liboqs support");
            }

            const UniValue& pq_privkeys_arr = block_spec["pq_privkeys"].get_array();
            if (pq_privkeys_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "MULTISIG PQ requires at least one pq_privkey");
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }

            std::span<const uint8_t> msg{sighash.begin(), 32};
            for (size_t s = 0; s < pq_privkeys_arr.size(); ++s) {
                auto pq_privkey = ParseHex(pq_privkeys_arr[s].get_str());
                std::vector<uint8_t> pq_sig;
                if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ MULTISIG signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::move(pq_sig)});
            }
            break;
        }

        const UniValue& privkeys_arr = block_spec["privkeys"].get_array();
        if (privkeys_arr.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "MULTISIG requires at least one privkey");
        }

        uint256 sighash;
        if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
        }

        for (size_t s = 0; s < privkeys_arr.size(); ++s) {
            CKey privkey = DecodeSecret(privkeys_arr[s].get_str());
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid MULTISIG private key");
            }

            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "MULTISIG Schnorr signing failed");
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        }
        break;
    }
    case RungBlockType::ADAPTOR_SIG: {
        // Adaptor signature: privkey + adaptor_secret → adapted Schnorr sig
        if (block_spec.exists("privkey")) {
            std::string wif = block_spec["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }
            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }
            if (block_spec.exists("adaptor_secret")) {
                // Adapted signing: tweak the nonce by the adaptor secret
                auto secret_bytes = ParseHex(block_spec["adaptor_secret"].get_str());
                if (secret_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_secret must be 32 bytes hex");
                }
                std::vector<uint8_t> sig_out(64);
                if (!rung::CreateAdaptedSignature(privkey, sighash, secret_bytes, sig_out)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Adapted Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, sig_out});
            } else {
                // Plain Schnorr (pre-signature without adaptor — useful for testing)
                unsigned char sig_buf[64];
                uint256 aux_rand = GetRandHash();
                if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
            }
        }
        break;
    }
    case RungBlockType::VAULT_LOCK: {
        // Vault lock: plain Schnorr signature from privkey
        if (block_spec.exists("privkey")) {
            std::string wif = block_spec["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }
            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash");
            }
            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed");
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
        }
        break;
    }
    case RungBlockType::HASH_PREIMAGE:
    case RungBlockType::HASH160_PREIMAGE: {
        std::string preimage_hex = block_spec["preimage"].get_str();
        auto preimage_data = ParseHex(preimage_hex);
        if (preimage_data.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HASH_PREIMAGE requires non-empty preimage hex");
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        break;
    }
    case RungBlockType::TAGGED_HASH: {
        // TAGGED_HASH needs a PREIMAGE field in witness (same as HASH_PREIMAGE)
        if (block_spec.exists("preimage")) {
            std::string preimage_hex = block_spec["preimage"].get_str();
            auto preimage_data = ParseHex(preimage_hex);
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "TAGGED_HASH requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        }
        break;
    }
    case RungBlockType::CSV:
    case RungBlockType::CSV_TIME:
    case RungBlockType::CLTV:
    case RungBlockType::CLTV_TIME:
        // No witness fields needed — NUMERIC comes from conditions
        break;
    default:
        // Phase 2/3/4 blocks — no witness fields needed
        break;
    }

    return block;
}

static RPCHelpMan signrungtx()
{
    return RPCHelpMan{
        "signrungtx",
        "Sign a v3 RUNG_TX transaction's inputs.\n"
        "Supports two formats:\n"
        "  Legacy: [{\"privkey\":\"cVt...\",\"input\":0}] — single SIG block\n"
        "  Full:   [{\"input\":0,\"blocks\":[{\"type\":\"SIG\",\"privkey\":\"cVt...\"},...]}] — any block types\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The unsigned v3 transaction hex"},
            {"signers", RPCArg::Type::ARR, RPCArg::Optional::NO, "Per-input signing specifications",
                {
                    {"signer", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A signing spec",
                        {
                            {"input", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index to sign"},
                            {"privkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF key (legacy SIG-only format)"},
                            {"rung", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Target rung index for multi-rung conditions (default 0)"},
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Block signing specs (new format)",
                                {
                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block spec",
                                        {
                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                            {"privkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF key for SIG"},
                                            {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "WIF keys for MULTISIG",
                                                {{"key", RPCArg::Type::STR, RPCArg::Optional::NO, "A WIF key"}},
                                            },
                                            {"preimage", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Preimage hex for HASH_PREIMAGE/HASH160_PREIMAGE"},
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            {"spent_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs being spent (for sighash computation)",
                {
                    {"spent_output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A spent output",
                        {
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in BTC"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The scriptPubKey hex"},
                        },
                    },
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
            {RPCResult::Type::BOOL, "complete", "Whether all inputs are signed"},
        }},
        RPCExamples{
            HelpExampleCli("signrungtx", "<txhex> '[{\"privkey\":\"cVt...\",\"input\":0}]' '[{\"amount\":0.001,\"scriptPubKey\":\"c1...\"}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string hex_str = self.Arg<std::string>("hex");
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex_str)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction");
    }

    if (mtx.version != CTransaction::RUNG_TX_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not v3 RUNG_TX");
    }

    const UniValue& signers_arr = request.params[1].get_array();
    const UniValue& spent_arr = request.params[2].get_array();

    if (spent_arr.size() != mtx.vin.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "spent_outputs count (" + std::to_string(spent_arr.size()) +
            ") must match input count (" + std::to_string(mtx.vin.size()) + ")");
    }

    // Build spent outputs vector
    std::vector<CTxOut> spent_outputs;
    for (size_t i = 0; i < spent_arr.size(); ++i) {
        const UniValue& so = spent_arr[i];
        CTxOut txout;
        txout.nValue = AmountFromValue(so["amount"]);
        auto spk_bytes = ParseHex(so["scriptPubKey"].get_str());
        txout.scriptPubKey = CScript(spk_bytes.begin(), spk_bytes.end());
        spent_outputs.push_back(txout);
    }

    // Precompute transaction data
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>(spent_outputs));

    bool all_signed = true;

    for (size_t k = 0; k < signers_arr.size(); ++k) {
        const UniValue& signer_obj = signers_arr[k];
        unsigned int input_idx = signer_obj["input"].getInt<unsigned int>();

        if (input_idx >= mtx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Input index " + std::to_string(input_idx) + " out of range");
        }

        // Determine conditions from spent output
        RungConditions conditions;
        std::string cond_error;
        bool has_conditions = rung::DeserializeRungConditions(
            spent_outputs[input_idx].scriptPubKey, conditions, cond_error);
        if (!has_conditions) {
            conditions = RungConditions{};
        }

        LadderWitness ladder;

        if (signer_obj.exists("privkey") && !signer_obj.exists("blocks")) {
            // Legacy format: single SIG block
            std::string wif = signer_obj["privkey"].get_str();
            CKey privkey = DecodeSecret(wif);
            if (!privkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key: " + wif);
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute sighash for input " + std::to_string(input_idx));
            }

            unsigned char sig_buf[64];
            uint256 aux_rand = GetRandHash();
            if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Schnorr signing failed for input " + std::to_string(input_idx));
            }
            std::vector<unsigned char> sig(sig_buf, sig_buf + 64);

            CPubKey pubkey = privkey.GetPubKey();
            std::vector<uint8_t> pubkey_data(pubkey.begin(), pubkey.end());

            Rung rung;
            RungBlock block;
            block.type = RungBlockType::SIG;
            block.fields.push_back({RungDataType::PUBKEY, pubkey_data});
            block.fields.push_back({RungDataType::SIGNATURE, sig});
            rung.blocks.push_back(std::move(block));
            ladder.rungs.push_back(std::move(rung));
        } else if (signer_obj.exists("blocks")) {
            const UniValue& blocks_arr = signer_obj["blocks"].get_array();

            if (has_conditions) {
                for (size_t r = 0; r < conditions.rungs.size(); ++r) {
                    Rung wit_rung;
                    unsigned int target_rung = 0;
                    if (signer_obj.exists("rung")) {
                        target_rung = signer_obj["rung"].getInt<unsigned int>();
                    }

                    if (r == target_rung) {
                        if (blocks_arr.size() != conditions.rungs[r].blocks.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "blocks count (" + std::to_string(blocks_arr.size()) +
                                ") must match conditions rung " + std::to_string(r) +
                                " block count (" + std::to_string(conditions.rungs[r].blocks.size()) + ")");
                        }
                        for (size_t b = 0; b < blocks_arr.size(); ++b) {
                            wit_rung.blocks.push_back(
                                BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                        }
                    } else {
                        // Dummy rung — correct types, empty fields
                        for (const auto& cond_block : conditions.rungs[r].blocks) {
                            RungBlock dummy;
                            dummy.type = cond_block.type;
                            wit_rung.blocks.push_back(std::move(dummy));
                        }
                    }
                    ladder.rungs.push_back(std::move(wit_rung));
                }
            } else {
                // Bootstrap spend
                Rung rung;
                for (size_t b = 0; b < blocks_arr.size(); ++b) {
                    rung.blocks.push_back(
                        BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                }
                ladder.rungs.push_back(std::move(rung));
            }
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Signer entry must have either 'privkey' (legacy) or 'blocks' (new format)");
        }

        auto witness_bytes = rung::SerializeLadderWitness(ladder);
        mtx.vin[input_idx].scriptWitness.stack.clear();
        mtx.vin[input_idx].scriptWitness.stack.push_back(witness_bytes);
    }

    // Check if all inputs have witnesses
    for (const auto& vin : mtx.vin) {
        if (vin.scriptWitness.stack.empty()) {
            all_signed = false;
            break;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    result.pushKV("complete", all_signed);
    return result;
},
    };
}

static RPCHelpMan computectvhash()
{
    return RPCHelpMan{
        "computectvhash",
        "Compute the BIP-119 CTV template hash for a v3 RUNG_TX transaction.\n"
        "The hash commits to the transaction's version, locktime, inputs, outputs, and input index.\n"
        "Use this to create CTV conditions that constrain how an output can be spent.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The spending transaction hex (the tx that will spend the CTV output)"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Default{0}, "The input index being constrained by CTV"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "The 32-byte CTV template hash"},
            }
        },
        RPCExamples{
            HelpExampleCli("computectvhash", "\"0300000001...\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode transaction hex");
            }

            uint32_t input_index = 0;
            if (!request.params[1].isNull()) {
                input_index = request.params[1].getInt<uint32_t>();
            }

            if (input_index >= mtx.vin.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "input_index " + std::to_string(input_index) + " out of range (tx has " +
                    std::to_string(mtx.vin.size()) + " inputs)");
            }

            CTransaction tx(mtx);
            uint256 hash = rung::ComputeCTVHash(tx, input_index);

            UniValue result(UniValue::VOBJ);
            result.pushKV("hash", HexStr(hash));
            return result;
        },
    };
}

static RPCHelpMan generatepqkeypair()
{
    return RPCHelpMan{
        "generatepqkeypair",
        "Generate a post-quantum keypair for the specified scheme.\n"
        "Requires liboqs support.\n",
        {
            {"scheme", RPCArg::Type::STR, RPCArg::Optional::NO,
             "PQ scheme: FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "scheme", "The scheme used"},
            {RPCResult::Type::STR_HEX, "pubkey", "The public key (hex)"},
            {RPCResult::Type::STR_HEX, "privkey", "The private key (hex)"},
        }},
        RPCExamples{
            HelpExampleCli("generatepqkeypair", "FALCON512")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        std::string scheme_str = self.Arg<std::string>("scheme");
        RungScheme scheme;
        if (scheme_str == "FALCON512") scheme = RungScheme::FALCON512;
        else if (scheme_str == "FALCON1024") scheme = RungScheme::FALCON1024;
        else if (scheme_str == "DILITHIUM3") scheme = RungScheme::DILITHIUM3;
        else if (scheme_str == "SPHINCS_SHA") scheme = RungScheme::SPHINCS_SHA;
        else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown PQ scheme: " + scheme_str);

        if (!rung::HasPQSupport()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ keygen requires liboqs support (not compiled in)");
        }

        std::vector<uint8_t> pubkey, privkey;
        if (!rung::GeneratePQKeypair(scheme, pubkey, privkey)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ keypair generation failed");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("scheme", scheme_str);
        result.pushKV("pubkey", HexStr(pubkey));
        result.pushKV("privkey", HexStr(privkey));
        return result;
    },
    };
}

static RPCHelpMan pqpubkeycommit()
{
    return RPCHelpMan{
        "pqpubkeycommit",
        "Compute the SHA256 commitment hash of a post-quantum public key.\n"
        "Use this to create PUBKEY_COMMIT condition fields for compact UTXO storage.\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The full PQ public key (hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "commit", "The 32-byte SHA256 commitment hash"},
        }},
        RPCExamples{
            HelpExampleCli("pqpubkeycommit", "\"<897-byte falcon512 pubkey hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pubkey = ParseHex(self.Arg<std::string>("pubkey"));
        if (pubkey.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty pubkey");
        }

        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(hash);

        UniValue result(UniValue::VOBJ);
        result.pushKV("commit", HexStr(std::span<const unsigned char>(hash, CSHA256::OUTPUT_SIZE)));
        return result;
    },
    };
}

static RPCHelpMan extractadaptorsecret()
{
    return RPCHelpMan{
        "extractadaptorsecret",
        "Extract the adaptor secret from a pre-signature and adapted signature.\n"
        "Computes t = s_adapted - s_pre (scalar subtraction mod n).\n",
        {
            {"pre_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte pre-signature hex"},
            {"adapted_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte adapted signature hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "secret", "The 32-byte adaptor secret"},
        }},
        RPCExamples{
            HelpExampleCli("extractadaptorsecret", "\"<pre_sig_hex>\" \"<adapted_sig_hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pre_sig = ParseHex(self.Arg<std::string>("pre_sig"));
        auto adapted_sig = ParseHex(self.Arg<std::string>("adapted_sig"));

        if (pre_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pre_sig must be 64 bytes");
        }
        if (adapted_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "adapted_sig must be 64 bytes");
        }

        std::vector<uint8_t> secret;
        if (!rung::ExtractAdaptorSecret(pre_sig, adapted_sig, secret)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to extract adaptor secret");
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("secret", HexStr(secret));
        return result;
    },
    };
}

static RPCHelpMan verifyadaptorpresig()
{
    return RPCHelpMan{
        "verifyadaptorpresig",
        "Verify an adaptor pre-signature.\n"
        "Checks that s'*G == R + e*P where e = H(R+T||P||m).\n",
        {
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte x-only public key hex"},
            {"adaptor_point", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte x-only adaptor point hex"},
            {"pre_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte pre-signature hex"},
            {"sighash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte sighash hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether the pre-signature is valid"},
        }},
        RPCExamples{
            HelpExampleCli("verifyadaptorpresig", "\"<pubkey>\" \"<adaptor_point>\" \"<pre_sig>\" \"<sighash>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pubkey = ParseHex(self.Arg<std::string>("pubkey"));
        auto adaptor_point = ParseHex(self.Arg<std::string>("adaptor_point"));
        auto pre_sig = ParseHex(self.Arg<std::string>("pre_sig"));
        auto sighash_bytes = ParseHex(self.Arg<std::string>("sighash"));

        if (pubkey.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkey must be 32 bytes (x-only)");
        }
        if (adaptor_point.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_point must be 32 bytes (x-only)");
        }
        if (pre_sig.size() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "pre_sig must be 64 bytes");
        }
        if (sighash_bytes.size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "sighash must be 32 bytes");
        }

        uint256 sighash;
        std::memcpy(sighash.begin(), sighash_bytes.data(), 32);

        bool valid = rung::VerifyAdaptorPreSignature(pubkey, adaptor_point, pre_sig, sighash);

        UniValue result(UniValue::VOBJ);
        result.pushKV("valid", valid);
        return result;
    },
    };
}

void RegisterRungRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rung", &decoderung},
        {"rung", &createrung},
        {"rung", &validateladder},
        {"rung", &createrungtx},
        {"rung", &signrungtx},
        {"rung", &computectvhash},
        {"rung", &generatepqkeypair},
        {"rung", &pqpubkeycommit},
        {"rung", &extractadaptorsecret},
        {"rung", &verifyadaptorpresig},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
