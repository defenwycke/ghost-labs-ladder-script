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
#include <set>

using rung::RungBlockType;
using rung::RungDataType;
using rung::RungConditions;
using rung::LadderWitness;
using rung::RungBlock;
using rung::RungField;
using rung::Rung;
using rung::Relay;
using rung::RungCoil;
using rung::RungCoilType;
using rung::RungAttestationMode;
using rung::RungScheme;
using rung::WitnessReference;
using rung::WitnessDiff;
using rung::CompactRungType;
using rung::CompactRungData;

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
static UniValue RelayRefsToJSON(const std::vector<uint16_t>& refs)
{
    UniValue arr(UniValue::VARR);
    for (uint16_t ref : refs) {
        arr.push_back(static_cast<int>(ref));
    }
    return arr;
}

static UniValue LadderWitnessToJSON(const LadderWitness& ladder)
{
    UniValue result(UniValue::VOBJ);

    // Diff witness mode
    if (ladder.IsWitnessRef()) {
        const auto& ref = *ladder.witness_ref;
        result.pushKV("witness_ref", true);
        result.pushKV("source_input", static_cast<int>(ref.input_index));

        UniValue diffs_arr(UniValue::VARR);
        for (const auto& diff : ref.diffs) {
            UniValue diff_obj(UniValue::VOBJ);
            diff_obj.pushKV("rung_index", static_cast<int>(diff.rung_index));
            diff_obj.pushKV("block_index", static_cast<int>(diff.block_index));
            diff_obj.pushKV("field_index", static_cast<int>(diff.field_index));

            UniValue field_obj(UniValue::VOBJ);
            field_obj.pushKV("type", rung::DataTypeName(diff.new_field.type));
            field_obj.pushKV("size", static_cast<int>(diff.new_field.data.size()));
            field_obj.pushKV("hex", HexStr(diff.new_field.data));
            diff_obj.pushKV("field", field_obj);

            diffs_arr.push_back(diff_obj);
        }
        result.pushKV("diffs", diffs_arr);
        result.pushKV("coil", CoilToJSON(ladder.coil));
        return result;
    }

    // Normal witness mode
    if (!ladder.relays.empty()) {
        UniValue relays_arr(UniValue::VARR);
        for (size_t i = 0; i < ladder.relays.size(); ++i) {
            UniValue relay_obj(UniValue::VOBJ);
            relay_obj.pushKV("relay_index", static_cast<int>(i));
            relay_obj.pushKV("blocks", BlocksToJSON(ladder.relays[i].blocks));
            if (!ladder.relays[i].relay_refs.empty()) {
                relay_obj.pushKV("relay_refs", RelayRefsToJSON(ladder.relays[i].relay_refs));
            }
            relays_arr.push_back(relay_obj);
        }
        result.pushKV("relays", relays_arr);
    }

    UniValue rungs_arr(UniValue::VARR);
    for (size_t r = 0; r < ladder.rungs.size(); ++r) {
        UniValue rung_obj(UniValue::VOBJ);
        rung_obj.pushKV("rung_index", static_cast<int>(r));
        if (ladder.rungs[r].IsCompact()) {
            const auto& compact = *ladder.rungs[r].compact;
            rung_obj.pushKV("compact", true);
            if (compact.type == rung::CompactRungType::COMPACT_SIG) {
                rung_obj.pushKV("compact_type", "COMPACT_SIG");
                rung_obj.pushKV("pubkey_commit", HexStr(compact.pubkey_commit));
                switch (compact.scheme) {
                case RungScheme::SCHNORR:     rung_obj.pushKV("scheme", "SCHNORR"); break;
                case RungScheme::ECDSA:       rung_obj.pushKV("scheme", "ECDSA"); break;
                case RungScheme::FALCON512:   rung_obj.pushKV("scheme", "FALCON512"); break;
                case RungScheme::FALCON1024:  rung_obj.pushKV("scheme", "FALCON1024"); break;
                case RungScheme::DILITHIUM3:  rung_obj.pushKV("scheme", "DILITHIUM3"); break;
                case RungScheme::SPHINCS_SHA: rung_obj.pushKV("scheme", "SPHINCS_SHA"); break;
                default: rung_obj.pushKV("scheme", "UNKNOWN"); break;
                }
            }
        } else {
            rung_obj.pushKV("blocks", BlocksToJSON(ladder.rungs[r].blocks));
            if (!ladder.rungs[r].relay_refs.empty()) {
                rung_obj.pushKV("relay_refs", RelayRefsToJSON(ladder.rungs[r].relay_refs));
            }
        }
        rungs_arr.push_back(rung_obj);
    }
    result.pushKV("rungs", rungs_arr);
    result.pushKV("coil", CoilToJSON(ladder.coil));

    return result;
}

/** Parse a block type string to enum. Returns false on unknown type. */
static bool ParseBlockType(const std::string& name, RungBlockType& out)
{
    // Signature family
    if (name == "SIG")              { out = RungBlockType::SIG; return true; }
    if (name == "MULTISIG")         { out = RungBlockType::MULTISIG; return true; }
    if (name == "ADAPTOR_SIG")      { out = RungBlockType::ADAPTOR_SIG; return true; }
    if (name == "MUSIG_THRESHOLD")  { out = RungBlockType::MUSIG_THRESHOLD; return true; }
    if (name == "KEY_REF_SIG")      { out = RungBlockType::KEY_REF_SIG; return true; }
    // Timelock family
    if (name == "CSV")              { out = RungBlockType::CSV; return true; }
    if (name == "CSV_TIME")         { out = RungBlockType::CSV_TIME; return true; }
    if (name == "CLTV")             { out = RungBlockType::CLTV; return true; }
    if (name == "CLTV_TIME")        { out = RungBlockType::CLTV_TIME; return true; }
    // Hash family
    if (name == "HASH_PREIMAGE")    { out = RungBlockType::HASH_PREIMAGE; return true; }
    if (name == "HASH160_PREIMAGE") { out = RungBlockType::HASH160_PREIMAGE; return true; }
    if (name == "TAGGED_HASH")      { out = RungBlockType::TAGGED_HASH; return true; }
    // Compound family
    if (name == "TIMELOCKED_SIG")   { out = RungBlockType::TIMELOCKED_SIG; return true; }
    if (name == "HTLC")             { out = RungBlockType::HTLC; return true; }
    if (name == "HASH_SIG")         { out = RungBlockType::HASH_SIG; return true; }
    if (name == "PTLC")             { out = RungBlockType::PTLC; return true; }
    if (name == "CLTV_SIG")         { out = RungBlockType::CLTV_SIG; return true; }
    if (name == "TIMELOCKED_MULTISIG") { out = RungBlockType::TIMELOCKED_MULTISIG; return true; }
    // Covenant family
    if (name == "CTV")              { out = RungBlockType::CTV; return true; }
    if (name == "VAULT_LOCK")       { out = RungBlockType::VAULT_LOCK; return true; }
    if (name == "AMOUNT_LOCK")      { out = RungBlockType::AMOUNT_LOCK; return true; }
    // Anchor family
    if (name == "ANCHOR")           { out = RungBlockType::ANCHOR; return true; }
    if (name == "ANCHOR_CHANNEL")   { out = RungBlockType::ANCHOR_CHANNEL; return true; }
    if (name == "ANCHOR_POOL")      { out = RungBlockType::ANCHOR_POOL; return true; }
    if (name == "ANCHOR_RESERVE")   { out = RungBlockType::ANCHOR_RESERVE; return true; }
    if (name == "ANCHOR_SEAL")      { out = RungBlockType::ANCHOR_SEAL; return true; }
    if (name == "ANCHOR_ORACLE")    { out = RungBlockType::ANCHOR_ORACLE; return true; }
    // Governance family
    if (name == "EPOCH_GATE")       { out = RungBlockType::EPOCH_GATE; return true; }
    if (name == "WEIGHT_LIMIT")     { out = RungBlockType::WEIGHT_LIMIT; return true; }
    if (name == "INPUT_COUNT")      { out = RungBlockType::INPUT_COUNT; return true; }
    if (name == "OUTPUT_COUNT")     { out = RungBlockType::OUTPUT_COUNT; return true; }
    if (name == "RELATIVE_VALUE")   { out = RungBlockType::RELATIVE_VALUE; return true; }
    if (name == "ACCUMULATOR")      { out = RungBlockType::ACCUMULATOR; return true; }
    // Recursion family
    if (name == "RECURSE_SAME")     { out = RungBlockType::RECURSE_SAME; return true; }
    if (name == "RECURSE_MODIFIED") { out = RungBlockType::RECURSE_MODIFIED; return true; }
    if (name == "RECURSE_UNTIL")    { out = RungBlockType::RECURSE_UNTIL; return true; }
    if (name == "RECURSE_COUNT")    { out = RungBlockType::RECURSE_COUNT; return true; }
    if (name == "RECURSE_SPLIT")    { out = RungBlockType::RECURSE_SPLIT; return true; }
    if (name == "RECURSE_DECAY")    { out = RungBlockType::RECURSE_DECAY; return true; }
    // PLC family
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
    // Legacy family
    if (name == "P2PK_LEGACY")      { out = RungBlockType::P2PK_LEGACY; return true; }
    if (name == "P2PKH_LEGACY")     { out = RungBlockType::P2PKH_LEGACY; return true; }
    if (name == "P2SH_LEGACY")      { out = RungBlockType::P2SH_LEGACY; return true; }
    if (name == "P2WPKH_LEGACY")    { out = RungBlockType::P2WPKH_LEGACY; return true; }
    if (name == "P2WSH_LEGACY")     { out = RungBlockType::P2WSH_LEGACY; return true; }
    if (name == "P2TR_LEGACY")      { out = RungBlockType::P2TR_LEGACY; return true; }
    if (name == "P2TR_SCRIPT_LEGACY") { out = RungBlockType::P2TR_SCRIPT_LEGACY; return true; }
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
    if (name == "PUBKEY_COMMIT") {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Use PUBKEY instead of PUBKEY_COMMIT; the node computes the commitment automatically");
    }
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
        std::string hex_data = field_obj["hex"].get_str();
        field.data = ParseHex(hex_data);
        std::string reason;
        if (!field.IsValid(reason)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid field: " + reason);
        }
        // Auto-convert PUBKEY to PUBKEY_COMMIT in conditions (PUBKEY is witness-only)
        if (conditions_only && field.type == RungDataType::PUBKEY) {
            RungField commit_field;
            commit_field.type = RungDataType::PUBKEY_COMMIT;
            commit_field.data.resize(CSHA256::OUTPUT_SIZE);
            CSHA256().Write(field.data.data(), field.data.size()).Finalize(commit_field.data.data());
            block.fields.push_back(std::move(commit_field));
            continue;
        }
        if (conditions_only && !rung::IsConditionDataType(field.type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Data type " + ftype_str + " not allowed in conditions (witness-only)");
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
            {RPCResult::Type::NUM, "num_rungs", "Number of rungs (0 for diff witness)"},
            {RPCResult::Type::BOOL, "witness_ref", /*optional=*/ true, "True if this is a diff witness reference"},
            {RPCResult::Type::NUM, "source_input", /*optional=*/ true, "Source input index for diff witness"},
            {RPCResult::Type::ARR, "diffs", /*optional=*/ true, "Field-level diffs applied to source witness",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::NUM, "rung_index", "Target rung index"},
                        {RPCResult::Type::NUM, "block_index", "Target block index"},
                        {RPCResult::Type::NUM, "field_index", "Target field index"},
                        {RPCResult::Type::OBJ, "field", "Replacement field data",
                            {
                                {RPCResult::Type::STR, "type", "Data type name"},
                                {RPCResult::Type::NUM, "size", "Field data size"},
                                {RPCResult::Type::STR_HEX, "hex", "Field data hex"},
                            }},
                    }},
                }},
            {RPCResult::Type::ARR, "rungs", /*optional=*/ true, "The rungs (normal witness only)",
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
        "Validate a raw v4 RUNG_TX transaction's ladder witnesses.\n"
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
        result.pushKV("error", "Not a v4 RUNG_TX (version=" + std::to_string(tx.version) + ")");
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

/** Helper: parse relay_refs from a JSON array of integers. */
static std::vector<uint16_t> ParseRelayRefs(const UniValue& arr)
{
    std::vector<uint16_t> refs;
    for (size_t i = 0; i < arr.size(); ++i) {
        refs.push_back(static_cast<uint16_t>(arr[i].getInt<int>()));
    }
    return refs;
}

/** Helper: parse a conditions JSON spec into a RungConditions struct.
 *  rungs_arr is the array of rung specs; coil_obj is the optional coil spec (per-output).
 *  relays_arr is the optional relays array (top-level, shared across outputs). */
static RungConditions ParseConditionsSpec(const UniValue& rungs_arr,
                                          const UniValue& coil_obj = UniValue(),
                                          const UniValue& relays_arr = UniValue())
{
    RungConditions conditions;

    // Parse relays (if provided)
    if (!relays_arr.isNull() && relays_arr.isArray()) {
        for (size_t i = 0; i < relays_arr.size(); ++i) {
            const UniValue& relay_obj = relays_arr[i];
            Relay relay;

            const UniValue& blocks_arr = relay_obj["blocks"].get_array();
            for (size_t b = 0; b < blocks_arr.size(); ++b) {
                relay.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true));
            }

            if (relay_obj.exists("relay_refs")) {
                relay.relay_refs = ParseRelayRefs(relay_obj["relay_refs"].get_array());
            }

            conditions.relays.push_back(std::move(relay));
        }
    }

    for (size_t r = 0; r < rungs_arr.size(); ++r) {
        const UniValue& rung_obj = rungs_arr[r];
        Rung rung;

        // Compact rung: {"compact_type": "COMPACT_SIG", "pubkey": "hex", "scheme": "SCHNORR"}
        if (rung_obj.exists("compact_type")) {
            std::string ctype = rung_obj["compact_type"].get_str();
            if (ctype == "COMPACT_SIG") {
                CompactRungData compact;
                compact.type = CompactRungType::COMPACT_SIG;
                // Accept both "pubkey" (preferred) and "pubkey_commit" (backward compat)
                std::string pubkey_field = rung_obj.exists("pubkey") ? "pubkey" : "pubkey_commit";
                auto pubkey_bytes = ParseHex(rung_obj[pubkey_field].get_str());
                size_t pk_size = pubkey_bytes.size();
                // Validate pubkey size: 33 (compressed secp256k1), 32 (x-only Schnorr),
                // 897 (FALCON512), 1793 (FALCON1024), 1952 (DILITHIUM3), or >=32 (SPHINCS+/other PQ)
                if (pk_size == 33) {
                    // Compressed secp256k1: must start with 0x02 or 0x03
                    if (pubkey_bytes[0] != 0x02 && pubkey_bytes[0] != 0x03) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "33-byte pubkey must be compressed secp256k1 (prefix 0x02 or 0x03)");
                    }
                } else if (pk_size != 32 && pk_size != 897 && pk_size != 1793 &&
                           pk_size != 1952 && pk_size < 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "Invalid pubkey size " + std::to_string(pk_size) +
                        ". Expected: 32 (x-only), 33 (compressed), 897 (FALCON512), "
                        "1793 (FALCON1024), 1952 (DILITHIUM3), or 32+ (SPHINCS+)");
                }
                // Always compute SHA256(pubkey) — node never accepts raw commits
                compact.pubkey_commit.resize(CSHA256::OUTPUT_SIZE);
                CSHA256().Write(pubkey_bytes.data(), pubkey_bytes.size()).Finalize(compact.pubkey_commit.data());
                if (rung_obj.exists("scheme")) {
                    std::string scheme_str = rung_obj["scheme"].get_str();
                    if (scheme_str == "SCHNORR") compact.scheme = RungScheme::SCHNORR;
                    else if (scheme_str == "ECDSA") compact.scheme = RungScheme::ECDSA;
                    else if (scheme_str == "FALCON512") compact.scheme = RungScheme::FALCON512;
                    else if (scheme_str == "FALCON1024") compact.scheme = RungScheme::FALCON1024;
                    else if (scheme_str == "DILITHIUM3") compact.scheme = RungScheme::DILITHIUM3;
                    else if (scheme_str == "SPHINCS_SHA") compact.scheme = RungScheme::SPHINCS_SHA;
                    else throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown scheme: " + scheme_str);
                }
                rung.compact = std::move(compact);
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown compact_type: " + ctype);
            }
            conditions.rungs.push_back(std::move(rung));
            continue;
        }

        const UniValue& blocks_arr = rung_obj["blocks"].get_array();
        for (size_t b = 0; b < blocks_arr.size(); ++b) {
            rung.blocks.push_back(ParseBlockSpec(blocks_arr[b], /*conditions_only=*/true));
        }

        if (rung_obj.exists("relay_refs")) {
            rung.relay_refs = ParseRelayRefs(rung_obj["relay_refs"].get_array());
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
        "Create an unsigned v4 RUNG_TX transaction with rung condition outputs.\n"
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
                            {"mlsc", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Create MLSC output (0xC2 + Merkle root) instead of inline conditions"},
                        },
                    },
                },
            },
            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Transaction nLockTime (default 0). Set for CLTV spends."},
            {"relays", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Relay definitions (shared condition sets referenced by rung relay_refs)",
                {
                    {"relay", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A relay definition",
                        {
                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Block specs (same format as rung blocks)",
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
                            {"relay_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Indices of required relays (must be < own index)",
                                {{"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Relay index"}},
                            },
                        },
                    },
                },
            },
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

    // Optional relays (4th param) — shared across all outputs
    UniValue relays_val = !request.params[3].isNull() ? request.params[3] : UniValue();

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
        RungConditions conditions = ParseConditionsSpec(cond_arr, coil_val, relays_val);

        CTxOut txout;
        txout.nValue = amount;

        // MLSC: compute Merkle root and create 0xC2 output
        if (outp.exists("mlsc") && outp["mlsc"].get_bool()) {
            uint256 root = rung::ComputeConditionsRoot(conditions);
            txout.scriptPubKey = rung::CreateMLSCScript(root);
        } else {
            txout.scriptPubKey = rung::SerializeRungConditions(conditions);
        }
        mtx.vout.push_back(txout);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
    return result;
},
    };
}

/** Determine if a PQ scheme string is valid. Returns the scheme enum if so. */
static bool ParsePQScheme(const std::string& s, RungScheme& out)
{
    if (s == "FALCON512")  { out = RungScheme::FALCON512; return true; }
    if (s == "FALCON1024") { out = RungScheme::FALCON1024; return true; }
    if (s == "DILITHIUM3") { out = RungScheme::DILITHIUM3; return true; }
    if (s == "SPHINCS_SHA") { out = RungScheme::SPHINCS_SHA; return true; }
    return false;
}

/** Sign with PQ or Schnorr, routing based on block_spec fields.
 *  - If "pq_privkey" + "scheme" → PQ sign, push PUBKEY (if pq_pubkey given) + SIGNATURE.
 *  - If "privkey" → Schnorr sign, push PUBKEY + SIGNATURE.
 *  - If "scheme" is a PQ scheme but pq_privkey is missing → ERROR (prevents silent fallback).
 *  Returns true if signing was handled. */
static void SignSingleKey(const UniValue& block_spec,
                          RungBlock& block,
                          const CMutableTransaction& mtx,
                          unsigned int input_idx,
                          const PrecomputedTransactionData& txdata,
                          const RungConditions& conditions,
                          const char* block_name)
{
    // Check for PQ scheme
    if (block_spec.exists("scheme")) {
        std::string scheme_str = block_spec["scheme"].get_str();
        RungScheme scheme;
        if (ParsePQScheme(scheme_str, scheme)) {
            // PQ scheme declared — require pq_privkey
            if (!block_spec.exists("pq_privkey")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("%s: PQ scheme %s requires 'pq_privkey' (hex), not 'privkey' (WIF)", block_name, scheme_str));
            }
            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("%s: PQ signing requires liboqs support (not compiled in)", block_name));
            }

            auto pq_privkey = ParseHex(block_spec["pq_privkey"].get_str());
            if (pq_privkey.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: Empty pq_privkey", block_name));
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
            }

            // Push PQ pubkey for PUBKEY_COMMIT resolution
            if (block_spec.exists("pq_pubkey")) {
                auto pubkey_bytes = ParseHex(block_spec["pq_pubkey"].get_str());
                if (pubkey_bytes.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: Empty pq_pubkey", block_name));
                }
                block.fields.push_back({RungDataType::PUBKEY, std::move(pubkey_bytes)});
            }

            std::vector<uint8_t> pq_sig;
            std::span<const uint8_t> msg{sighash.begin(), 32};
            if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: PQ signing failed", block_name));
            }
            block.fields.push_back({RungDataType::SIGNATURE, std::move(pq_sig)});
            return;
        }
        // SCHNORR / ECDSA scheme strings fall through to classical path
    }

    // Classical Schnorr path
    if (!block_spec.exists("privkey")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: requires 'privkey' (WIF)", block_name));
    }
    std::string wif = block_spec["privkey"].get_str();
    CKey privkey = DecodeSecret(wif);
    if (!privkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s: Invalid private key", block_name));
    }

    uint256 sighash;
    if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
    }

    CPubKey pubkey = privkey.GetPubKey();
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});

    unsigned char sig_buf[64];
    uint256 aux_rand = GetRandHash();
    if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Schnorr signing failed", block_name));
    }
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
}

/** PQ-aware multi-key signing for MULTISIG and TIMELOCKED_MULTISIG.
 *  Routes to PQ if "scheme" + "pq_privkeys" present, else classical. */
static void SignMultiKey(const UniValue& block_spec,
                         RungBlock& block,
                         const CMutableTransaction& mtx,
                         unsigned int input_idx,
                         const PrecomputedTransactionData& txdata,
                         const RungConditions& conditions,
                         const char* block_name)
{
    // Check for PQ scheme
    if (block_spec.exists("scheme")) {
        std::string scheme_str = block_spec["scheme"].get_str();
        RungScheme scheme;
        if (ParsePQScheme(scheme_str, scheme)) {
            if (!block_spec.exists("pq_privkeys")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("%s: PQ scheme %s requires 'pq_privkeys' (hex array), not 'privkeys' (WIF array)", block_name, scheme_str));
            }
            if (!rung::HasPQSupport()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("%s: PQ signing requires liboqs support (not compiled in)", block_name));
            }

            const UniValue& pq_privkeys_arr = block_spec["pq_privkeys"].get_array();
            if (pq_privkeys_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: requires at least one pq_privkey", block_name));
            }

            uint256 sighash;
            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
            }

            // Include PQ PUBKEYs for PUBKEY_COMMIT resolution
            if (block_spec.exists("pq_pubkeys")) {
                const UniValue& pq_pubkeys_arr = block_spec["pq_pubkeys"].get_array();
                for (size_t p = 0; p < pq_pubkeys_arr.size(); ++p) {
                    auto pubkey_bytes = ParseHex(pq_pubkeys_arr[p].get_str());
                    block.fields.push_back({RungDataType::PUBKEY, std::move(pubkey_bytes)});
                }
            }

            std::span<const uint8_t> msg{sighash.begin(), 32};
            for (size_t s = 0; s < pq_privkeys_arr.size(); ++s) {
                auto pq_privkey = ParseHex(pq_privkeys_arr[s].get_str());
                std::vector<uint8_t> pq_sig;
                if (!rung::SignPQ(scheme, pq_privkey, msg, pq_sig)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: PQ signing failed for key %d", block_name, s));
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::move(pq_sig)});
            }
            return;
        }
    }

    // Classical path
    const UniValue& privkeys_arr = block_spec["privkeys"].get_array();
    if (privkeys_arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s: requires at least one privkey", block_name));
    }

    uint256 sighash;
    if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Failed to compute sighash", block_name));
    }

    for (size_t s = 0; s < privkeys_arr.size(); ++s) {
        CKey privkey = DecodeSecret(privkeys_arr[s].get_str());
        if (!privkey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s: Invalid private key at index %d", block_name, s));
        }

        CPubKey pubkey = privkey.GetPubKey();
        block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});

        unsigned char sig_buf[64];
        uint256 aux_rand = GetRandHash();
        if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s: Schnorr signing failed for key %d", block_name, s));
        }
        block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
    }
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
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "SIG");
        break;
    }
    case RungBlockType::MULTISIG: {
        SignMultiKey(block_spec, block, mtx, input_idx, txdata, conditions, "MULTISIG");
        break;
    }
    case RungBlockType::ADAPTOR_SIG: {
        // Adaptor signature: privkey + adaptor_secret → adapted Schnorr sig (no PQ support)
        if (block_spec.exists("scheme")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (ParsePQScheme(scheme_str, scheme)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ADAPTOR_SIG does not support PQ schemes (Schnorr-only)");
            }
        }
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
            // Include PUBKEY for PUBKEY_COMMIT resolution by evaluator
            CPubKey pubkey = privkey.GetPubKey();
            block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});
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
    case RungBlockType::MUSIG_THRESHOLD: {
        // MuSig2/FROST aggregate threshold: Schnorr-only (no PQ path).
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "MUSIG_THRESHOLD");
        break;
    }
    case RungBlockType::VAULT_LOCK: {
        // Vault lock: PQ or Schnorr signature
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "VAULT_LOCK");
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
    case RungBlockType::TIMELOCKED_SIG: {
        // Compound SIG + CSV: PQ or Schnorr sign, CSV timelock comes from conditions
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "TIMELOCKED_SIG");
        break;
    }
    case RungBlockType::HASH_SIG: {
        // Compound HASH_PREIMAGE + SIG: preimage + PQ/Schnorr sign
        std::string preimage_hex = block_spec["preimage"].get_str();
        auto preimage_data = ParseHex(preimage_hex);
        if (preimage_data.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HASH_SIG requires non-empty preimage hex");
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "HASH_SIG");
        break;
    }
    case RungBlockType::HTLC: {
        // Compound HASH_PREIMAGE + CSV + SIG: preimage + PQ/Schnorr sign, CSV from conditions
        std::string preimage_hex = block_spec["preimage"].get_str();
        auto preimage_data = ParseHex(preimage_hex);
        if (preimage_data.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "HTLC requires non-empty preimage hex");
        }
        block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "HTLC");
        break;
    }
    case RungBlockType::PTLC: {
        // Compound ADAPTOR_SIG + CSV: adaptor sign, CSV from conditions (no PQ support)
        if (block_spec.exists("scheme")) {
            std::string scheme_str = block_spec["scheme"].get_str();
            RungScheme scheme;
            if (ParsePQScheme(scheme_str, scheme)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PTLC does not support PQ schemes (Schnorr-only adaptor signatures)");
            }
        }
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
            // Include PUBKEY for PUBKEY_COMMIT resolution by evaluator
            CPubKey pubkey = privkey.GetPubKey();
            block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(pubkey.begin(), pubkey.end())});
            if (block_spec.exists("adaptor_secret")) {
                auto secret_bytes = ParseHex(block_spec["adaptor_secret"].get_str());
                if (secret_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "adaptor_secret must be 32 bytes hex");
                }
                std::vector<uint8_t> sig_out(64);
                if (!rung::CreateAdaptedSignature(privkey, sighash, secret_bytes, sig_out)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "PTLC adapted signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, sig_out});
            } else {
                unsigned char sig_buf[64];
                uint256 aux_rand = GetRandHash();
                if (!privkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "PTLC Schnorr signing failed");
                }
                block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(sig_buf, sig_buf + 64)});
            }
        }
        break;
    }
    case RungBlockType::CLTV_SIG: {
        // Compound SIG + CLTV: PQ or Schnorr sign, CLTV from conditions
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "CLTV_SIG");
        break;
    }
    case RungBlockType::TIMELOCKED_MULTISIG: {
        // Compound MULTISIG + CSV: PQ or Schnorr multi-sign, CSV from conditions
        SignMultiKey(block_spec, block, mtx, input_idx, txdata, conditions, "TIMELOCKED_MULTISIG");
        break;
    }
    case RungBlockType::KEY_REF_SIG: {
        // Sign using a key whose pubkey commitment lives in a relay block.
        // PQ or Schnorr, depending on scheme. Relay resolves SCHEME at evaluation time.
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "KEY_REF_SIG");
        break;
    }
    case RungBlockType::ACCUMULATOR: {
        // Merkle proof witness: array of HASH256 sibling hashes followed by leaf hash
        // The evaluator expects: conditions=[root], witness=[sibling_0..N, leaf]
        if (block_spec.exists("proof")) {
            const UniValue& proof_arr = block_spec["proof"].get_array();
            for (size_t i = 0; i < proof_arr.size(); ++i) {
                auto h = ParseHex(proof_arr[i].get_str());
                if (h.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "ACCUMULATOR proof hash at index " + std::to_string(i) + " must be exactly 32 bytes");
                }
                block.fields.push_back({RungDataType::HASH256, h});
            }
        }
        if (block_spec.exists("leaf")) {
            auto leaf = ParseHex(block_spec["leaf"].get_str());
            if (leaf.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "ACCUMULATOR leaf must be exactly 32 bytes");
            }
            block.fields.push_back({RungDataType::HASH256, leaf});
        }
        break;
    }
    case RungBlockType::P2PK_LEGACY:
    case RungBlockType::P2TR_LEGACY: {
        // Delegates to EvalSigBlock — same witness as SIG (PUBKEY + SIGNATURE)
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions,
                      btype == RungBlockType::P2PK_LEGACY ? "P2PK_LEGACY" : "P2TR_LEGACY");
        break;
    }
    case RungBlockType::P2PKH_LEGACY:
    case RungBlockType::P2WPKH_LEGACY: {
        // Witness: PUBKEY + SIGNATURE (evaluator checks HASH160(pubkey) == committed hash)
        SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions,
                      btype == RungBlockType::P2PKH_LEGACY ? "P2PKH_LEGACY" : "P2WPKH_LEGACY");
        break;
    }
    case RungBlockType::P2SH_LEGACY: {
        // Witness: PREIMAGE (serialized inner conditions) + inner witness fields
        // The preimage is the serialized Ladder conditions that hash to the committed HASH160.
        // Inner SIG witness fields (PUBKEY + SIGNATURE) are also needed.
        if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2SH_LEGACY requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        }
        if (block_spec.exists("privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "P2SH_LEGACY");
        }
        break;
    }
    case RungBlockType::P2WSH_LEGACY: {
        // Witness: PREIMAGE (serialized inner conditions) + inner witness fields
        // The preimage is the serialized Ladder conditions that hash to the committed SHA256.
        if (block_spec.exists("preimage")) {
            auto preimage_data = ParseHex(block_spec["preimage"].get_str());
            if (preimage_data.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "P2WSH_LEGACY requires non-empty preimage hex");
            }
            block.fields.push_back({RungDataType::PREIMAGE, preimage_data});
        }
        if (block_spec.exists("privkey")) {
            SignSingleKey(block_spec, block, mtx, input_idx, txdata, conditions, "P2WSH_LEGACY");
        }
        break;
    }
    default:
        // Covenant/governance/recursion/PLC blocks — no witness fields needed
        break;
    }

    return block;
}

static RPCHelpMan signrungtx()
{
    return RPCHelpMan{
        "signrungtx",
        "Sign a v4 RUNG_TX transaction's inputs.\n"
        "Supports two formats:\n"
        "  Legacy: [{\"privkey\":\"cVt...\",\"input\":0}] — single SIG block\n"
        "  Full:   [{\"input\":0,\"blocks\":[{\"type\":\"SIG\",\"privkey\":\"cVt...\"},...]}] — any block types\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The unsigned v4 transaction hex"},
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
                            {"relay_blocks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-relay signing specs (indexed same as conditions relays)",
                                {
                                    {"relay", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Relay signing spec (null/empty to skip)",
                                        {
                                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Block signing specs for this relay",
                                                {
                                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block spec",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                                            {"privkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF key for SIG"},
                                                            {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "WIF keys for MULTISIG",
                                                                {{"key", RPCArg::Type::STR, RPCArg::Optional::NO, "A WIF key"}},
                                                            },
                                                            {"preimage", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Preimage hex"},
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            {"conditions", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full conditions (required for MLSC inputs — conditions are not on-chain). Same format as createrungtx output conditions.",
                                {
                                    {"rung", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A rung spec",
                                        {
                                            {"blocks", RPCArg::Type::ARR, RPCArg::Optional::NO, "Block specs (same format as createrungtx)",
                                                {
                                                    {"block", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A block spec",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Block type"},
                                                            {"fields", RPCArg::Type::ARR, RPCArg::Optional::NO, "Field specs",
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
                            {"diff_witness", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Diff witness: inherit from another input's witness with field-level diffs",
                                {
                                    {"source_input", RPCArg::Type::NUM, RPCArg::Optional::NO, "Source input index to inherit witness from"},
                                    {"diffs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Field-level diffs to apply",
                                        {
                                            {"diff", RPCArg::Type::OBJ, RPCArg::Optional::NO, "A field diff",
                                                {
                                                    {"rung_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Target rung index"},
                                                    {"block_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Target block index"},
                                                    {"field_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Target field index"},
                                                    {"field", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Replacement field",
                                                        {
                                                            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "Data type (SIGNATURE, PUBKEY, PREIMAGE, SCHEME)"},
                                                            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Field data hex (raw replacement)"},
                                                            {"privkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "WIF key (auto-sign for SIGNATURE, auto-derive for PUBKEY)"},
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
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not v4 RUNG_TX");
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
        bool is_mlsc = rung::IsMLSCScript(spent_outputs[input_idx].scriptPubKey);
        bool has_conditions = false;

        if (is_mlsc) {
            // MLSC: conditions must be provided by the signer (not on-chain)
            if (!signer_obj.exists("conditions")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "MLSC input " + std::to_string(input_idx) +
                    " requires 'conditions' array (conditions are not on-chain)");
            }
            UniValue coil_val = signer_obj.exists("coil") ? signer_obj["coil"] : UniValue();
            UniValue relays_val2 = signer_obj.exists("relays") ? signer_obj["relays"] : UniValue();
            conditions = ParseConditionsSpec(signer_obj["conditions"].get_array(), coil_val, relays_val2);

            // Set the conditions_root from the spent output
            uint256 root;
            rung::GetMLSCRoot(spent_outputs[input_idx].scriptPubKey, root);
            conditions.conditions_root = root;
            has_conditions = true;
        } else {
            has_conditions = rung::DeserializeRungConditions(
                spent_outputs[input_idx].scriptPubKey, conditions, cond_error);
            if (!has_conditions) {
                conditions = RungConditions{};
            }
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
                unsigned int target_rung = 0;
                if (signer_obj.exists("rung")) {
                    target_rung = signer_obj["rung"].getInt<unsigned int>();
                }

                if (is_mlsc) {
                    // MLSC: build witness for only the target rung (1 rung in witness)
                    if (target_rung >= conditions.rungs.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "target rung " + std::to_string(target_rung) +
                            " out of range (conditions have " + std::to_string(conditions.rungs.size()) + " rungs)");
                    }

                    const auto& cond_target = conditions.rungs[target_rung];
                    if (cond_target.IsCompact()) {
                        // Compact rung: witness must provide exactly 1 SIG block
                        if (blocks_arr.size() != 1) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "compact SIG rung requires exactly 1 witness block, got " +
                                std::to_string(blocks_arr.size()));
                        }
                        Rung wit_rung;
                        wit_rung.blocks.push_back(
                            BuildWitnessBlock(blocks_arr[0], mtx, input_idx, txdata, conditions));
                        ladder.rungs.push_back(std::move(wit_rung));
                    } else {
                        if (blocks_arr.size() != cond_target.blocks.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "blocks count (" + std::to_string(blocks_arr.size()) +
                                ") must match conditions rung " + std::to_string(target_rung) +
                                " block count (" + std::to_string(cond_target.blocks.size()) + ")");
                        }
                        Rung wit_rung;
                        for (size_t b = 0; b < blocks_arr.size(); ++b) {
                            wit_rung.blocks.push_back(
                                BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                        }
                        ladder.rungs.push_back(std::move(wit_rung));
                    }
                } else {
                    // Legacy: build witness for all rungs (target gets real data, others get dummies)
                    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
                        Rung wit_rung;

                        if (r == target_rung) {
                            const auto& cond_r = conditions.rungs[r];
                            if (cond_r.IsCompact()) {
                                // Compact rung: witness must provide exactly 1 SIG block
                                if (blocks_arr.size() != 1) {
                                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                        "compact SIG rung requires exactly 1 witness block, got " +
                                        std::to_string(blocks_arr.size()));
                                }
                                wit_rung.blocks.push_back(
                                    BuildWitnessBlock(blocks_arr[0], mtx, input_idx, txdata, conditions));
                            } else {
                                if (blocks_arr.size() != cond_r.blocks.size()) {
                                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                        "blocks count (" + std::to_string(blocks_arr.size()) +
                                        ") must match conditions rung " + std::to_string(r) +
                                        " block count (" + std::to_string(cond_r.blocks.size()) + ")");
                                }
                                for (size_t b = 0; b < blocks_arr.size(); ++b) {
                                    wit_rung.blocks.push_back(
                                        BuildWitnessBlock(blocks_arr[b], mtx, input_idx, txdata, conditions));
                                }
                            }
                        } else {
                            const auto& cond_r = conditions.rungs[r];
                            if (cond_r.IsCompact()) {
                                // Compact dummy: 1 SIG block with empty fields
                                RungBlock dummy;
                                dummy.type = RungBlockType::SIG;
                                wit_rung.blocks.push_back(std::move(dummy));
                            } else {
                                // Normal dummy: correct types, empty fields
                                for (const auto& cond_block : cond_r.blocks) {
                                    RungBlock dummy;
                                    dummy.type = cond_block.type;
                                    wit_rung.blocks.push_back(std::move(dummy));
                                }
                            }
                        }
                        ladder.rungs.push_back(std::move(wit_rung));
                    }
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
        } else if (signer_obj.exists("diff_witness")) {
            // Diff witness mode: inherit from source input, apply diffs
            const UniValue& dw_obj = signer_obj["diff_witness"].get_obj();
            uint32_t source_input = dw_obj["source_input"].getInt<uint32_t>();

            WitnessReference ref;
            ref.input_index = source_input;

            if (dw_obj.exists("diffs")) {
                const UniValue& diffs_arr = dw_obj["diffs"].get_array();
                for (size_t d = 0; d < diffs_arr.size(); ++d) {
                    const UniValue& diff_obj = diffs_arr[d].get_obj();
                    WitnessDiff wd;
                    wd.rung_index = diff_obj["rung_index"].getInt<uint16_t>();
                    wd.block_index = diff_obj["block_index"].getInt<uint16_t>();
                    wd.field_index = diff_obj["field_index"].getInt<uint16_t>();

                    const UniValue& field_obj = diff_obj["field"].get_obj();
                    RungDataType dtype;
                    if (!ParseDataType(field_obj["type"].get_str(), dtype)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Unknown diff field type: " + field_obj["type"].get_str());
                    }

                    if (field_obj.exists("privkey")) {
                        CKey dkey = DecodeSecret(field_obj["privkey"].get_str());
                        if (!dkey.IsValid()) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                "Invalid diff privkey at diff " + std::to_string(d));
                        }
                        if (dtype == RungDataType::SIGNATURE) {
                            uint256 sighash;
                            if (!rung::SignatureHashLadder(txdata, mtx, input_idx, SIGHASH_DEFAULT, conditions, sighash)) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                    "Failed to compute sighash for diff witness input " + std::to_string(input_idx));
                            }
                            unsigned char sig_buf[64];
                            uint256 aux_rand = GetRandHash();
                            if (!dkey.SignSchnorr(sighash, sig_buf, nullptr, aux_rand)) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                    "Schnorr signing failed for diff witness input " + std::to_string(input_idx));
                            }
                            wd.new_field.type = RungDataType::SIGNATURE;
                            wd.new_field.data.assign(sig_buf, sig_buf + 64);
                        } else if (dtype == RungDataType::PUBKEY) {
                            CPubKey pub = dkey.GetPubKey();
                            wd.new_field.type = RungDataType::PUBKEY;
                            wd.new_field.data.assign(pub.begin(), pub.end());
                        } else {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "privkey auto-derive only supported for SIGNATURE and PUBKEY diff types");
                        }
                    } else if (field_obj.exists("hex")) {
                        wd.new_field.type = dtype;
                        wd.new_field.data = ParseHex(field_obj["hex"].get_str());
                    } else {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Diff field must have either 'hex' or 'privkey'");
                    }

                    ref.diffs.push_back(std::move(wd));
                }
            }

            ladder.witness_ref = std::move(ref);
            // Skip relay building — diff witnesses inherit relays from source
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Signer entry must have 'privkey' (legacy), 'blocks' (new format), or 'diff_witness'");
        }

        // Build relay witnesses if conditions have relays (skip for diff witness)
        if (!ladder.IsWitnessRef() && has_conditions && !conditions.relays.empty()) {
            if (signer_obj.exists("relay_blocks")) {
                const UniValue& relay_blocks_arr = signer_obj["relay_blocks"].get_array();
                if (relay_blocks_arr.size() != conditions.relays.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "relay_blocks count (" + std::to_string(relay_blocks_arr.size()) +
                        ") must match conditions relay count (" + std::to_string(conditions.relays.size()) + ")");
                }
                for (size_t rl = 0; rl < relay_blocks_arr.size(); ++rl) {
                    Relay wit_relay;
                    wit_relay.relay_refs = conditions.relays[rl].relay_refs;
                    const UniValue& relay_spec = relay_blocks_arr[rl];
                    if (relay_spec.isNull() || !relay_spec.exists("blocks")) {
                        // Dummy relay — correct types, empty fields
                        for (const auto& cond_block : conditions.relays[rl].blocks) {
                            RungBlock dummy;
                            dummy.type = cond_block.type;
                            wit_relay.blocks.push_back(std::move(dummy));
                        }
                    } else {
                        const UniValue& rb_arr = relay_spec["blocks"].get_array();
                        if (rb_arr.size() != conditions.relays[rl].blocks.size()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                "relay_blocks[" + std::to_string(rl) + "] block count (" +
                                std::to_string(rb_arr.size()) + ") must match conditions relay " +
                                std::to_string(rl) + " block count (" +
                                std::to_string(conditions.relays[rl].blocks.size()) + ")");
                        }
                        for (size_t b = 0; b < rb_arr.size(); ++b) {
                            wit_relay.blocks.push_back(
                                BuildWitnessBlock(rb_arr[b], mtx, input_idx, txdata, conditions));
                        }
                    }
                    ladder.relays.push_back(std::move(wit_relay));
                }
            } else {
                // No relay_blocks provided — build dummy relays for all
                for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
                    Relay wit_relay;
                    wit_relay.relay_refs = conditions.relays[rl].relay_refs;
                    for (const auto& cond_block : conditions.relays[rl].blocks) {
                        RungBlock dummy;
                        dummy.type = cond_block.type;
                        wit_relay.blocks.push_back(std::move(dummy));
                    }
                    ladder.relays.push_back(std::move(wit_relay));
                }
            }
            // Copy relay_refs from conditions to witness rungs
            for (size_t r = 0; r < ladder.rungs.size() && r < conditions.rungs.size(); ++r) {
                ladder.rungs[r].relay_refs = conditions.rungs[r].relay_refs;
            }
        }

        auto witness_bytes = rung::SerializeLadderWitness(ladder);
        mtx.vin[input_idx].scriptWitness.stack.clear();
        mtx.vin[input_idx].scriptWitness.stack.push_back(witness_bytes);

        // MLSC: build and push Merkle proof as stack[1]
        if (is_mlsc && has_conditions) {
            unsigned int target_rung = 0;
            if (signer_obj.exists("rung")) {
                target_rung = signer_obj["rung"].getInt<unsigned int>();
            }

            rung::MLSCProof mlsc_proof;
            mlsc_proof.total_rungs = static_cast<uint16_t>(conditions.rungs.size());
            mlsc_proof.total_relays = static_cast<uint16_t>(conditions.relays.size());
            mlsc_proof.rung_index = static_cast<uint16_t>(target_rung);
            mlsc_proof.revealed_rung = conditions.rungs[target_rung];

            // Reveal relays referenced by the target rung
            for (uint16_t ref : conditions.rungs[target_rung].relay_refs) {
                if (ref < conditions.relays.size()) {
                    mlsc_proof.revealed_relays.push_back({ref, conditions.relays[ref]});
                }
            }

            // Compute proof hashes for unrevealed leaves
            // Leaf order: [rung_leaf[0..N-1], relay_leaf[0..M-1], coil_leaf]
            std::set<uint16_t> revealed_relay_indices;
            for (const auto& [idx, _] : mlsc_proof.revealed_relays) {
                revealed_relay_indices.insert(idx);
            }

            for (uint16_t r = 0; r < conditions.rungs.size(); ++r) {
                if (r != target_rung) {
                    mlsc_proof.proof_hashes.push_back(rung::ComputeRungLeaf(conditions.rungs[r]));
                }
            }
            for (uint16_t rl = 0; rl < conditions.relays.size(); ++rl) {
                if (revealed_relay_indices.find(rl) == revealed_relay_indices.end()) {
                    mlsc_proof.proof_hashes.push_back(rung::ComputeRelayLeaf(conditions.relays[rl]));
                }
            }
            // Coil leaf is NOT a proof hash — it's computed from the witness coil

            auto proof_bytes = rung::SerializeMLSCProof(mlsc_proof);
            mtx.vin[input_idx].scriptWitness.stack.push_back(proof_bytes);
        }
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
        "Compute the BIP-119 CTV template hash for a v4 RUNG_TX transaction.\n"
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
        "Informational tool — createrungtx computes commitments automatically from pubkey fields.\n"
        "Use this to inspect what commitment a given key will produce.\n",
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
