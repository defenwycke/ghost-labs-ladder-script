// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/serialize.h>

#include <crypto/sha256.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>

namespace rung {

bool IsConditionDataType(RungDataType type)
{
    switch (type) {
    case RungDataType::PUBKEY_COMMIT:
    case RungDataType::HASH256:
    case RungDataType::HASH160:
    case RungDataType::NUMERIC:
    case RungDataType::SCHEME:
    case RungDataType::SPEND_INDEX:
        return true;
    case RungDataType::PUBKEY:
    case RungDataType::SIGNATURE:
    case RungDataType::PREIMAGE:
    case RungDataType::SCRIPT_BODY:
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

    // Strip the prefix byte
    std::vector<uint8_t> data(scriptPubKey.begin() + 1, scriptPubKey.end());

    if (data.empty()) {
        error = "empty conditions data";
        return false;
    }

    DataStream ss{data};

    try {
        uint64_t n_rungs = ReadCompactSize(ss);

        if (n_rungs == 0) {
            // Template mode: n_rungs==0 signals template inheritance
            uint64_t input_index = ReadCompactSize(ss);
            uint64_t n_diffs = ReadCompactSize(ss);

            if (n_diffs > MAX_FIELDS_PER_BLOCK * MAX_BLOCKS_PER_RUNG * MAX_RUNGS) {
                error = "too many template diffs: " + std::to_string(n_diffs);
                return false;
            }

            TemplateReference ref;
            ref.input_index = static_cast<uint32_t>(input_index);
            ref.diffs.resize(n_diffs);

            for (uint64_t d = 0; d < n_diffs; ++d) {
                ref.diffs[d].rung_index = static_cast<uint16_t>(ReadCompactSize(ss));
                ref.diffs[d].block_index = static_cast<uint16_t>(ReadCompactSize(ss));
                ref.diffs[d].field_index = static_cast<uint16_t>(ReadCompactSize(ss));

                // Read the replacement field: type + data
                uint8_t dtype_byte;
                ss >> dtype_byte;
                if (!IsKnownDataType(dtype_byte)) {
                    error = "unknown data type in template diff: 0x" +
                            HexStr(std::span<const uint8_t>{&dtype_byte, 1});
                    return false;
                }
                RungDataType dtype = static_cast<RungDataType>(dtype_byte);

                // Validate condition data type
                if (!IsConditionDataType(dtype)) {
                    error = "template diff contains witness-only data type: " + DataTypeName(dtype);
                    return false;
                }

                ref.diffs[d].new_field.type = dtype;
                if (dtype == RungDataType::NUMERIC) {
                    // Varint NUMERIC: values not sizes, skip range check
                    uint64_t val = ReadCompactSize(ss, false);
                    if (val > 0xFFFFFFFF) {
                        error = "NUMERIC value exceeds uint32 max in template diff";
                        return false;
                    }
                    // Always store as 4-byte LE for evaluator compatibility
                    ref.diffs[d].new_field.data.resize(4);
                    ref.diffs[d].new_field.data[0] = static_cast<uint8_t>(val & 0xFF);
                    ref.diffs[d].new_field.data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                    ref.diffs[d].new_field.data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                    ref.diffs[d].new_field.data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                } else {
                    uint64_t dlen = ReadCompactSize(ss);
                    size_t min_sz = FieldMinSize(dtype);
                    size_t max_sz = FieldMaxSize(dtype);
                    if (dlen < min_sz || dlen > max_sz) {
                        error = DataTypeName(dtype) + " size out of range in template diff";
                        return false;
                    }
                    ref.diffs[d].new_field.data.resize(dlen);
                    if (dlen > 0) {
                        ss.read(MakeWritableByteSpan(ref.diffs[d].new_field.data));
                    }
                }

                std::string field_reason;
                if (!ref.diffs[d].new_field.IsValid(field_reason)) {
                    error = "template diff field invalid: " + field_reason;
                    return false;
                }
            }

            // Reject trailing bytes
            if (!ss.empty()) {
                error = "trailing bytes in template reference";
                return false;
            }

            out.template_ref = std::move(ref);
            return true;
        }

        // Normal mode: deserialize via LadderWitness
        // Put n_rungs back by re-creating the data stream with the full data
        // (we already consumed n_rungs from ss, so just proceed with ss)
    } catch (const std::ios_base::failure& e) {
        error = std::string("template deserialization failure: ") + e.what();
        return false;
    }

    // Normal (non-template) path: use full LadderWitness deserialization
    LadderWitness ladder;
    if (!DeserializeLadderWitness(data, ladder, error, SerializationContext::CONDITIONS)) {
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

    // Validate relay blocks: no witness-only fields in conditions
    for (size_t i = 0; i < ladder.relays.size(); ++i) {
        for (const auto& block : ladder.relays[i].blocks) {
            for (const auto& field : block.fields) {
                if (!IsConditionDataType(field.type)) {
                    error = "relay " + std::to_string(i) + " contains witness-only data type: " + DataTypeName(field.type);
                    return false;
                }
            }
        }
    }

    out.rungs = std::move(ladder.rungs);
    out.coil = std::move(ladder.coil);
    out.relays = std::move(ladder.relays);
    return true;
}

CScript SerializeRungConditions(const RungConditions& conditions)
{
    CScript result;
    result.push_back(RUNG_CONDITIONS_PREFIX);

    if (conditions.IsTemplateRef()) {
        // Template mode: n_rungs=0 + input_index + diffs
        DataStream ss{};
        WriteCompactSize(ss, 0); // n_rungs = 0 signals template mode
        WriteCompactSize(ss, conditions.template_ref->input_index);
        WriteCompactSize(ss, conditions.template_ref->diffs.size());
        for (const auto& diff : conditions.template_ref->diffs) {
            WriteCompactSize(ss, diff.rung_index);
            WriteCompactSize(ss, diff.block_index);
            WriteCompactSize(ss, diff.field_index);
            // Write replacement field: type + data
            ss << static_cast<uint8_t>(diff.new_field.type);
            if (diff.new_field.type == RungDataType::NUMERIC) {
                uint32_t val = 0;
                for (size_t i = 0; i < diff.new_field.data.size(); ++i) {
                    val |= static_cast<uint32_t>(diff.new_field.data[i]) << (8 * i);
                }
                WriteCompactSize(ss, val);
            } else {
                WriteCompactSize(ss, diff.new_field.data.size());
                if (!diff.new_field.data.empty()) {
                    ss.write(MakeByteSpan(diff.new_field.data));
                }
            }
        }
        std::vector<uint8_t> bytes(ss.size());
        ss.read(MakeWritableByteSpan(bytes));
        result.insert(result.end(), bytes.begin(), bytes.end());
    } else {
        // Normal mode: serialize as ladder witness (CONDITIONS context)
        LadderWitness ladder;
        ladder.rungs = conditions.rungs;
        ladder.coil = conditions.coil;
        ladder.relays = conditions.relays;
        auto bytes = SerializeLadderWitness(ladder, SerializationContext::CONDITIONS);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }

    return result;
}

bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error)
{
    if (!conditions.IsTemplateRef()) {
        error = "conditions do not have a template reference";
        return false;
    }

    const auto& ref = *conditions.template_ref;

    if (ref.input_index >= all_conditions.size()) {
        error = "template reference input_index out of range: " +
                std::to_string(ref.input_index) + " >= " +
                std::to_string(all_conditions.size());
        return false;
    }

    const auto& source = all_conditions[ref.input_index];

    // Source must not itself be a template reference (no chaining)
    if (source.IsTemplateRef()) {
        error = "template reference points to another template reference";
        return false;
    }

    // Copy conditions from source
    conditions.rungs = source.rungs;
    conditions.coil = source.coil;
    conditions.relays = source.relays;

    // Apply diffs
    for (const auto& diff : ref.diffs) {
        if (diff.rung_index >= conditions.rungs.size()) {
            error = "template diff rung_index out of range: " +
                    std::to_string(diff.rung_index);
            return false;
        }
        auto& rung = conditions.rungs[diff.rung_index];
        if (diff.block_index >= rung.blocks.size()) {
            error = "template diff block_index out of range: " +
                    std::to_string(diff.block_index);
            return false;
        }
        auto& block = rung.blocks[diff.block_index];
        if (diff.field_index >= block.fields.size()) {
            error = "template diff field_index out of range: " +
                    std::to_string(diff.field_index);
            return false;
        }

        // Replace the field (type must match for safety)
        if (block.fields[diff.field_index].type != diff.new_field.type) {
            error = "template diff type mismatch at rung " +
                    std::to_string(diff.rung_index) + " block " +
                    std::to_string(diff.block_index) + " field " +
                    std::to_string(diff.field_index) + ": expected " +
                    DataTypeName(block.fields[diff.field_index].type) +
                    ", got " + DataTypeName(diff.new_field.type);
            return false;
        }
        block.fields[diff.field_index] = diff.new_field;
    }

    // Clear template reference — conditions are now fully resolved
    conditions.template_ref.reset();
    return true;
}

// ============================================================================
// MLSC (Merkelized Ladder Script Conditions)
// ============================================================================

/**
 * BIP-341-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
 * The double-tag prefix provides domain separation — a hash computed with
 * one tag can never collide with a hash computed with a different tag,
 * preventing second-preimage attacks between leaf and internal nodes.
 */
static uint256 TaggedHash(const char* tag, const unsigned char* data, size_t len)
{
    // Compute SHA256(tag)
    unsigned char tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), strlen(tag)).Finalize(tag_hash);

    // SHA256(SHA256(tag) || SHA256(tag) || data)
    CSHA256 hasher;
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(data, len);
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Pre-computed tagged hashers for leaf and internal node domains (BIP-341 pattern). */
static CSHA256 InitTaggedHasher(const char* tag)
{
    unsigned char tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), strlen(tag)).Finalize(tag_hash);
    CSHA256 hasher;
    hasher.Write(tag_hash, sizeof(tag_hash));
    hasher.Write(tag_hash, sizeof(tag_hash));
    return hasher;
}

static const CSHA256 LEAF_HASHER = InitTaggedHasher("LadderLeaf");
static const CSHA256 INTERNAL_HASHER = InitTaggedHasher("LadderInternal");

/** Compute MLSC_EMPTY_LEAF = TaggedHash("LadderLeaf", "") at startup. */
static uint256 ComputeEmptyLeaf()
{
    return TaggedHash("LadderLeaf", nullptr, 0);
}

const uint256 MLSC_EMPTY_LEAF = ComputeEmptyLeaf();

bool IsMLSCScript(const CScript& scriptPubKey)
{
    return scriptPubKey.size() == 33 && scriptPubKey[0] == RUNG_MLSC_PREFIX;
}

bool IsLadderScript(const CScript& scriptPubKey)
{
    return IsRungConditionsScript(scriptPubKey) || IsMLSCScript(scriptPubKey);
}

bool GetMLSCRoot(const CScript& scriptPubKey, uint256& root_out)
{
    if (!IsMLSCScript(scriptPubKey)) return false;
    memcpy(root_out.data(), scriptPubKey.data() + 1, 32);
    return true;
}

CScript CreateMLSCScript(const uint256& conditions_root)
{
    CScript result;
    result.push_back(RUNG_MLSC_PREFIX);
    result.insert(result.end(), conditions_root.begin(), conditions_root.end());
    return result;
}

uint256 ComputeRungLeaf(const Rung& rung)
{
    auto bytes = SerializeRungBlocks(rung, SerializationContext::CONDITIONS);
    CSHA256 hasher = LEAF_HASHER; // copy pre-computed prefix
    hasher.Write(bytes.data(), bytes.size());
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeCoilLeaf(const RungCoil& coil)
{
    auto bytes = SerializeCoilData(coil);
    CSHA256 hasher = LEAF_HASHER;
    hasher.Write(bytes.data(), bytes.size());
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

uint256 ComputeRelayLeaf(const Relay& relay)
{
    auto bytes = SerializeRelayBlocks(relay, SerializationContext::CONDITIONS);
    CSHA256 hasher = LEAF_HASHER;
    hasher.Write(bytes.data(), bytes.size());
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Compute a sorted interior Merkle node: TaggedHash("LadderInternal", min(a,b) || max(a,b)). */
static uint256 MerkleInterior(const uint256& a, const uint256& b)
{
    unsigned char children[32 + 32];
    if (memcmp(a.data(), b.data(), 32) <= 0) {
        memcpy(children, a.data(), 32);
        memcpy(children + 32, b.data(), 32);
    } else {
        memcpy(children, b.data(), 32);
        memcpy(children + 32, a.data(), 32);
    }
    CSHA256 hasher = INTERNAL_HASHER; // copy pre-computed prefix
    hasher.Write(children, sizeof(children));
    uint256 result;
    hasher.Finalize(result.data());
    return result;
}

/** Next power of 2 >= n (for n > 0). */
static size_t NextPowerOf2(size_t n)
{
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

uint256 BuildMerkleTree(std::vector<uint256> leaves)
{
    if (leaves.empty()) return MLSC_EMPTY_LEAF;
    if (leaves.size() == 1) return leaves[0];

    // Pad to next power of 2
    size_t padded = NextPowerOf2(leaves.size());
    while (leaves.size() < padded) {
        leaves.push_back(MLSC_EMPTY_LEAF);
    }

    // Build tree bottom-up
    while (leaves.size() > 1) {
        std::vector<uint256> parents;
        parents.reserve(leaves.size() / 2);
        for (size_t i = 0; i < leaves.size(); i += 2) {
            parents.push_back(MerkleInterior(leaves[i], leaves[i + 1]));
        }
        leaves = std::move(parents);
    }

    return leaves[0];
}

uint256 ComputeConditionsRoot(const RungConditions& conditions)
{
    // Leaf order: [rung_leaf[0..N-1], relay_leaf[0..M-1], coil_leaf]
    std::vector<uint256> leaves;
    leaves.reserve(conditions.rungs.size() + conditions.relays.size() + 1);

    for (const auto& rung : conditions.rungs) {
        leaves.push_back(ComputeRungLeaf(rung));
    }
    for (const auto& relay : conditions.relays) {
        leaves.push_back(ComputeRelayLeaf(relay));
    }
    leaves.push_back(ComputeCoilLeaf(conditions.coil));

    return BuildMerkleTree(leaves);
}

bool DeserializeMLSCProof(const std::vector<uint8_t>& data, MLSCProof& proof, std::string& error)
{
    if (data.empty()) {
        error = "empty MLSC proof";
        return false;
    }

    DataStream ss{data};

    try {
        uint64_t total_rungs = ReadCompactSize(ss);
        uint64_t total_relays = ReadCompactSize(ss);
        uint64_t rung_index = ReadCompactSize(ss);

        if (total_rungs == 0 || total_rungs > MAX_RUNGS) {
            error = "MLSC proof total_rungs out of range: " + std::to_string(total_rungs);
            return false;
        }
        if (total_relays > MAX_RELAYS) {
            error = "MLSC proof total_relays out of range: " + std::to_string(total_relays);
            return false;
        }
        if (rung_index >= total_rungs) {
            error = "MLSC proof rung_index out of range: " + std::to_string(rung_index) +
                    " >= " + std::to_string(total_rungs);
            return false;
        }

        proof.total_rungs = static_cast<uint16_t>(total_rungs);
        proof.total_relays = static_cast<uint16_t>(total_relays);
        proof.rung_index = static_cast<uint16_t>(rung_index);

        // Deserialize revealed rung condition blocks
        uint64_t n_blocks = ReadCompactSize(ss);
        if (n_blocks > MAX_BLOCKS_PER_RUNG) {
            error = "MLSC proof rung block count invalid: " + std::to_string(n_blocks);
            return false;
        }

        uint8_t cond_ctx = static_cast<uint8_t>(SerializationContext::CONDITIONS);

        if (n_blocks == 0) {
            // Compact rung: n_blocks == 0 signals compact encoding
            uint8_t compact_type_byte;
            ss >> compact_type_byte;
            if (!IsKnownCompactRungType(compact_type_byte)) {
                error = "MLSC proof unknown compact type: 0x" +
                        HexStr(std::span<const uint8_t>{&compact_type_byte, 1});
                return false;
            }
            CompactRungData compact;
            compact.type = static_cast<CompactRungType>(compact_type_byte);
            if (compact.type == CompactRungType::COMPACT_SIG) {
                compact.pubkey_commit.resize(32);
                ss.read(MakeWritableByteSpan(compact.pubkey_commit));
                uint8_t scheme_byte;
                ss >> scheme_byte;
                if (!IsKnownScheme(scheme_byte)) {
                    error = "MLSC proof compact SIG unknown scheme";
                    return false;
                }
                compact.scheme = static_cast<RungScheme>(scheme_byte);
            }
            proof.revealed_rung.compact = std::move(compact);
        } else {
            // Normal rung: deserialize blocks
            proof.revealed_rung.blocks.resize(n_blocks);
            for (uint64_t b = 0; b < n_blocks; ++b) {
                uint8_t first_byte;
                ss >> first_byte;

                RungBlock& block = proof.revealed_rung.blocks[b];

                if (first_byte < MICRO_HEADER_ESCAPE) {
                    if (MICRO_HEADER_TABLE[first_byte] == 0xFFFF) {
                        error = "MLSC proof: unused micro-header slot";
                        return false;
                    }
                    uint16_t btype = MICRO_HEADER_TABLE[first_byte];
                    if (!IsKnownBlockType(btype)) {
                        error = "MLSC proof: unknown block type from micro-header";
                        return false;
                    }
                    block.type = static_cast<RungBlockType>(btype);
                    block.inverted = false;

                    // Check for implicit layout
                    const auto& layout = GetImplicitLayout(block.type, cond_ctx);
                    if (layout.count > 0) {
                        block.fields.resize(layout.count);
                        for (uint8_t fi = 0; fi < layout.count; ++fi) {
                            block.fields[fi].type = layout.fields[fi].type;
                            if (layout.fields[fi].type == RungDataType::NUMERIC) {
                                uint64_t val = ReadCompactSize(ss, false);
                                if (val > 0xFFFFFFFF) { error = "NUMERIC overflow in MLSC proof"; return false; }
                                block.fields[fi].data.resize(4);
                                block.fields[fi].data[0] = static_cast<uint8_t>(val & 0xFF);
                                block.fields[fi].data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                                block.fields[fi].data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                                block.fields[fi].data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                            } else if (layout.fields[fi].fixed_size > 0) {
                                block.fields[fi].data.resize(layout.fields[fi].fixed_size);
                                ss.read(MakeWritableByteSpan(block.fields[fi].data));
                            } else {
                                uint64_t dlen = ReadCompactSize(ss);
                                if (dlen < FieldMinSize(layout.fields[fi].type) ||
                                    dlen > FieldMaxSize(layout.fields[fi].type)) {
                                    error = "MLSC proof field size out of range";
                                    return false;
                                }
                                block.fields[fi].data.resize(dlen);
                                if (dlen > 0) ss.read(MakeWritableByteSpan(block.fields[fi].data));
                            }
                        }
                    } else {
                        // No implicit layout — read explicit fields
                        uint64_t nf = ReadCompactSize(ss);
                        if (nf > MAX_FIELDS_PER_BLOCK) { error = "MLSC proof too many fields"; return false; }
                        block.fields.resize(nf);
                        for (uint64_t fi = 0; fi < nf; ++fi) {
                            uint8_t dtype;
                            ss >> dtype;
                            if (!IsKnownDataType(dtype)) { error = "MLSC proof unknown data type"; return false; }
                            block.fields[fi].type = static_cast<RungDataType>(dtype);
                            if (block.fields[fi].type == RungDataType::NUMERIC) {
                                uint64_t val = ReadCompactSize(ss, false);
                                if (val > 0xFFFFFFFF) { error = "NUMERIC overflow"; return false; }
                                block.fields[fi].data.resize(4);
                                block.fields[fi].data[0] = static_cast<uint8_t>(val & 0xFF);
                                block.fields[fi].data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                                block.fields[fi].data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                                block.fields[fi].data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                            } else {
                                uint64_t dlen = ReadCompactSize(ss);
                                if (dlen < FieldMinSize(block.fields[fi].type) ||
                                    dlen > FieldMaxSize(block.fields[fi].type)) {
                                    error = "MLSC proof explicit field size out of range";
                                    return false;
                                }
                                block.fields[fi].data.resize(dlen);
                                if (dlen > 0) ss.read(MakeWritableByteSpan(block.fields[fi].data));
                            }
                        }
                    }
                } else if (first_byte == MICRO_HEADER_ESCAPE || first_byte == MICRO_HEADER_ESCAPE_INV) {
                    uint8_t lo, hi;
                    ss >> lo >> hi;
                    uint16_t btype = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
                    if (!IsKnownBlockType(btype)) { error = "MLSC proof unknown block type"; return false; }
                    block.type = static_cast<RungBlockType>(btype);
                    block.inverted = (first_byte == MICRO_HEADER_ESCAPE_INV);

                    uint64_t nf = ReadCompactSize(ss);
                    if (nf > MAX_FIELDS_PER_BLOCK) { error = "MLSC proof too many fields"; return false; }
                    block.fields.resize(nf);
                    for (uint64_t fi = 0; fi < nf; ++fi) {
                        uint8_t dtype;
                        ss >> dtype;
                        if (!IsKnownDataType(dtype)) { error = "MLSC proof unknown data type"; return false; }
                        block.fields[fi].type = static_cast<RungDataType>(dtype);
                        if (block.fields[fi].type == RungDataType::NUMERIC) {
                            uint64_t val = ReadCompactSize(ss, false);
                            if (val > 0xFFFFFFFF) { error = "NUMERIC overflow"; return false; }
                            block.fields[fi].data.resize(4);
                            block.fields[fi].data[0] = static_cast<uint8_t>(val & 0xFF);
                            block.fields[fi].data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                            block.fields[fi].data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                            block.fields[fi].data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                        } else {
                            uint64_t dlen = ReadCompactSize(ss);
                            if (dlen < FieldMinSize(block.fields[fi].type) ||
                                dlen > FieldMaxSize(block.fields[fi].type)) {
                                error = "MLSC proof escape field size out of range";
                                return false;
                            }
                            block.fields[fi].data.resize(dlen);
                            if (dlen > 0) ss.read(MakeWritableByteSpan(block.fields[fi].data));
                        }
                    }
                } else {
                    error = "MLSC proof invalid header byte";
                    return false;
                }

                // Validate condition fields only
                for (const auto& field : block.fields) {
                    if (!IsConditionDataType(field.type)) {
                        error = "MLSC proof contains witness-only field: " + DataTypeName(field.type);
                        return false;
                    }
                    std::string field_reason;
                    if (!field.IsValid(field_reason)) {
                        error = "MLSC proof invalid field: " + field_reason;
                        return false;
                    }
                }
            }
        }

        // Read rung relay_refs
        uint64_t n_rung_refs = ReadCompactSize(ss);
        if (n_rung_refs > MAX_REQUIRES) {
            error = "MLSC proof too many rung relay_refs";
            return false;
        }
        proof.revealed_rung.relay_refs.resize(n_rung_refs);
        for (uint64_t ri = 0; ri < n_rung_refs; ++ri) {
            proof.revealed_rung.relay_refs[ri] = static_cast<uint16_t>(ReadCompactSize(ss));
        }

        // Read revealed relays
        uint64_t n_revealed = ReadCompactSize(ss);
        if (n_revealed > total_relays) {
            error = "MLSC proof more revealed relays than total";
            return false;
        }
        proof.revealed_relays.resize(n_revealed);
        for (uint64_t rl = 0; rl < n_revealed; ++rl) {
            uint64_t relay_idx = ReadCompactSize(ss);
            if (relay_idx >= total_relays) {
                error = "MLSC proof relay index out of range";
                return false;
            }
            proof.revealed_relays[rl].first = static_cast<uint16_t>(relay_idx);

            // Read relay blocks (same format as rung blocks above)
            uint64_t rnb = ReadCompactSize(ss);
            if (rnb == 0 || rnb > MAX_BLOCKS_PER_RUNG) {
                error = "MLSC proof relay block count invalid";
                return false;
            }
            Relay& relay = proof.revealed_relays[rl].second;
            relay.blocks.resize(rnb);

            // Simplified: use explicit format for relay blocks to avoid code duplication
            for (uint64_t rb = 0; rb < rnb; ++rb) {
                uint8_t fb;
                ss >> fb;
                RungBlock& rblock = relay.blocks[rb];

                if (fb < MICRO_HEADER_ESCAPE) {
                    if (MICRO_HEADER_TABLE[fb] == 0xFFFF) { error = "MLSC proof relay: unused micro-header"; return false; }
                    uint16_t bt = MICRO_HEADER_TABLE[fb];
                    if (!IsKnownBlockType(bt)) { error = "MLSC proof relay: unknown block type"; return false; }
                    rblock.type = static_cast<RungBlockType>(bt);
                    rblock.inverted = false;
                } else if (fb == MICRO_HEADER_ESCAPE || fb == MICRO_HEADER_ESCAPE_INV) {
                    uint8_t lo2, hi2;
                    ss >> lo2 >> hi2;
                    uint16_t bt = static_cast<uint16_t>(lo2) | (static_cast<uint16_t>(hi2) << 8);
                    if (!IsKnownBlockType(bt)) { error = "MLSC proof relay: unknown block type"; return false; }
                    rblock.type = static_cast<RungBlockType>(bt);
                    rblock.inverted = (fb == MICRO_HEADER_ESCAPE_INV);
                } else {
                    error = "MLSC proof relay: invalid header byte";
                    return false;
                }

                // For relay blocks, always use explicit field format
                const auto& layout = GetImplicitLayout(rblock.type, cond_ctx);
                if (layout.count > 0 && fb < MICRO_HEADER_ESCAPE) {
                    rblock.fields.resize(layout.count);
                    for (uint8_t fi = 0; fi < layout.count; ++fi) {
                        rblock.fields[fi].type = layout.fields[fi].type;
                        if (layout.fields[fi].type == RungDataType::NUMERIC) {
                            uint64_t val = ReadCompactSize(ss, false);
                            if (val > 0xFFFFFFFF) { error = "NUMERIC overflow in relay"; return false; }
                            rblock.fields[fi].data.resize(4);
                            rblock.fields[fi].data[0] = static_cast<uint8_t>(val & 0xFF);
                            rblock.fields[fi].data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                            rblock.fields[fi].data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                            rblock.fields[fi].data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                        } else if (layout.fields[fi].fixed_size > 0) {
                            rblock.fields[fi].data.resize(layout.fields[fi].fixed_size);
                            ss.read(MakeWritableByteSpan(rblock.fields[fi].data));
                        } else {
                            uint64_t dlen = ReadCompactSize(ss);
                            if (dlen < FieldMinSize(layout.fields[fi].type) ||
                                dlen > FieldMaxSize(layout.fields[fi].type)) {
                                error = "MLSC proof relay field size out of range";
                                return false;
                            }
                            rblock.fields[fi].data.resize(dlen);
                            if (dlen > 0) ss.read(MakeWritableByteSpan(rblock.fields[fi].data));
                        }
                    }
                } else {
                    uint64_t nf = ReadCompactSize(ss);
                    if (nf > MAX_FIELDS_PER_BLOCK) { error = "MLSC proof relay too many fields"; return false; }
                    rblock.fields.resize(nf);
                    for (uint64_t fi = 0; fi < nf; ++fi) {
                        uint8_t dtype;
                        ss >> dtype;
                        if (!IsKnownDataType(dtype)) { error = "MLSC proof relay unknown dtype"; return false; }
                        rblock.fields[fi].type = static_cast<RungDataType>(dtype);
                        if (rblock.fields[fi].type == RungDataType::NUMERIC) {
                            uint64_t val = ReadCompactSize(ss, false);
                            if (val > 0xFFFFFFFF) { error = "NUMERIC overflow"; return false; }
                            rblock.fields[fi].data.resize(4);
                            rblock.fields[fi].data[0] = static_cast<uint8_t>(val & 0xFF);
                            rblock.fields[fi].data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
                            rblock.fields[fi].data[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
                            rblock.fields[fi].data[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
                        } else {
                            uint64_t dlen = ReadCompactSize(ss);
                            if (dlen < FieldMinSize(rblock.fields[fi].type) ||
                                dlen > FieldMaxSize(rblock.fields[fi].type)) {
                                error = "MLSC proof relay explicit field size out of range";
                                return false;
                            }
                            rblock.fields[fi].data.resize(dlen);
                            if (dlen > 0) ss.read(MakeWritableByteSpan(rblock.fields[fi].data));
                        }
                    }
                }
            }

            // Read relay relay_refs
            uint64_t n_rrefs = ReadCompactSize(ss);
            if (n_rrefs > MAX_REQUIRES) {
                error = "MLSC proof relay too many relay_refs";
                return false;
            }
            relay.relay_refs.resize(n_rrefs);
            for (uint64_t rri = 0; rri < n_rrefs; ++rri) {
                relay.relay_refs[rri] = static_cast<uint16_t>(ReadCompactSize(ss));
            }
        }

        // Read proof hashes (unrevealed leaf hashes)
        uint64_t n_proofs = ReadCompactSize(ss);
        // Max possible unrevealed leaves: total_rungs - 1 + total_relays - revealed_relays
        size_t max_proofs = (total_rungs - 1) + (total_relays - n_revealed);
        if (n_proofs > max_proofs) {
            error = "MLSC proof too many proof hashes: " + std::to_string(n_proofs) +
                    " > " + std::to_string(max_proofs);
            return false;
        }
        proof.proof_hashes.resize(n_proofs);
        for (uint64_t ph = 0; ph < n_proofs; ++ph) {
            ss.read(MakeWritableByteSpan(proof.proof_hashes[ph]));
        }

        if (!ss.empty()) {
            error = "trailing bytes in MLSC proof";
            return false;
        }

    } catch (const std::ios_base::failure& e) {
        error = std::string("MLSC proof deserialization failure: ") + e.what();
        return false;
    }

    return true;
}

std::vector<uint8_t> SerializeMLSCProof(const MLSCProof& proof)
{
    DataStream ss{};

    WriteCompactSize(ss, proof.total_rungs);
    WriteCompactSize(ss, proof.total_relays);
    WriteCompactSize(ss, proof.rung_index);

    // Serialize revealed rung blocks using existing block serialization
    auto rung_bytes = SerializeRungBlocks(proof.revealed_rung, SerializationContext::CONDITIONS);
    ss.write(MakeByteSpan(rung_bytes));

    // Serialize revealed relays
    WriteCompactSize(ss, proof.revealed_relays.size());
    for (const auto& [relay_idx, relay] : proof.revealed_relays) {
        WriteCompactSize(ss, relay_idx);
        auto relay_bytes = SerializeRelayBlocks(relay, SerializationContext::CONDITIONS);
        ss.write(MakeByteSpan(relay_bytes));
    }

    // Serialize proof hashes
    WriteCompactSize(ss, proof.proof_hashes.size());
    for (const auto& hash : proof.proof_hashes) {
        ss.write(MakeByteSpan(hash));
    }

    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     std::string& error)
{
    // Total leaves: total_rungs + total_relays + 1 (coil)
    size_t total_leaves = proof.total_rungs + proof.total_relays + 1;

    // Build the leaf array
    std::vector<uint256> leaves(total_leaves);

    // Track which leaves are revealed vs proof
    std::vector<bool> revealed(total_leaves, false);

    // Rung leaf: the revealed rung goes at rung_index
    leaves[proof.rung_index] = ComputeRungLeaf(proof.revealed_rung);
    revealed[proof.rung_index] = true;

    // Revealed relay leaves: relays start at index total_rungs
    for (const auto& [relay_idx, relay] : proof.revealed_relays) {
        size_t leaf_idx = proof.total_rungs + relay_idx;
        if (leaf_idx >= total_leaves - 1) { // -1 because last leaf is coil
            error = "revealed relay index out of range";
            return false;
        }
        leaves[leaf_idx] = ComputeRelayLeaf(relay);
        revealed[leaf_idx] = true;
    }

    // Coil leaf: always last
    leaves[total_leaves - 1] = ComputeCoilLeaf(coil);
    revealed[total_leaves - 1] = true;

    // Fill unrevealed leaves with proof hashes (in order)
    size_t proof_idx = 0;
    for (size_t i = 0; i < total_leaves; ++i) {
        if (!revealed[i]) {
            if (proof_idx >= proof.proof_hashes.size()) {
                error = "not enough proof hashes: need hash for leaf " + std::to_string(i);
                return false;
            }
            leaves[i] = proof.proof_hashes[proof_idx++];
        }
    }

    if (proof_idx != proof.proof_hashes.size()) {
        error = "excess proof hashes: used " + std::to_string(proof_idx) +
                " of " + std::to_string(proof.proof_hashes.size());
        return false;
    }

    // Build Merkle tree and compare
    uint256 computed_root = BuildMerkleTree(std::move(leaves));
    if (computed_root != expected_root) {
        error = "MLSC Merkle root mismatch";
        return false;
    }

    return true;
}

} // namespace rung
