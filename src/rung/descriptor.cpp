// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/descriptor.h>

#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace rung {

// ============================================================================
// Parser internals
// ============================================================================

namespace {

struct ParseContext {
    const std::string& desc;
    const std::map<std::string, std::vector<uint8_t>>& keys;
    size_t pos{0};
    std::string error;
};

void SkipWhitespace(ParseContext& ctx)
{
    while (ctx.pos < ctx.desc.size() && std::isspace(ctx.desc[ctx.pos])) {
        ++ctx.pos;
    }
}

bool Expect(ParseContext& ctx, char c)
{
    SkipWhitespace(ctx);
    if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] != c) {
        ctx.error = std::string("expected '") + c + "' at position " + std::to_string(ctx.pos);
        return false;
    }
    ++ctx.pos;
    return true;
}

bool Match(ParseContext& ctx, const std::string& keyword)
{
    SkipWhitespace(ctx);
    if (ctx.pos + keyword.size() > ctx.desc.size()) return false;
    if (ctx.desc.substr(ctx.pos, keyword.size()) != keyword) return false;
    // Ensure not a prefix of a longer identifier
    size_t end = ctx.pos + keyword.size();
    if (end < ctx.desc.size() && (std::isalnum(ctx.desc[end]) || ctx.desc[end] == '_')) return false;
    ctx.pos += keyword.size();
    return true;
}

bool Peek(ParseContext& ctx, const std::string& keyword)
{
    SkipWhitespace(ctx);
    if (ctx.pos + keyword.size() > ctx.desc.size()) return false;
    if (ctx.desc.substr(ctx.pos, keyword.size()) != keyword) return false;
    size_t end = ctx.pos + keyword.size();
    if (end < ctx.desc.size() && (std::isalnum(ctx.desc[end]) || ctx.desc[end] == '_')) return false;
    return true;
}

std::string ReadIdentifier(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() &&
           (std::isalnum(ctx.desc[ctx.pos]) || ctx.desc[ctx.pos] == '_')) {
        ++ctx.pos;
    }
    return ctx.desc.substr(start, ctx.pos - start);
}

std::string ReadAlias(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    if (ctx.pos >= ctx.desc.size() || ctx.desc[ctx.pos] != '@') {
        ctx.error = "expected '@' alias at position " + std::to_string(ctx.pos);
        return "";
    }
    ++ctx.pos;
    return ReadIdentifier(ctx);
}

bool ReadUint32(ParseContext& ctx, uint32_t& out)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() && std::isdigit(ctx.desc[ctx.pos])) {
        ++ctx.pos;
    }
    if (ctx.pos == start) {
        ctx.error = "expected number at position " + std::to_string(ctx.pos);
        return false;
    }
    try {
        unsigned long val = std::stoul(ctx.desc.substr(start, ctx.pos - start));
        if (val > 0xFFFFFFFF) {
            ctx.error = "number too large at position " + std::to_string(start);
            return false;
        }
        out = static_cast<uint32_t>(val);
    } catch (...) {
        ctx.error = "invalid number at position " + std::to_string(start);
        return false;
    }
    return true;
}

std::string ReadHex(ParseContext& ctx)
{
    SkipWhitespace(ctx);
    size_t start = ctx.pos;
    while (ctx.pos < ctx.desc.size() && HexDigit(ctx.desc[ctx.pos]) != -1) {
        ++ctx.pos;
    }
    return ctx.desc.substr(start, ctx.pos - start);
}

std::vector<uint8_t> MakeNumericField(uint32_t val)
{
    std::vector<uint8_t> data(4);
    data[0] = val & 0xFF;
    data[1] = (val >> 8) & 0xFF;
    data[2] = (val >> 16) & 0xFF;
    data[3] = (val >> 24) & 0xFF;
    return data;
}

RungScheme ParseScheme(const std::string& name)
{
    if (name == "schnorr") return RungScheme::SCHNORR;
    if (name == "ecdsa") return RungScheme::ECDSA;
    if (name == "falcon512") return RungScheme::FALCON512;
    if (name == "falcon1024") return RungScheme::FALCON1024;
    if (name == "dilithium3") return RungScheme::DILITHIUM3;
    if (name == "sphincs_sha") return RungScheme::SPHINCS_SHA;
    return RungScheme::SCHNORR; // default
}

std::string SchemeToString(RungScheme s)
{
    switch (s) {
    case RungScheme::SCHNORR: return "schnorr";
    case RungScheme::ECDSA: return "ecdsa";
    case RungScheme::FALCON512: return "falcon512";
    case RungScheme::FALCON1024: return "falcon1024";
    case RungScheme::DILITHIUM3: return "dilithium3";
    case RungScheme::SPHINCS_SHA: return "sphincs_sha";
    }
    return "schnorr";
}

bool LookupKey(ParseContext& ctx, const std::string& alias, std::vector<uint8_t>& out)
{
    auto it = ctx.keys.find(alias);
    if (it == ctx.keys.end()) {
        ctx.error = "unknown key alias: @" + alias;
        return false;
    }
    out = it->second;
    return true;
}

bool ParseBlock(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks);

bool ParseSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // sig(@alias) or sig(@alias, scheme)
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;

    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);

    block.type = RungBlockType::SIG;
    RungScheme scheme = RungScheme::SCHNORR;

    SkipWhitespace(ctx);
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ',') {
        ++ctx.pos;
        std::string scheme_name = ReadIdentifier(ctx);
        scheme = ParseScheme(scheme_name);
    }

    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(scheme)}});
    return Expect(ctx, ')');
}

bool ParseCsv(ParseContext& ctx, RungBlock& block, RungBlockType type)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t val;
    if (!ReadUint32(ctx, val)) return false;
    block.type = type;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(val)});
    return Expect(ctx, ')');
}

bool ParseMultisig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    // multisig(M, @pk1, @pk2, ...) or multisig(M, @pk1, @pk2, ..., scheme)
    if (!Expect(ctx, '(')) return false;
    uint32_t threshold;
    if (!ReadUint32(ctx, threshold)) return false;

    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(threshold)});

    while (true) {
        SkipWhitespace(ctx);
        if (ctx.pos >= ctx.desc.size()) break;
        if (ctx.desc[ctx.pos] == ')') break;
        if (!Expect(ctx, ',')) return false;
        SkipWhitespace(ctx);
        if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '@') {
            std::string alias = ReadAlias(ctx);
            if (alias.empty()) return false;
            std::vector<uint8_t> pk;
            if (!LookupKey(ctx, alias, pk)) return false;
            rung_pks.push_back(pk);
        } else {
            // Must be a scheme name at the end
            break;
        }
    }

    return Expect(ctx, ')');
}

bool ParseHashGuarded(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "hash_guarded requires 32-byte hash";
        return false;
    }
    block.type = RungBlockType::HASH_GUARDED;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseCtv(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "ctv requires 32-byte template hash";
        return false;
    }
    block.type = RungBlockType::CTV;
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseAmountLock(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t min_val, max_val;
    if (!ReadUint32(ctx, min_val)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_val)) return false;
    block.type = RungBlockType::AMOUNT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_val)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_val)});
    return Expect(ctx, ')');
}

bool ParseTimelockedSig(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    if (!Expect(ctx, '(')) return false;
    std::string alias = ReadAlias(ctx);
    if (alias.empty()) return false;
    std::vector<uint8_t> pk;
    if (!LookupKey(ctx, alias, pk)) return false;
    rung_pks.push_back(pk);

    if (!Expect(ctx, ',')) return false;
    uint32_t csv_val;
    if (!ReadUint32(ctx, csv_val)) return false;

    block.type = RungBlockType::TIMELOCKED_SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(csv_val)});
    return Expect(ctx, ')');
}

bool ParseOutputCheck(ParseContext& ctx, RungBlock& block)
{
    if (!Expect(ctx, '(')) return false;
    uint32_t idx, min_sats, max_sats;
    if (!ReadUint32(ctx, idx)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, min_sats)) return false;
    if (!Expect(ctx, ',')) return false;
    if (!ReadUint32(ctx, max_sats)) return false;
    if (!Expect(ctx, ',')) return false;

    std::string hex = ReadHex(ctx);
    auto bytes = ParseHex(hex);
    if (bytes.size() != 32) {
        ctx.error = "output_check requires 32-byte script_hash";
        return false;
    }

    block.type = RungBlockType::OUTPUT_CHECK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(idx)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(min_sats)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumericField(max_sats)});
    block.fields.push_back({RungDataType::HASH256, bytes});
    return Expect(ctx, ')');
}

bool ParseBlock(ParseContext& ctx, RungBlock& block, std::vector<std::vector<uint8_t>>& rung_pks)
{
    SkipWhitespace(ctx);

    // Check for inversion prefix
    bool inverted = false;
    if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == '!') {
        inverted = true;
        ++ctx.pos;
    }

    SkipWhitespace(ctx);
    std::string name = ReadIdentifier(ctx);

    bool ok = false;
    if (name == "sig") ok = ParseSig(ctx, block, rung_pks);
    else if (name == "csv") ok = ParseCsv(ctx, block, RungBlockType::CSV);
    else if (name == "csv_time") ok = ParseCsv(ctx, block, RungBlockType::CSV_TIME);
    else if (name == "cltv") ok = ParseCsv(ctx, block, RungBlockType::CLTV);
    else if (name == "cltv_time") ok = ParseCsv(ctx, block, RungBlockType::CLTV_TIME);
    else if (name == "multisig") ok = ParseMultisig(ctx, block, rung_pks);
    else if (name == "hash_guarded") ok = ParseHashGuarded(ctx, block);
    else if (name == "ctv") ok = ParseCtv(ctx, block);
    else if (name == "amount_lock") ok = ParseAmountLock(ctx, block);
    else if (name == "timelocked_sig") ok = ParseTimelockedSig(ctx, block, rung_pks);
    else if (name == "output_check") ok = ParseOutputCheck(ctx, block);
    else {
        ctx.error = "unknown block type: " + name;
        return false;
    }

    if (ok && inverted) {
        if (!IsInvertibleBlockType(block.type)) {
            ctx.error = "block type " + name + " cannot be inverted";
            return false;
        }
        block.inverted = true;
    }

    return ok;
}

bool ParseRung(ParseContext& ctx, Rung& rung, std::vector<std::vector<uint8_t>>& rung_pks)
{
    SkipWhitespace(ctx);

    if (Peek(ctx, "and")) {
        Match(ctx, "and");
        if (!Expect(ctx, '(')) return false;

        RungBlock block;
        if (!ParseBlock(ctx, block, rung_pks)) return false;
        rung.blocks.push_back(std::move(block));

        while (true) {
            SkipWhitespace(ctx);
            if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
                ++ctx.pos;
                break;
            }
            if (!Expect(ctx, ',')) return false;
            RungBlock next_block;
            if (!ParseBlock(ctx, next_block, rung_pks)) return false;
            rung.blocks.push_back(std::move(next_block));
        }
    } else {
        // Single block rung
        RungBlock block;
        if (!ParseBlock(ctx, block, rung_pks)) return false;
        rung.blocks.push_back(std::move(block));
    }

    return true;
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

bool ParseDescriptor(const std::string& desc,
                     const std::map<std::string, std::vector<uint8_t>>& keys,
                     RungConditions& out,
                     std::vector<std::vector<std::vector<uint8_t>>>& pubkeys,
                     std::string& error)
{
    ParseContext ctx{desc, keys, 0, {}};

    SkipWhitespace(ctx);
    if (!Match(ctx, "ladder")) {
        ctx.error = "descriptor must start with 'ladder('";
        error = ctx.error;
        return false;
    }
    if (!Expect(ctx, '(')) { error = ctx.error; return false; }

    if (!Match(ctx, "or")) {
        // Single rung (no or() wrapper)
        Rung rung;
        std::vector<std::vector<uint8_t>> rung_pks;
        if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
        out.rungs.push_back(std::move(rung));
        pubkeys.push_back(std::move(rung_pks));
    } else {
        if (!Expect(ctx, '(')) { error = ctx.error; return false; }

        // Parse first rung
        Rung first_rung;
        std::vector<std::vector<uint8_t>> first_pks;
        if (!ParseRung(ctx, first_rung, first_pks)) { error = ctx.error; return false; }
        out.rungs.push_back(std::move(first_rung));
        pubkeys.push_back(std::move(first_pks));

        // Parse remaining rungs
        while (true) {
            SkipWhitespace(ctx);
            if (ctx.pos < ctx.desc.size() && ctx.desc[ctx.pos] == ')') {
                ++ctx.pos;
                break;
            }
            if (!Expect(ctx, ',')) { error = ctx.error; return false; }

            Rung rung;
            std::vector<std::vector<uint8_t>> rung_pks;
            if (!ParseRung(ctx, rung, rung_pks)) { error = ctx.error; return false; }
            out.rungs.push_back(std::move(rung));
            pubkeys.push_back(std::move(rung_pks));
        }
    }

    if (!Expect(ctx, ')')) { error = ctx.error; return false; }

    SkipWhitespace(ctx);
    if (ctx.pos != ctx.desc.size()) {
        error = "unexpected trailing characters at position " + std::to_string(ctx.pos);
        return false;
    }

    return true;
}

std::string FormatDescriptor(const RungConditions& conditions,
                             const std::vector<std::vector<std::vector<uint8_t>>>& pubkeys,
                             const std::map<std::string, std::string>& aliases)
{
    auto format_block = [&](const RungBlock& block, size_t rung_idx, size_t& pk_cursor) -> std::string {
        std::string result;
        if (block.inverted) result += "!";

        auto get_alias = [&](size_t ri) -> std::string {
            if (ri < pubkeys.size() && pk_cursor < pubkeys[ri].size()) {
                std::string hex = HexStr(pubkeys[ri][pk_cursor]);
                pk_cursor++;
                auto it = aliases.find(hex);
                if (it != aliases.end()) return "@" + it->second;
                return "@" + hex.substr(0, 8);
            }
            pk_cursor++;
            return "@?";
        };

        switch (block.type) {
        case RungBlockType::SIG: {
            result += "sig(" + get_alias(rung_idx);
            if (!block.fields.empty() && block.fields[0].type == RungDataType::SCHEME &&
                !block.fields[0].data.empty()) {
                auto s = static_cast<RungScheme>(block.fields[0].data[0]);
                if (s != RungScheme::SCHNORR) {
                    result += ", " + SchemeToString(s);
                }
            }
            result += ")";
            return result;
        }
        case RungBlockType::CSV:
        case RungBlockType::CSV_TIME:
        case RungBlockType::CLTV:
        case RungBlockType::CLTV_TIME: {
            std::string name;
            switch (block.type) {
            case RungBlockType::CSV: name = "csv"; break;
            case RungBlockType::CSV_TIME: name = "csv_time"; break;
            case RungBlockType::CLTV: name = "cltv"; break;
            case RungBlockType::CLTV_TIME: name = "cltv_time"; break;
            default: break;
            }
            if (!block.fields.empty()) {
                uint32_t val = 0;
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    val |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
                result += name + "(" + std::to_string(val) + ")";
            }
            return result;
        }
        case RungBlockType::MULTISIG: {
            uint32_t threshold = 0;
            if (!block.fields.empty()) {
                for (size_t i = 0; i < block.fields[0].data.size() && i < 4; ++i)
                    threshold |= static_cast<uint32_t>(block.fields[0].data[i]) << (8 * i);
            }
            result += "multisig(" + std::to_string(threshold);
            // Count pubkeys from pubkeys array
            size_t n_pks = PubkeyCountForBlock(block.type, block);
            for (size_t i = 0; i < n_pks; ++i) {
                result += ", " + get_alias(rung_idx);
            }
            result += ")";
            return result;
        }
        default: {
            result += BlockTypeName(block.type) + "(...)";
            return result;
        }
        }
    };

    std::string result = "ladder(";
    if (conditions.rungs.size() > 1) result += "or(";

    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        if (r > 0) result += ", ";
        const auto& rung = conditions.rungs[r];
        size_t pk_cursor = 0;

        if (rung.blocks.size() > 1) {
            result += "and(";
            for (size_t b = 0; b < rung.blocks.size(); ++b) {
                if (b > 0) result += ", ";
                result += format_block(rung.blocks[b], r, pk_cursor);
            }
            result += ")";
        } else if (rung.blocks.size() == 1) {
            result += format_block(rung.blocks[0], r, pk_cursor);
        }
    }

    if (conditions.rungs.size() > 1) result += ")";
    result += ")";
    return result;
}

} // namespace rung
