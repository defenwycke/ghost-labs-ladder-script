// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/serialize.h>

#include <streams.h>
#include <util/strencodings.h>

#include <ios>

namespace rung {

bool DeserializeLadderWitness(const std::vector<uint8_t>& witness_bytes,
                              LadderWitness& ladder_out,
                              std::string& error)
{
    if (witness_bytes.empty()) {
        error = "empty ladder witness";
        return false;
    }

    if (witness_bytes.size() > MAX_LADDER_WITNESS_SIZE) {
        error = "ladder witness exceeds maximum size";
        return false;
    }

    DataStream ss{witness_bytes};

    try {
        uint64_t n_rungs = ReadCompactSize(ss);
        if (n_rungs == 0) {
            error = "ladder witness has zero rungs";
            return false;
        }
        if (n_rungs > MAX_RUNGS) {
            error = "too many rungs: " + std::to_string(n_rungs);
            return false;
        }

        ladder_out.rungs.resize(n_rungs);
        for (uint64_t r = 0; r < n_rungs; ++r) {
            uint64_t n_blocks = ReadCompactSize(ss);
            if (n_blocks == 0) {
                error = "rung " + std::to_string(r) + " has zero blocks";
                return false;
            }
            if (n_blocks > MAX_BLOCKS_PER_RUNG) {
                error = "rung " + std::to_string(r) + " has too many blocks: " + std::to_string(n_blocks);
                return false;
            }

            ladder_out.rungs[r].blocks.resize(n_blocks);
            for (uint64_t b = 0; b < n_blocks; ++b) {
                // Read block type — uint16_t little-endian
                uint8_t lo, hi;
                ss >> lo >> hi;
                uint16_t block_type_val = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
                if (!IsKnownBlockType(block_type_val)) {
                    error = "unknown block type: 0x" + HexStr(std::vector<uint8_t>{lo, hi});
                    return false;
                }
                ladder_out.rungs[r].blocks[b].type = static_cast<RungBlockType>(block_type_val);

                // Read inverted flag — single byte, must be 0x00 or 0x01
                uint8_t inverted_byte;
                ss >> inverted_byte;
                if (inverted_byte > 0x01) {
                    error = "invalid inverted flag: 0x" + HexStr(std::span<const uint8_t>{&inverted_byte, 1});
                    return false;
                }
                ladder_out.rungs[r].blocks[b].inverted = (inverted_byte == 0x01);

                // Read fields
                uint64_t n_fields = ReadCompactSize(ss);
                if (n_fields > MAX_FIELDS_PER_BLOCK) {
                    error = "block has too many fields: " + std::to_string(n_fields);
                    return false;
                }

                ladder_out.rungs[r].blocks[b].fields.resize(n_fields);
                for (uint64_t f = 0; f < n_fields; ++f) {
                    // Read data type
                    uint8_t data_type_byte;
                    ss >> data_type_byte;
                    if (!IsKnownDataType(data_type_byte)) {
                        error = "unknown data type: 0x" + HexStr(std::span<const uint8_t>{&data_type_byte, 1});
                        return false;
                    }
                    RungDataType dtype = static_cast<RungDataType>(data_type_byte);

                    // Read data length
                    uint64_t data_len = ReadCompactSize(ss);

                    // Validate field size against type constraints
                    size_t min_sz = FieldMinSize(dtype);
                    size_t max_sz = FieldMaxSize(dtype);
                    if (data_len < min_sz) {
                        error = DataTypeName(dtype) + " too small: " + std::to_string(data_len) +
                                " < " + std::to_string(min_sz);
                        return false;
                    }
                    if (data_len > max_sz) {
                        error = DataTypeName(dtype) + " too large: " + std::to_string(data_len) +
                                " > " + std::to_string(max_sz);
                        return false;
                    }

                    // Read data
                    ladder_out.rungs[r].blocks[b].fields[f].type = dtype;
                    ladder_out.rungs[r].blocks[b].fields[f].data.resize(data_len);
                    if (data_len > 0) {
                        ss.read(MakeWritableByteSpan(ladder_out.rungs[r].blocks[b].fields[f].data));
                    }

                    // Validate field content
                    std::string field_reason;
                    if (!ladder_out.rungs[r].blocks[b].fields[f].IsValid(field_reason)) {
                        error = field_reason;
                        return false;
                    }
                }
            }

        }

        // Read coil (per-ladder, after all rungs)
        uint8_t coil_type_byte, attestation_byte, scheme_byte;
        ss >> coil_type_byte >> attestation_byte >> scheme_byte;
        ladder_out.coil.coil_type = static_cast<RungCoilType>(coil_type_byte);
        ladder_out.coil.attestation = static_cast<RungAttestationMode>(attestation_byte);
        ladder_out.coil.scheme = static_cast<RungScheme>(scheme_byte);

        // Read coil address (variable-length scriptPubKey)
        uint64_t addr_len = ReadCompactSize(ss);
        if (addr_len > 520) { // Max scriptPubKey size
            error = "coil address too large: " + std::to_string(addr_len);
            return false;
        }
        if (addr_len > 0) {
            ladder_out.coil.address.resize(addr_len);
            ss.read(MakeWritableByteSpan(ladder_out.coil.address));
        }

        // Read coil condition rungs
        uint64_t n_coil_rungs = ReadCompactSize(ss);
        if (n_coil_rungs > MAX_RUNGS) {
            error = "too many coil condition rungs: " + std::to_string(n_coil_rungs);
            return false;
        }
        ladder_out.coil.conditions.resize(n_coil_rungs);
        for (uint64_t cr = 0; cr < n_coil_rungs; ++cr) {
            uint64_t n_cblocks = ReadCompactSize(ss);
            if (n_cblocks == 0) {
                error = "coil condition rung " + std::to_string(cr) + " has zero blocks";
                return false;
            }
            if (n_cblocks > MAX_BLOCKS_PER_RUNG) {
                error = "coil condition rung has too many blocks: " + std::to_string(n_cblocks);
                return false;
            }
            ladder_out.coil.conditions[cr].blocks.resize(n_cblocks);
            for (uint64_t cb = 0; cb < n_cblocks; ++cb) {
                uint8_t clo, chi;
                ss >> clo >> chi;
                uint16_t cblock_type = static_cast<uint16_t>(clo) | (static_cast<uint16_t>(chi) << 8);
                if (!IsKnownBlockType(cblock_type)) {
                    error = "unknown coil block type: 0x" + HexStr(std::vector<uint8_t>{clo, chi});
                    return false;
                }
                ladder_out.coil.conditions[cr].blocks[cb].type = static_cast<RungBlockType>(cblock_type);

                uint8_t cinv;
                ss >> cinv;
                if (cinv > 0x01) {
                    error = "invalid coil inverted flag";
                    return false;
                }
                ladder_out.coil.conditions[cr].blocks[cb].inverted = (cinv == 0x01);

                uint64_t cn_fields = ReadCompactSize(ss);
                if (cn_fields > MAX_FIELDS_PER_BLOCK) {
                    error = "coil block has too many fields: " + std::to_string(cn_fields);
                    return false;
                }
                ladder_out.coil.conditions[cr].blocks[cb].fields.resize(cn_fields);
                for (uint64_t cf = 0; cf < cn_fields; ++cf) {
                    uint8_t cdt;
                    ss >> cdt;
                    if (!IsKnownDataType(cdt)) {
                        error = "unknown coil data type: 0x" + HexStr(std::span<const uint8_t>{&cdt, 1});
                        return false;
                    }
                    RungDataType cdtype = static_cast<RungDataType>(cdt);
                    uint64_t cdl = ReadCompactSize(ss);
                    size_t cmin = FieldMinSize(cdtype);
                    size_t cmax = FieldMaxSize(cdtype);
                    if (cdl < cmin || cdl > cmax) {
                        error = DataTypeName(cdtype) + " size out of range in coil condition";
                        return false;
                    }
                    ladder_out.coil.conditions[cr].blocks[cb].fields[cf].type = cdtype;
                    ladder_out.coil.conditions[cr].blocks[cb].fields[cf].data.resize(cdl);
                    if (cdl > 0) {
                        ss.read(MakeWritableByteSpan(ladder_out.coil.conditions[cr].blocks[cb].fields[cf].data));
                    }
                    std::string cfield_reason;
                    if (!ladder_out.coil.conditions[cr].blocks[cb].fields[cf].IsValid(cfield_reason)) {
                        error = cfield_reason;
                        return false;
                    }
                }
            }
        }

        // Read relays (optional — backward compatible, 0 relays if EOF)
        if (!ss.empty()) {
            uint64_t n_relays = ReadCompactSize(ss);
            if (n_relays > MAX_RELAYS) {
                error = "too many relays: " + std::to_string(n_relays);
                return false;
            }

            ladder_out.relays.resize(n_relays);
            for (uint64_t rl = 0; rl < n_relays; ++rl) {
                // Read relay blocks (same format as rung blocks)
                uint64_t n_rblocks = ReadCompactSize(ss);
                if (n_rblocks == 0) {
                    error = "relay " + std::to_string(rl) + " has zero blocks";
                    return false;
                }
                if (n_rblocks > MAX_BLOCKS_PER_RUNG) {
                    error = "relay " + std::to_string(rl) + " has too many blocks: " + std::to_string(n_rblocks);
                    return false;
                }

                ladder_out.relays[rl].blocks.resize(n_rblocks);
                for (uint64_t rb = 0; rb < n_rblocks; ++rb) {
                    uint8_t rlo, rhi;
                    ss >> rlo >> rhi;
                    uint16_t rblock_type = static_cast<uint16_t>(rlo) | (static_cast<uint16_t>(rhi) << 8);
                    if (!IsKnownBlockType(rblock_type)) {
                        error = "unknown relay block type: 0x" + HexStr(std::vector<uint8_t>{rlo, rhi});
                        return false;
                    }
                    ladder_out.relays[rl].blocks[rb].type = static_cast<RungBlockType>(rblock_type);

                    uint8_t rinv;
                    ss >> rinv;
                    if (rinv > 0x01) {
                        error = "invalid relay inverted flag";
                        return false;
                    }
                    ladder_out.relays[rl].blocks[rb].inverted = (rinv == 0x01);

                    uint64_t rn_fields = ReadCompactSize(ss);
                    if (rn_fields > MAX_FIELDS_PER_BLOCK) {
                        error = "relay block has too many fields: " + std::to_string(rn_fields);
                        return false;
                    }
                    ladder_out.relays[rl].blocks[rb].fields.resize(rn_fields);
                    for (uint64_t rf = 0; rf < rn_fields; ++rf) {
                        uint8_t rdt;
                        ss >> rdt;
                        if (!IsKnownDataType(rdt)) {
                            error = "unknown relay data type: 0x" + HexStr(std::span<const uint8_t>{&rdt, 1});
                            return false;
                        }
                        RungDataType rdtype = static_cast<RungDataType>(rdt);
                        uint64_t rdl = ReadCompactSize(ss);
                        size_t rmin = FieldMinSize(rdtype);
                        size_t rmax = FieldMaxSize(rdtype);
                        if (rdl < rmin || rdl > rmax) {
                            error = DataTypeName(rdtype) + " size out of range in relay";
                            return false;
                        }
                        ladder_out.relays[rl].blocks[rb].fields[rf].type = rdtype;
                        ladder_out.relays[rl].blocks[rb].fields[rf].data.resize(rdl);
                        if (rdl > 0) {
                            ss.read(MakeWritableByteSpan(ladder_out.relays[rl].blocks[rb].fields[rf].data));
                        }
                        std::string rfield_reason;
                        if (!ladder_out.relays[rl].blocks[rb].fields[rf].IsValid(rfield_reason)) {
                            error = rfield_reason;
                            return false;
                        }
                    }
                }

                // Read relay relay_refs (indices of other relays)
                uint64_t n_relay_reqs = ReadCompactSize(ss);
                if (n_relay_reqs > MAX_REQUIRES) {
                    error = "relay " + std::to_string(rl) + " has too many relay_refs";
                    return false;
                }
                ladder_out.relays[rl].relay_refs.resize(n_relay_reqs);
                for (uint64_t rr = 0; rr < n_relay_reqs; ++rr) {
                    uint64_t req_idx = ReadCompactSize(ss);
                    if (req_idx >= rl) {
                        error = "relay " + std::to_string(rl) + " requires forward/self reference: " + std::to_string(req_idx);
                        return false;
                    }
                    ladder_out.relays[rl].relay_refs[rr] = static_cast<uint16_t>(req_idx);
                }
            }

            // Read per-rung relay_refs
            if (!ss.empty()) {
                uint64_t n_rung_reqs = ReadCompactSize(ss);
                if (n_rung_reqs != ladder_out.rungs.size()) {
                    error = "rung relay_refs count mismatch: " + std::to_string(n_rung_reqs) +
                            " vs " + std::to_string(ladder_out.rungs.size()) + " rungs";
                    return false;
                }
                for (uint64_t rq = 0; rq < n_rung_reqs; ++rq) {
                    uint64_t n_reqs = ReadCompactSize(ss);
                    if (n_reqs > MAX_REQUIRES) {
                        error = "rung " + std::to_string(rq) + " has too many relay_refs";
                        return false;
                    }
                    ladder_out.rungs[rq].relay_refs.resize(n_reqs);
                    for (uint64_t ri = 0; ri < n_reqs; ++ri) {
                        uint64_t req_idx = ReadCompactSize(ss);
                        if (req_idx >= ladder_out.relays.size()) {
                            error = "rung " + std::to_string(rq) + " relay_refs invalid relay index: " + std::to_string(req_idx);
                            return false;
                        }
                        ladder_out.rungs[rq].relay_refs[ri] = static_cast<uint16_t>(req_idx);
                    }
                }
            }
        }

        // Reject trailing bytes — no extra data allowed
        if (!ss.empty()) {
            error = "trailing bytes in ladder witness";
            return false;
        }

    } catch (const std::ios_base::failure& e) {
        error = std::string("deserialization failure: ") + e.what();
        return false;
    }

    return true;
}

std::vector<uint8_t> SerializeLadderWitness(const LadderWitness& ladder)
{
    DataStream ss{};

    WriteCompactSize(ss, ladder.rungs.size());
    for (const auto& rung : ladder.rungs) {
        WriteCompactSize(ss, rung.blocks.size());
        for (const auto& block : rung.blocks) {
            // Write block type as uint16_t little-endian
            uint16_t btype = static_cast<uint16_t>(block.type);
            ss << static_cast<uint8_t>(btype & 0xFF);
            ss << static_cast<uint8_t>((btype >> 8) & 0xFF);
            // Write inverted flag
            ss << static_cast<uint8_t>(block.inverted ? 0x01 : 0x00);
            // Write fields
            WriteCompactSize(ss, block.fields.size());
            for (const auto& field : block.fields) {
                ss << static_cast<uint8_t>(field.type);
                WriteCompactSize(ss, field.data.size());
                if (!field.data.empty()) {
                    ss.write(MakeByteSpan(field.data));
                }
            }
        }
    }

    // Write coil (per-ladder, after all rungs)
    ss << static_cast<uint8_t>(ladder.coil.coil_type);
    ss << static_cast<uint8_t>(ladder.coil.attestation);
    ss << static_cast<uint8_t>(ladder.coil.scheme);

    // Write coil address
    WriteCompactSize(ss, ladder.coil.address.size());
    if (!ladder.coil.address.empty()) {
        ss.write(MakeByteSpan(ladder.coil.address));
    }

    // Write coil condition rungs
    WriteCompactSize(ss, ladder.coil.conditions.size());
    for (const auto& crung : ladder.coil.conditions) {
        WriteCompactSize(ss, crung.blocks.size());
        for (const auto& cblock : crung.blocks) {
            uint16_t cbtype = static_cast<uint16_t>(cblock.type);
            ss << static_cast<uint8_t>(cbtype & 0xFF);
            ss << static_cast<uint8_t>((cbtype >> 8) & 0xFF);
            ss << static_cast<uint8_t>(cblock.inverted ? 0x01 : 0x00);
            WriteCompactSize(ss, cblock.fields.size());
            for (const auto& cfield : cblock.fields) {
                ss << static_cast<uint8_t>(cfield.type);
                WriteCompactSize(ss, cfield.data.size());
                if (!cfield.data.empty()) {
                    ss.write(MakeByteSpan(cfield.data));
                }
            }
        }
    }

    // Write relays (only if any relays or rung relay_refs exist)
    bool has_relay_refs = !ladder.relays.empty();
    if (!has_relay_refs) {
        for (const auto& rung : ladder.rungs) {
            if (!rung.relay_refs.empty()) { has_relay_refs = true; break; }
        }
    }

    if (has_relay_refs) {
        WriteCompactSize(ss, ladder.relays.size());
        for (const auto& relay : ladder.relays) {
            WriteCompactSize(ss, relay.blocks.size());
            for (const auto& block : relay.blocks) {
                uint16_t btype = static_cast<uint16_t>(block.type);
                ss << static_cast<uint8_t>(btype & 0xFF);
                ss << static_cast<uint8_t>((btype >> 8) & 0xFF);
                ss << static_cast<uint8_t>(block.inverted ? 0x01 : 0x00);
                WriteCompactSize(ss, block.fields.size());
                for (const auto& field : block.fields) {
                    ss << static_cast<uint8_t>(field.type);
                    WriteCompactSize(ss, field.data.size());
                    if (!field.data.empty()) {
                        ss.write(MakeByteSpan(field.data));
                    }
                }
            }
            // Write relay relay_refs
            WriteCompactSize(ss, relay.relay_refs.size());
            for (uint16_t req : relay.relay_refs) {
                WriteCompactSize(ss, req);
            }
        }

        // Write per-rung relay_refs
        WriteCompactSize(ss, ladder.rungs.size());
        for (const auto& rung : ladder.rungs) {
            WriteCompactSize(ss, rung.relay_refs.size());
            for (uint16_t req : rung.relay_refs) {
                WriteCompactSize(ss, req);
            }
        }
    }

    // Extract serialized bytes
    std::vector<uint8_t> result(ss.size());
    ss.read(MakeWritableByteSpan(result));
    return result;
}

} // namespace rung
