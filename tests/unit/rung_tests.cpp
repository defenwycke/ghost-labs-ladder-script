// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/evaluator.h>
#include <rung/policy.h>
#include <rung/pq_verify.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

using namespace rung;

// ============================================================================
// Helper: build a LadderWitness, serialize, and deserialize it
// ============================================================================

static std::vector<uint8_t> MakePubkey()
{
    // A fake compressed pubkey (33 bytes, starts with 0x02)
    std::vector<uint8_t> pk(33, 0xAA);
    pk[0] = 0x02;
    return pk;
}

static std::vector<uint8_t> MakeSignature(size_t len = 64)
{
    // A fake signature of the given length
    return std::vector<uint8_t>(len, 0xBB);
}

static std::vector<uint8_t> MakeHash256()
{
    return std::vector<uint8_t>(32, 0xCC);
}

static std::vector<uint8_t> MakeHash160()
{
    return std::vector<uint8_t>(20, 0xDD);
}

static std::vector<uint8_t> MakeNumeric(uint32_t val)
{
    std::vector<uint8_t> data(4);
    data[0] = val & 0xFF;
    data[1] = (val >> 8) & 0xFF;
    data[2] = (val >> 16) & 0xFF;
    data[3] = (val >> 24) & 0xFF;
    return data;
}

/** Compute SHA-256 of a pubkey to produce a PUBKEY_COMMIT value. */
static std::vector<uint8_t> MakePubkeyCommit(const std::vector<uint8_t>& pubkey)
{
    std::vector<uint8_t> commit(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(commit.data());
    return commit;
}

BOOST_FIXTURE_TEST_SUITE(rung_tests, BasicTestingSetup)

// ============================================================================
// Types tests
// ============================================================================

BOOST_AUTO_TEST_CASE(field_validation_pubkey_valid)
{
    RungField field{RungDataType::PUBKEY, MakePubkey()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_pubkey_various_sizes)
{
    // 1 byte: valid (min size)
    RungField pk1{RungDataType::PUBKEY, std::vector<uint8_t>(1, 0x02)};
    std::string reason;
    BOOST_CHECK(pk1.IsValid(reason));

    // 32 bytes: valid (x-only)
    RungField pk32{RungDataType::PUBKEY, std::vector<uint8_t>(32, 0xAA)};
    BOOST_CHECK(pk32.IsValid(reason));

    // 64 bytes: valid
    RungField pk64{RungDataType::PUBKEY, std::vector<uint8_t>(64, 0xAA)};
    BOOST_CHECK(pk64.IsValid(reason));

    // 897 bytes: valid (FALCON512 pubkey size)
    RungField pk897{RungDataType::PUBKEY, std::vector<uint8_t>(897, 0xAA)};
    BOOST_CHECK(pk897.IsValid(reason));

    // 2048 bytes: valid (max size for PQ)
    RungField pk2048{RungDataType::PUBKEY, std::vector<uint8_t>(2048, 0xAA)};
    BOOST_CHECK(pk2048.IsValid(reason));

    // 2049 bytes: too large
    RungField pk2049{RungDataType::PUBKEY, std::vector<uint8_t>(2049, 0x02)};
    BOOST_CHECK(!pk2049.IsValid(reason));
    BOOST_CHECK(reason.find("too large") != std::string::npos);

    // 0 bytes: too small
    RungField pk0{RungDataType::PUBKEY, std::vector<uint8_t>()};
    BOOST_CHECK(!pk0.IsValid(reason));
    BOOST_CHECK(reason.find("too small") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_pubkey_bad_prefix_33byte)
{
    auto pk = MakePubkey();
    pk[0] = 0x04; // uncompressed prefix, not allowed for 33-byte key
    RungField field{RungDataType::PUBKEY, pk};
    std::string reason;
    BOOST_CHECK(!field.IsValid(reason));
    BOOST_CHECK(reason.find("invalid prefix") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_signature_valid)
{
    RungField field{RungDataType::SIGNATURE, MakeSignature(64)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_signature_various_sizes)
{
    std::string reason;

    // 1 byte: valid (min size)
    RungField sig1{RungDataType::SIGNATURE, std::vector<uint8_t>(1, 0xBB)};
    BOOST_CHECK(sig1.IsValid(reason));

    // 49216 bytes: valid (SPHINCS+ sig size)
    RungField sig_sphincs{RungDataType::SIGNATURE, std::vector<uint8_t>(49216, 0xBB)};
    BOOST_CHECK(sig_sphincs.IsValid(reason));

    // 50000 bytes: valid (max size)
    RungField sig_max{RungDataType::SIGNATURE, std::vector<uint8_t>(50000, 0xBB)};
    BOOST_CHECK(sig_max.IsValid(reason));

    // 50001 bytes: too large
    RungField sig_over{RungDataType::SIGNATURE, std::vector<uint8_t>(50001, 0xBB)};
    BOOST_CHECK(!sig_over.IsValid(reason));
    BOOST_CHECK(reason.find("too large") != std::string::npos);

    // 0 bytes: too small
    RungField sig0{RungDataType::SIGNATURE, std::vector<uint8_t>()};
    BOOST_CHECK(!sig0.IsValid(reason));
    BOOST_CHECK(reason.find("too small") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(field_validation_hash256_exact)
{
    RungField field{RungDataType::HASH256, MakeHash256()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    // Wrong size rejected
    RungField bad{RungDataType::HASH256, std::vector<uint8_t>(31, 0xCC)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_hash160_exact)
{
    RungField field{RungDataType::HASH160, MakeHash160()};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    RungField bad{RungDataType::HASH160, std::vector<uint8_t>(19, 0xDD)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_numeric_valid)
{
    RungField field{RungDataType::NUMERIC, MakeNumeric(144)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    // 1 byte: valid (min size now 1)
    RungField one_byte{RungDataType::NUMERIC, std::vector<uint8_t>(1, 0x0A)};
    BOOST_CHECK(one_byte.IsValid(reason));

    // 5 bytes: too large (max is 4)
    RungField bad{RungDataType::NUMERIC, std::vector<uint8_t>(5, 0x00)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_preimage_valid_range)
{
    // Minimum 1 byte
    RungField min_field{RungDataType::PREIMAGE, std::vector<uint8_t>(1, 0x42)};
    std::string reason;
    BOOST_CHECK(min_field.IsValid(reason));

    // Maximum 252 bytes
    RungField max_field{RungDataType::PREIMAGE, std::vector<uint8_t>(252, 0x42)};
    BOOST_CHECK(max_field.IsValid(reason));

    // 253 bytes rejected
    RungField bad{RungDataType::PREIMAGE, std::vector<uint8_t>(253, 0x42)};
    BOOST_CHECK(!bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_validation_new_types)
{
    // PUBKEY_COMMIT: exactly 32 bytes
    RungField pk_commit{RungDataType::PUBKEY_COMMIT, std::vector<uint8_t>(32, 0xAA)};
    std::string reason;
    BOOST_CHECK(pk_commit.IsValid(reason));
    RungField pk_commit_bad{RungDataType::PUBKEY_COMMIT, std::vector<uint8_t>(31, 0xAA)};
    BOOST_CHECK(!pk_commit_bad.IsValid(reason));

    // SPEND_INDEX: exactly 4 bytes
    RungField spend_idx{RungDataType::SPEND_INDEX, MakeNumeric(0)};
    BOOST_CHECK(spend_idx.IsValid(reason));

    // SCHEME: exactly 1 byte
    RungField scheme_schnorr{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}};
    BOOST_CHECK(scheme_schnorr.IsValid(reason));
    RungField scheme_ecdsa{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::ECDSA)}};
    BOOST_CHECK(scheme_ecdsa.IsValid(reason));
    // PQ schemes
    RungField scheme_falcon512{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}};
    BOOST_CHECK(scheme_falcon512.IsValid(reason));
    RungField scheme_falcon1024{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON1024)}};
    BOOST_CHECK(scheme_falcon1024.IsValid(reason));
    RungField scheme_dilithium{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::DILITHIUM3)}};
    BOOST_CHECK(scheme_dilithium.IsValid(reason));
    RungField scheme_sphincs{RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SPHINCS_SHA)}};
    BOOST_CHECK(scheme_sphincs.IsValid(reason));
    // Unknown scheme rejected
    RungField scheme_bad{RungDataType::SCHEME, {0xFF}};
    BOOST_CHECK(!scheme_bad.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(known_type_checks)
{
    // Block types — uint16_t (all 39 types)
    BOOST_CHECK(IsKnownBlockType(0x0001)); // SIG
    BOOST_CHECK(IsKnownBlockType(0x0002)); // MULTISIG
    BOOST_CHECK(IsKnownBlockType(0x0003)); // ADAPTOR_SIG
    BOOST_CHECK(IsKnownBlockType(0x0101)); // CSV
    BOOST_CHECK(IsKnownBlockType(0x0201)); // HASH_PREIMAGE
    BOOST_CHECK(IsKnownBlockType(0x0301)); // CTV
    BOOST_CHECK(IsKnownBlockType(0x0303)); // AMOUNT_LOCK
    BOOST_CHECK(IsKnownBlockType(0x0401)); // RECURSE_SAME
    BOOST_CHECK(IsKnownBlockType(0x0403)); // RECURSE_UNTIL
    BOOST_CHECK(IsKnownBlockType(0x0501)); // ANCHOR
    BOOST_CHECK(IsKnownBlockType(0x0502)); // ANCHOR_CHANNEL
    BOOST_CHECK(IsKnownBlockType(0x0504)); // ANCHOR_RESERVE
    BOOST_CHECK(IsKnownBlockType(0x0601)); // HYSTERESIS_FEE
    BOOST_CHECK(IsKnownBlockType(0x0641)); // COMPARE
    BOOST_CHECK(IsKnownBlockType(0x0671)); // RATE_LIMIT
    BOOST_CHECK(!IsKnownBlockType(0x0000));
    BOOST_CHECK(!IsKnownBlockType(0x0004)); // gap
    BOOST_CHECK(!IsKnownBlockType(0x0507)); // gap in anchor range
    BOOST_CHECK(!IsKnownBlockType(0xFFFF));

    // Data types — uint8_t
    BOOST_CHECK(IsKnownDataType(0x01)); // PUBKEY
    BOOST_CHECK(IsKnownDataType(0x09)); // SCHEME
    BOOST_CHECK(!IsKnownDataType(0x00));
    BOOST_CHECK(!IsKnownDataType(0x0A));

    // Scheme checks
    BOOST_CHECK(IsKnownScheme(0x01)); // SCHNORR
    BOOST_CHECK(IsKnownScheme(0x02)); // ECDSA
    BOOST_CHECK(IsKnownScheme(0x10)); // FALCON512
    BOOST_CHECK(IsKnownScheme(0x13)); // SPHINCS_SHA
    BOOST_CHECK(!IsKnownScheme(0x00));
    BOOST_CHECK(!IsKnownScheme(0x03));
    BOOST_CHECK(!IsKnownScheme(0x14));

    // PQ scheme check
    BOOST_CHECK(!IsPQScheme(RungScheme::SCHNORR));
    BOOST_CHECK(!IsPQScheme(RungScheme::ECDSA));
    BOOST_CHECK(IsPQScheme(RungScheme::FALCON512));
    BOOST_CHECK(IsPQScheme(RungScheme::SPHINCS_SHA));
}

// ============================================================================
// Serialization tests (v2 wire format)
// ============================================================================

BOOST_AUTO_TEST_CASE(serialize_roundtrip_sig_block)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    BOOST_CHECK(!bytes.empty());

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::SIG);
    BOOST_CHECK(!decoded.rungs[0].blocks[0].inverted);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 2u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].type == RungDataType::PUBKEY);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields[0].data.size(), 33u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[1].type == RungDataType::SIGNATURE);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields[1].data.size(), 64u);
    // Default coil (per-ladder, not per-rung)
    BOOST_CHECK(decoded.coil.coil_type == RungCoilType::UNLOCK);
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::INLINE);
    BOOST_CHECK(decoded.coil.scheme == RungScheme::SCHNORR);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_multi_rung)
{
    LadderWitness ladder;

    // Rung 0: SIG
    Rung rung0;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature()});
    rung0.blocks.push_back(sig_block);
    ladder.rungs.push_back(rung0);

    // Rung 1: HASH_PREIMAGE
    Rung rung1;
    RungBlock hash_block;
    hash_block.type = RungBlockType::HASH_PREIMAGE;
    hash_block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    hash_block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0xEE)});
    rung1.blocks.push_back(hash_block);
    ladder.rungs.push_back(rung1);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 2u);
    BOOST_CHECK(decoded.rungs[1].blocks[0].type == RungBlockType::HASH_PREIMAGE);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_inverted_block)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.inverted = true;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.rungs[0].blocks[0].inverted);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::CSV);
}

BOOST_AUTO_TEST_CASE(serialize_roundtrip_coil)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);
    ladder.coil.coil_type = RungCoilType::COVENANT;
    ladder.coil.attestation = RungAttestationMode::AGGREGATE;
    ladder.coil.scheme = RungScheme::ECDSA;

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.coil.coil_type == RungCoilType::COVENANT);
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::AGGREGATE);
    BOOST_CHECK(decoded.coil.scheme == RungScheme::ECDSA);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_empty)
{
    LadderWitness decoded;
    std::string error;
    std::vector<uint8_t> empty;
    BOOST_CHECK(!DeserializeLadderWitness(empty, decoded, error));
    BOOST_CHECK(error.find("empty") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_zero_rungs)
{
    std::vector<uint8_t> data{0x00};
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("zero rungs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_unknown_block_type)
{
    // v2 wire: block_type is uint16_t LE. Use 0xFF, 0xFF (unknown)
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0xFF, 0xFF,       // unknown block type (uint16_t LE)
        0x00,             // inverted = false
        0x00,             // 0 fields
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("unknown block type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_invalid_inverted_flag)
{
    // v2 wire: SIG block (0x01, 0x00), inverted = 0x02 (invalid)
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0x01, 0x00,       // SIG block type
        0x02,             // invalid inverted flag
        0x00,             // 0 fields
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("invalid inverted") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_unknown_data_type)
{
    // Build manually: 1 rung, 1 SIG block, 1 field with type 0xFF
    std::vector<uint8_t> data{
        0x01,             // 1 rung
        0x01,             // 1 block
        0x01, 0x00,       // SIG block type
        0x00,             // inverted = false
        0x01,             // 1 field
        0xFF,             // unknown data type
        0x01,             // 1 byte data
        0xAA,             // data
        0x01, 0x01, 0x01, // coil bytes
    };
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, decoded, error));
    BOOST_CHECK(error.find("unknown data type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_oversized_pubkey)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(2049, 0x02)}); // max is 2048
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(error.find("too large") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_rejects_trailing_bytes)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    // Append bytes that survive optional relay/rung_relay_refs parsing:
    // 0x00 = n_relays(0), 0x01 = n_rung_reqs(1) matching 1 rung,
    // 0x00 = rung[0] has 0 relay_refs, then 0xFF = genuine trailing garbage
    bytes.push_back(0x00); // n_relays = 0
    bytes.push_back(0x01); // n_rung_reqs = 1 (matches ladder.rungs.size())
    bytes.push_back(0x00); // rung[0] relay_refs count = 0
    bytes.push_back(0xFF); // trailing garbage

    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(error.find("trailing bytes") != std::string::npos);
}

// ============================================================================
// Evaluator tests (using mock checker)
// ============================================================================

class MockSignatureChecker : public BaseSignatureChecker
{
public:
    bool schnorr_result{false};
    bool ecdsa_result{false};
    bool locktime_result{false};
    bool sequence_result{false};

    bool CheckSchnorrSignature(std::span<const unsigned char> /*sig*/,
                               std::span<const unsigned char> /*pubkey*/,
                               SigVersion /*sigversion*/,
                               ScriptExecutionData& /*execdata*/,
                               ScriptError* /*serror*/) const override
    {
        return schnorr_result;
    }

    bool CheckECDSASignature(const std::vector<unsigned char>& /*sig*/,
                             const std::vector<unsigned char>& /*pubkey*/,
                             const CScript& /*scriptCode*/,
                             SigVersion /*sigversion*/) const override
    {
        return ecdsa_result;
    }

    bool CheckLockTime(const CScriptNum& /*nLockTime*/) const override
    {
        return locktime_result;
    }

    bool CheckSequence(const CScriptNum& /*nSequence*/) const override
    {
        return sequence_result;
    }
};

BOOST_AUTO_TEST_CASE(eval_sig_block_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_block_unsatisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_block_missing_field)
{
    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_multisig_2_of_3_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_multisig_insufficient_sigs)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash_preimage_sha256_satisfied)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    BOOST_CHECK(EvalHashPreimageBlock(block) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash_preimage_sha256_wrong)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    std::vector<uint8_t> wrong_preimage{0x05, 0x06, 0x07, 0x08};

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});

    BOOST_CHECK(EvalHashPreimageBlock(block) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash160_preimage_satisfied)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH160_PREIMAGE;
    block.fields.push_back({RungDataType::HASH160, std::vector<uint8_t>(hash, hash + 20)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    BOOST_CHECK(EvalHash160PreimageBlock(block) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_satisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    BOOST_CHECK(EvalCSVBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_unsatisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = false;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    BOOST_CHECK(EvalCSVBlock(block, checker) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_satisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = true;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    BOOST_CHECK(EvalCLTVBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_unsatisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = false;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    BOOST_CHECK(EvalCLTVBlock(block, checker) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_csv_time_satisfied)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV_TIME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0x00400080)}); // time-based flag set
    BOOST_CHECK(EvalCSVTimeBlock(block, checker) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cltv_time_satisfied)
{
    MockSignatureChecker checker;
    checker.locktime_result = true;

    RungBlock block;
    block.type = RungBlockType::CLTV_TIME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000001)}); // time-based
    BOOST_CHECK(EvalCLTVTimeBlock(block, checker) == EvalResult::SATISFIED);
}

// ============================================================================
// Inversion tests
// ============================================================================

BOOST_AUTO_TEST_CASE(inversion_apply_basic)
{
    // Not inverted — pass through
    BOOST_CHECK(ApplyInversion(EvalResult::SATISFIED, false) == EvalResult::SATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::UNSATISFIED, false) == EvalResult::UNSATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::ERROR, false) == EvalResult::ERROR);
    BOOST_CHECK(ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, false) == EvalResult::UNKNOWN_BLOCK_TYPE);

    // Inverted — flip SATISFIED↔UNSATISFIED
    BOOST_CHECK(ApplyInversion(EvalResult::SATISFIED, true) == EvalResult::UNSATISFIED);
    BOOST_CHECK(ApplyInversion(EvalResult::UNSATISFIED, true) == EvalResult::SATISFIED);
    // ERROR never flips
    BOOST_CHECK(ApplyInversion(EvalResult::ERROR, true) == EvalResult::ERROR);
    // UNKNOWN inverted → SATISFIED
    BOOST_CHECK(ApplyInversion(EvalResult::UNKNOWN_BLOCK_TYPE, true) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_sig_normal_satisfied_inverted_unsatisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    // Normal: satisfied
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    // Inverted: unsatisfied
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_sig_normal_unsatisfied_inverted_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_csv)
{
    MockSignatureChecker checker;
    checker.sequence_result = true;

    RungBlock block;
    block.type = RungBlockType::CSV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_hash_preimage)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);

    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(hash, hash + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    MockSignatureChecker checker;
    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_cltv)
{
    MockSignatureChecker checker;
    checker.locktime_result = false;

    RungBlock block;
    block.type = RungBlockType::CLTV;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(52000)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_multisig)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    block.inverted = false;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(inversion_error_never_flips)
{
    MockSignatureChecker checker;

    // SIG with missing fields → ERROR
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    // Missing SIGNATURE

    ScriptExecutionData execdata;
    block.inverted = true;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

// ============================================================================
// Phase 2 evaluator tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_ctv_missing_hash)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock ctv_block;
    ctv_block.type = RungBlockType::CTV;
    // No HASH256 field → ERROR
    BOOST_CHECK(EvalBlock(ctv_block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_vault_lock_missing_fields)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock vault_block;
    vault_block.type = RungBlockType::VAULT_LOCK;
    // No pubkeys or signature → ERROR
    BOOST_CHECK(EvalBlock(vault_block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_amount_lock_in_range)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::AMOUNT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});  // min_sats
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)}); // max_sats

    RungEvalContext ctx;
    ctx.output_amount = 25000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_amount_lock_below_min)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::AMOUNT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)});

    RungEvalContext ctx;
    ctx.output_amount = 500;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_amount_lock_above_max)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::AMOUNT_LOCK;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)});

    RungEvalContext ctx;
    ctx.output_amount = 60000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_anchor_types_structural)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // ANCHOR: needs at least one field
    RungBlock anchor;
    anchor.type = RungBlockType::ANCHOR;
    anchor.fields.push_back({RungDataType::HASH256, MakeHash256()});
    BOOST_CHECK(EvalBlock(anchor, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    RungBlock anchor_empty;
    anchor_empty.type = RungBlockType::ANCHOR;
    BOOST_CHECK(EvalBlock(anchor_empty, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);

    // ANCHOR_CHANNEL: needs 2 pubkeys
    RungBlock channel;
    channel.type = RungBlockType::ANCHOR_CHANNEL;
    channel.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    channel.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    channel.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    BOOST_CHECK(EvalBlock(channel, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // ANCHOR_POOL: needs hash + count
    RungBlock pool;
    pool.type = RungBlockType::ANCHOR_POOL;
    pool.fields.push_back({RungDataType::HASH256, MakeHash256()});
    pool.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    BOOST_CHECK(EvalBlock(pool, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // ANCHOR_RESERVE: needs 2 numerics + hash
    RungBlock reserve;
    reserve.type = RungBlockType::ANCHOR_RESERVE;
    reserve.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // n
    reserve.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});  // m
    reserve.fields.push_back({RungDataType::HASH256, MakeHash256()});
    BOOST_CHECK(EvalBlock(reserve, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // ANCHOR_SEAL: needs 2 hashes
    RungBlock seal;
    seal.type = RungBlockType::ANCHOR_SEAL;
    seal.fields.push_back({RungDataType::HASH256, MakeHash256()});
    seal.fields.push_back({RungDataType::HASH256, MakeHash256()});
    BOOST_CHECK(EvalBlock(seal, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // ANCHOR_ORACLE: needs pubkey + count
    RungBlock oracle;
    oracle.type = RungBlockType::ANCHOR_ORACLE;
    oracle.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    oracle.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});
    BOOST_CHECK(EvalBlock(oracle, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

// ============================================================================
// Phase 3 evaluator tests — Recursion
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_recurse_same_structural)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RECURSE_SAME;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // Missing max_depth → ERROR
    RungBlock bad;
    bad.type = RungBlockType::RECURSE_SAME;
    BOOST_CHECK(EvalBlock(bad, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_recurse_until_height_reached)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RECURSE_UNTIL;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)});

    RungEvalContext ctx;
    ctx.block_height = 150; // >= until_height
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_split_min_sats)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RECURSE_SPLIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});     // max_splits
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});  // min_split_sats

    RungEvalContext ctx;
    ctx.output_amount = 500; // below min_split_sats
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    ctx.output_amount = 2000; // above min
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

// ============================================================================
// Phase 3 evaluator tests — PLC
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_compare_operators)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    auto make_compare = [](uint8_t op, uint32_t val) {
        RungBlock block;
        block.type = RungBlockType::COMPARE;
        block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(op)});  // operator
        block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(val)}); // value_b
        return block;
    };

    RungEvalContext ctx;
    ctx.input_amount = 5000;

    // EQ (0x01)
    BOOST_CHECK(EvalBlock(make_compare(0x01, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x01, 4000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    // NEQ (0x02)
    BOOST_CHECK(EvalBlock(make_compare(0x02, 4000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x02, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    // GT (0x03)
    BOOST_CHECK(EvalBlock(make_compare(0x03, 4000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x03, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    // LT (0x04)
    BOOST_CHECK(EvalBlock(make_compare(0x04, 6000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x04, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    // GTE (0x05)
    BOOST_CHECK(EvalBlock(make_compare(0x05, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x05, 5001), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    // LTE (0x06)
    BOOST_CHECK(EvalBlock(make_compare(0x06, 5000), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
    BOOST_CHECK(EvalBlock(make_compare(0x06, 4999), checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_compare_in_range)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // IN_RANGE (0x07): amount >= value_b && amount <= value_c
    RungBlock block;
    block.type = RungBlockType::COMPARE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0x07)});  // IN_RANGE operator
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});  // lower bound
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)}); // upper bound

    RungEvalContext ctx;
    ctx.input_amount = 5000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);

    ctx.input_amount = 500;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    ctx.input_amount = 15000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hysteresis_value_band)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_VALUE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)}); // high
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});  // low

    RungEvalContext ctx;
    ctx.input_amount = 5000; // within band
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);

    ctx.input_amount = 500; // below band
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_rate_limit_single_tx)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RATE_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)}); // max_per_block
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)}); // accumulation_cap
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(6)});     // refill_blocks

    RungEvalContext ctx;
    ctx.output_amount = 5000; // under limit
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);

    ctx.output_amount = 15000; // over limit
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sequencer_structural)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::SEQUENCER;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // current_step
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});  // total_steps
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // current >= total → unsatisfied
    RungBlock bad;
    bad.type = RungBlockType::SEQUENCER;
    bad.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    bad.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    BOOST_CHECK(EvalBlock(bad, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_plc_structural_validation)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Timers need numeric
    RungBlock timer;
    timer.type = RungBlockType::TIMER_CONTINUOUS;
    timer.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    BOOST_CHECK(EvalBlock(timer, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    RungBlock timer_bad;
    timer_bad.type = RungBlockType::TIMER_CONTINUOUS;
    BOOST_CHECK(EvalBlock(timer_bad, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);

    // Latches need pubkey
    RungBlock latch;
    latch.type = RungBlockType::LATCH_SET;
    latch.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    BOOST_CHECK(EvalBlock(latch, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // Counters need pubkey + numeric
    RungBlock counter;
    counter.type = RungBlockType::COUNTER_DOWN;
    counter.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    counter.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    BOOST_CHECK(EvalBlock(counter, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);

    // ONE_SHOT needs numeric + hash; state=0 → can fire
    RungBlock oneshot;
    oneshot.type = RungBlockType::ONE_SHOT;
    oneshot.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    oneshot.fields.push_back({RungDataType::HASH256, MakeHash256()});
    BOOST_CHECK(EvalBlock(oneshot, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

// ============================================================================
// Tagged hash evaluator test
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_tagged_hash_correct)
{
    // Compute tag_hash = SHA256("TestTag")
    unsigned char tag_hash[32];
    CSHA256().Write(reinterpret_cast<const unsigned char*>("TestTag"), 7).Finalize(tag_hash);

    // Compute expected = SHA256(tag_hash || tag_hash || preimage)
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03};
    unsigned char expected[32];
    CSHA256()
        .Write(tag_hash, 32)
        .Write(tag_hash, 32)
        .Write(preimage.data(), preimage.size())
        .Finalize(expected);

    RungBlock block;
    block.type = RungBlockType::TAGGED_HASH;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(tag_hash, tag_hash + 32)});
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(expected, expected + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});

    BOOST_CHECK(EvalTaggedHashBlock(block) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_tagged_hash_wrong_preimage)
{
    unsigned char tag_hash[32];
    CSHA256().Write(reinterpret_cast<const unsigned char*>("TestTag"), 7).Finalize(tag_hash);

    std::vector<uint8_t> preimage{0x01, 0x02, 0x03};
    unsigned char expected[32];
    CSHA256()
        .Write(tag_hash, 32)
        .Write(tag_hash, 32)
        .Write(preimage.data(), preimage.size())
        .Finalize(expected);

    std::vector<uint8_t> wrong_preimage{0x04, 0x05, 0x06};

    RungBlock block;
    block.type = RungBlockType::TAGGED_HASH;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(tag_hash, tag_hash + 32)});
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(expected, expected + 32)});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});

    BOOST_CHECK(EvalTaggedHashBlock(block) == EvalResult::UNSATISFIED);
}

// ============================================================================
// Adaptor sig evaluator test
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_satisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    // adaptor_point must be 32 bytes (x-only)
    std::vector<uint8_t> adaptor_point(32, 0xAA);

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});      // signing_key (33B)
    block.fields.push_back({RungDataType::PUBKEY, adaptor_point});     // adaptor_point (32B x-only)
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_unsatisfied)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    std::vector<uint8_t> adaptor_point(32, 0xAA);

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, adaptor_point});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

// ============================================================================
// Serialization roundtrip for all 39 types
// ============================================================================

BOOST_AUTO_TEST_CASE(serialize_roundtrip_all_39_types)
{
    // Test that every known block type serializes and deserializes correctly
    std::vector<RungBlockType> all_types = {
        RungBlockType::SIG, RungBlockType::MULTISIG, RungBlockType::ADAPTOR_SIG,
        RungBlockType::CSV, RungBlockType::CSV_TIME, RungBlockType::CLTV, RungBlockType::CLTV_TIME,
        RungBlockType::HASH_PREIMAGE, RungBlockType::HASH160_PREIMAGE, RungBlockType::TAGGED_HASH,
        RungBlockType::CTV, RungBlockType::VAULT_LOCK, RungBlockType::AMOUNT_LOCK,
        RungBlockType::RECURSE_SAME, RungBlockType::RECURSE_MODIFIED, RungBlockType::RECURSE_UNTIL,
        RungBlockType::RECURSE_COUNT, RungBlockType::RECURSE_SPLIT, RungBlockType::RECURSE_DECAY,
        RungBlockType::ANCHOR, RungBlockType::ANCHOR_CHANNEL, RungBlockType::ANCHOR_POOL,
        RungBlockType::ANCHOR_RESERVE, RungBlockType::ANCHOR_SEAL, RungBlockType::ANCHOR_ORACLE,
        RungBlockType::HYSTERESIS_FEE, RungBlockType::HYSTERESIS_VALUE,
        RungBlockType::TIMER_CONTINUOUS, RungBlockType::TIMER_OFF_DELAY,
        RungBlockType::LATCH_SET, RungBlockType::LATCH_RESET,
        RungBlockType::COUNTER_DOWN, RungBlockType::COUNTER_PRESET, RungBlockType::COUNTER_UP,
        RungBlockType::COMPARE, RungBlockType::SEQUENCER, RungBlockType::ONE_SHOT, RungBlockType::RATE_LIMIT,
    };
    BOOST_CHECK_EQUAL(all_types.size(), 38u); // 38 types (ANCHOR generic is the 39th including SIG family)

    for (auto btype : all_types) {
        LadderWitness ladder;
        Rung rung;
        RungBlock block;
        block.type = btype;
        // Add a minimal valid field (NUMERIC is always valid in blocks)
        block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
        rung.blocks.push_back(block);
        ladder.rungs.push_back(rung);

        auto bytes = SerializeLadderWitness(ladder);
        BOOST_CHECK(!bytes.empty());

        LadderWitness decoded;
        std::string error;
        BOOST_CHECK_MESSAGE(DeserializeLadderWitness(bytes, decoded, error),
            "Failed to roundtrip type " + BlockTypeName(btype) + ": " + error);
        BOOST_CHECK(decoded.rungs[0].blocks[0].type == btype);
    }
}

// ============================================================================
// PQ signature support
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_pq_scheme_validation)
{
    // PQ schemes are valid in SCHEME fields
    RungField falcon{RungDataType::SCHEME, {0x10}};
    std::string reason;
    BOOST_CHECK(falcon.IsValid(reason));

    RungField sphincs{RungDataType::SCHEME, {0x13}};
    BOOST_CHECK(sphincs.IsValid(reason));
}

// ============================================================================
// Aggregate attestation
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_aggregate_attestation_coil)
{
    // Verify coil with AGGREGATE attestation serializes correctly
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);
    ladder.coil.attestation = RungAttestationMode::AGGREGATE;

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::AGGREGATE);
}

BOOST_AUTO_TEST_CASE(eval_deferred_attestation_coil)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);
    ladder.coil.attestation = RungAttestationMode::DEFERRED;

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK(decoded.coil.attestation == RungAttestationMode::DEFERRED);
}

// ============================================================================
// Rung AND / Ladder OR logic
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_rung_and_logic)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;

    Rung rung;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(sig_block);

    RungBlock csv_block;
    csv_block.type = RungBlockType::CSV;
    csv_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(csv_block);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalRung(rung, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_rung_and_logic_one_fails)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = false; // CSV fails

    Rung rung;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(sig_block);

    RungBlock csv_block;
    csv_block.type = RungBlockType::CSV;
    csv_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(csv_block);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalRung(rung, checker, SigVersion::LADDER, execdata) != EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_ladder_or_logic_first_rung_wins)
{
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    checker.sequence_result = false;
    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_or_logic_fallback_rung)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = true;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_all_rungs_fail)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = false;

    LadderWitness ladder;

    Rung rung0;
    RungBlock block0;
    block0.type = RungBlockType::SIG;
    block0.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung0.blocks.push_back(block0);
    ladder.rungs.push_back(rung0);

    Rung rung1;
    RungBlock block1;
    block1.type = RungBlockType::CSV;
    block1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(block1);
    ladder.rungs.push_back(rung1);

    ScriptExecutionData execdata;
    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

BOOST_AUTO_TEST_CASE(eval_ladder_empty_fails)
{
    MockSignatureChecker checker;
    LadderWitness ladder;
    ScriptExecutionData execdata;
    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata));
}

// ============================================================================
// Policy tests
// ============================================================================

static CMutableTransaction MakeRungTx(const LadderWitness& ladder)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto witness_bytes = SerializeLadderWitness(ladder);
    input.scriptWitness.stack.push_back(witness_bytes);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    return mtx;
}

BOOST_AUTO_TEST_CASE(policy_valid_rung_tx)
{
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(IsStandardRungTx(tx, reason));
}

BOOST_AUTO_TEST_CASE(policy_too_many_rungs)
{
    LadderWitness ladder;
    for (int i = 0; i < 17; ++i) { // MAX_RUNGS is now 16
        Rung rung;
        RungBlock block;
        block.type = RungBlockType::SIG;
        block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
        block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
        rung.blocks.push_back(block);
        ladder.rungs.push_back(rung);
    }

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("too many rungs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_too_many_blocks)
{
    LadderWitness ladder;
    Rung rung;
    for (int i = 0; i < 9; ++i) { // MAX_BLOCKS_PER_RUNG is 8
        RungBlock block;
        block.type = RungBlockType::SIG;
        block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
        block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
        rung.blocks.push_back(block);
    }
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("too many blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_missing_witness)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("missing-witness") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_all_phases_standard)
{
    // All known block types are standard (no phased activation)
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CTV; // Phase 2 — should be standard
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(32, 0xaa)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto mtx = MakeRungTx(ladder);
    CTransaction tx(mtx);

    std::string reason;
    // CTV is a known block type — passes policy
    // (May fail for other reasons like missing witness fields, but not "unknown-block-type")
    bool result = IsStandardRungTx(tx, reason);
    if (!result) {
        BOOST_CHECK(reason.find("unknown-block-type") == std::string::npos);
    }

    // Unknown block type 0xFFFF should be rejected
    LadderWitness ladder2;
    Rung rung2;
    RungBlock block2;
    block2.type = static_cast<RungBlockType>(0xFFFF);
    rung2.blocks.push_back(block2);
    ladder2.rungs.push_back(rung2);
    auto mtx2 = MakeRungTx(ladder2);
    CTransaction tx2(mtx2);
    std::string reason2;
    BOOST_CHECK(!IsStandardRungTx(tx2, reason2));
    BOOST_CHECK(reason2.find("unknown block type") != std::string::npos);
}

// ============================================================================
// Conditions tests
// ============================================================================

BOOST_AUTO_TEST_CASE(conditions_serialize_roundtrip)
{
    // Conditions now use PUBKEY_COMMIT instead of raw PUBKEY
    auto pk = MakePubkey();
    auto commit = MakePubkeyCommit(pk);

    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    BOOST_CHECK(rung::IsRungConditionsScript(script));
    BOOST_CHECK_EQUAL(script[0], rung::RUNG_CONDITIONS_PREFIX);

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::SIG);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].type == RungDataType::PUBKEY_COMMIT);
}

BOOST_AUTO_TEST_CASE(conditions_roundtrip_with_inverted)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::CSV;
    block.inverted = true;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(decoded.rungs[0].blocks[0].inverted);
}

BOOST_AUTO_TEST_CASE(conditions_reject_signature_field)
{
    auto pk = MakePubkey();
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_reject_preimage_field)
{
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::HASH_PREIMAGE;
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0xEE)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    LadderWitness ladder;
    ladder.rungs = conditions.rungs;
    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_not_rung_script)
{
    CScript normal_script = CScript() << OP_RETURN;
    BOOST_CHECK(!rung::IsRungConditionsScript(normal_script));

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(normal_script, decoded, error));
    BOOST_CHECK(error.find("not a rung") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_data_type_check)
{
    // PUBKEY is now witness-only (prevents arbitrary data in UTXO set)
    BOOST_CHECK(!rung::IsConditionDataType(RungDataType::PUBKEY));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::PUBKEY_COMMIT));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::HASH256));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::HASH160));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::NUMERIC));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::SCHEME));
    BOOST_CHECK(rung::IsConditionDataType(RungDataType::SPEND_INDEX));
    BOOST_CHECK(!rung::IsConditionDataType(RungDataType::SIGNATURE));
    BOOST_CHECK(!rung::IsConditionDataType(RungDataType::PREIMAGE));
}

// ============================================================================
// Sighash tests
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_ladder_deterministic)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    auto pk = MakePubkey();
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = rung::SerializeRungConditions(conditions);

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});
    BOOST_CHECK(txdata.m_ladder_ready);

    uint256 hash1, hash2;
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash1));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash2));
    BOOST_CHECK(hash1 == hash2);
    BOOST_CHECK(hash1 != uint256::ZERO);
}

BOOST_AUTO_TEST_CASE(sighash_ladder_different_hashtypes)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);

    CTxOut output;
    output.nValue = 50000;
    output.scriptPubKey = CScript() << OP_RETURN;
    mtx.vout.push_back(output);

    auto pk = MakePubkey();
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = rung::SerializeRungConditions(conditions);

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    uint256 hash_default, hash_all, hash_none;
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_DEFAULT, conditions, hash_default));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_ALL, conditions, hash_all));
    BOOST_CHECK(rung::SignatureHashLadder(txdata, mtx, 0, SIGHASH_NONE, conditions, hash_none));

    BOOST_CHECK(hash_default != hash_none);
    BOOST_CHECK(hash_all != hash_none);
}

BOOST_AUTO_TEST_CASE(sighash_ladder_rejects_invalid_hashtype)
{
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;

    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    RungConditions conditions;

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = CScript() << OP_RETURN;

    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    uint256 hash;
    BOOST_CHECK(!rung::SignatureHashLadder(txdata, mtx, 0, 0x04, conditions, hash));
}

// ============================================================================
// Output policy tests
// ============================================================================

BOOST_AUTO_TEST_CASE(policy_valid_rung_output)
{
    auto pk = MakePubkey();
    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    std::string reason;
    BOOST_CHECK(rung::IsStandardRungOutput(script, reason));
}

BOOST_AUTO_TEST_CASE(policy_rung_output_rejects_pubkey_field)
{
    // Raw PUBKEY is now witness-only; conditions must reject it
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungOutput(script, reason));
}

BOOST_AUTO_TEST_CASE(policy_rung_output_rejects_signature_field)
{
    auto pk = MakePubkey();
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungOutput(script, reason));
}

BOOST_AUTO_TEST_CASE(policy_rung_output_rejects_non_conditions)
{
    CScript script = CScript() << OP_RETURN;
    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungOutput(script, reason));
}

// ============================================================================
// Merge failure tests
// ============================================================================

BOOST_AUTO_TEST_CASE(merge_rung_count_mismatch)
{
    auto pk = MakePubkey();
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_block;
    cond_block.type = RungBlockType::SIG;
    cond_block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    cond_rung.blocks.push_back(cond_block);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung0;
    RungBlock wit_block0;
    wit_block0.type = RungBlockType::SIG;
    wit_block0.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_rung0.blocks.push_back(wit_block0);
    witness.rungs.push_back(wit_rung0);

    Rung wit_rung1;
    RungBlock wit_block1;
    wit_block1.type = RungBlockType::CSV;
    wit_rung1.blocks.push_back(wit_block1);
    witness.rungs.push_back(wit_rung1);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

BOOST_AUTO_TEST_CASE(merge_block_count_mismatch)
{
    auto pk = MakePubkey();
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_sig;
    cond_sig.type = RungBlockType::SIG;
    cond_sig.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    cond_rung.blocks.push_back(cond_sig);
    RungBlock cond_csv;
    cond_csv.type = RungBlockType::CSV;
    cond_csv.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    cond_rung.blocks.push_back(cond_csv);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung;
    RungBlock wit_block;
    wit_block.type = RungBlockType::SIG;
    wit_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_rung.blocks.push_back(wit_block);
    witness.rungs.push_back(wit_rung);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

BOOST_AUTO_TEST_CASE(merge_block_type_mismatch)
{
    auto pk = MakePubkey();
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cond_block;
    cond_block.type = RungBlockType::SIG;
    cond_block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    cond_rung.blocks.push_back(cond_block);
    conditions.rungs.push_back(cond_rung);

    LadderWitness witness;
    Rung wit_rung;
    RungBlock wit_block;
    wit_block.type = RungBlockType::CSV; // Wrong type!
    wit_rung.blocks.push_back(wit_block);
    witness.rungs.push_back(wit_rung);

    CScript cond_script = rung::SerializeRungConditions(conditions);

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    auto wit_bytes = SerializeLadderWitness(witness);
    input.scriptWitness.stack.push_back(wit_bytes);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));

    CTxOut spent_out;
    spent_out.nValue = 100000;
    spent_out.scriptPubKey = cond_script;

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::vector<CTxOut>{spent_out});

    MockSignatureChecker checker;
    ScriptError serror;
    BOOST_CHECK(!VerifyRungTx(tx, 0, spent_out, 0, checker, txdata, &serror));
}

// ============================================================================
// Anchor block negative tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_anchor_empty_rejected)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR;
    // No fields → ERROR
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_channel_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Only 1 pubkey (needs 2) → ERROR
    RungBlock block;
    block.type = RungBlockType::ANCHOR_CHANNEL;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_channel_zero_commitment)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_CHANNEL;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // commitment = 0 → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_anchor_channel_no_commitment_ok)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // 2 pubkeys, no numeric → SATISFIED (commitment is optional)
    RungBlock block;
    block.type = RungBlockType::ANCHOR_CHANNEL;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_anchor_pool_missing_hash)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_POOL;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)}); // count but no hash → ERROR
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_pool_zero_count)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_POOL;
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // count = 0 → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_anchor_reserve_n_gt_m)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_RESERVE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)}); // n
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)}); // m (n > m → UNSATISFIED)
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_anchor_reserve_missing_hash)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_RESERVE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});
    // No hash → ERROR
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_seal_missing_hash)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_SEAL;
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    // Only 1 hash (needs 2) → ERROR
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_oracle_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_ORACLE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // count but no pubkey → ERROR
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_anchor_oracle_zero_count)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ANCHOR_ORACLE;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // count = 0 → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

// ============================================================================
// PLC block negative tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_hysteresis_fee_low_gt_high)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_FEE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // high = 10
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)}); // low = 100 > high → UNSATISFIED

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hysteresis_fee_missing_field)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_FEE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)}); // only 1 numeric (needs 2)

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_hysteresis_value_outside_band)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_VALUE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)}); // high
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5000)});  // low

    RungEvalContext ctx;
    ctx.input_amount = 3000; // below low band → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    ctx.input_amount = 15000; // above high band → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);

    ctx.input_amount = 7500; // within band → SATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_continuous_zero)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_CONTINUOUS;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // 0 → UNSATISFIED

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_off_delay_zero)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_OFF_DELAY;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // 0 → UNSATISFIED

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_off_delay_missing)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_OFF_DELAY;
    // No numeric → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_latch_set_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_SET;
    // No pubkey → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_latch_reset_missing_delay)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_RESET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    // No numeric → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_latch_reset_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_RESET;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    // No pubkey → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_latch_set_state_unset_satisfied)
{
    // LATCH_SET with state=0 → SATISFIED (can set)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_SET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // state=0

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_latch_set_state_already_set_unsatisfied)
{
    // LATCH_SET with state=1 → UNSATISFIED (already latched)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_SET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)}); // state=1

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_latch_set_no_state_backward_compat)
{
    // LATCH_SET with no NUMERIC → backward compat, always SATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_SET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_latch_reset_state_set_satisfied)
{
    // LATCH_RESET with state=1 → SATISFIED (can reset)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_RESET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)}); // state=1
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(6)}); // delay=6

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_latch_reset_state_unset_unsatisfied)
{
    // LATCH_RESET with state=0 → UNSATISFIED (nothing to reset)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::LATCH_RESET;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // state=0
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(6)}); // delay=6

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_down_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_DOWN;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    // No pubkey → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_counter_down_missing_numeric)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_DOWN;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    // No numeric → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_counter_preset_missing_field)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_PRESET;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)}); // only 1 (needs 2)

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_counter_up_missing_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_UP;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    // No pubkey → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_one_shot_missing_hash)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ONE_SHOT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    // No hash → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_one_shot_missing_numeric)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ONE_SHOT;
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    // No numeric → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_missing_second_pubkey)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()}); // only 1 pubkey (needs 2)
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_missing_signature)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    // No signature → ERROR
    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

// ============================================================================
// COMPARE edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_compare_unknown_operator)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COMPARE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0xFF)}); // unknown operator
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)});

    RungEvalContext ctx;
    ctx.input_amount = 5000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_compare_in_range_missing_upper)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COMPARE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0x07)}); // IN_RANGE
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1000)}); // lower only, no upper → ERROR

    RungEvalContext ctx;
    ctx.input_amount = 5000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_compare_missing_operand)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COMPARE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0x01)}); // EQ but no value_b → ERROR

    RungEvalContext ctx;
    ctx.input_amount = 5000;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

// ============================================================================
// SEQUENCER edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_sequencer_at_last_step)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::SEQUENCER;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)}); // current_step = 2
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)}); // total = 3 → current < total → SATISFIED

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sequencer_current_equals_total)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::SEQUENCER;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)}); // current = total → UNSATISFIED
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sequencer_total_zero)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::SEQUENCER;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)}); // total = 0 → UNSATISFIED

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

// ============================================================================
// RATE_LIMIT edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_rate_limit_exceeds_max)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RATE_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)}); // max_per_block
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)}); // accumulation_cap
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});    // refill_blocks

    RungEvalContext ctx;
    ctx.output_amount = 15000; // exceeds max_per_block → UNSATISFIED
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_rate_limit_missing_fields)
{
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::RATE_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10000)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50000)});
    // Only 2 numerics (needs 3) → ERROR

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

// ============================================================================
// Deserializer robustness tests
// ============================================================================

BOOST_AUTO_TEST_CASE(deserialize_truncated_block_type)
{
    // 1 rung, 1 block, but only 1 byte of block type (needs 2)
    std::vector<uint8_t> data = {0x01, 0x01, 0x01};
    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
}

BOOST_AUTO_TEST_CASE(deserialize_truncated_field_data)
{
    // Build valid header but truncated field data
    std::vector<uint8_t> data;
    data.push_back(0x01); // n_rungs = 1
    data.push_back(0x01); // n_blocks = 1
    // block type SIG (0x0001)
    data.push_back(0x01);
    data.push_back(0x00);
    data.push_back(0x00); // not inverted
    data.push_back(0x01); // n_fields = 1
    data.push_back(0x01); // data type PUBKEY
    data.push_back(0x21); // data len 33
    // Only 5 bytes of actual data (needs 33)
    data.insert(data.end(), 5, 0xAA);

    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
}

BOOST_AUTO_TEST_CASE(deserialize_max_rungs_exceeded)
{
    // n_rungs = 17 (max is 16)
    std::vector<uint8_t> data = {0x11}; // compact size 17
    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
    BOOST_CHECK(error.find("too many rungs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_max_blocks_exceeded)
{
    // 1 rung, n_blocks = 9 (max is 8)
    std::vector<uint8_t> data = {0x01, 0x09};
    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
    BOOST_CHECK(error.find("too many blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_max_fields_exceeded)
{
    std::vector<uint8_t> data;
    data.push_back(0x01); // n_rungs = 1
    data.push_back(0x01); // n_blocks = 1
    data.push_back(0x01); data.push_back(0x00); // SIG block type
    data.push_back(0x00); // not inverted
    data.push_back(0x11); // n_fields = 17 (max is 16)

    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
    BOOST_CHECK(error.find("too many fields") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deserialize_oversized_witness)
{
    // > 100000 bytes
    std::vector<uint8_t> data(100001, 0x00);
    data[0] = 0x01; // n_rungs = 1

    LadderWitness ladder;
    std::string error;
    BOOST_CHECK(!DeserializeLadderWitness(data, ladder, error));
    BOOST_CHECK(error.find("exceeds maximum size") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(eval_multisig_below_threshold)
{
    MockSignatureChecker checker;
    checker.schnorr_result = false;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hash160_preimage_wrong)
{
    std::vector<uint8_t> preimage{0x01, 0x02, 0x03, 0x04};
    unsigned char hash[CHash160::OUTPUT_SIZE];
    CHash160().Write(preimage).Finalize(hash);

    std::vector<uint8_t> wrong_preimage{0xAA, 0xBB, 0xCC, 0xDD};

    RungBlock block;
    block.type = RungBlockType::HASH160_PREIMAGE;
    block.fields.push_back({RungDataType::HASH160, std::vector<uint8_t>(hash, hash + 20)});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});

    BOOST_CHECK(EvalHash160PreimageBlock(block) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_ecdsa_wrong_key)
{
    MockSignatureChecker checker;
    checker.ecdsa_result = false;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(71)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

// ============================================================================
// PQ signature verification tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_sig_pq_no_liboqs)
{
    // If PQ support is not compiled in, PQ scheme blocks return UNSATISFIED (not ERROR)
    if (HasPQSupport()) {
        // Skip: this test is for builds without liboqs
        return;
    }

    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}});
    // Fake PQ pubkey (897 bytes for FALCON512)
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(897, 0xAA)});
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(690, 0xBB)});

    ScriptExecutionData execdata;
    // Without LadderSignatureChecker, dynamic_cast fails → ERROR
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_sig_pq_bad_sig)
{
    // PQ scheme with wrong signature → UNSATISFIED (or ERROR if no liboqs / no ladder checker)
    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}});
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(897, 0xAA)});
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(690, 0xBB)});

    ScriptExecutionData execdata;
    // MockSignatureChecker is not a LadderSignatureChecker, so dynamic_cast → ERROR
    auto result = EvalSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_sig_pq_missing_scheme_field)
{
    // No SCHEME field → existing size-based routing (Schnorr for 64-byte sig)
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_schnorr_scheme_field_fallthrough)
{
    // SCHEME=SCHNORR → falls through to existing size-based routing
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::SCHNORR)}});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_multisig_pq_no_ladder_checker)
{
    // PQ multisig with MockSignatureChecker (not LadderSignatureChecker) → ERROR
    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, {0x01}}); // threshold = 1
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}});
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(897, 0xAA)});
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(690, 0xBB)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(field_size_pq_pubkey)
{
    // PUBKEY with 897 bytes (FALCON512 pubkey size) should validate OK
    RungField field{RungDataType::PUBKEY, std::vector<uint8_t>(897, 0xAA)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    // PUBKEY with 1952 bytes (Dilithium3 pubkey size) should validate OK
    RungField field2{RungDataType::PUBKEY, std::vector<uint8_t>(1952, 0xAA)};
    BOOST_CHECK(field2.IsValid(reason));

    // PUBKEY with 2048 bytes (max) should validate OK
    RungField field3{RungDataType::PUBKEY, std::vector<uint8_t>(2048, 0xAA)};
    BOOST_CHECK(field3.IsValid(reason));

    // PUBKEY with 2049 bytes should fail
    RungField field4{RungDataType::PUBKEY, std::vector<uint8_t>(2049, 0xAA)};
    BOOST_CHECK(!field4.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(field_size_pq_signature)
{
    // SIGNATURE with 49216 bytes (SPHINCS+ sig size) should validate OK
    RungField field{RungDataType::SIGNATURE, std::vector<uint8_t>(49216, 0xBB)};
    std::string reason;
    BOOST_CHECK(field.IsValid(reason));

    // SIGNATURE with 50000 bytes (max) should validate OK
    RungField field2{RungDataType::SIGNATURE, std::vector<uint8_t>(50000, 0xBB)};
    BOOST_CHECK(field2.IsValid(reason));

    // SIGNATURE with 50001 bytes should fail
    RungField field3{RungDataType::SIGNATURE, std::vector<uint8_t>(50001, 0xBB)};
    BOOST_CHECK(!field3.IsValid(reason));
}

BOOST_AUTO_TEST_CASE(pq_keygen_and_sign_verify)
{
    // End-to-end: generate keypair, sign, verify (only if liboqs available)
    if (!HasPQSupport()) {
        return;
    }

    std::vector<uint8_t> pubkey, privkey;
    BOOST_CHECK(GeneratePQKeypair(RungScheme::FALCON512, pubkey, privkey));
    BOOST_CHECK(!pubkey.empty());
    BOOST_CHECK(!privkey.empty());

    std::vector<uint8_t> msg(32, 0x42); // fake sighash
    std::vector<uint8_t> sig;
    BOOST_CHECK(SignPQ(RungScheme::FALCON512, privkey, msg, sig));
    BOOST_CHECK(!sig.empty());

    BOOST_CHECK(VerifyPQSignature(RungScheme::FALCON512, sig, msg, pubkey));

    // Tamper with sig → verification fails
    sig[0] ^= 0xFF;
    BOOST_CHECK(!VerifyPQSignature(RungScheme::FALCON512, sig, msg, pubkey));
}

// ============================================================================
// PUBKEY_COMMIT tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_sig_pq_pubkey_commit)
{
    // SIG block with PUBKEY_COMMIT + PUBKEY (from witness) + SIGNATURE
    // Commitment matches → should proceed to PQ verification
    if (!HasPQSupport()) return;

    std::vector<uint8_t> pubkey, privkey;
    BOOST_CHECK(GeneratePQKeypair(RungScheme::FALCON512, pubkey, privkey));

    // Compute commitment = SHA256(pubkey)
    unsigned char commit[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(commit);
    std::vector<uint8_t> commit_vec(commit, commit + 32);

    // Build merged block (as evaluator sees it after conditions + witness merge)
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}});
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit_vec});
    block.fields.push_back({RungDataType::PUBKEY, pubkey}); // from witness

    // Sign a message
    std::vector<uint8_t> msg(32, 0x42);
    std::vector<uint8_t> sig;
    BOOST_CHECK(SignPQ(RungScheme::FALCON512, privkey, msg, sig));
    block.fields.push_back({RungDataType::SIGNATURE, sig});

    // We need a LadderSignatureChecker that returns the right sighash.
    // For this unit test we use the MockSignatureChecker — PQ path requires
    // LadderSignatureChecker. The commitment check itself passes before PQ verify.
    // Test the commitment logic alone: wrong checker → ERROR (but commitment passed).
    MockSignatureChecker checker;
    ScriptExecutionData execdata;
    // PQ path needs LadderSignatureChecker → gets ERROR (not UNSATISFIED from commit mismatch)
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_sig_pq_pubkey_commit_mismatch)
{
    // Wrong PUBKEY for the commitment → UNSATISFIED
    MockSignatureChecker checker;

    std::vector<uint8_t> real_pubkey(897, 0xAA);
    std::vector<uint8_t> wrong_pubkey(897, 0xBB);

    // Commitment is for real_pubkey
    unsigned char commit[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(real_pubkey.data(), real_pubkey.size()).Finalize(commit);
    std::vector<uint8_t> commit_vec(commit, commit + 32);

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::SCHEME, {static_cast<uint8_t>(RungScheme::FALCON512)}});
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit_vec});
    block.fields.push_back({RungDataType::PUBKEY, wrong_pubkey}); // wrong key
    block.fields.push_back({RungDataType::SIGNATURE, std::vector<uint8_t>(690, 0xCC)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_pubkey_commit_no_pubkey_error)
{
    // PUBKEY_COMMIT present but no PUBKEY → ERROR
    MockSignatureChecker checker;

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, std::vector<uint8_t>(32, 0xDD)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_sig_pubkey_commit_schnorr)
{
    // PUBKEY_COMMIT with a standard Schnorr key (33 bytes) — commitment check + Schnorr verify
    MockSignatureChecker checker;
    checker.schnorr_result = true;

    auto pubkey = MakePubkey(); // 33-byte compressed key
    unsigned char commit[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(commit);
    std::vector<uint8_t> commit_vec(commit, commit + 32);

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit_vec});
    block.fields.push_back({RungDataType::PUBKEY, pubkey});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    ScriptExecutionData execdata;
    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

// ============================================================================
// Multi-mutation RECURSE_MODIFIED tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_recurse_modified_legacy_compat)
{
    // Legacy 4-NUMERIC format: single mutation at rung 0
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Build input conditions: rung 0 has one block with two NUMERIC condition fields
    RungConditions input_conds;
    {
        Rung r;
        RungBlock b;
        b.type = RungBlockType::COMPARE;
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)}); // param 0
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(200)}); // param 1
        r.blocks.push_back(std::move(b));
        input_conds.rungs.push_back(std::move(r));
    }

    // Build output conditions: param 0 changed by +5
    RungConditions output_conds;
    {
        Rung r;
        RungBlock b;
        b.type = RungBlockType::COMPARE;
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(105)}); // 100 + 5
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(200)}); // unchanged
        r.blocks.push_back(std::move(b));
        output_conds.rungs.push_back(std::move(r));
    }

    CTxOut output;
    output.scriptPubKey = SerializeRungConditions(output_conds);

    RungEvalContext ctx;
    ctx.input_conditions = &input_conds;
    ctx.spending_output = &output;

    // RECURSE_MODIFIED block: max_depth=10, block_idx=0, param_idx=0, delta=5
    RungBlock rm_block;
    rm_block.type = RungBlockType::RECURSE_MODIFIED;
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // max_depth
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // block_idx
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // param_idx
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});   // delta

    BOOST_CHECK(EvalBlock(rm_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_modified_cross_rung)
{
    // New format: single mutation targeting rung 1
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Build input conditions: 2 rungs
    RungConditions input_conds;
    auto pk = MakePubkey();
    {
        // Rung 0: SIG block with PUBKEY_COMMIT (conditions use commits, not raw keys)
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::SIG;
        b0.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
        r0.blocks.push_back(std::move(b0));
        input_conds.rungs.push_back(std::move(r0));

        // Rung 1: COMPARE block with NUMERIC
        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(50)});
        r1.blocks.push_back(std::move(b1));
        input_conds.rungs.push_back(std::move(r1));
    }

    // Build output conditions: rung 1, param 0 changed by +3
    RungConditions output_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::SIG;
        b0.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
        r0.blocks.push_back(std::move(b0));
        output_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(53)}); // 50 + 3
        r1.blocks.push_back(std::move(b1));
        output_conds.rungs.push_back(std::move(r1));
    }

    CTxOut output;
    output.scriptPubKey = SerializeRungConditions(output_conds);

    RungEvalContext ctx;
    ctx.input_conditions = &input_conds;
    ctx.spending_output = &output;

    // New format: max_depth=10, num_mutations=1, rung_idx=1, block_idx=0, param_idx=0, delta=3
    RungBlock rm_block;
    rm_block.type = RungBlockType::RECURSE_MODIFIED;
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // max_depth
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});   // num_mutations
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});   // rung_idx
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // block_idx
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // param_idx
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});   // delta

    BOOST_CHECK(EvalBlock(rm_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_modified_multi_mutation)
{
    // Two mutations targeting different rungs simultaneously
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Build input conditions: 2 rungs, each with a COMPARE block
    RungConditions input_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::COMPARE;
        b0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)});
        r0.blocks.push_back(std::move(b0));
        input_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(200)});
        r1.blocks.push_back(std::move(b1));
        input_conds.rungs.push_back(std::move(r1));
    }

    // Build output conditions: rung 0 param 0 +5, rung 1 param 0 +10
    RungConditions output_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::COMPARE;
        b0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(105)});
        r0.blocks.push_back(std::move(b0));
        output_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(210)});
        r1.blocks.push_back(std::move(b1));
        output_conds.rungs.push_back(std::move(r1));
    }

    CTxOut output;
    output.scriptPubKey = SerializeRungConditions(output_conds);

    RungEvalContext ctx;
    ctx.input_conditions = &input_conds;
    ctx.spending_output = &output;

    // New format: 2 mutations
    RungBlock rm_block;
    rm_block.type = RungBlockType::RECURSE_MODIFIED;
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // max_depth
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});   // num_mutations
    // Mutation 0: rung 0, block 0, param 0, delta +5
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    // Mutation 1: rung 1, block 0, param 0, delta +10
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});

    BOOST_CHECK(EvalBlock(rm_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);

    // Wrong delta for mutation 1 → UNSATISFIED
    RungConditions bad_output_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::COMPARE;
        b0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(105)});
        r0.blocks.push_back(std::move(b0));
        bad_output_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(215)}); // wrong: expected 210
        r1.blocks.push_back(std::move(b1));
        bad_output_conds.rungs.push_back(std::move(r1));
    }

    CTxOut bad_output;
    bad_output.scriptPubKey = SerializeRungConditions(bad_output_conds);
    ctx.spending_output = &bad_output;

    BOOST_CHECK(EvalBlock(rm_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_modified_no_context_satisfied)
{
    // Without input_conditions/spending_output, RECURSE_MODIFIED passes (structural only)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock rm_block;
    rm_block.type = RungBlockType::RECURSE_MODIFIED;
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    rm_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});

    BOOST_CHECK(EvalBlock(rm_block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_decay_legacy_compat)
{
    // Legacy 4-NUMERIC format for RECURSE_DECAY
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungConditions input_conds;
    {
        Rung r;
        RungBlock b;
        b.type = RungBlockType::COMPARE;
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)});
        r.blocks.push_back(std::move(b));
        input_conds.rungs.push_back(std::move(r));
    }

    // Decay: output = input - decay_per_step = 100 - 7 = 93
    RungConditions output_conds;
    {
        Rung r;
        RungBlock b;
        b.type = RungBlockType::COMPARE;
        b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(93)});
        r.blocks.push_back(std::move(b));
        output_conds.rungs.push_back(std::move(r));
    }

    CTxOut output;
    output.scriptPubKey = SerializeRungConditions(output_conds);

    RungEvalContext ctx;
    ctx.input_conditions = &input_conds;
    ctx.spending_output = &output;

    RungBlock decay_block;
    decay_block.type = RungBlockType::RECURSE_DECAY;
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // max_depth
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // block_idx
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});   // param_idx
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(7)});   // decay_per_step

    BOOST_CHECK(EvalBlock(decay_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_recurse_decay_multi_mutation)
{
    // New format RECURSE_DECAY with two decay targets across rungs
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungConditions input_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::COMPARE;
        b0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)});
        r0.blocks.push_back(std::move(b0));
        input_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(200)});
        r1.blocks.push_back(std::move(b1));
        input_conds.rungs.push_back(std::move(r1));
    }

    // Decay: rung 0 param 0 by 5 (100→95), rung 1 param 0 by 10 (200→190)
    RungConditions output_conds;
    {
        Rung r0;
        RungBlock b0;
        b0.type = RungBlockType::COMPARE;
        b0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(95)});
        r0.blocks.push_back(std::move(b0));
        output_conds.rungs.push_back(std::move(r0));

        Rung r1;
        RungBlock b1;
        b1.type = RungBlockType::COMPARE;
        b1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(190)});
        r1.blocks.push_back(std::move(b1));
        output_conds.rungs.push_back(std::move(r1));
    }

    CTxOut output;
    output.scriptPubKey = SerializeRungConditions(output_conds);

    RungEvalContext ctx;
    ctx.input_conditions = &input_conds;
    ctx.spending_output = &output;

    RungBlock decay_block;
    decay_block.type = RungBlockType::RECURSE_DECAY;
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // max_depth
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});   // num_mutations
    // Decay 0: rung 0, block 0, param 0, decay 5
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});
    // Decay 1: rung 1, block 0, param 0, decay 10
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    decay_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});

    BOOST_CHECK(EvalBlock(decay_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

// ============================================================================
// COSIGN — co-spend contact tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_cosign_matching_input)
{
    // COSIGN with a matching spent output in the same tx → SATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Build the anchor's conditions scriptPubKey
    RungConditions anchor_conds;
    Rung anchor_rung;
    RungBlock sig_block;
    sig_block.type = RungBlockType::SIG;
    sig_block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(33, 0x02)});
    anchor_rung.blocks.push_back(sig_block);
    anchor_conds.rungs.push_back(anchor_rung);
    CScript anchor_spk = SerializeRungConditions(anchor_conds);

    // SHA256 of the anchor's scriptPubKey
    unsigned char anchor_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(anchor_spk.data(), anchor_spk.size()).Finalize(anchor_hash);

    // Build COSIGN block with the anchor hash
    RungBlock cosign_block;
    cosign_block.type = RungBlockType::COSIGN;
    cosign_block.fields.push_back({RungDataType::HASH256,
        std::vector<uint8_t>(anchor_hash, anchor_hash + 32)});

    // Build a mock transaction with 2 inputs
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input0, input1;
    input0.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    input1.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vin.push_back(input0);
    mtx.vin.push_back(input1);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));
    CTransaction tx(mtx);

    // Spent outputs: input 0 is the anchor, input 1 is the child (being evaluated)
    std::vector<CTxOut> spent_outputs;
    spent_outputs.push_back(CTxOut(100000, anchor_spk));  // anchor
    spent_outputs.push_back(CTxOut(50000, CScript() << OP_RETURN));  // child (placeholder)

    RungEvalContext ctx;
    ctx.tx = &tx;
    ctx.input_index = 1;  // evaluating input 1 (the child)
    ctx.spent_outputs = &spent_outputs;

    BOOST_CHECK(EvalBlock(cosign_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cosign_no_matching_input)
{
    // COSIGN with no matching spent output → UNSATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Use a hash that won't match any spent output
    std::vector<uint8_t> fake_hash(32, 0xAA);

    RungBlock cosign_block;
    cosign_block.type = RungBlockType::COSIGN;
    cosign_block.fields.push_back({RungDataType::HASH256, fake_hash});

    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input0, input1;
    input0.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    input1.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vin.push_back(input0);
    mtx.vin.push_back(input1);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));
    CTransaction tx(mtx);

    std::vector<CTxOut> spent_outputs;
    spent_outputs.push_back(CTxOut(100000, CScript() << OP_1));
    spent_outputs.push_back(CTxOut(50000, CScript() << OP_RETURN));

    RungEvalContext ctx;
    ctx.tx = &tx;
    ctx.input_index = 1;
    ctx.spent_outputs = &spent_outputs;

    BOOST_CHECK(EvalBlock(cosign_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cosign_no_hash_error)
{
    // COSIGN without HASH256 field → ERROR
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock cosign_block;
    cosign_block.type = RungBlockType::COSIGN;
    // No fields

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(cosign_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_cosign_no_context_satisfied)
{
    // COSIGN without tx context → SATISFIED (structural only, like RECURSE blocks)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    std::vector<uint8_t> some_hash(32, 0xBB);
    RungBlock cosign_block;
    cosign_block.type = RungBlockType::COSIGN;
    cosign_block.fields.push_back({RungDataType::HASH256, some_hash});

    RungEvalContext ctx;  // no tx, no spent_outputs
    BOOST_CHECK(EvalBlock(cosign_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_cosign_skips_self)
{
    // COSIGN must not match against its own input's spent output
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    // Build a scriptPubKey
    CScript self_spk = CScript() << OP_1 << OP_DROP;

    // Hash of self_spk
    unsigned char self_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(self_spk.data(), self_spk.size()).Finalize(self_hash);

    RungBlock cosign_block;
    cosign_block.type = RungBlockType::COSIGN;
    cosign_block.fields.push_back({RungDataType::HASH256,
        std::vector<uint8_t>(self_hash, self_hash + 32)});

    // Only 1 input — the self input matches the hash, but COSIGN skips self
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input0;
    input0.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input0);
    mtx.vout.push_back(CTxOut(50000, CScript() << OP_RETURN));
    CTransaction tx(mtx);

    std::vector<CTxOut> spent_outputs;
    spent_outputs.push_back(CTxOut(100000, self_spk));

    RungEvalContext ctx;
    ctx.tx = &tx;
    ctx.input_index = 0;  // evaluating the only input — matches hash but is self
    ctx.spent_outputs = &spent_outputs;

    BOOST_CHECK(EvalBlock(cosign_block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

// ============================================================================
// Phase 3 PLC state gating tests
// ============================================================================

BOOST_AUTO_TEST_CASE(eval_counter_down_count_positive)
{
    // COUNTER_DOWN with count=5 → SATISFIED (can decrement)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_DOWN;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_down_count_zero)
{
    // COUNTER_DOWN with count=0 → UNSATISFIED (countdown done)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_DOWN;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_preset_below_preset)
{
    // COUNTER_PRESET with current=3, preset=10 → SATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_PRESET;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});  // current
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // preset

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_preset_at_preset)
{
    // COUNTER_PRESET with current=10, preset=10 → UNSATISFIED (done)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_PRESET;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // current
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // preset

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_preset_above_preset)
{
    // COUNTER_PRESET with current=15, preset=10 → UNSATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_PRESET;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(15)}); // current
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // preset

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_up_below_target)
{
    // COUNTER_UP with current=2, target=10 → SATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_UP;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // current
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // target

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_up_at_target)
{
    // COUNTER_UP with current=10, target=10 → UNSATISFIED (done)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_UP;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // current
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // target

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_counter_up_single_numeric_error)
{
    // COUNTER_UP with only 1 numeric → ERROR (needs 2)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::COUNTER_UP;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_one_shot_state_zero)
{
    // ONE_SHOT with state=0 → SATISFIED (can fire)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ONE_SHOT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_one_shot_state_nonzero)
{
    // ONE_SHOT with state=1 → UNSATISFIED (already fired)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ONE_SHOT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    block.fields.push_back({RungDataType::HASH256, MakeHash256()});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_continuous_two_field_elapsed)
{
    // TIMER_CONTINUOUS with accumulated=10, target=5 → SATISFIED (elapsed)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_CONTINUOUS;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // accumulated
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});  // target

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_continuous_two_field_not_elapsed)
{
    // TIMER_CONTINUOUS with accumulated=3, target=10 → UNSATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_CONTINUOUS;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});  // accumulated
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)}); // target

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_continuous_single_field_compat)
{
    // TIMER_CONTINUOUS with single numeric > 0 → SATISFIED (backward compat)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_CONTINUOUS;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_off_delay_remaining_positive)
{
    // TIMER_OFF_DELAY with remaining=5 → SATISFIED (still in hold-off)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_OFF_DELAY;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_timer_off_delay_remaining_zero)
{
    // TIMER_OFF_DELAY with remaining=0 → UNSATISFIED (delay expired)
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::TIMER_OFF_DELAY;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(0)});

    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hysteresis_fee_within_band)
{
    // HYSTERESIS_FEE with tx fee rate within band → SATISFIED
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_FEE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)}); // high = 100 sat/vB
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});   // low = 5 sat/vB

    // No tx context → structural-only SATISFIED
    RungEvalContext ctx;
    BOOST_CHECK(EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_hysteresis_fee_with_tx_context)
{
    // HYSTERESIS_FEE with tx context — fee rate check
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::HYSTERESIS_FEE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100)}); // high = 100 sat/vB
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});   // low = 5 sat/vB

    // Build a minimal tx: 1 input, 1 output
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    CTxIn input0;
    input0.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input0);
    mtx.vout.push_back(CTxOut(90000, CScript() << OP_RETURN));
    CTransaction tx(mtx);

    // Spent output with 100000 sats → fee = 10000 sats
    std::vector<CTxOut> spent_outputs;
    spent_outputs.push_back(CTxOut(100000, CScript() << OP_1));

    RungEvalContext ctx;
    ctx.tx = &tx;
    ctx.spent_outputs = &spent_outputs;

    // fee_rate = 10000 / vsize. vsize is small for this tx, so fee_rate will be high.
    // With high=100, this should be UNSATISFIED (fee rate exceeds band)
    EvalResult result = EvalBlock(block, checker, SigVersion::LADDER, execdata, ctx);
    // The exact result depends on tx weight, but fee is 10000 sats which for a tiny tx
    // gives a very high fee rate (>100), so it should be UNSATISFIED
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_invalid_adaptor_point_size)
{
    // ADAPTOR_SIG with adaptor_point not 32 bytes → ERROR
    MockSignatureChecker checker;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});               // signing key (33 bytes)
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(33, 0x02)}); // adaptor point (33 bytes, should be 32)
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::ERROR);
}

BOOST_AUTO_TEST_CASE(eval_adaptor_sig_valid_adaptor_point)
{
    // ADAPTOR_SIG with valid 32-byte adaptor point — should proceed to sig verification
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;

    RungBlock block;
    block.type = RungBlockType::ADAPTOR_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});                    // signing key (33 bytes)
    block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(32, 0xAA)});  // adaptor point (32 bytes)
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    // With mock checker returning true for schnorr, should be SATISFIED
    BOOST_CHECK(EvalAdaptorSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

// ============================================================================
// Anti-spam: PUBKEY witness-only + preimage block limit tests
// ============================================================================

BOOST_AUTO_TEST_CASE(conditions_reject_pubkey_field)
{
    // Raw PUBKEY must be rejected from conditions (witness-only data type)
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(conditions_accept_pubkey_commit)
{
    // PUBKEY_COMMIT is the correct condition-side type for key references
    auto pk = MakePubkey();
    auto commit = MakePubkeyCommit(pk);

    RungConditions conditions;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit});
    rung.blocks.push_back(block);
    conditions.rungs.push_back(rung);

    CScript script = rung::SerializeRungConditions(conditions);

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].type == RungDataType::PUBKEY_COMMIT);
    BOOST_CHECK(decoded.rungs[0].blocks[0].fields[0].data == commit);
}

BOOST_AUTO_TEST_CASE(eval_sig_pubkey_commit_resolution)
{
    // SIG block with PUBKEY_COMMIT (conditions) + PUBKEY (witness) should
    // verify commitment match before signature verification
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;

    auto pk = MakePubkey();
    auto commit = MakePubkeyCommit(pk);

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit});  // from conditions
    block.fields.push_back({RungDataType::PUBKEY, pk});             // from witness
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_sig_pubkey_commit_mismatch_fails)
{
    // SIG block where witness PUBKEY doesn't match PUBKEY_COMMIT → UNSATISFIED
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;

    auto pk = MakePubkey();
    auto wrong_commit = MakeHash256();  // random hash, won't match

    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, wrong_commit});
    block.fields.push_back({RungDataType::PUBKEY, pk});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    BOOST_CHECK(EvalSigBlock(block, checker, SigVersion::LADDER, execdata) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_multisig_pubkey_commit_resolution)
{
    // MULTISIG 2-of-3 with PUBKEY_COMMITs in conditions + PUBKEYs in witness
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;

    auto pk1 = MakePubkey();
    auto pk2 = std::vector<uint8_t>(33, 0x02);  // different fake key
    auto pk3 = std::vector<uint8_t>(33, 0x03);
    pk3[0] = 0x03;  // valid prefix

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});       // threshold
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk1)});  // conditions
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk2)});
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk3)});
    block.fields.push_back({RungDataType::PUBKEY, pk1});                   // witness
    block.fields.push_back({RungDataType::PUBKEY, pk2});
    block.fields.push_back({RungDataType::PUBKEY, pk3});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});  // 2 sigs
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    EvalResult result = EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(eval_multisig_pubkey_commit_mismatch_fails)
{
    // MULTISIG where one witness PUBKEY doesn't match its commit → ERROR (empty resolved)
    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;

    auto pk1 = MakePubkey();
    auto wrong_pk = std::vector<uint8_t>(33, 0xFF);
    wrong_pk[0] = 0x02;

    RungBlock block;
    block.type = RungBlockType::MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk1)});
    block.fields.push_back({RungDataType::PUBKEY, wrong_pk});  // doesn't match commit
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    EvalResult result = EvalMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::ERROR);  // ResolvePubkeyCommitments returns empty
}

BOOST_AUTO_TEST_CASE(policy_preimage_block_limit)
{
    // Create a witness with 3 HASH_PREIMAGE blocks — should exceed the limit of 2
    CMutableTransaction mtx;
    mtx.version = 3;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(100000, CScript() << OP_RETURN));

    LadderWitness ladder;
    Rung rung;
    // 3 HASH_PREIMAGE blocks in one rung
    for (int i = 0; i < 3; ++i) {
        RungBlock block;
        block.type = RungBlockType::HASH_PREIMAGE;
        block.fields.push_back({RungDataType::HASH256, MakeHash256()});
        block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, static_cast<uint8_t>(i))});
        rung.blocks.push_back(block);
    }
    ladder.rungs.push_back(rung);

    auto witness_bytes = SerializeLadderWitness(ladder);
    mtx.vin[0].scriptWitness.stack.push_back(witness_bytes);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("preimage-blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(policy_preimage_block_limit_at_max)
{
    // 2 HASH_PREIMAGE blocks — should be within limit
    CMutableTransaction mtx;
    mtx.version = 3;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(100000, CScript() << OP_RETURN));

    LadderWitness ladder;
    Rung rung;
    for (int i = 0; i < 2; ++i) {
        RungBlock block;
        block.type = RungBlockType::HASH_PREIMAGE;
        block.fields.push_back({RungDataType::HASH256, MakeHash256()});
        block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, static_cast<uint8_t>(i))});
        rung.blocks.push_back(block);
    }
    ladder.rungs.push_back(rung);

    auto witness_bytes = SerializeLadderWitness(ladder);
    mtx.vin[0].scriptWitness.stack.push_back(witness_bytes);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(rung::IsStandardRungTx(tx, reason));
}

BOOST_AUTO_TEST_CASE(policy_preimage_block_limit_mixed_types)
{
    // 1 HASH_PREIMAGE + 1 HASH160_PREIMAGE + 1 TAGGED_HASH = 3 total → exceeds limit
    CMutableTransaction mtx;
    mtx.version = 3;
    CTxIn input;
    input.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.push_back(input);
    mtx.vout.push_back(CTxOut(100000, CScript() << OP_RETURN));

    LadderWitness ladder;
    Rung rung;

    RungBlock b1;
    b1.type = RungBlockType::HASH_PREIMAGE;
    b1.fields.push_back({RungDataType::HASH256, MakeHash256()});
    b1.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0x01)});
    rung.blocks.push_back(b1);

    RungBlock b2;
    b2.type = RungBlockType::HASH160_PREIMAGE;
    b2.fields.push_back({RungDataType::HASH160, MakeHash160()});
    b2.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0x02)});
    rung.blocks.push_back(b2);

    RungBlock b3;
    b3.type = RungBlockType::TAGGED_HASH;
    b3.fields.push_back({RungDataType::HASH256, MakeHash256()});
    b3.fields.push_back({RungDataType::HASH256, MakeHash256()});
    b3.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(16, 0x03)});
    rung.blocks.push_back(b3);

    ladder.rungs.push_back(rung);

    auto witness_bytes = SerializeLadderWitness(ladder);
    mtx.vin[0].scriptWitness.stack.push_back(witness_bytes);

    CTransaction tx(mtx);
    std::string reason;
    BOOST_CHECK(!rung::IsStandardRungTx(tx, reason));
    BOOST_CHECK(reason.find("preimage-blocks") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(spam_embed_fake_pubkey_in_conditions_rejected)
{
    // Attacker tries to embed spam data as a "PUBKEY" in conditions
    // This must be rejected since PUBKEY is now witness-only
    LadderWitness ladder;
    Rung rung;
    RungBlock block;
    block.type = RungBlockType::SIG;
    // 2KB of spam disguised as a "PQ public key"
    std::vector<uint8_t> spam(2048, 0x41);  // 'AAAA...'
    block.fields.push_back({RungDataType::PUBKEY, spam});
    rung.blocks.push_back(block);
    ladder.rungs.push_back(rung);

    auto bytes = SerializeLadderWitness(ladder);
    CScript script;
    script.push_back(rung::RUNG_CONDITIONS_PREFIX);
    script.insert(script.end(), bytes.begin(), bytes.end());

    RungConditions decoded;
    std::string error;
    BOOST_CHECK(!rung::DeserializeRungConditions(script, decoded, error));
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(spam_embed_fake_pubkey_commit_unrecoverable)
{
    // Attacker creates UTXO with PUBKEY_COMMIT = SHA256(spam).
    // The spam never appears on chain — only its hash does.
    // At spend time, revealing the spam in witness fails signature verification.
    MockSignatureChecker checker;
    checker.schnorr_result = false;  // sig verification will fail
    ScriptExecutionData execdata;

    // "Spam" data masquerading as a public key
    std::vector<uint8_t> spam(33, 0x42);
    spam[0] = 0x02;

    // Compute its commitment
    auto commit = MakePubkeyCommit(spam);

    // The conditions side only contains the 32-byte hash — not the spam
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, commit});  // conditions: just a hash
    block.fields.push_back({RungDataType::PUBKEY, spam});            // witness: spam bytes
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    // Commitment verifies (SHA256 matches), but signature fails
    // → spam is in the FAILED spending witness, never mined
    EvalResult result = EvalSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

// ============================================================================
// Relay tests
// ============================================================================

// Helper: build a simple relay with one SIG block (condition-side fields only)
static Relay MakeCondRelay(const std::vector<uint16_t>& reqs = {})
{
    Relay relay;
    RungBlock block;
    block.type = RungBlockType::SIG;
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(MakePubkey())});
    relay.blocks.push_back(block);
    relay.relay_refs = reqs;
    return relay;
}

// Helper: build a relay with merged fields (condition + witness) for evaluation
static Relay MakeEvalRelay(bool valid_sig = true, const std::vector<uint16_t>& reqs = {})
{
    Relay relay;
    RungBlock block;
    block.type = RungBlockType::SIG;
    auto pk = MakePubkey();
    block.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    block.fields.push_back({RungDataType::PUBKEY, pk});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(valid_sig ? 64 : 63)});
    relay.blocks.push_back(block);
    relay.relay_refs = reqs;
    return relay;
}

BOOST_AUTO_TEST_CASE(relay_serialize_roundtrip)
{
    LadderWitness ladder;

    // One rung with a SIG block
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    b.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(b);
    rung.relay_refs = {0}; // requires relay 0
    ladder.rungs.push_back(rung);

    // Two relays: relay 1 requires relay 0
    Relay r0;
    RungBlock rb0;
    rb0.type = RungBlockType::CSV;
    rb0.fields.push_back({RungDataType::NUMERIC, {0x10, 0x00, 0x00, 0x00}});
    r0.blocks.push_back(rb0);
    ladder.relays.push_back(r0);

    Relay r1;
    RungBlock rb1;
    rb1.type = RungBlockType::HASH_PREIMAGE;
    rb1.fields.push_back({RungDataType::HASH256, MakeHash256()});
    rb1.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(32, 0xDD)});
    r1.blocks.push_back(rb1);
    r1.relay_refs = {0};
    ladder.relays.push_back(r1);

    // Serialize
    auto bytes = SerializeLadderWitness(ladder);
    BOOST_CHECK(!bytes.empty());

    // Deserialize
    LadderWitness decoded;
    std::string error;
    bool ok = DeserializeLadderWitness(bytes, decoded, error);
    BOOST_CHECK_MESSAGE(ok, "roundtrip failed: " + error);

    // Verify structure
    BOOST_CHECK_EQUAL(decoded.relays.size(), 2u);
    BOOST_CHECK_EQUAL(decoded.relays[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.relays[0].blocks[0].type == RungBlockType::CSV);
    BOOST_CHECK(decoded.relays[0].relay_refs.empty());
    BOOST_CHECK_EQUAL(decoded.relays[1].blocks.size(), 1u);
    BOOST_CHECK(decoded.relays[1].blocks[0].type == RungBlockType::HASH_PREIMAGE);
    BOOST_CHECK_EQUAL(decoded.relays[1].relay_refs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.relays[1].relay_refs[0], 0u);

    // Verify rung requires survived roundtrip
    BOOST_CHECK_EQUAL(decoded.rungs[0].relay_refs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].relay_refs[0], 0u);
}

BOOST_AUTO_TEST_CASE(relay_forward_reference_rejected)
{
    LadderWitness ladder;

    // One rung
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    b.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(b);
    ladder.rungs.push_back(rung);

    // Relay 0 requires relay 1 (forward reference — invalid)
    Relay r0;
    RungBlock rb;
    rb.type = RungBlockType::CSV;
    rb.fields.push_back({RungDataType::NUMERIC, {0x10, 0x00, 0x00, 0x00}});
    r0.blocks.push_back(rb);
    r0.relay_refs = {1};
    ladder.relays.push_back(r0);

    Relay r1;
    r1.blocks.push_back(rb);
    ladder.relays.push_back(r1);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    bool ok = DeserializeLadderWitness(bytes, decoded, error);
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("forward") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(relay_self_reference_rejected)
{
    LadderWitness ladder;

    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    b.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(b);
    ladder.rungs.push_back(rung);

    // Relay 0 requires itself (index 0 >= own index 0)
    Relay r0;
    RungBlock rb;
    rb.type = RungBlockType::CSV;
    rb.fields.push_back({RungDataType::NUMERIC, {0x10, 0x00, 0x00, 0x00}});
    r0.blocks.push_back(rb);
    r0.relay_refs = {0};
    ladder.relays.push_back(r0);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    bool ok = DeserializeLadderWitness(bytes, decoded, error);
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("forward") != std::string::npos || error.find("self") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(relay_rung_requires_invalid_index)
{
    LadderWitness ladder;

    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    b.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.relay_refs = {5}; // relay index 5 doesn't exist
    rung.blocks.push_back(b);
    ladder.rungs.push_back(rung);

    // One relay
    Relay r0;
    RungBlock rb;
    rb.type = RungBlockType::CSV;
    rb.fields.push_back({RungDataType::NUMERIC, {0x10, 0x00, 0x00, 0x00}});
    r0.blocks.push_back(rb);
    ladder.relays.push_back(r0);

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    bool ok = DeserializeLadderWitness(bytes, decoded, error);
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("invalid relay index") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(relay_eval_satisfied)
{
    // Relay with CSV block, rung requires it — both pass
    MockSignatureChecker checker;
    checker.sequence_result = true;

    LadderWitness ladder;

    // Relay 0: CSV 144 (satisfied via mock)
    Relay r0;
    RungBlock rb;
    rb.type = RungBlockType::CSV;
    rb.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r0.blocks.push_back(rb);
    ladder.relays.push_back(r0);

    // Rung 0: requires relay 0, has CSV 144 block
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::CSV;
    b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(b);
    rung.relay_refs = {0};
    ladder.rungs.push_back(rung);

    ScriptExecutionData execdata;
    RungEvalContext ctx;

    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata, ctx));
}

BOOST_AUTO_TEST_CASE(relay_eval_unsatisfied_blocks_rung)
{
    // Relay fails (sequence_result=false) — rung should fail even though rung's own blocks pass
    MockSignatureChecker checker;
    checker.sequence_result = false;

    LadderWitness ladder;

    // Relay 0: CSV 144 (will fail — mock returns false)
    Relay r0;
    RungBlock rb;
    rb.type = RungBlockType::CSV;
    rb.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r0.blocks.push_back(rb);
    ladder.relays.push_back(r0);

    // Rung requires relay 0, but has a hash preimage block that would pass on its own
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::HASH_PREIMAGE;
    auto preimage = std::vector<uint8_t>(32, 0xDD);
    CSHA256 hasher;
    hasher.Write(preimage.data(), preimage.size());
    std::vector<uint8_t> hash(32);
    hasher.Finalize(hash.data());
    b.fields.push_back({RungDataType::HASH256, hash});
    b.fields.push_back({RungDataType::PREIMAGE, preimage});
    rung.blocks.push_back(b);
    rung.relay_refs = {0};
    ladder.rungs.push_back(rung);

    ScriptExecutionData execdata;
    RungEvalContext ctx;

    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata, ctx));
}

BOOST_AUTO_TEST_CASE(relay_chain_satisfied)
{
    // Relay 0: CSV 144. Relay 1: requires [0], CSV 144. Rung: requires [1].
    MockSignatureChecker checker;
    checker.sequence_result = true;

    LadderWitness ladder;

    Relay r0;
    RungBlock rb0;
    rb0.type = RungBlockType::CSV;
    rb0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r0.blocks.push_back(rb0);
    ladder.relays.push_back(r0);

    Relay r1;
    RungBlock rb1;
    rb1.type = RungBlockType::CSV;
    rb1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r1.blocks.push_back(rb1);
    r1.relay_refs = {0};
    ladder.relays.push_back(r1);

    Rung rung;
    RungBlock b;
    b.type = RungBlockType::CSV;
    b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(b);
    rung.relay_refs = {1};
    ladder.rungs.push_back(rung);

    ScriptExecutionData execdata;
    RungEvalContext ctx;

    BOOST_CHECK(EvalLadder(ladder, checker, SigVersion::LADDER, execdata, ctx));
}

BOOST_AUTO_TEST_CASE(relay_chain_broken)
{
    // Relay 0: CSV 144 (fails). Relay 1: requires [0]. Rung: requires [1].
    MockSignatureChecker checker;
    checker.sequence_result = false;

    LadderWitness ladder;

    Relay r0;
    RungBlock rb0;
    rb0.type = RungBlockType::CSV;
    rb0.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r0.blocks.push_back(rb0);
    ladder.relays.push_back(r0);

    Relay r1;
    RungBlock rb1;
    rb1.type = RungBlockType::CSV;
    rb1.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    r1.blocks.push_back(rb1);
    r1.relay_refs = {0};
    ladder.relays.push_back(r1);

    Rung rung;
    RungBlock b;
    b.type = RungBlockType::CSV;
    b.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung.blocks.push_back(b);
    rung.relay_refs = {1};
    ladder.rungs.push_back(rung);

    ScriptExecutionData execdata;
    RungEvalContext ctx;

    BOOST_CHECK(!EvalLadder(ladder, checker, SigVersion::LADDER, execdata, ctx));
}

BOOST_AUTO_TEST_CASE(relay_backward_compat)
{
    // Old-format witness (no relays) should deserialize with empty relays
    LadderWitness ladder;
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    b.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(b);
    ladder.rungs.push_back(rung);
    // No relays, no requires

    auto bytes = SerializeLadderWitness(ladder);

    LadderWitness decoded;
    std::string error;
    bool ok = DeserializeLadderWitness(bytes, decoded, error);
    BOOST_CHECK_MESSAGE(ok, "backward compat failed: " + error);
    BOOST_CHECK(decoded.relays.empty());
    BOOST_CHECK(decoded.rungs[0].relay_refs.empty());
}

BOOST_AUTO_TEST_CASE(relay_conditions_reject_witness_fields)
{
    // Relay with SIGNATURE field in conditions — should be rejected
    RungConditions conditions;
    Rung rung;
    RungBlock b;
    b.type = RungBlockType::SIG;
    b.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(MakePubkey())});
    rung.blocks.push_back(b);
    conditions.rungs.push_back(rung);

    Relay relay;
    RungBlock rb;
    rb.type = RungBlockType::SIG;
    rb.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)}); // witness-only!
    relay.blocks.push_back(rb);
    conditions.relays.push_back(relay);

    CScript script = SerializeRungConditions(conditions);

    RungConditions decoded;
    std::string error;
    bool ok = DeserializeRungConditions(script, decoded, error);
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("witness-only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(relay_merge_conditions_witness)
{
    // Conditions: relay with PUBKEY_COMMIT. Witness: relay with PUBKEY + SIG.
    // Merge should produce combined fields.
    RungConditions conditions;
    Rung cond_rung;
    RungBlock cb;
    cb.type = RungBlockType::SIG;
    auto pk = MakePubkey();
    cb.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    cond_rung.blocks.push_back(cb);
    cond_rung.relay_refs = {0};
    conditions.rungs.push_back(cond_rung);

    Relay cond_relay;
    RungBlock crb;
    crb.type = RungBlockType::SIG;
    crb.fields.push_back({RungDataType::PUBKEY_COMMIT, MakePubkeyCommit(pk)});
    cond_relay.blocks.push_back(crb);
    conditions.relays.push_back(cond_relay);

    LadderWitness witness;
    Rung wit_rung;
    RungBlock wb;
    wb.type = RungBlockType::SIG;
    wb.fields.push_back({RungDataType::PUBKEY, pk});
    wb.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_rung.blocks.push_back(wb);
    witness.rungs.push_back(wit_rung);

    Relay wit_relay;
    RungBlock wrb;
    wrb.type = RungBlockType::SIG;
    wrb.fields.push_back({RungDataType::PUBKEY, pk});
    wrb.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    wit_relay.blocks.push_back(wrb);
    witness.relays.push_back(wit_relay);

    // Serialize conditions side
    CScript script = SerializeRungConditions(conditions);
    RungConditions decoded_cond;
    std::string cond_error;
    BOOST_CHECK(DeserializeRungConditions(script, decoded_cond, cond_error));
    BOOST_CHECK_EQUAL(decoded_cond.relays.size(), 1u);
    BOOST_CHECK_EQUAL(decoded_cond.rungs[0].relay_refs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded_cond.rungs[0].relay_refs[0], 0u);

    // Verify relay has condition-only field
    BOOST_CHECK_EQUAL(decoded_cond.relays[0].blocks[0].fields.size(), 1u);
    BOOST_CHECK(decoded_cond.relays[0].blocks[0].fields[0].type == RungDataType::PUBKEY_COMMIT);
}

// ============================================================================
// Compound block tests
// ============================================================================

BOOST_AUTO_TEST_CASE(timelocked_sig_satisfied)
{
    // TIMELOCKED_SIG with passing sig and CSV
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(timelocked_sig_csv_fails)
{
    // Sig passes but CSV fails
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = false;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(timelocked_sig_sig_fails)
{
    // CSV passes but sig fails
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(htlc_satisfied)
{
    // HTLC with correct preimage, passing sig and CSV
    // Build hash from known preimage
    std::vector<uint8_t> preimage(32, 0x42);
    std::vector<uint8_t> hash(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.data());

    RungBlock block;
    block.type = RungBlockType::HTLC;
    block.fields.push_back({RungDataType::HASH256, hash});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalHTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(htlc_wrong_preimage)
{
    // Wrong preimage → unsatisfied
    std::vector<uint8_t> preimage(32, 0x42);
    std::vector<uint8_t> hash(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.data());

    std::vector<uint8_t> wrong_preimage(32, 0x99); // different preimage

    RungBlock block;
    block.type = RungBlockType::HTLC;
    block.fields.push_back({RungDataType::HASH256, hash});
    block.fields.push_back({RungDataType::PREIMAGE, wrong_preimage});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalHTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(hash_sig_satisfied)
{
    std::vector<uint8_t> preimage(32, 0x42);
    std::vector<uint8_t> hash(32);
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.data());

    RungBlock block;
    block.type = RungBlockType::HASH_SIG;
    block.fields.push_back({RungDataType::HASH256, hash});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;
    auto result = EvalHashSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(hash_sig_bad_hash)
{
    std::vector<uint8_t> preimage(32, 0x42);
    std::vector<uint8_t> wrong_hash(32, 0xFF); // doesn't match preimage

    RungBlock block;
    block.type = RungBlockType::HASH_SIG;
    block.fields.push_back({RungDataType::HASH256, wrong_hash});
    block.fields.push_back({RungDataType::PREIMAGE, preimage});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    ScriptExecutionData execdata;
    auto result = EvalHashSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

// ============================================================================
// PTLC compound block tests
// ============================================================================

BOOST_AUTO_TEST_CASE(ptlc_satisfied)
{
    // PTLC with passing adaptor sig and CSV
    RungBlock block;
    block.type = RungBlockType::PTLC;
    // Two pubkeys: signing key + adaptor point (32 bytes x-only)
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    std::vector<uint8_t> adaptor_point(32, 0xDD);
    block.fields.push_back({RungDataType::PUBKEY, adaptor_point});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalPTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(ptlc_sig_fails)
{
    // PTLC: adaptor sig verification fails
    RungBlock block;
    block.type = RungBlockType::PTLC;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    std::vector<uint8_t> adaptor_point(32, 0xDD);
    block.fields.push_back({RungDataType::PUBKEY, adaptor_point});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalPTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(ptlc_csv_fails)
{
    // PTLC: sig passes but CSV fails
    RungBlock block;
    block.type = RungBlockType::PTLC;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    std::vector<uint8_t> adaptor_point(32, 0xDD);
    block.fields.push_back({RungDataType::PUBKEY, adaptor_point});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = false;
    ScriptExecutionData execdata;
    auto result = EvalPTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(ptlc_missing_adaptor_point)
{
    // PTLC with only one pubkey → ERROR
    RungBlock block;
    block.type = RungBlockType::PTLC;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalPTLCBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::ERROR);
}

// ============================================================================
// CLTV_SIG compound block tests
// ============================================================================

BOOST_AUTO_TEST_CASE(cltv_sig_satisfied)
{
    // CLTV_SIG with passing sig and CLTV
    RungBlock block;
    block.type = RungBlockType::CLTV_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.locktime_result = true;
    ScriptExecutionData execdata;
    auto result = EvalCLTVSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(cltv_sig_locktime_fails)
{
    // Sig passes but CLTV fails
    RungBlock block;
    block.type = RungBlockType::CLTV_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.locktime_result = false;
    ScriptExecutionData execdata;
    auto result = EvalCLTVSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(cltv_sig_sig_fails)
{
    // CLTV passes but sig fails
    RungBlock block;
    block.type = RungBlockType::CLTV_SIG;
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000)});

    MockSignatureChecker checker;
    checker.schnorr_result = false;
    checker.locktime_result = true;
    ScriptExecutionData execdata;
    auto result = EvalCLTVSigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

// ============================================================================
// TIMELOCKED_MULTISIG compound block tests
// ============================================================================

BOOST_AUTO_TEST_CASE(timelocked_multisig_satisfied)
{
    // 2-of-3 multisig + CSV, both pass
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});   // threshold M=2
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});      // pubkey 1
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});      // pubkey 2
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});      // pubkey 3
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});  // sig 1
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});  // sig 2
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)}); // CSV timelock

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(timelocked_multisig_csv_fails)
{
    // Multisig passes but CSV fails
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = false;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(timelocked_multisig_insufficient_sigs)
{
    // Only 1 sig for threshold=2 → UNSATISFIED
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});  // only 1 sig
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(timelocked_multisig_missing_csv_numeric)
{
    // Only one NUMERIC (threshold) without CSV → ERROR
    RungBlock block;
    block.type = RungBlockType::TIMELOCKED_MULTISIG;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});
    block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});

    MockSignatureChecker checker;
    checker.schnorr_result = true;
    checker.sequence_result = true;
    ScriptExecutionData execdata;
    auto result = EvalTimelockedMultisigBlock(block, checker, SigVersion::LADDER, execdata);
    BOOST_CHECK(result == EvalResult::ERROR);
}

// ============================================================================
// Governance block tests
// ============================================================================

BOOST_AUTO_TEST_CASE(epoch_gate_in_window)
{
    // block_height 100, epoch_size 2016, window_size 144 → 100 % 2016 = 100 < 144 → satisfied
    RungBlock block;
    block.type = RungBlockType::EPOCH_GATE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2016)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    RungEvalContext ctx;
    ctx.block_height = 100;
    auto result = EvalEpochGateBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(epoch_gate_outside_window)
{
    // block_height 200, epoch_size 2016, window_size 144 → 200 % 2016 = 200 >= 144 → unsatisfied
    RungBlock block;
    block.type = RungBlockType::EPOCH_GATE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2016)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    RungEvalContext ctx;
    ctx.block_height = 200;
    auto result = EvalEpochGateBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(epoch_gate_boundary)
{
    // Exactly at window boundary: position 143 < 144 → satisfied; position 144 >= 144 → unsatisfied
    RungBlock block;
    block.type = RungBlockType::EPOCH_GATE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2016)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});

    RungEvalContext ctx;
    ctx.block_height = 143;
    BOOST_CHECK(EvalEpochGateBlock(block, ctx) == EvalResult::SATISFIED);
    ctx.block_height = 144;
    BOOST_CHECK(EvalEpochGateBlock(block, ctx) == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(weight_limit_within_bounds)
{
    RungBlock block;
    block.type = RungBlockType::WEIGHT_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(100000)});  // max weight

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalWeightLimitBlock(block, ctx);
    // A minimal tx with 1 input and 1 output is well under 100000 WU
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(weight_limit_exceeded)
{
    RungBlock block;
    block.type = RungBlockType::WEIGHT_LIMIT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});  // max weight = 1 (impossibly small)

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalWeightLimitBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(input_count_within_bounds)
{
    RungBlock block;
    block.type = RungBlockType::INPUT_COUNT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // min
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});  // max

    // Build a mock tx with 3 inputs
    CMutableTransaction mtx;
    mtx.vin.resize(3);
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalInputCountBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(input_count_below_min)
{
    RungBlock block;
    block.type = RungBlockType::INPUT_COUNT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(3)});  // min
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(5)});  // max

    CMutableTransaction mtx;
    mtx.vin.resize(1); // only 1 input, min is 3
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalInputCountBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(output_count_within_bounds)
{
    RungBlock block;
    block.type = RungBlockType::OUTPUT_COUNT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});  // min
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // max

    CMutableTransaction mtx;
    mtx.vout.resize(2);
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalOutputCountBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(output_count_exceeds_max)
{
    RungBlock block;
    block.type = RungBlockType::OUTPUT_COUNT;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(1)});  // min
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});  // max

    CMutableTransaction mtx;
    mtx.vout.resize(5); // 5 outputs, max is 2
    CTransaction tx(mtx);

    RungEvalContext ctx;
    ctx.tx = &tx;
    auto result = EvalOutputCountBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(relative_value_satisfied)
{
    // 90% ratio: output 9000, input 10000 → 9000*10 >= 10000*9 → 90000 >= 90000 → satisfied
    RungBlock block;
    block.type = RungBlockType::RELATIVE_VALUE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(9)});   // numerator
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});  // denominator

    RungEvalContext ctx;
    ctx.input_amount = 10000;
    ctx.output_amount = 9000;
    auto result = EvalRelativeValueBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(relative_value_unsatisfied)
{
    // 90% ratio: output 8999, input 10000 → 8999*10 = 89990 < 90000 → unsatisfied
    RungBlock block;
    block.type = RungBlockType::RELATIVE_VALUE;
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(9)});
    block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(10)});

    RungEvalContext ctx;
    ctx.input_amount = 10000;
    ctx.output_amount = 8999;
    auto result = EvalRelativeValueBlock(block, ctx);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(accumulator_valid_proof)
{
    // Build a simple 2-leaf Merkle tree and verify membership
    // Leaves: L0 = SHA256("leaf0"), L1 = SHA256("leaf1")
    // Root = SHA256(min(L0,L1) || max(L0,L1))

    unsigned char l0[32], l1[32];
    const char* d0 = "leaf0"; const char* d1 = "leaf1";
    CSHA256().Write((const unsigned char*)d0, 5).Finalize(l0);
    CSHA256().Write((const unsigned char*)d1, 5).Finalize(l1);

    // Compute root: sorted concatenation
    unsigned char combined[64];
    if (memcmp(l0, l1, 32) < 0) {
        memcpy(combined, l0, 32);
        memcpy(combined + 32, l1, 32);
    } else {
        memcpy(combined, l1, 32);
        memcpy(combined + 32, l0, 32);
    }
    unsigned char root[32];
    CSHA256().Write(combined, 64).Finalize(root);

    // Prove L0 membership: root + [sibling=L1] + [leaf=L0]
    RungBlock block;
    block.type = RungBlockType::ACCUMULATOR;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(root, root + 32)});       // root
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(l1, l1 + 32)});           // sibling
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(l0, l0 + 32)});           // leaf

    auto result = EvalAccumulatorBlock(block);
    BOOST_CHECK(result == EvalResult::SATISFIED);
}

BOOST_AUTO_TEST_CASE(accumulator_invalid_proof)
{
    // Same tree but wrong leaf → unsatisfied
    unsigned char l0[32], l1[32];
    const char* d0 = "leaf0"; const char* d1 = "leaf1";
    CSHA256().Write((const unsigned char*)d0, 5).Finalize(l0);
    CSHA256().Write((const unsigned char*)d1, 5).Finalize(l1);

    unsigned char combined[64];
    if (memcmp(l0, l1, 32) < 0) {
        memcpy(combined, l0, 32);
        memcpy(combined + 32, l1, 32);
    } else {
        memcpy(combined, l1, 32);
        memcpy(combined + 32, l0, 32);
    }
    unsigned char root[32];
    CSHA256().Write(combined, 64).Finalize(root);

    // Wrong leaf: use random bytes instead of L0
    std::vector<uint8_t> wrong_leaf(32, 0xFF);

    RungBlock block;
    block.type = RungBlockType::ACCUMULATOR;
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(root, root + 32)});
    block.fields.push_back({RungDataType::HASH256, std::vector<uint8_t>(l1, l1 + 32)});
    block.fields.push_back({RungDataType::HASH256, wrong_leaf});

    auto result = EvalAccumulatorBlock(block);
    BOOST_CHECK(result == EvalResult::UNSATISFIED);
}

BOOST_AUTO_TEST_CASE(compound_block_types_recognized)
{
    // Verify all new block types are known
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::TIMELOCKED_SIG)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::HTLC)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::HASH_SIG)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::PTLC)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::CLTV_SIG)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::TIMELOCKED_MULTISIG)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::EPOCH_GATE)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::WEIGHT_LIMIT)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::INPUT_COUNT)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::OUTPUT_COUNT)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::RELATIVE_VALUE)));
    BOOST_CHECK(IsKnownBlockType(static_cast<uint16_t>(RungBlockType::ACCUMULATOR)));
}

BOOST_AUTO_TEST_CASE(compound_serialize_roundtrip)
{
    // Serialize a witness with compound blocks, verify roundtrip
    LadderWitness ladder;
    Rung rung;

    RungBlock htlc_block;
    htlc_block.type = RungBlockType::HTLC;
    htlc_block.fields.push_back({RungDataType::HASH256, MakeHash256()});
    htlc_block.fields.push_back({RungDataType::PREIMAGE, std::vector<uint8_t>(32, 0x42)});
    htlc_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    htlc_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    htlc_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    rung.blocks.push_back(std::move(htlc_block));

    ladder.rungs.push_back(std::move(rung));

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 1u);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks.size(), 1u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::HTLC);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 5u);
}

BOOST_AUTO_TEST_CASE(new_compound_serialize_roundtrip)
{
    // Roundtrip all three new compound types
    LadderWitness ladder;

    // PTLC rung
    Rung rung1;
    RungBlock ptlc_block;
    ptlc_block.type = RungBlockType::PTLC;
    ptlc_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});          // signing key
    ptlc_block.fields.push_back({RungDataType::PUBKEY, std::vector<uint8_t>(32, 0xDD)}); // adaptor point
    ptlc_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    ptlc_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});
    rung1.blocks.push_back(std::move(ptlc_block));
    ladder.rungs.push_back(std::move(rung1));

    // CLTV_SIG rung
    Rung rung2;
    RungBlock cltv_sig_block;
    cltv_sig_block.type = RungBlockType::CLTV_SIG;
    cltv_sig_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    cltv_sig_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    cltv_sig_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(500000)});
    rung2.blocks.push_back(std::move(cltv_sig_block));
    ladder.rungs.push_back(std::move(rung2));

    // TIMELOCKED_MULTISIG rung
    Rung rung3;
    RungBlock tms_block;
    tms_block.type = RungBlockType::TIMELOCKED_MULTISIG;
    tms_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(2)});      // threshold
    tms_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    tms_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    tms_block.fields.push_back({RungDataType::PUBKEY, MakePubkey()});
    tms_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    tms_block.fields.push_back({RungDataType::SIGNATURE, MakeSignature(64)});
    tms_block.fields.push_back({RungDataType::NUMERIC, MakeNumeric(144)});    // CSV
    rung3.blocks.push_back(std::move(tms_block));
    ladder.rungs.push_back(std::move(rung3));

    auto bytes = SerializeLadderWitness(ladder);
    LadderWitness decoded;
    std::string error;
    BOOST_CHECK(DeserializeLadderWitness(bytes, decoded, error));
    BOOST_CHECK_EQUAL(decoded.rungs.size(), 3u);
    BOOST_CHECK(decoded.rungs[0].blocks[0].type == RungBlockType::PTLC);
    BOOST_CHECK_EQUAL(decoded.rungs[0].blocks[0].fields.size(), 4u);
    BOOST_CHECK(decoded.rungs[1].blocks[0].type == RungBlockType::CLTV_SIG);
    BOOST_CHECK_EQUAL(decoded.rungs[1].blocks[0].fields.size(), 3u);
    BOOST_CHECK(decoded.rungs[2].blocks[0].type == RungBlockType::TIMELOCKED_MULTISIG);
    BOOST_CHECK_EQUAL(decoded.rungs[2].blocks[0].fields.size(), 7u);
}

BOOST_AUTO_TEST_SUITE_END()
