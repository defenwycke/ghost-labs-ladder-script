// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/evaluator.h>
#include <rung/conditions.h>
#include <rung/pq_verify.h>
#include <rung/serialize.h>
#include <rung/sighash.h>

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>

#include <algorithm>
#include <map>

namespace rung {

bool LadderSignatureChecker::CheckSchnorrSignature(std::span<const unsigned char> sig,
                                                    std::span<const unsigned char> pubkey_in,
                                                    SigVersion sigversion,
                                                    ScriptExecutionData& /*execdata*/,
                                                    ScriptError* serror) const
{
    if (sigversion != SigVersion::LADDER) {
        // Fall through to the wrapped checker for non-ladder sigversions
        ScriptExecutionData fallback_execdata;
        return m_checker.CheckSchnorrSignature(sig, pubkey_in, sigversion, fallback_execdata, serror);
    }

    // Schnorr signatures are 64 bytes (default hashtype) or 65 bytes (explicit hashtype)
    if (sig.size() != 64 && sig.size() != 65) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_SIZE;
        return false;
    }

    if (pubkey_in.size() != 32) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }

    XOnlyPubKey pubkey{pubkey_in};

    uint8_t hashtype = SIGHASH_DEFAULT;
    // For 65-byte sig, last byte is hashtype (copy sig to strip it)
    std::vector<unsigned char> sig_data(sig.begin(), sig.end());
    if (sig_data.size() == 65) {
        hashtype = sig_data.back();
        sig_data.pop_back();
        if (hashtype == SIGHASH_DEFAULT) {
            if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
            return false;
        }
    }

    uint256 sighash;
    if (!SignatureHashLadder(m_txdata, m_tx, m_nIn, hashtype, m_conditions, sighash)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG_HASHTYPE;
        return false;
    }

    std::span<const unsigned char> sig_span{sig_data.data(), sig_data.size()};
    if (!pubkey.VerifySchnorr(sighash, sig_span)) {
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }
    return true;
}

bool LadderSignatureChecker::ComputeSighash(uint8_t hash_type, uint256& hash_out) const
{
    return SignatureHashLadder(m_txdata, m_tx, m_nIn, hash_type, m_conditions, hash_out);
}

/** Helper: find the first field of a given type in a block. Returns nullptr if not found. */
static const RungField* FindField(const RungBlock& block, RungDataType type)
{
    for (const auto& field : block.fields) {
        if (field.type == type) return &field;
    }
    return nullptr;
}

/** Helper: collect all fields of a given type from a block. */
static std::vector<const RungField*> FindAllFields(const RungBlock& block, RungDataType type)
{
    std::vector<const RungField*> result;
    for (const auto& field : block.fields) {
        if (field.type == type) result.push_back(&field);
    }
    return result;
}

/** Helper: read a little-endian numeric value from a NUMERIC field (1-4 bytes). */
static int64_t ReadNumeric(const RungField& field)
{
    if (field.data.empty() || field.data.size() > 4) return -1;
    uint32_t val = 0;
    for (size_t i = 0; i < field.data.size(); ++i) {
        val |= static_cast<uint32_t>(field.data[i]) << (8 * i);
    }
    return static_cast<int64_t>(val);
}

/** Helper: check if a pubkey field exists and has valid size.
 *  Accepts either raw PUBKEY (witness) or PUBKEY_COMMIT (conditions). */
static bool HasRequiredPubkeys(const RungBlock& block, size_t count)
{
    auto pks = FindAllFields(block, RungDataType::PUBKEY);
    auto commits = FindAllFields(block, RungDataType::PUBKEY_COMMIT);
    return (pks.size() + commits.size()) >= count;
}

/** Verify all PUBKEY_COMMIT fields in a block match corresponding PUBKEY fields.
 *  Returns the resolved PUBKEY fields (in commit order) on success, or empty on failure.
 *  Each PUBKEY_COMMIT must have exactly one matching PUBKEY where SHA256(PUBKEY) == PUBKEY_COMMIT. */
static std::vector<const RungField*> ResolvePubkeyCommitments(const RungBlock& block)
{
    auto commits = FindAllFields(block, RungDataType::PUBKEY_COMMIT);
    auto pubkeys = FindAllFields(block, RungDataType::PUBKEY);

    if (commits.empty()) {
        // No commits — return raw pubkeys (backward compat / bootstrap)
        return pubkeys;
    }

    std::vector<const RungField*> resolved;
    std::vector<bool> pk_used(pubkeys.size(), false);

    for (const auto* commit : commits) {
        if (commit->data.size() != 32) return {};

        bool found = false;
        for (size_t i = 0; i < pubkeys.size(); ++i) {
            if (pk_used[i]) continue;
            unsigned char hash[CSHA256::OUTPUT_SIZE];
            CSHA256().Write(pubkeys[i]->data.data(), pubkeys[i]->data.size()).Finalize(hash);
            if (memcmp(hash, commit->data.data(), 32) == 0) {
                resolved.push_back(pubkeys[i]);
                pk_used[i] = true;
                found = true;
                break;
            }
        }
        if (!found) return {}; // commitment without matching pubkey
    }

    return resolved;
}

/** Helper: compare two RungBlocks for structural equality (same type, same condition fields).
 *  Only compares condition data types (PUBKEY_COMMIT, HASH256, HASH160, NUMERIC, SCHEME),
 *  skips witness types (PUBKEY, SIGNATURE, PREIMAGE). */
static bool BlockConditionsEqual(const RungBlock& a, const RungBlock& b)
{
    if (a.type != b.type) return false;
    if (a.inverted != b.inverted) return false;

    // Collect condition-only fields from each
    std::vector<const RungField*> a_conds, b_conds;
    for (const auto& f : a.fields) {
        if (IsConditionDataType(f.type)) a_conds.push_back(&f);
    }
    for (const auto& f : b.fields) {
        if (IsConditionDataType(f.type)) b_conds.push_back(&f);
    }
    if (a_conds.size() != b_conds.size()) return false;
    for (size_t i = 0; i < a_conds.size(); ++i) {
        if (a_conds[i]->type != b_conds[i]->type) return false;
        if (a_conds[i]->data != b_conds[i]->data) return false;
    }
    return true;
}

/** Helper: compare two Rungs for condition equality (all blocks must match). */
static bool RungConditionsEqual(const Rung& a, const Rung& b)
{
    if (a.blocks.size() != b.blocks.size()) return false;
    for (size_t i = 0; i < a.blocks.size(); ++i) {
        if (!BlockConditionsEqual(a.blocks[i], b.blocks[i])) return false;
    }
    return true;
}

/** Helper: compare full conditions structures (all rungs). */
static bool FullConditionsEqual(const RungConditions& a, const RungConditions& b)
{
    if (a.rungs.size() != b.rungs.size()) return false;
    for (size_t i = 0; i < a.rungs.size(); ++i) {
        if (!RungConditionsEqual(a.rungs[i], b.rungs[i])) return false;
    }
    return true;
}

/** Helper: try to deserialize a CTxOut's scriptPubKey as rung conditions.
 *  Returns true on success. */
static bool TryDeserializeOutputConditions(const CTxOut& output, RungConditions& out)
{
    std::string error;
    return DeserializeRungConditions(output.scriptPubKey, out, error);
}

EvalResult ApplyInversion(EvalResult raw, bool inverted)
{
    if (!inverted) return raw;
    switch (raw) {
    case EvalResult::SATISFIED:        return EvalResult::UNSATISFIED;
    case EvalResult::UNSATISFIED:      return EvalResult::SATISFIED;
    case EvalResult::ERROR:            return EvalResult::ERROR; // errors never flip
    case EvalResult::UNKNOWN_BLOCK_TYPE: return EvalResult::SATISFIED; // unknown inverted → satisfied
    }
    return raw;
}

// ============================================================================
// PQ signature verification helper
// ============================================================================

/** Verify a post-quantum signature using the SCHEME field routing.
 *  Computes the ladder sighash via dynamic_cast to LadderSignatureChecker. */
static EvalResult EvalPQSig(RungScheme scheme,
                             const RungField& sig_field,
                             const RungField& pubkey_field,
                             const BaseSignatureChecker& checker)
{
    auto* ladder_checker = dynamic_cast<const LadderSignatureChecker*>(&checker);
    if (!ladder_checker) return EvalResult::ERROR;

    uint256 sighash;
    if (!ladder_checker->ComputeSighash(SIGHASH_DEFAULT, sighash)) {
        return EvalResult::ERROR;
    }

    std::span<const uint8_t> sig{sig_field.data.data(), sig_field.data.size()};
    std::span<const uint8_t> msg{sighash.begin(), 32};
    std::span<const uint8_t> pubkey{pubkey_field.data.data(), pubkey_field.data.size()};

    if (VerifyPQSignature(scheme, sig, msg, pubkey)) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Signature evaluators
// ============================================================================

EvalResult EvalSigBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker,
                        SigVersion sigversion,
                        ScriptExecutionData& execdata)
{
    const RungField* pubkey_commit = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    // PUBKEY_COMMIT: commitment without revealed pubkey is an error
    if (pubkey_commit && !pubkey_field) {
        return EvalResult::ERROR;
    }

    // If PUBKEY_COMMIT present, verify the revealed PUBKEY matches the commitment
    if (pubkey_commit && pubkey_field) {
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey_field->data.data(), pubkey_field->data.size()).Finalize(hash);
        if (pubkey_commit->data.size() != 32 ||
            memcmp(hash, pubkey_commit->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
        // Commitment verified — proceed with pubkey_field for signature check
    }

    if (!pubkey_field || !sig_field) {
        return EvalResult::ERROR;
    }

    // Check for explicit SCHEME field — routes to PQ verifier if present
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            return EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
        }
        // SCHNORR/ECDSA scheme values fall through to existing size-based routing
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    // Schnorr sigs are 64 bytes (no sighash type byte) or 65 bytes (with sighash type).
    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        // For Schnorr, use x-only pubkey (32 bytes). If we have compressed key (33 bytes),
        // strip the prefix.
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    // ECDSA signatures (DER encoded, 71-72 bytes typically)
    if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalMultisigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata)
{
    // Expected field layout: NUMERIC (threshold M), N x PUBKEY_COMMIT (conditions),
    //                        N x PUBKEY (witness), M x SIGNATURE (witness)
    const RungField* threshold_field = FindField(block, RungDataType::NUMERIC);
    if (!threshold_field || threshold_field->data.size() < 1) {
        return EvalResult::ERROR;
    }

    int64_t threshold_val = ReadNumeric(*threshold_field);
    if (threshold_val <= 0) {
        return EvalResult::ERROR;
    }
    uint32_t threshold = static_cast<uint32_t>(threshold_val);

    // Resolve pubkey commitments: verify each PUBKEY_COMMIT matches a witness PUBKEY
    auto pubkeys = ResolvePubkeyCommitments(block);
    auto sigs = FindAllFields(block, RungDataType::SIGNATURE);

    if (pubkeys.empty() || threshold > pubkeys.size()) {
        return EvalResult::ERROR;
    }
    if (sigs.size() < threshold) {
        return EvalResult::UNSATISFIED;
    }

    // Check for explicit SCHEME field — routes to PQ verifier if present
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            // PQ multisig: compute sighash once, verify each sig against pubkeys
            auto* ladder_checker = dynamic_cast<const LadderSignatureChecker*>(&checker);
            if (!ladder_checker) return EvalResult::ERROR;

            uint256 sighash;
            if (!ladder_checker->ComputeSighash(SIGHASH_DEFAULT, sighash)) {
                return EvalResult::ERROR;
            }

            std::span<const uint8_t> msg{sighash.begin(), 32};
            std::vector<bool> pubkey_used(pubkeys.size(), false);
            uint32_t valid_count = 0;

            for (const auto* sig_f : sigs) {
                std::span<const uint8_t> sig_span{sig_f->data.data(), sig_f->data.size()};
                for (size_t k = 0; k < pubkeys.size(); ++k) {
                    if (pubkey_used[k]) continue;
                    std::span<const uint8_t> pk_span{pubkeys[k]->data.data(), pubkeys[k]->data.size()};
                    if (VerifyPQSignature(scheme, sig_span, msg, pk_span)) {
                        pubkey_used[k] = true;
                        valid_count++;
                        break;
                    }
                }
            }
            return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
        }
        // SCHNORR/ECDSA scheme values fall through to existing size-based routing
    }

    // Verify signatures: each signature must match a distinct pubkey.
    std::vector<bool> pubkey_used(pubkeys.size(), false);
    uint32_t valid_count = 0;

    for (const auto* sig_field : sigs) {
        for (size_t k = 0; k < pubkeys.size(); ++k) {
            if (pubkey_used[k]) continue;

            const auto* pk = pubkeys[k];
            std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

            bool verified = false;
            if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
                // Schnorr
                std::vector<unsigned char> xonly;
                std::span<const unsigned char> pk_span{pk->data.data(), pk->data.size()};
                if (pk->data.size() == 33) {
                    xonly.assign(pk->data.begin() + 1, pk->data.end());
                    pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
                }
                verified = checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr);
            } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
                // ECDSA
                std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
                std::vector<unsigned char> pk_vec(pk->data.begin(), pk->data.end());
                CScript empty_script;
                verified = checker.CheckECDSASignature(sig_vec, pk_vec, empty_script, sigversion);
            }

            if (verified) {
                pubkey_used[k] = true;
                valid_count++;
                break;
            }
        }
    }

    return (valid_count >= threshold) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
}

EvalResult EvalHashPreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash256_field = FindField(block, RungDataType::HASH256);
    if (hash256_field) {
        unsigned char computed[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed);
        if (hash256_field->data.size() == 32 &&
            memcmp(computed, hash256_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalHash160PreimageBlock(const RungBlock& block)
{
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!preimage_field) {
        return EvalResult::ERROR;
    }

    const RungField* hash160_field = FindField(block, RungDataType::HASH160);
    if (hash160_field) {
        unsigned char computed[CHash160::OUTPUT_SIZE];
        CHash160().Write(preimage_field->data).Finalize(computed);
        if (hash160_field->data.size() == 20 &&
            memcmp(computed, hash160_field->data.data(), 20) == 0) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalCSVBlock(const RungBlock& block,
                        const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nSequence(sequence_val);

    // If the disable flag is set, sequence lock is satisfied unconditionally
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCSVTimeBlock(const RungBlock& block,
                            const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nSequence(sequence_val);

    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) {
        return EvalResult::SATISFIED;
    }

    if (!checker.CheckSequence(nSequence)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVBlock(const RungBlock& block,
                         const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalCLTVTimeBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker)
{
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) {
        return EvalResult::ERROR;
    }

    int64_t locktime_val = ReadNumeric(*numeric_field);
    if (locktime_val < 0) {
        return EvalResult::ERROR;
    }

    CScriptNum nLockTime(locktime_val);

    if (!checker.CheckLockTime(nLockTime)) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAdaptorSigBlock(const RungBlock& block,
                                const BaseSignatureChecker& checker,
                                SigVersion sigversion,
                                ScriptExecutionData& execdata)
{
    // Adaptor signature verification:
    // Requires two PUBKEY_COMMIT fields (conditions) resolved to PUBKEYs (witness)
    // Plus a SIGNATURE field (the adapted signature)
    auto pubkeys = ResolvePubkeyCommitments(block);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (pubkeys.size() < 2 || !sig_field) {
        return EvalResult::ERROR;
    }

    // First PUBKEY is the signing key, second is the adaptor point
    const RungField* signing_key = pubkeys[0];
    const RungField* adaptor_point = pubkeys[1];

    // Adaptor point must be 32 bytes (valid x-only point)
    if (adaptor_point->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // The adapted signature verifies against the signing key directly
    // (the adaptor secret has already been applied to produce the full signature)
    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        // Schnorr adaptor: verify adapted sig against signing key
        std::vector<unsigned char> xonly;
        std::span<const unsigned char> pk_span{signing_key->data.data(), signing_key->data.size()};
        if (signing_key->data.size() == 33) {
            xonly.assign(signing_key->data.begin() + 1, signing_key->data.end());
            pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }

        if (checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }
        return EvalResult::UNSATISFIED;
    }

    return EvalResult::ERROR;
}

EvalResult EvalTaggedHashBlock(const RungBlock& block)
{
    // BIP-340 tagged hash verification:
    // Requires two HASH256 fields: tag_hash and expected_hash
    // Plus a PREIMAGE field from witness
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);

    if (hashes.size() < 2 || !preimage_field) {
        return EvalResult::ERROR;
    }

    // First HASH256 is the tag hash, second is the expected result
    const RungField* tag_hash = hashes[0];
    const RungField* expected_hash = hashes[1];

    if (tag_hash->data.size() != 32 || expected_hash->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute TaggedHash(tag, preimage) = SHA256(SHA256(tag) || SHA256(tag) || preimage)
    // The tag_hash field IS SHA256(tag) already, so we compute:
    // SHA256(tag_hash || tag_hash || preimage)
    unsigned char computed[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(tag_hash->data.data(), 32)
        .Write(tag_hash->data.data(), 32)
        .Write(preimage_field->data.data(), preimage_field->data.size())
        .Finalize(computed);

    if (memcmp(computed, expected_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Covenant evaluators
// ============================================================================

uint256 ComputeCTVHash(const CTransaction& tx, uint32_t input_index)
{
    // BIP-119 template hash:
    // SHA256(version || locktime || scriptsigs_hash || num_inputs || sequences_hash ||
    //        num_outputs || outputs_hash || input_index)

    // scriptsigs hash (SHA256 of all scriptSigs concatenated)
    CSHA256 scriptsigs_hasher;
    for (const auto& vin : tx.vin) {
        scriptsigs_hasher.Write(reinterpret_cast<const unsigned char*>(vin.scriptSig.data()), vin.scriptSig.size());
    }
    unsigned char scriptsigs_hash[32];
    scriptsigs_hasher.Finalize(scriptsigs_hash);

    // sequences hash
    CSHA256 sequences_hasher;
    for (const auto& vin : tx.vin) {
        unsigned char seq_buf[4];
        seq_buf[0] = vin.nSequence & 0xFF;
        seq_buf[1] = (vin.nSequence >> 8) & 0xFF;
        seq_buf[2] = (vin.nSequence >> 16) & 0xFF;
        seq_buf[3] = (vin.nSequence >> 24) & 0xFF;
        sequences_hasher.Write(seq_buf, 4);
    }
    unsigned char sequences_hash[32];
    sequences_hasher.Finalize(sequences_hash);

    // outputs hash
    CSHA256 outputs_hasher;
    for (const auto& vout : tx.vout) {
        unsigned char amt_buf[8];
        uint64_t amt = static_cast<uint64_t>(vout.nValue);
        for (int i = 0; i < 8; ++i) amt_buf[i] = (amt >> (8 * i)) & 0xFF;
        outputs_hasher.Write(amt_buf, 8);
        uint64_t spk_len = vout.scriptPubKey.size();
        unsigned char len_buf[8];
        for (int i = 0; i < 8; ++i) len_buf[i] = (spk_len >> (8 * i)) & 0xFF;
        outputs_hasher.Write(len_buf, 8);
        outputs_hasher.Write(vout.scriptPubKey.data(), vout.scriptPubKey.size());
    }
    unsigned char outputs_hash[32];
    outputs_hasher.Finalize(outputs_hash);

    // Compute final template hash
    CSHA256 hasher;
    unsigned char version_buf[4];
    uint32_t version = static_cast<uint32_t>(tx.version);
    for (int i = 0; i < 4; ++i) version_buf[i] = (version >> (8 * i)) & 0xFF;
    hasher.Write(version_buf, 4);

    unsigned char locktime_buf[4];
    for (int i = 0; i < 4; ++i) locktime_buf[i] = (tx.nLockTime >> (8 * i)) & 0xFF;
    hasher.Write(locktime_buf, 4);

    hasher.Write(scriptsigs_hash, 32);

    unsigned char nins_buf[4];
    uint32_t nins = static_cast<uint32_t>(tx.vin.size());
    for (int i = 0; i < 4; ++i) nins_buf[i] = (nins >> (8 * i)) & 0xFF;
    hasher.Write(nins_buf, 4);

    hasher.Write(sequences_hash, 32);

    unsigned char nouts_buf[4];
    uint32_t nouts = static_cast<uint32_t>(tx.vout.size());
    for (int i = 0; i < 4; ++i) nouts_buf[i] = (nouts >> (8 * i)) & 0xFF;
    hasher.Write(nouts_buf, 4);

    hasher.Write(outputs_hash, 32);

    unsigned char idx_buf[4];
    for (int i = 0; i < 4; ++i) idx_buf[i] = (input_index >> (8 * i)) & 0xFF;
    hasher.Write(idx_buf, 4);

    unsigned char computed[32];
    hasher.Finalize(computed);

    uint256 result;
    memcpy(result.data(), computed, 32);
    return result;
}

EvalResult EvalCTVBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // CheckTemplateVerify: verify template hash matches spending transaction
    const RungField* template_hash = FindField(block, RungDataType::HASH256);
    if (!template_hash || template_hash->data.size() != 32) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) {
        return EvalResult::UNSATISFIED;
    }

    uint256 computed = ComputeCTVHash(*ctx.tx, ctx.input_index);

    if (memcmp(computed.data(), template_hash->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalVaultLockBlock(const RungBlock& block,
                               const BaseSignatureChecker& checker,
                               SigVersion sigversion,
                               ScriptExecutionData& execdata)
{
    // Two-path vault:
    // - recovery_key sig → SATISFIED immediately (cold sweep)
    // - hot_key sig → check CSV hot_delay elapsed
    auto pubkeys = ResolvePubkeyCommitments(block);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* delay_field = FindField(block, RungDataType::NUMERIC);

    if (pubkeys.size() < 2 || !sig_field || !delay_field) {
        return EvalResult::ERROR;
    }

    // First PUBKEY = recovery_key, second = hot_key
    const RungField* recovery_key = pubkeys[0];
    const RungField* hot_key = pubkeys[1];

    int64_t hot_delay = ReadNumeric(*delay_field);
    if (hot_delay < 0) {
        return EvalResult::ERROR;
    }

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};

    // Try recovery key first (cold sweep — no delay)
    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        std::span<const unsigned char> pk_span{recovery_key->data.data(), recovery_key->data.size()};
        if (recovery_key->data.size() == 33) {
            xonly.assign(recovery_key->data.begin() + 1, recovery_key->data.end());
            pk_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (checker.CheckSchnorrSignature(sig_span, pk_span, sigversion, execdata, nullptr)) {
            return EvalResult::SATISFIED;
        }

        // Try hot key (requires delay)
        std::vector<unsigned char> hot_xonly;
        std::span<const unsigned char> hot_pk_span{hot_key->data.data(), hot_key->data.size()};
        if (hot_key->data.size() == 33) {
            hot_xonly.assign(hot_key->data.begin() + 1, hot_key->data.end());
            hot_pk_span = std::span<const unsigned char>{hot_xonly.data(), hot_xonly.size()};
        }
        if (checker.CheckSchnorrSignature(sig_span, hot_pk_span, sigversion, execdata, nullptr)) {
            // Hot key matched — check CSV delay
            CScriptNum nSequence(hot_delay);
            if (checker.CheckSequence(nSequence)) {
                return EvalResult::SATISFIED;
            }
            return EvalResult::UNSATISFIED; // delay not met
        }
    }

    return EvalResult::UNSATISFIED;
}

EvalResult EvalAmountLockBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Output amount range check: min_sats <= output_amount <= max_sats
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }

    int64_t min_sats = ReadNumeric(*numerics[0]);
    int64_t max_sats = ReadNumeric(*numerics[1]);
    if (min_sats < 0 || max_sats < 0) {
        return EvalResult::ERROR;
    }

    CAmount output = ctx.output_amount;
    if (output >= min_sats && output <= max_sats) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Anchor evaluators
// ============================================================================

static bool HasRequiredHashes(const RungBlock& block, size_t count)
{
    return FindAllFields(block, RungDataType::HASH256).size() >= count;
}

EvalResult EvalAnchorBlock(const RungBlock& block)
{
    // Generic anchor: validate at least one typed param is present
    if (block.fields.empty()) {
        return EvalResult::ERROR;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorChannelBlock(const RungBlock& block)
{
    // Verify local_key and remote_key are valid pubkeys, commitment_number > 0
    if (!HasRequiredPubkeys(block, 2)) {
        return EvalResult::ERROR;
    }
    const RungField* commitment = FindField(block, RungDataType::NUMERIC);
    if (commitment) {
        int64_t val = ReadNumeric(*commitment);
        if (val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorPoolBlock(const RungBlock& block)
{
    // Verify vtxo_tree_root present, participant_count > 0
    if (!HasRequiredHashes(block, 1)) {
        return EvalResult::ERROR;
    }
    const RungField* count = FindField(block, RungDataType::NUMERIC);
    if (count) {
        int64_t val = ReadNumeric(*count);
        if (val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorReserveBlock(const RungBlock& block)
{
    // Verify threshold_n <= threshold_m, guardian set hash present
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2 || !HasRequiredHashes(block, 1)) {
        return EvalResult::ERROR;
    }
    int64_t threshold_n = ReadNumeric(*numerics[0]);
    int64_t threshold_m = ReadNumeric(*numerics[1]);
    if (threshold_n < 0 || threshold_m < 0 || threshold_n > threshold_m) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorSealBlock(const RungBlock& block)
{
    // Verify asset_id and state_transition hashes present
    if (!HasRequiredHashes(block, 2)) {
        return EvalResult::ERROR;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalAnchorOracleBlock(const RungBlock& block)
{
    // Verify oracle_key valid pubkey, outcome_count > 0
    if (!HasRequiredPubkeys(block, 1)) {
        return EvalResult::ERROR;
    }
    const RungField* count = FindField(block, RungDataType::NUMERIC);
    if (count) {
        int64_t val = ReadNumeric(*count);
        if (val <= 0) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

// ============================================================================
// Recursion evaluators
// ============================================================================

EvalResult EvalRecurseSameBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Verify output carries identical rung conditions as input
    const RungField* max_depth = FindField(block, RungDataType::NUMERIC);
    if (!max_depth) {
        return EvalResult::ERROR;
    }
    int64_t depth = ReadNumeric(*max_depth);
    if (depth <= 0) {
        return EvalResult::UNSATISFIED;
    }

    // If we have both input conditions and a spending output, verify the covenant
    if (ctx.input_conditions && ctx.spending_output) {
        RungConditions output_conds;
        if (!TryDeserializeOutputConditions(*ctx.spending_output, output_conds)) {
            return EvalResult::UNSATISFIED; // output must be a valid rung script
        }
        // Output conditions must be identical to input conditions
        if (!FullConditionsEqual(*ctx.input_conditions, output_conds)) {
            return EvalResult::UNSATISFIED;
        }
    }
    return EvalResult::SATISFIED;
}

/** Helper: a single mutation target (rung, block, param, delta). */
struct MutationSpec {
    int64_t rung_idx;
    int64_t block_idx;
    int64_t param_idx;
    int64_t delta;
};

/** Parse mutation specs from NUMERIC fields. Returns max_depth via out-param.
 *  Supports legacy (4 NUMERICs: rung 0, single mutation) and new format (6+ NUMERICs). */
static bool ParseMutationSpecs(const std::vector<const RungField*>& numerics,
                                int64_t& max_depth,
                                std::vector<MutationSpec>& mutations)
{
    if (numerics.size() < 4) return false;

    max_depth = ReadNumeric(*numerics[0]);

    if (numerics.size() == 4 || numerics.size() == 5) {
        // Legacy format: single mutation at rung 0
        mutations.push_back({0, ReadNumeric(*numerics[1]),
                             ReadNumeric(*numerics[2]), ReadNumeric(*numerics[3])});
        return true;
    }

    // New format: numerics[1] = num_mutations, then 4 fields per mutation
    int64_t num_mutations = ReadNumeric(*numerics[1]);
    if (num_mutations < 1 || static_cast<size_t>(2 + 4 * num_mutations) > numerics.size()) {
        return false;
    }
    for (int64_t i = 0; i < num_mutations; ++i) {
        size_t base = 2 + 4 * i;
        mutations.push_back({ReadNumeric(*numerics[base]),
                             ReadNumeric(*numerics[base + 1]),
                             ReadNumeric(*numerics[base + 2]),
                             ReadNumeric(*numerics[base + 3])});
    }
    return true;
}

/** Verify output conditions match input except for specified mutations (additive delta).
 *  Used by both RECURSE_MODIFIED and RECURSE_DECAY. For DECAY, caller negates the delta. */
static EvalResult VerifyMutatedConditions(const RungEvalContext& ctx,
                                           const std::vector<MutationSpec>& mutations)
{
    if (!ctx.input_conditions || !ctx.spending_output) {
        return EvalResult::SATISFIED; // no conditions to check
    }

    RungConditions output_conds;
    if (!TryDeserializeOutputConditions(*ctx.spending_output, output_conds)) {
        return EvalResult::UNSATISFIED;
    }
    if (output_conds.rungs.size() != ctx.input_conditions->rungs.size()) {
        return EvalResult::UNSATISFIED;
    }

    // Build a map: (rung_idx, block_idx) → list of (param_idx, delta)
    std::map<std::pair<int64_t, int64_t>, std::vector<std::pair<int64_t, int64_t>>> mut_map;
    for (const auto& m : mutations) {
        mut_map[{m.rung_idx, m.block_idx}].push_back({m.param_idx, m.delta});
    }

    for (size_t ri = 0; ri < output_conds.rungs.size(); ++ri) {
        const auto& in_rung = ctx.input_conditions->rungs[ri];
        const auto& out_rung = output_conds.rungs[ri];
        if (in_rung.blocks.size() != out_rung.blocks.size()) {
            return EvalResult::UNSATISFIED;
        }
        for (size_t bi = 0; bi < in_rung.blocks.size(); ++bi) {
            auto it = mut_map.find({static_cast<int64_t>(ri), static_cast<int64_t>(bi)});
            if (it != mut_map.end()) {
                // This block has mutation targets
                const auto& in_blk = in_rung.blocks[bi];
                const auto& out_blk = out_rung.blocks[bi];
                if (in_blk.type != out_blk.type) return EvalResult::UNSATISFIED;

                std::vector<const RungField*> in_conds, out_conds;
                for (const auto& f : in_blk.fields) {
                    if (IsConditionDataType(f.type)) in_conds.push_back(&f);
                }
                for (const auto& f : out_blk.fields) {
                    if (IsConditionDataType(f.type)) out_conds.push_back(&f);
                }
                if (in_conds.size() != out_conds.size()) return EvalResult::UNSATISFIED;

                // Build param_idx → delta map for this block
                std::map<int64_t, int64_t> param_deltas;
                for (const auto& [pidx, delta] : it->second) {
                    param_deltas[pidx] = delta;
                }

                for (size_t pi = 0; pi < in_conds.size(); ++pi) {
                    auto pd_it = param_deltas.find(static_cast<int64_t>(pi));
                    if (pd_it != param_deltas.end()) {
                        if (in_conds[pi]->type != RungDataType::NUMERIC ||
                            out_conds[pi]->type != RungDataType::NUMERIC) {
                            return EvalResult::UNSATISFIED;
                        }
                        int64_t in_val = ReadNumeric(*in_conds[pi]);
                        int64_t out_val = ReadNumeric(*out_conds[pi]);
                        if (out_val != in_val + pd_it->second) {
                            return EvalResult::UNSATISFIED;
                        }
                    } else {
                        if (in_conds[pi]->type != out_conds[pi]->type ||
                            in_conds[pi]->data != out_conds[pi]->data) {
                            return EvalResult::UNSATISFIED;
                        }
                    }
                }
            } else {
                if (!BlockConditionsEqual(in_rung.blocks[bi], out_rung.blocks[bi])) {
                    return EvalResult::UNSATISFIED;
                }
            }
        }
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseModifiedBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    int64_t max_depth;
    std::vector<MutationSpec> mutations;
    if (!ParseMutationSpecs(numerics, max_depth, mutations)) {
        return EvalResult::ERROR;
    }
    if (max_depth <= 0) {
        return EvalResult::UNSATISFIED;
    }
    return VerifyMutatedConditions(ctx, mutations);
}

EvalResult EvalRecurseUntilBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    const RungField* until_height_field = FindField(block, RungDataType::NUMERIC);
    if (!until_height_field) {
        return EvalResult::ERROR;
    }
    int64_t until_height = ReadNumeric(*until_height_field);
    if (until_height < 0) {
        return EvalResult::ERROR;
    }
    // Use tx nLockTime as height proxy (like CLTV — consensus ensures tx can't
    // be included before nLockTime). If nLockTime >= until_height, covenant terminates.
    int64_t effective_height = ctx.block_height;
    if (ctx.tx && ctx.tx->nLockTime < LOCKTIME_THRESHOLD) {
        effective_height = std::max(effective_height, static_cast<int64_t>(ctx.tx->nLockTime));
    }
    if (effective_height >= until_height) {
        return EvalResult::SATISFIED;
    }
    // Before until_height: must re-encumber output with same conditions
    if (ctx.input_conditions && ctx.spending_output) {
        RungConditions output_conds;
        if (!TryDeserializeOutputConditions(*ctx.spending_output, output_conds)) {
            return EvalResult::UNSATISFIED;
        }
        if (!FullConditionsEqual(*ctx.input_conditions, output_conds)) {
            return EvalResult::UNSATISFIED;
        }
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    const RungField* max_count = FindField(block, RungDataType::NUMERIC);
    if (!max_count) {
        return EvalResult::ERROR;
    }
    int64_t count = ReadNumeric(*max_count);
    if (count < 0) {
        return EvalResult::ERROR;
    }
    if (count == 0) {
        return EvalResult::SATISFIED; // countdown reached zero — covenant terminates
    }
    // Count > 0: output must re-encumber with count-1
    // Uses RECURSE_MODIFIED semantics on the count field (first NUMERIC in the block)
    if (ctx.input_conditions && ctx.spending_output) {
        RungConditions output_conds;
        if (!TryDeserializeOutputConditions(*ctx.spending_output, output_conds)) {
            return EvalResult::UNSATISFIED;
        }
        // Find the RECURSE_COUNT block in output conditions and verify count decremented
        bool found_valid = false;
        for (const auto& rung : output_conds.rungs) {
            for (const auto& blk : rung.blocks) {
                if (blk.type == RungBlockType::RECURSE_COUNT) {
                    const RungField* out_count_field = nullptr;
                    for (const auto& f : blk.fields) {
                        if (f.type == RungDataType::NUMERIC) { out_count_field = &f; break; }
                    }
                    if (out_count_field) {
                        int64_t out_count = ReadNumeric(*out_count_field);
                        if (out_count == count - 1) {
                            found_valid = true;
                            break;
                        }
                    }
                }
            }
            if (found_valid) break;
        }
        if (!found_valid) return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseSplitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    int64_t max_splits = ReadNumeric(*numerics[0]);
    int64_t min_split_sats = ReadNumeric(*numerics[1]);
    if (max_splits <= 0 || min_split_sats < 0) {
        return EvalResult::UNSATISFIED;
    }

    // Verify all outputs: each must be >= min_split_sats and re-encumber with max_splits-1
    if (ctx.tx && ctx.input_conditions) {
        CAmount total_output = 0;
        for (const auto& vout : ctx.tx->vout) {
            if (vout.nValue < min_split_sats) {
                return EvalResult::UNSATISFIED;
            }
            total_output += vout.nValue;
            // Each output must carry valid rung conditions with decremented max_splits
            RungConditions out_conds;
            if (TryDeserializeOutputConditions(vout, out_conds)) {
                // Check that RECURSE_SPLIT block exists with max_splits-1
                for (const auto& rung : out_conds.rungs) {
                    for (const auto& blk : rung.blocks) {
                        if (blk.type == RungBlockType::RECURSE_SPLIT) {
                            auto out_nums = FindAllFields(blk, RungDataType::NUMERIC);
                            if (out_nums.size() >= 1) {
                                int64_t out_splits = ReadNumeric(*out_nums[0]);
                                if (out_splits != max_splits - 1) {
                                    return EvalResult::UNSATISFIED;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Value conservation: total outputs must not exceed input
        if (total_output > ctx.input_amount) {
            return EvalResult::UNSATISFIED;
        }
    } else if (ctx.output_amount > 0 && ctx.output_amount < min_split_sats) {
        return EvalResult::UNSATISFIED;
    }
    return EvalResult::SATISFIED;
}

EvalResult EvalRecurseDecayBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    int64_t max_depth;
    std::vector<MutationSpec> mutations;
    if (!ParseMutationSpecs(numerics, max_depth, mutations)) {
        return EvalResult::ERROR;
    }
    if (max_depth <= 0) {
        return EvalResult::UNSATISFIED;
    }
    // Decay: negate deltas (output = input - decay_per_step)
    for (auto& m : mutations) {
        m.delta = -m.delta;
    }
    return VerifyMutatedConditions(ctx, mutations);
}

// ============================================================================
// PLC evaluators
// ============================================================================

EvalResult EvalHysteresisFeeBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Fee hysteresis: check the spending transaction's fee rate against band.
    // 2 NUMERICs: high_sat_vb, low_sat_vb.
    // SATISFIED if low <= fee_rate <= high.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    int64_t high = ReadNumeric(*numerics[0]);
    int64_t low = ReadNumeric(*numerics[1]);
    if (high < 0 || low < 0 || low > high) {
        return EvalResult::UNSATISFIED;
    }
    // If no tx context (structural-only mode), fall back to satisfied
    if (!ctx.tx || !ctx.spent_outputs) {
        return EvalResult::SATISFIED;
    }
    // Compute fee = sum(input values) - sum(output values)
    int64_t total_in = 0;
    for (const auto& spent : *ctx.spent_outputs) {
        total_in += spent.nValue;
    }
    int64_t total_out = 0;
    for (const auto& out : ctx.tx->vout) {
        total_out += out.nValue;
    }
    int64_t fee = total_in - total_out;
    if (fee < 0) {
        return EvalResult::UNSATISFIED;
    }
    // fee_rate = fee / vsize (sat/vB)
    int64_t vsize = GetVirtualTransactionSize(*ctx.tx);
    if (vsize <= 0) {
        return EvalResult::ERROR;
    }
    int64_t fee_rate = fee / vsize;
    if (fee_rate >= low && fee_rate <= high) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalHysteresisValueBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Value hysteresis: check input_amount against high/low band
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }
    int64_t high_sats = ReadNumeric(*numerics[0]);
    int64_t low_sats = ReadNumeric(*numerics[1]);
    if (high_sats < 0 || low_sats < 0 || low_sats > high_sats) {
        return EvalResult::UNSATISFIED;
    }
    // UTXO value within band
    if (ctx.input_amount >= low_sats && ctx.input_amount <= high_sats) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalTimerContinuousBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Continuous timer: 2 NUMERICs (accumulated, target).
    // SATISFIED if accumulated >= target (timer elapsed).
    // RECURSE_MODIFIED increments accumulated each covenant spend.
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) {
        // Single-field backward compat: treat as target, satisfied if > 0
        if (numerics.empty()) return EvalResult::ERROR;
        int64_t val = ReadNumeric(*numerics[0]);
        if (val <= 0) return EvalResult::UNSATISFIED;
        return EvalResult::SATISFIED;
    }
    int64_t accumulated = ReadNumeric(*numerics[0]);
    int64_t target = ReadNumeric(*numerics[1]);
    if (accumulated < 0 || target < 0) return EvalResult::ERROR;
    if (accumulated >= target) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalTimerOffDelayBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Off-delay timer: NUMERIC (remaining).
    // SATISFIED if remaining > 0 (still in hold-off period).
    // UNSATISFIED when remaining == 0 (delay expired).
    // RECURSE_MODIFIED decrements remaining each covenant spend.
    const RungField* hold = FindField(block, RungDataType::NUMERIC);
    if (!hold) return EvalResult::ERROR;
    int64_t remaining = ReadNumeric(*hold);
    if (remaining < 0) return EvalResult::ERROR;
    if (remaining > 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalLatchSetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Latch set — activates when state == 0 (unset).
    // Field layout: PUBKEY (setter key), NUMERIC (state: 0=unset, 1=set)
    // Pair with RECURSE_MODIFIED to enforce state 0→1 in the output.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.empty()) {
        // No state field — structural-only mode (backward compat)
        return EvalResult::SATISFIED;
    }
    int64_t state = ReadNumeric(*numerics[0]);
    if (state == 0) return EvalResult::SATISFIED;   // unset → can set
    return EvalResult::UNSATISFIED;                  // already set → SET rung inactive
}

EvalResult EvalLatchResetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Latch reset — activates when state >= 1 (set).
    // Field layout: PUBKEY (resetter key), NUMERIC (state), NUMERIC (delay blocks)
    // Pair with RECURSE_MODIFIED to enforce state 1→0 in the output.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR; // need state + delay
    int64_t state = ReadNumeric(*numerics[0]);
    int64_t delay = ReadNumeric(*numerics[1]);
    if (delay < 0) return EvalResult::ERROR;
    if (state >= 1) return EvalResult::SATISFIED;    // set → can reset
    return EvalResult::UNSATISFIED;                   // already unset → RESET rung inactive
}

EvalResult EvalCounterDownBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Down counter: PUBKEY (event signer) + NUMERIC (count).
    // SATISFIED if count > 0 (can still decrement). RECURSE_MODIFIED decrements each spend.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.empty()) return EvalResult::ERROR;
    int64_t count = ReadNumeric(*numerics[0]);
    if (count < 0) return EvalResult::ERROR;
    if (count > 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED; // countdown done
}

EvalResult EvalCounterPresetBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Preset counter: 2 NUMERICs (current, preset).
    // SATISFIED if current < preset (accumulating). UNSATISFIED when current >= preset (done).
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t preset = ReadNumeric(*numerics[1]);
    if (current < 0 || preset < 0) return EvalResult::ERROR;
    if (current < preset) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalCounterUpBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Up counter: PUBKEY (event signer) + 2 NUMERICs (current, target).
    // SATISFIED if current < target (still counting). UNSATISFIED when done.
    if (!HasRequiredPubkeys(block, 1)) return EvalResult::ERROR;
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t target = ReadNumeric(*numerics[1]);
    if (current < 0 || target < 0) return EvalResult::ERROR;
    if (current < target) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalCompareBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Comparator: compare input_amount against thresholds using specified operator
    // First NUMERIC is the operator, second is value_b, optional third is value_c
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);

    if (numerics.size() < 2) {
        return EvalResult::ERROR;
    }

    uint8_t op = static_cast<uint8_t>(ReadNumeric(*numerics[0]));
    int64_t value_b = ReadNumeric(*numerics[1]);
    if (value_b < 0) return EvalResult::ERROR;

    CAmount amount = ctx.input_amount;

    // Operators: EQ=0x01, NEQ=0x02, GT=0x03, LT=0x04, GTE=0x05, LTE=0x06, IN_RANGE=0x07
    switch (op) {
    case 0x01: return (amount == value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x02: return (amount != value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x03: return (amount > value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x04: return (amount < value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x05: return (amount >= value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x06: return (amount <= value_b) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    case 0x07: {
        // IN_RANGE: needs value_c as upper bound
        if (numerics.size() < 3) return EvalResult::ERROR;
        int64_t value_c = ReadNumeric(*numerics[2]);
        if (value_c < 0) return EvalResult::ERROR;
        return (amount >= value_b && amount <= value_c) ? EvalResult::SATISFIED : EvalResult::UNSATISFIED;
    }
    default:
        return EvalResult::ERROR;
    }
}

EvalResult EvalSequencerBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // Step sequencer — needs UTXO chain state, validate structure
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR; // current_step + total_steps
    int64_t current = ReadNumeric(*numerics[0]);
    int64_t total = ReadNumeric(*numerics[1]);
    if (current < 0 || total <= 0 || current >= total) return EvalResult::UNSATISFIED;
    return EvalResult::SATISFIED;
}

EvalResult EvalOneShotBlock(const RungBlock& block, const RungEvalContext& /*ctx*/)
{
    // One-shot: NUMERIC (state) + HASH256 (commitment).
    // SATISFIED if state == 0 (can fire). UNSATISFIED if state != 0 (already fired).
    const RungField* state_field = FindField(block, RungDataType::NUMERIC);
    if (!state_field) return EvalResult::ERROR;
    if (!HasRequiredHashes(block, 1)) return EvalResult::ERROR;
    int64_t state = ReadNumeric(*state_field);
    if (state == 0) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalRateLimitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // Rate limiter: check single-tx limit against output amount
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 3) return EvalResult::ERROR; // max_per_block, accumulation_cap, refill_blocks

    int64_t max_per_block = ReadNumeric(*numerics[0]);
    if (max_per_block < 0) return EvalResult::ERROR;

    // Single-tx limit check: output_amount must not exceed max_per_block
    if (ctx.output_amount > max_per_block) {
        return EvalResult::UNSATISFIED;
    }
    // Accumulation tracking needs UTXO chain state
    return EvalResult::SATISFIED;
}

// ============================================================================
// COSIGN — co-spend contact
// ============================================================================

EvalResult EvalCosignBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // COSIGN requires a HASH256 field containing SHA256 of the anchor's conditions scriptPubKey.
    // At spend time, verifies that another input in the same transaction has a spent output
    // whose scriptPubKey matches this hash.
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    if (!hash_field || hash_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Without transaction context or spent outputs, we can only do structural validation
    if (!ctx.tx || !ctx.spent_outputs) {
        return EvalResult::SATISFIED;
    }

    // Check each other input's spent output scriptPubKey
    for (size_t i = 0; i < ctx.tx->vin.size(); ++i) {
        if (i == ctx.input_index) continue; // skip self

        if (i >= ctx.spent_outputs->size()) continue;

        const CScript& other_spk = (*ctx.spent_outputs)[i].scriptPubKey;

        // SHA256 of the other input's spent scriptPubKey
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(other_spk.data(), other_spk.size()).Finalize(hash);

        if (memcmp(hash, hash_field->data.data(), 32) == 0) {
            return EvalResult::SATISFIED;
        }
    }

    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Compound evaluators (multi-block patterns in single block)
// ============================================================================

EvalResult EvalTimelockedSigBlock(const RungBlock& block,
                                   const BaseSignatureChecker& checker,
                                   SigVersion sigversion,
                                   ScriptExecutionData& execdata)
{
    // TIMELOCKED_SIG = SIG + CSV in one block
    // Fields: PUBKEY_COMMIT (conditions), PUBKEY (witness), SIGNATURE (witness), NUMERIC (timelock blocks)
    // Optional: SCHEME field for PQ routing

    // 1. Verify signature (same logic as EvalSigBlock)
    const RungField* pubkey_commit = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);

    if (pubkey_commit && !pubkey_field) return EvalResult::ERROR;
    if (pubkey_commit && pubkey_field) {
        unsigned char hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey_field->data.data(), pubkey_field->data.size()).Finalize(hash);
        if (pubkey_commit->data.size() != 32 || memcmp(hash, pubkey_commit->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
    }
    if (!pubkey_field || !sig_field || !numeric_field) return EvalResult::ERROR;

    // Check for PQ scheme
    bool sig_verified = false;
    const RungField* scheme_field = FindField(block, RungDataType::SCHEME);
    if (scheme_field && !scheme_field->data.empty()) {
        auto scheme = static_cast<RungScheme>(scheme_field->data[0]);
        if (IsPQScheme(scheme)) {
            EvalResult sig_result = EvalPQSig(scheme, *sig_field, *pubkey_field, checker);
            if (sig_result != EvalResult::SATISFIED) return sig_result;
            sig_verified = true;
        }
    }

    if (!sig_verified) {
        std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
        std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

        if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
            std::vector<unsigned char> xonly;
            if (pubkey_field->data.size() == 33) {
                xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
                pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
            }
            if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
                return EvalResult::UNSATISFIED;
            }
        } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
            std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
            std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
            CScript empty_script;
            if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
                return EvalResult::UNSATISFIED;
            }
        } else {
            return EvalResult::ERROR;
        }
    }

    // 2. Check CSV timelock (same logic as EvalCSVBlock)
    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return EvalResult::SATISFIED;
    CScriptNum nSequence(sequence_val);
    if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;

    return EvalResult::SATISFIED;
}

EvalResult EvalHTLCBlock(const RungBlock& block,
                          const BaseSignatureChecker& checker,
                          SigVersion sigversion,
                          ScriptExecutionData& execdata)
{
    // HTLC = HASH_PREIMAGE + CSV + SIG in one block
    // Fields: HASH256 (conditions), PREIMAGE (witness), NUMERIC (timelock),
    //         PUBKEY_COMMIT (conditions), PUBKEY (witness), SIGNATURE (witness)

    // 1. Verify hash preimage
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!hash_field || !preimage_field) return EvalResult::ERROR;
    if (hash_field->data.size() != 32) return EvalResult::ERROR;

    unsigned char computed_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed_hash);
    if (memcmp(computed_hash, hash_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // 2. Verify CSV timelock
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) return EvalResult::ERROR;
    int64_t sequence_val = ReadNumeric(*numeric_field);
    if (sequence_val < 0) return EvalResult::ERROR;
    if ((sequence_val & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0) {
        CScriptNum nSequence(sequence_val);
        if (!checker.CheckSequence(nSequence)) return EvalResult::UNSATISFIED;
    }

    // 3. Verify signature
    const RungField* pubkey_commit = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (pubkey_commit && !pubkey_field) return EvalResult::ERROR;
    if (pubkey_commit && pubkey_field) {
        unsigned char pk_hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey_field->data.data(), pubkey_field->data.size()).Finalize(pk_hash);
        if (pubkey_commit->data.size() != 32 || memcmp(pk_hash, pubkey_commit->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
    }
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::UNSATISFIED;
        }
    } else {
        return EvalResult::ERROR;
    }

    return EvalResult::SATISFIED;
}

EvalResult EvalHashSigBlock(const RungBlock& block,
                             const BaseSignatureChecker& checker,
                             SigVersion sigversion,
                             ScriptExecutionData& execdata)
{
    // HASH_SIG = HASH_PREIMAGE + SIG in one block
    // Fields: HASH256 (conditions), PREIMAGE (witness),
    //         PUBKEY_COMMIT (conditions), PUBKEY (witness), SIGNATURE (witness)

    // 1. Verify hash preimage
    const RungField* hash_field = FindField(block, RungDataType::HASH256);
    const RungField* preimage_field = FindField(block, RungDataType::PREIMAGE);
    if (!hash_field || !preimage_field) return EvalResult::ERROR;
    if (hash_field->data.size() != 32) return EvalResult::ERROR;

    unsigned char computed_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage_field->data.data(), preimage_field->data.size()).Finalize(computed_hash);
    if (memcmp(computed_hash, hash_field->data.data(), 32) != 0) {
        return EvalResult::UNSATISFIED;
    }

    // 2. Verify signature
    const RungField* pubkey_commit = FindField(block, RungDataType::PUBKEY_COMMIT);
    const RungField* pubkey_field = FindField(block, RungDataType::PUBKEY);
    const RungField* sig_field = FindField(block, RungDataType::SIGNATURE);

    if (pubkey_commit && !pubkey_field) return EvalResult::ERROR;
    if (pubkey_commit && pubkey_field) {
        unsigned char pk_hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(pubkey_field->data.data(), pubkey_field->data.size()).Finalize(pk_hash);
        if (pubkey_commit->data.size() != 32 || memcmp(pk_hash, pubkey_commit->data.data(), 32) != 0) {
            return EvalResult::UNSATISFIED;
        }
    }
    if (!pubkey_field || !sig_field) return EvalResult::ERROR;

    std::span<const unsigned char> sig_span{sig_field->data.data(), sig_field->data.size()};
    std::span<const unsigned char> pubkey_span{pubkey_field->data.data(), pubkey_field->data.size()};

    if (sig_field->data.size() >= 64 && sig_field->data.size() <= 65) {
        std::vector<unsigned char> xonly;
        if (pubkey_field->data.size() == 33) {
            xonly.assign(pubkey_field->data.begin() + 1, pubkey_field->data.end());
            pubkey_span = std::span<const unsigned char>{xonly.data(), xonly.size()};
        }
        if (!checker.CheckSchnorrSignature(sig_span, pubkey_span, sigversion, execdata, nullptr)) {
            return EvalResult::UNSATISFIED;
        }
    } else if (sig_field->data.size() >= 8 && sig_field->data.size() <= 72) {
        std::vector<unsigned char> sig_vec(sig_field->data.begin(), sig_field->data.end());
        std::vector<unsigned char> pubkey_vec(pubkey_field->data.begin(), pubkey_field->data.end());
        CScript empty_script;
        if (!checker.CheckECDSASignature(sig_vec, pubkey_vec, empty_script, sigversion)) {
            return EvalResult::UNSATISFIED;
        }
    } else {
        return EvalResult::ERROR;
    }

    return EvalResult::SATISFIED;
}

// ============================================================================
// Governance evaluators (transaction-level constraints)
// ============================================================================

EvalResult EvalEpochGateBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // EPOCH_GATE: spending allowed only within periodic windows.
    // Fields: NUMERIC[0] = epoch_size (blocks per epoch),
    //         NUMERIC[1] = window_size (blocks within epoch where spending is allowed)
    // Gate opens at block_height % epoch_size < window_size
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t epoch_size = ReadNumeric(*numerics[0]);
    int64_t window_size = ReadNumeric(*numerics[1]);
    if (epoch_size <= 0 || window_size <= 0 || window_size > epoch_size) {
        return EvalResult::ERROR;
    }

    int64_t position = ctx.block_height % epoch_size;
    if (position < window_size) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalWeightLimitBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // WEIGHT_LIMIT: max transaction weight
    // Fields: NUMERIC = max weight units (1 WU = 4 bytes for non-witness, 1 byte for witness)
    const RungField* numeric_field = FindField(block, RungDataType::NUMERIC);
    if (!numeric_field) return EvalResult::ERROR;

    int64_t max_weight = ReadNumeric(*numeric_field);
    if (max_weight <= 0) return EvalResult::ERROR;

    if (!ctx.tx) return EvalResult::SATISFIED; // structural validation only

    int64_t tx_weight = GetTransactionWeight(*ctx.tx);
    if (tx_weight <= max_weight) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalInputCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // INPUT_COUNT: bounds on number of inputs in spending tx
    // Fields: NUMERIC[0] = min_inputs, NUMERIC[1] = max_inputs
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t min_inputs = ReadNumeric(*numerics[0]);
    int64_t max_inputs = ReadNumeric(*numerics[1]);
    if (min_inputs < 0 || max_inputs < 0 || min_inputs > max_inputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::SATISFIED;

    int64_t count = static_cast<int64_t>(ctx.tx->vin.size());
    if (count >= min_inputs && count <= max_inputs) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalOutputCountBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // OUTPUT_COUNT: bounds on number of outputs in spending tx
    // Fields: NUMERIC[0] = min_outputs, NUMERIC[1] = max_outputs
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t min_outputs = ReadNumeric(*numerics[0]);
    int64_t max_outputs = ReadNumeric(*numerics[1]);
    if (min_outputs < 0 || max_outputs < 0 || min_outputs > max_outputs) {
        return EvalResult::ERROR;
    }

    if (!ctx.tx) return EvalResult::SATISFIED;

    int64_t count = static_cast<int64_t>(ctx.tx->vout.size());
    if (count >= min_outputs && count <= max_outputs) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

EvalResult EvalRelativeValueBlock(const RungBlock& block, const RungEvalContext& ctx)
{
    // RELATIVE_VALUE: output must be within a ratio of input value
    // Fields: NUMERIC[0] = numerator, NUMERIC[1] = denominator
    // Satisfied when: output_amount * denominator >= input_amount * numerator
    // Example: 9/10 means output must be >= 90% of input (anti-fee-siphon)
    auto numerics = FindAllFields(block, RungDataType::NUMERIC);
    if (numerics.size() < 2) return EvalResult::ERROR;

    int64_t numerator = ReadNumeric(*numerics[0]);
    int64_t denominator = ReadNumeric(*numerics[1]);
    if (numerator < 0 || denominator <= 0) return EvalResult::ERROR;

    // Use 64-bit multiplication to avoid overflow: compare output*denom >= input*num
    // Both amounts are in satoshis (max ~2.1e15), and num/denom are small (max 2^32),
    // so the products fit in int64_t (max ~9.2e18).
    int64_t lhs = ctx.output_amount * denominator;
    int64_t rhs = ctx.input_amount * numerator;

    // Overflow check: if either multiplication would overflow, use __int128
    if (ctx.output_amount > 0 && lhs / denominator != ctx.output_amount) {
        // Overflow — use extended precision
        __int128 lhs128 = static_cast<__int128>(ctx.output_amount) * denominator;
        __int128 rhs128 = static_cast<__int128>(ctx.input_amount) * numerator;
        if (lhs128 >= rhs128) return EvalResult::SATISFIED;
        return EvalResult::UNSATISFIED;
    }

    if (lhs >= rhs) return EvalResult::SATISFIED;
    return EvalResult::UNSATISFIED;
}

EvalResult EvalAccumulatorBlock(const RungBlock& block)
{
    // ACCUMULATOR: Merkle set membership proof
    // Conditions fields: HASH256[0] = merkle_root
    // Witness fields: HASH256[1..N] = merkle_proof (sibling hashes from leaf to root)
    //                 HASH256[N+1] = leaf_hash (the element being proven)
    // Proof verification: hash leaf with siblings bottom-up, compare to root.
    auto hashes = FindAllFields(block, RungDataType::HASH256);
    if (hashes.size() < 3) return EvalResult::ERROR; // root + at least 1 proof node + leaf

    const RungField* root_field = hashes[0];
    const RungField* leaf_field = hashes[hashes.size() - 1];
    if (root_field->data.size() != 32 || leaf_field->data.size() != 32) {
        return EvalResult::ERROR;
    }

    // Compute Merkle path: start from leaf, hash with each sibling
    // Convention: if computed_hash < sibling, hash(computed || sibling), else hash(sibling || computed)
    unsigned char current[32];
    memcpy(current, leaf_field->data.data(), 32);

    for (size_t i = 1; i < hashes.size() - 1; ++i) {
        const auto& sibling = hashes[i]->data;
        if (sibling.size() != 32) return EvalResult::ERROR;

        unsigned char combined[64];
        if (memcmp(current, sibling.data(), 32) < 0) {
            memcpy(combined, current, 32);
            memcpy(combined + 32, sibling.data(), 32);
        } else {
            memcpy(combined, sibling.data(), 32);
            memcpy(combined + 32, current, 32);
        }
        CSHA256().Write(combined, 64).Finalize(current);
    }

    if (memcmp(current, root_field->data.data(), 32) == 0) {
        return EvalResult::SATISFIED;
    }
    return EvalResult::UNSATISFIED;
}

// ============================================================================
// Block dispatch
// ============================================================================

EvalResult EvalBlock(const RungBlock& block,
                     const BaseSignatureChecker& checker,
                     SigVersion sigversion,
                     ScriptExecutionData& execdata,
                     const RungEvalContext& ctx)
{
    EvalResult raw;
    switch (block.type) {
    // Signature
    case RungBlockType::SIG:
        raw = EvalSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::MULTISIG:
        raw = EvalMultisigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::ADAPTOR_SIG:
        raw = EvalAdaptorSigBlock(block, checker, sigversion, execdata);
        break;
    // Timelock
    case RungBlockType::CSV:
        raw = EvalCSVBlock(block, checker);
        break;
    case RungBlockType::CSV_TIME:
        raw = EvalCSVTimeBlock(block, checker);
        break;
    case RungBlockType::CLTV:
        raw = EvalCLTVBlock(block, checker);
        break;
    case RungBlockType::CLTV_TIME:
        raw = EvalCLTVTimeBlock(block, checker);
        break;
    // Hash
    case RungBlockType::HASH_PREIMAGE:
        raw = EvalHashPreimageBlock(block);
        break;
    case RungBlockType::HASH160_PREIMAGE:
        raw = EvalHash160PreimageBlock(block);
        break;
    case RungBlockType::TAGGED_HASH:
        raw = EvalTaggedHashBlock(block);
        break;
    // Covenant
    case RungBlockType::CTV:
        raw = EvalCTVBlock(block, ctx);
        break;
    case RungBlockType::VAULT_LOCK:
        raw = EvalVaultLockBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::AMOUNT_LOCK:
        raw = EvalAmountLockBlock(block, ctx);
        break;
    // Anchor
    case RungBlockType::ANCHOR:
        raw = EvalAnchorBlock(block);
        break;
    case RungBlockType::ANCHOR_CHANNEL:
        raw = EvalAnchorChannelBlock(block);
        break;
    case RungBlockType::ANCHOR_POOL:
        raw = EvalAnchorPoolBlock(block);
        break;
    case RungBlockType::ANCHOR_RESERVE:
        raw = EvalAnchorReserveBlock(block);
        break;
    case RungBlockType::ANCHOR_SEAL:
        raw = EvalAnchorSealBlock(block);
        break;
    case RungBlockType::ANCHOR_ORACLE:
        raw = EvalAnchorOracleBlock(block);
        break;
    // Recursion
    case RungBlockType::RECURSE_SAME:
        raw = EvalRecurseSameBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_MODIFIED:
        raw = EvalRecurseModifiedBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_UNTIL:
        raw = EvalRecurseUntilBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_COUNT:
        raw = EvalRecurseCountBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_SPLIT:
        raw = EvalRecurseSplitBlock(block, ctx);
        break;
    case RungBlockType::RECURSE_DECAY:
        raw = EvalRecurseDecayBlock(block, ctx);
        break;
    // PLC
    case RungBlockType::HYSTERESIS_FEE:
        raw = EvalHysteresisFeeBlock(block, ctx);
        break;
    case RungBlockType::HYSTERESIS_VALUE:
        raw = EvalHysteresisValueBlock(block, ctx);
        break;
    case RungBlockType::TIMER_CONTINUOUS:
        raw = EvalTimerContinuousBlock(block, ctx);
        break;
    case RungBlockType::TIMER_OFF_DELAY:
        raw = EvalTimerOffDelayBlock(block, ctx);
        break;
    case RungBlockType::LATCH_SET:
        raw = EvalLatchSetBlock(block, ctx);
        break;
    case RungBlockType::LATCH_RESET:
        raw = EvalLatchResetBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_DOWN:
        raw = EvalCounterDownBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_PRESET:
        raw = EvalCounterPresetBlock(block, ctx);
        break;
    case RungBlockType::COUNTER_UP:
        raw = EvalCounterUpBlock(block, ctx);
        break;
    case RungBlockType::COMPARE:
        raw = EvalCompareBlock(block, ctx);
        break;
    case RungBlockType::SEQUENCER:
        raw = EvalSequencerBlock(block, ctx);
        break;
    case RungBlockType::ONE_SHOT:
        raw = EvalOneShotBlock(block, ctx);
        break;
    case RungBlockType::RATE_LIMIT:
        raw = EvalRateLimitBlock(block, ctx);
        break;
    case RungBlockType::COSIGN:
        raw = EvalCosignBlock(block, ctx);
        break;
    // Compound
    case RungBlockType::TIMELOCKED_SIG:
        raw = EvalTimelockedSigBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::HTLC:
        raw = EvalHTLCBlock(block, checker, sigversion, execdata);
        break;
    case RungBlockType::HASH_SIG:
        raw = EvalHashSigBlock(block, checker, sigversion, execdata);
        break;
    // Governance
    case RungBlockType::EPOCH_GATE:
        raw = EvalEpochGateBlock(block, ctx);
        break;
    case RungBlockType::WEIGHT_LIMIT:
        raw = EvalWeightLimitBlock(block, ctx);
        break;
    case RungBlockType::INPUT_COUNT:
        raw = EvalInputCountBlock(block, ctx);
        break;
    case RungBlockType::OUTPUT_COUNT:
        raw = EvalOutputCountBlock(block, ctx);
        break;
    case RungBlockType::RELATIVE_VALUE:
        raw = EvalRelativeValueBlock(block, ctx);
        break;
    case RungBlockType::ACCUMULATOR:
        raw = EvalAccumulatorBlock(block);
        break;
    default:
        raw = EvalResult::UNKNOWN_BLOCK_TYPE;
        break;
    }
    return ApplyInversion(raw, block.inverted);
}

bool EvalRelays(const std::vector<Relay>& relays,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx,
                std::vector<EvalResult>& relay_results_out)
{
    relay_results_out.resize(relays.size(), EvalResult::UNSATISFIED);

    for (size_t i = 0; i < relays.size(); ++i) {
        const auto& relay = relays[i];

        // Check relay_refs: all required relays must be SATISFIED
        bool requires_met = true;
        for (uint16_t req : relay.relay_refs) {
            if (req >= i || relay_results_out[req] != EvalResult::SATISFIED) {
                requires_met = false;
                break;
            }
        }

        if (!requires_met) {
            relay_results_out[i] = EvalResult::UNSATISFIED;
            continue;
        }

        // Evaluate relay blocks (AND logic, same as a rung)
        if (relay.blocks.empty()) {
            relay_results_out[i] = EvalResult::ERROR;
            return false;
        }

        EvalResult relay_result = EvalResult::SATISFIED;
        for (const auto& block : relay.blocks) {
            EvalResult result = EvalBlock(block, checker, sigversion, execdata, ctx);
            if (result != EvalResult::SATISFIED) {
                relay_result = result;
                break;
            }
        }

        if (relay_result == EvalResult::ERROR) {
            return false;
        }
        relay_results_out[i] = relay_result;
    }
    return true;
}

EvalResult EvalRung(const Rung& rung,
                    const BaseSignatureChecker& checker,
                    SigVersion sigversion,
                    ScriptExecutionData& execdata,
                    const RungEvalContext& ctx,
                    const std::vector<EvalResult>* relay_results)
{
    if (rung.blocks.empty()) {
        return EvalResult::ERROR;
    }

    // Check relay_refs: all required relays must be SATISFIED
    if (relay_results && !rung.relay_refs.empty()) {
        for (uint16_t req : rung.relay_refs) {
            if (req >= relay_results->size() || (*relay_results)[req] != EvalResult::SATISFIED) {
                return EvalResult::UNSATISFIED;
            }
        }
    }

    for (const auto& block : rung.blocks) {
        EvalResult result = EvalBlock(block, checker, sigversion, execdata, ctx);
        if (result != EvalResult::SATISFIED) {
            return result;
        }
    }
    return EvalResult::SATISFIED;
}

bool EvalLadder(const LadderWitness& ladder,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptExecutionData& execdata,
                const RungEvalContext& ctx)
{
    if (ladder.IsEmpty()) {
        return false;
    }

    // Evaluate relays first, cache results
    std::vector<EvalResult> relay_results;
    if (!ladder.relays.empty()) {
        if (!EvalRelays(ladder.relays, checker, sigversion, execdata, ctx, relay_results)) {
            return false;
        }
    }

    // First satisfied rung wins (OR logic across rungs)
    const std::vector<EvalResult>* relay_ptr = relay_results.empty() ? nullptr : &relay_results;
    for (const auto& rung : ladder.rungs) {
        EvalResult result = EvalRung(rung, checker, sigversion, execdata, ctx, relay_ptr);
        if (result == EvalResult::SATISFIED) {
            return true;
        }
    }
    return false;
}

/** Merge conditions (from spent output) with witness (from input).
 *  For each rung/block, the conditions provide the "locks" (pubkeys, hashes, timelocks)
 *  and the witness provides the "keys" (signatures, preimages). The merged result
 *  has all fields from both, which EvalLadder can then evaluate.
 *
 *  The witness must have the same rung/block structure as the conditions.
 *  The inverted flag is taken from conditions (witness doesn't override). */
static bool MergeConditionsAndWitness(const RungConditions& conditions,
                                       const LadderWitness& witness,
                                       LadderWitness& merged,
                                       std::string& error)
{
    if (conditions.rungs.size() != witness.rungs.size()) {
        error = "rung count mismatch: conditions=" + std::to_string(conditions.rungs.size()) +
                " witness=" + std::to_string(witness.rungs.size());
        return false;
    }

    merged.rungs.resize(conditions.rungs.size());
    merged.coil = conditions.coil;
    for (size_t r = 0; r < conditions.rungs.size(); ++r) {
        const auto& cond_rung = conditions.rungs[r];
        const auto& wit_rung = witness.rungs[r];

        if (cond_rung.blocks.size() != wit_rung.blocks.size()) {
            error = "block count mismatch in rung " + std::to_string(r);
            return false;
        }

        merged.rungs[r].blocks.resize(cond_rung.blocks.size());
        merged.rungs[r].rung_id = cond_rung.rung_id;
        merged.rungs[r].relay_refs = cond_rung.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_rung.blocks.size(); ++b) {
            const auto& cond_block = cond_rung.blocks[b];
            const auto& wit_block = wit_rung.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in rung " + std::to_string(r) +
                        " block " + std::to_string(b);
                return false;
            }

            // Merge: all condition fields first, then all witness fields
            auto& merged_block = merged.rungs[r].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted; // inverted comes from conditions
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    // Merge relays: conditions provide locks, witness provides keys
    if (conditions.relays.size() != witness.relays.size()) {
        error = "relay count mismatch: conditions=" + std::to_string(conditions.relays.size()) +
                " witness=" + std::to_string(witness.relays.size());
        return false;
    }
    merged.relays.resize(conditions.relays.size());
    for (size_t rl = 0; rl < conditions.relays.size(); ++rl) {
        const auto& cond_relay = conditions.relays[rl];
        const auto& wit_relay = witness.relays[rl];

        if (cond_relay.blocks.size() != wit_relay.blocks.size()) {
            error = "block count mismatch in relay " + std::to_string(rl);
            return false;
        }

        merged.relays[rl].blocks.resize(cond_relay.blocks.size());
        merged.relays[rl].relay_refs = cond_relay.relay_refs; // relay_refs come from conditions

        for (size_t b = 0; b < cond_relay.blocks.size(); ++b) {
            const auto& cond_block = cond_relay.blocks[b];
            const auto& wit_block = wit_relay.blocks[b];

            if (cond_block.type != wit_block.type) {
                error = "block type mismatch in relay " + std::to_string(rl) +
                        " block " + std::to_string(b);
                return false;
            }

            auto& merged_block = merged.relays[rl].blocks[b];
            merged_block.type = cond_block.type;
            merged_block.inverted = cond_block.inverted;
            merged_block.fields.insert(merged_block.fields.end(),
                                       cond_block.fields.begin(), cond_block.fields.end());
            merged_block.fields.insert(merged_block.fields.end(),
                                       wit_block.fields.begin(), wit_block.fields.end());
        }
    }

    return true;
}

bool VerifyRungTx(const CTransaction& tx,
                  unsigned int nIn,
                  const CTxOut& spent_output,
                  unsigned int /*flags*/,
                  const BaseSignatureChecker& checker,
                  const PrecomputedTransactionData& txdata,
                  ScriptError* serror,
                  int32_t block_height)
{
    if (nIn >= tx.vin.size()) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    const auto& witness = tx.vin[nIn].scriptWitness;
    if (witness.stack.empty()) {
        if (serror) *serror = SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY;
        return false;
    }

    // The ladder witness is the first element of the witness stack
    const auto& witness_bytes = witness.stack[0];

    LadderWitness witness_ladder;
    std::string deser_error;
    if (!DeserializeLadderWitness(witness_bytes, witness_ladder, deser_error)) {
        if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    // Try to deserialize spent output scriptPubKey as rung conditions
    RungConditions conditions;
    std::string cond_error;
    bool has_conditions = DeserializeRungConditions(spent_output.scriptPubKey, conditions, cond_error);

    // Build evaluation context for covenant, anchor, recursion, and PLC blocks
    RungEvalContext eval_ctx;
    eval_ctx.tx = &tx;
    eval_ctx.input_index = nIn;
    eval_ctx.input_amount = spent_output.nValue;
    eval_ctx.block_height = block_height;
    // output_amount: use first output amount as default (callers can refine)
    if (!tx.vout.empty()) {
        eval_ctx.output_amount = tx.vout[0].nValue;
        eval_ctx.spending_output = &tx.vout[0];
    }
    // Provide input conditions for recursion covenant checks
    if (has_conditions) {
        eval_ctx.input_conditions = &conditions;
    }
    // Provide all spent outputs for COSIGN cross-input verification
    if (txdata.m_spent_outputs_ready) {
        eval_ctx.spent_outputs = &txdata.m_spent_outputs;
    }

    LadderWitness eval_ladder;
    ScriptExecutionData execdata;

    if (has_conditions) {
        // Rung-to-rung spend: merge conditions with witness
        std::string merge_error;
        if (!MergeConditionsAndWitness(conditions, witness_ladder, eval_ladder, merge_error)) {
            if (serror) *serror = SCRIPT_ERR_UNKNOWN_ERROR;
            return false;
        }

        // Use LadderSignatureChecker with conditions context for proper sighash
        LadderSignatureChecker ladder_checker(checker, conditions, txdata, tx, nIn);
        if (!EvalLadder(eval_ladder, ladder_checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    } else {
        // Bootstrap spend: v3 tx spending a v1/v2 UTXO
        RungConditions empty_conditions;
        LadderSignatureChecker ladder_checker(checker, empty_conditions, txdata, tx, nIn);
        if (!EvalLadder(witness_ladder, ladder_checker, SigVersion::LADDER, execdata, eval_ctx)) {
            if (serror) *serror = SCRIPT_ERR_EVAL_FALSE;
            return false;
        }
    }

    return true;
}

} // namespace rung
