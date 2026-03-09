// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_CONDITIONS_H
#define BITCOIN_RUNG_CONDITIONS_H

#include <rung/types.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rung {

/** Magic prefix byte identifying a scriptPubKey as inline rung conditions (legacy). */
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1;

/** Magic prefix byte identifying a scriptPubKey as MLSC (Merkelized Ladder Script Conditions).
 *  Output format: 0xC2 + conditions_root(32 bytes) = 33-byte scriptPubKey.
 *  Full conditions are revealed only at spend time in the witness. */
static constexpr uint8_t RUNG_MLSC_PREFIX = 0xc2;

/** Nothing-up-my-sleeve constant for empty Merkle tree leaf padding.
 *  = SHA256("LADDER_EMPTY_LEAF"). Cannot collide with valid serialized rung/coil/relay data. */
extern const uint256 MLSC_EMPTY_LEAF;

/** A single field-level diff in a template reference. */
struct TemplateDiff {
    uint16_t rung_index;   //!< Which rung in the inherited conditions
    uint16_t block_index;  //!< Which block within that rung
    uint16_t field_index;  //!< Which field within that block
    RungField new_field;   //!< Replacement field data
};

/** Template reference: conditions inherited from another input with optional diffs. */
struct TemplateReference {
    uint32_t input_index;               //!< Which input's conditions to inherit
    std::vector<TemplateDiff> diffs;    //!< Field-level patches to apply
};

/** Rung conditions = the "locking" side of a v3 output.
 *  Stored in scriptPubKey with the same wire format as a LadderWitness
 *  but containing only condition data types (PUBKEY_COMMIT, HASH256,
 *  HASH160, NUMERIC, SCHEME, SPEND_INDEX) — never PUBKEY, SIGNATURE,
 *  or PREIMAGE. Raw public keys are witness-only; conditions use
 *  PUBKEY_COMMIT (SHA-256 of the key) to prevent arbitrary data
 *  embedding in the UTXO set.
 *
 *  When template_ref is set, n_rungs was 0 on the wire — conditions
 *  are inherited from the referenced input with diffs applied.
 *  Resolution happens in VerifyRungTx after all inputs' conditions
 *  are deserialized. */
struct RungConditions {
    std::vector<Rung> rungs;
    RungCoil coil;               //!< Output coil (per-output, serialized with conditions)
    std::vector<Relay> relays;   //!< Relay definitions (shared condition sets)
    std::optional<TemplateReference> template_ref; //!< Template inheritance reference (if set, rungs are empty until resolved)
    std::optional<uint256> conditions_root; //!< MLSC: Merkle root from UTXO (set for 0xC2 outputs)

    bool IsEmpty() const { return rungs.empty() && !template_ref.has_value() && !conditions_root.has_value(); }
    bool IsTemplateRef() const { return template_ref.has_value(); }
    bool IsMLSC() const { return conditions_root.has_value(); }
};

/** Quick prefix check: does this scriptPubKey start with the rung conditions prefix? */
bool IsRungConditionsScript(const CScript& scriptPubKey);

/** Deserialize rung conditions from a v3 output scriptPubKey. */
bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error);

/** Serialize rung conditions to a CScript suitable for v3 output scriptPubKey. */
CScript SerializeRungConditions(const RungConditions& conditions);

/** Resolve a template reference: copy conditions from the referenced input
 *  and apply field-level diffs.
 *  @param[in,out] conditions  The conditions with template_ref set (rungs empty).
 *                              On success, rungs/coil/relays are populated from
 *                              the referenced input and template_ref is cleared.
 *  @param[in]     all_conditions  All deserialized conditions for the transaction's inputs.
 *  @param[out]    error       Error message on failure.
 *  @return true on success. */
bool ResolveTemplateReference(RungConditions& conditions,
                              const std::vector<RungConditions>& all_conditions,
                              std::string& error);

/** Check whether a data type is allowed in conditions (locking side).
 *  SIGNATURE and PREIMAGE are witness-only and not permitted. */
bool IsConditionDataType(RungDataType type);

// Backward-compatible alias
inline bool IsConditionFieldType(RungDataType type) { return IsConditionDataType(type); }

// ============================================================================
// MLSC (Merkelized Ladder Script Conditions)
// ============================================================================

/** Check if scriptPubKey starts with the MLSC prefix (0xC2 + 32-byte root). */
bool IsMLSCScript(const CScript& scriptPubKey);

/** Check if scriptPubKey is either inline rung conditions (0xC1) or MLSC (0xC2). */
bool IsLadderScript(const CScript& scriptPubKey);

/** Extract the 32-byte conditions root from an MLSC scriptPubKey. */
bool GetMLSCRoot(const CScript& scriptPubKey, uint256& root_out);

/** Create an MLSC scriptPubKey: 0xC2 + conditions_root. */
CScript CreateMLSCScript(const uint256& conditions_root);

/** Compute the SHA256 leaf hash for a single rung (blocks + relay_refs). */
uint256 ComputeRungLeaf(const Rung& rung);

/** Compute the SHA256 leaf hash for coil metadata. */
uint256 ComputeCoilLeaf(const RungCoil& coil);

/** Compute the SHA256 leaf hash for a relay (blocks + relay_refs). */
uint256 ComputeRelayLeaf(const Relay& relay);

/** Build a binary Merkle tree from an arbitrary set of leaves.
 *  Pads to next power of 2 with MLSC_EMPTY_LEAF.
 *  Interior hashing: sort children lexicographically, then SHA256(0x01 || left || right).
 *  @return the Merkle root. */
uint256 BuildMerkleTree(std::vector<uint256> leaves);

/** Compute the MLSC conditions root for a complete set of conditions.
 *  Leaf order: [rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]. */
uint256 ComputeConditionsRoot(const RungConditions& conditions);

/** MLSC spending proof — revealed conditions + Merkle proof hashes.
 *  Carried in witness stack[1] when spending an MLSC (0xC2) output. */
struct MLSCProof {
    uint16_t total_rungs;      //!< Total number of rungs in the original conditions
    uint16_t total_relays;     //!< Total number of relays in the original conditions
    uint16_t rung_index;       //!< Which rung leaf is being revealed (0-based)
    Rung revealed_rung;        //!< Condition blocks for the revealed rung
    std::vector<std::pair<uint16_t, Relay>> revealed_relays; //!< (relay_index, condition blocks) for each revealed relay
    std::vector<uint256> proof_hashes; //!< Leaf hashes for unrevealed leaves, in leaf-order
};

/** Deserialize an MLSC proof from witness stack element bytes. */
bool DeserializeMLSCProof(const std::vector<uint8_t>& data, MLSCProof& proof, std::string& error);

/** Serialize an MLSC proof to bytes (for witness stack element). */
std::vector<uint8_t> SerializeMLSCProof(const MLSCProof& proof);

/** Verify an MLSC Merkle proof against a conditions root.
 *  Reconstructs the full leaf array from revealed data + proof hashes, builds the tree,
 *  and checks the computed root matches the expected root.
 *  @param[in]  proof           The deserialized MLSC proof
 *  @param[in]  coil            The coil from the spending witness (always revealed)
 *  @param[in]  expected_root   The conditions_root from the UTXO
 *  @param[out] error           Error message on failure
 *  @return true if the Merkle proof verifies correctly. */
bool VerifyMLSCProof(const MLSCProof& proof,
                     const RungCoil& coil,
                     const uint256& expected_root,
                     std::string& error);

} // namespace rung

#endif // BITCOIN_RUNG_CONDITIONS_H
