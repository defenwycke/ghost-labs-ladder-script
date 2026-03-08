// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_RUNG_CONDITIONS_H
#define BITCOIN_RUNG_CONDITIONS_H

#include <rung/types.h>
#include <script/script.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rung {

/** Magic prefix byte identifying a scriptPubKey as rung conditions.
 *  Chosen to not conflict with any existing OP_ prefix. */
static constexpr uint8_t RUNG_CONDITIONS_PREFIX = 0xc1;

/** Rung conditions = the "locking" side of a v3 output.
 *  Stored in scriptPubKey with the same wire format as a LadderWitness
 *  but containing only condition data types (PUBKEY_COMMIT, HASH256,
 *  HASH160, NUMERIC, SCHEME, SPEND_INDEX) — never PUBKEY, SIGNATURE,
 *  or PREIMAGE. Raw public keys are witness-only; conditions use
 *  PUBKEY_COMMIT (SHA-256 of the key) to prevent arbitrary data
 *  embedding in the UTXO set. */
struct RungConditions {
    std::vector<Rung> rungs;
    RungCoil coil;               //!< Output coil (per-output, serialized with conditions)
    std::vector<Relay> relays;   //!< Relay definitions (shared condition sets)

    bool IsEmpty() const { return rungs.empty(); }
};

/** Quick prefix check: does this scriptPubKey start with the rung conditions prefix? */
bool IsRungConditionsScript(const CScript& scriptPubKey);

/** Deserialize rung conditions from a v3 output scriptPubKey. */
bool DeserializeRungConditions(const CScript& scriptPubKey, RungConditions& out, std::string& error);

/** Serialize rung conditions to a CScript suitable for v3 output scriptPubKey. */
CScript SerializeRungConditions(const RungConditions& conditions);

/** Check whether a data type is allowed in conditions (locking side).
 *  SIGNATURE and PREIMAGE are witness-only and not permitted. */
bool IsConditionDataType(RungDataType type);

// Backward-compatible alias
inline bool IsConditionFieldType(RungDataType type) { return IsConditionDataType(type); }

} // namespace rung

#endif // BITCOIN_RUNG_CONDITIONS_H
