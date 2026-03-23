# Claude Code Prompt: Ladder Script — Ghost Core Implementation v2

> **Note:** This document is a historical build prompt. References to "phases" below reflect the original incremental build strategy used during development. All 61 block types across 10 families are now fully implemented and activate in a single soft fork. See [SOFT_FORK_GUIDE.md](SOFT_FORK_GUIDE.md) for the current activation strategy.

---

## Project Context

You are working on **Ghost Core**, a Bitcoin Core v30 fork that is part of the Bitcoin Ghost project. Ghost Core is a full Bitcoin node operating on Bitcoin mainnet/signet/regtest. It is **NOT a separate blockchain** — it is a Bitcoin node with additional infrastructure. Ghost Pool (Stratum V2 mining pool) and Ghost Pay (Layer 2 payment system) are companion projects.

The repository is a fork of Bitcoin Core. All existing Bitcoin consensus rules, p2p, wallet, and RPC must remain completely untouched and functional. Every test in the existing Bitcoin Core test suite must continue to pass.

Your task is to implement **Ladder Script** as a new module on a branch of Ghost Core. This is a softfork-compatible addition — new transaction version 4 (`RUNG_TX`) that old nodes treat as non-standard but do not reject, following the exact precedent of SegWit.

---

## Branch

```bash
git checkout -b feature/ladder-script
```

All new code lives in `src/rung/`. Modifications to existing files must be minimal and surgical, every changed line commented with `// LADDER SCRIPT:`.

---

## What Is Ladder Script

Ladder Script is a new Bitcoin transaction format derived from industrial PLC (Programmable Logic Controller) ladder logic. This is not an aesthetic choice — it is load-bearing architecture.

In PLC ladder logic, programs consist of horizontal **rungs**. Each rung has:
- **Contacts** (left side) — conditions that must be satisfied for current to flow
- **A coil** (right side) — the action that executes when all contacts are satisfied
- Current flows left to right only — deterministic, sequential, no side effects

```
|--[Contact_A]--[Contact_B]--( Coil )--|
```

Applied to Bitcoin: contacts are typed function blocks expressing spending conditions. Coils declare what happens when conditions are met. The first rung where ALL contacts satisfy executes its coil.

```
Output spending conditions:
  RUNG 0: [SIG: Alice] [CSV: 144] ──( UNLOCK )──
  RUNG 1: [MULTISIG: 2-of-3 A,B,C] ──( UNLOCK )──
  RUNG 2: [CLTV: 52000] [SIG: recovery] ──( UNLOCK )──
```

**Why this matters architecturally:**

1. **Spam is a parse error** — no untyped byte arrays exist in the format. Conditions contain zero user-chosen bytes (every field is a hash digest or bounded numeric). PUBKEY is witness-only; conditions use PUBKEY_COMMIT (SHA-256 hash). Inscriptions, ordinals, arbitrary data embedding are structurally impossible. Not policy-restricted — parse error.

2. **Coils declare, not carry** — the coil declares attestation mode. Heavy cryptographic data (PQ signatures, aggregate proofs) lives at the block level, not in every transaction. Transactions carry only what is necessary.

3. **Human readable** — a CFO, lawyer, or board member can audit a ladder diagram. A PLC engineer can read it immediately. No cryptographic knowledge required.

4. **Contact inversion** — any contact can be inverted (normally closed in PLC terms) using the `inverted` flag. `[/CSV: 144]` means "BEFORE 144 blocks" — a genuinely new Bitcoin primitive enabling dead man's switches, governance vetoes, and breach remediation improvements.

5. **One format** — replaces P2PKH/P2SH/P2WSH/P2TR fragmentation entirely.

---

## Architecture Overview

Implementation is split into four phases. Build Phase 1 completely before touching Phase 2. Phase 3 and 4 are placeholders only — stub the enums, add TODO comments, do not implement.

```
Phase 1 (THIS TASK):   Core format + basic blocks + Signet
Phase 2 (future):      Contact inversion + ANCHOR blocks + L2 support
Phase 3 (future):      Recursive covenants + bounded recursion
Phase 4 (future):      PQ signatures + AGGREGATE attestation
```

---

## Phase 1 Specification — Complete Implementation Required

### Transaction Version

```cpp
// src/primitives/transaction.h
// LADDER SCRIPT: new version constant
static const int32_t RUNG_TX_VERSION = 4;
```

### Data Type System

Every parameter in every function block must be one of these enumerated types. **No other types exist.** An unknown type byte is a parse error — the transaction is rejected before reaching the mempool. This is the spam prevention mechanism. It is enforced at the deserializer, before any cryptographic operation.

```cpp
enum class RungDataType : uint8_t {
    PUBKEY        = 0x01,  // max 2048 bytes — witness-only. Conditions use PUBKEY_COMMIT instead.
    PUBKEY_COMMIT = 0x02,  // exactly 32 bytes — SHA-256 hash of pubkey. Used in conditions instead of raw PUBKEY.
    HASH256       = 0x03,  // exactly 32 bytes — SHA-256 hash
    HASH160       = 0x04,  // exactly 20 bytes — HASH160
    PREIMAGE      = 0x05,  // max 32 bytes — hash preimage reveal
    SIGNATURE     = 0x06,  // max 50,000 bytes — PQ signatures (SPHINCS_SHA ~7,856B, Dilithium3 ~3,293B)
    SPEND_INDEX   = 0x07,  // exactly 4 bytes — reserved for Phase 4 AGGREGATE mode
    NUMERIC       = 0x08,  // max 4 bytes — timelock values, thresholds, counts
    SCHEME        = 0x09,  // exactly 1 byte — signature scheme enum value
};

// Size enforcement table — checked at parse time
static const std::map<RungDataType, std::pair<size_t,size_t>> RUNG_TYPE_LIMITS = {
    {RungDataType::PUBKEY,        {1,  64}},
    {RungDataType::PUBKEY_COMMIT, {32, 32}},
    {RungDataType::HASH256,       {32, 32}},
    {RungDataType::HASH160,       {20, 20}},
    {RungDataType::PREIMAGE,      {1,  32}},
    {RungDataType::SIGNATURE,     {1,  50000}},
    {RungDataType::SPEND_INDEX,   {4,  4}},
    {RungDataType::NUMERIC,       {1,  4}},
    {RungDataType::SCHEME,        {1,  1}},
};
```

### Block Type Enum — Phase 1 implement, Phase 2+ reserve

```cpp
enum class RungBlockType : uint16_t {
    // ── Phase 1: Implement fully ──────────────────────────────────
    SIG               = 0x0001,  // Single signature
    MULTISIG          = 0x0002,  // n-of-m threshold signatures
    ADAPTOR_SIG       = 0x0003,  // Adaptor signature (DLC/atomic swap)
    CSV               = 0x0101,  // Check Sequence Verify — relative timelock
    CSV_TIME          = 0x0102,  // CSV by median time past
    CLTV              = 0x0103,  // Check Lock Time Verify — absolute
    CLTV_TIME         = 0x0104,  // CLTV by median time past
    HASH_PREIMAGE     = 0x0201,  // SHA-256 preimage reveal
    HASH160_PREIMAGE  = 0x0202,  // HASH160 preimage
    TAGGED_HASH       = 0x0203,  // BIP-340 tagged hash

    // ── Phase 2: Reserve enum values, return UNSATISFIED if evaluated ──
    CTV               = 0x0301,  // CheckTemplateVerify
    VAULT_LOCK        = 0x0302,  // Vault with delay + recovery key

    // L2 Anchor blocks
    ANCHOR            = 0x0501,  // Generic L2 state anchor
    ANCHOR_CHANNEL    = 0x0502,  // Payment channel (Lightning-style)
    ANCHOR_POOL       = 0x0503,  // Shared UTXO pool (Ark-style)
    ANCHOR_RESERVE    = 0x0504,  // Federation reserve (Fedimint/Liquid)
    ANCHOR_SEAL       = 0x0505,  // Single-use seal (RGB-style)
    ANCHOR_ORACLE     = 0x0506,  // Oracle-attested contract (DLC-style)

    // ── Phase 3: Reserve only ─────────────────────────────────────
    RECURSE_SAME      = 0x0401,  // Inherit exact same rung set
    RECURSE_MODIFIED  = 0x0402,  // Inherit with typed mutations
    RECURSE_UNTIL     = 0x0403,  // Recurse until termination condition
    RECURSE_COUNT     = 0x0404,  // Recurse N times maximum
    RECURSE_SPLIT     = 0x0405,  // Split value, each piece inherits rules
    RECURSE_DECAY     = 0x0406,  // Each recursion relaxes one constraint
};
```

### Signature Schemes

```cpp
enum class RungScheme : uint8_t {
    SCHNORR     = 0x01,  // BIP-340 Schnorr — primary scheme
    ECDSA       = 0x02,  // Legacy ECDSA — compat only

    // Phase 4 — reserve values only, do not implement
    FALCON512   = 0x10,
    FALCON1024  = 0x11,
    DILITHIUM3  = 0x12,
    SPHINCS_SHA = 0x13,
};
```

### Coil Structure

The coil is not a signature. The coil is a **claim type declaration**. It declares what kind of unlock is being claimed and how the claim is proven. The transaction carries only what the attestation mode requires.

```cpp
enum class RungCoilType : uint8_t {
    UNLOCK      = 0x01,  // Standard UTXO unlock
    UNLOCK_TO   = 0x02,  // Unlock with output address constraint
    COVENANT    = 0x03,  // Covenant-constrained unlock (Phase 2+)
};

enum class RungAttestationMode : uint8_t {
    INLINE      = 0x01,  // Sig carried in tx witness — Phase 1, implement fully
    AGGREGATE   = 0x02,  // Sig contributed to block-level proof — Phase 4, reserve
    DEFERRED    = 0x03,  // Validity from prior commitment — Phase 4, reserve
};

struct RungCoil {
    RungCoilType       coil_type;
    RungAttestationMode attestation;
    RungScheme         scheme;
};
```

### Contact Inversion — The Normally Closed Contact

**This is a Phase 1 feature. Implement fully.**

In PLC ladder logic, a normally closed contact `[/]` passes current when the condition is FALSE — the inverse of a normally open contact. This is a fundamental PLC primitive that creates genuinely new Bitcoin spending primitives:

```
[/CSV: 144]        = spend BEFORE 144 blocks (not after — current Bitcoin has no native "before")
[/CLTV: 52000]     = spend BEFORE block 52000
[/HASH_PREIMAGE: H]= spend only if preimage NOT revealed
[/MULTISIG: 3-of-5]= spend only if 3-of-5 do NOT sign (governance veto)
[/SIG: key]        = spend only if key does NOT sign (exclusion)
```

Implementation: one boolean flag on `RungBlock`. The evaluator inverts the result after calling the block's native evaluator.

```cpp
struct RungBlock {
    RungBlockType              block_type;
    bool                       inverted;    // normally closed contact
    std::vector<RungTypedParam> params;

    // Convenience accessors
    RungScheme  GetScheme() const;
    CPubKey     GetPubKey() const;
    int64_t     GetNumeric() const;
    uint256     GetHash256() const;
};
```

Inversion evaluation:

```cpp
EvalResult ApplyInversion(EvalResult raw, bool inverted) {
    if (!inverted) return raw;
    switch (raw) {
        case EvalResult::SATISFIED:          return EvalResult::UNSATISFIED;
        case EvalResult::UNSATISFIED:        return EvalResult::SATISFIED;
        case EvalResult::ERROR:              return EvalResult::ERROR;
        // Unknown block when inverted = SATISFIED
        // Absence of unknown condition passes — forward compat
        case EvalResult::UNKNOWN_BLOCK_TYPE: return EvalResult::SATISFIED;
    }
    return EvalResult::ERROR;
}
```

Wire format: `inverted` is serialised as 1 byte (0x00 = normal, 0x01 = inverted) immediately after `block_type`.

### Core Data Structures

```cpp
// src/rung/rung_types.h

struct RungTypedParam {
    RungDataType            type;
    std::vector<uint8_t>    data;

    void Validate() const;  // throws on type size violation
    uint32_t GetNumeric() const;
    uint256  GetHash256() const;
    CPubKey  GetPubKey() const;
};

struct RungBlock {
    RungBlockType               block_type;
    bool                        inverted{false};
    std::vector<RungTypedParam> params;

    RungScheme GetScheme() const;
    CPubKey    GetPubKey() const;
    int64_t    GetNumeric() const;
    uint256    GetHash256() const;
};

struct RungCoil {
    RungCoilType        coil_type;
    RungAttestationMode attestation;
    RungScheme          scheme;
};

struct Rung {
    uint8_t                 rung_id;
    std::vector<RungBlock>  contacts;  // ALL contacts must satisfy
    RungCoil                coil;
};

struct RungOutput {
    CAmount             value;
    std::vector<Rung>   rungs;
    // Phase 2: OutputType enum for STEALTH/CONFIDENTIAL — reserved
};

struct RungTx {
    int32_t                 version{RUNG_TX_VERSION};
    uint32_t                locktime{0};
    std::vector<CTxIn>      inputs;        // standard CTxIn
    std::vector<RungOutput> rung_outputs;
};
```

### Wire Serialization

```
RUNG_TX:
  version:          int32_t     (must be 4)
  locktime:         uint32_t
  input_count:      varint
  inputs[]:
    outpoint:       32B txid + 4B vout
    sequence:       uint32_t
    witness_count:  varint
    witness[]:
      type:         uint8_t     (RungDataType — type-constrained)
      length:       varint
      data:         bytes
  output_count:     varint
  outputs[]:
    value:          int64_t
    rung_count:     varint
    rungs[]:
      rung_id:      uint8_t
      block_count:  varint
      blocks[]:
        block_type: uint16_t
        inverted:   uint8_t     (0x00 normal, 0x01 inverted)
        param_count: varint
        params[]:
          type:     uint8_t     (RungDataType)
          length:   varint
          data:     bytes       (type-constrained)
      coil:
        coil_type:   uint8_t
        attestation: uint8_t
        scheme:      uint8_t
```

---

## Files To Create

### New Directory: `src/rung/`

```
src/rung/
  rung_types.h              ← data structures, enums, constants
  rung_types.cpp            ← Validate() methods, convenience accessors
  rung_serialize.h          ← serialization interface
  rung_serialize.cpp        ← type-enforcing deserializer (THE spam barrier)
  rung_eval.h               ← evaluation engine interface
  rung_eval.cpp             ← evaluation engine + inversion logic
  rung_policy.h             ← mempool policy
  rung_policy.cpp
  rung_rpc.h                ← JSON <-> RungTx conversion
  rung_rpc.cpp
  blocks/
    block_sig.h / .cpp      ← SIG + MULTISIG + ADAPTOR_SIG
    block_csv.h / .cpp      ← CSV + CSV_TIME + CLTV + CLTV_TIME
    block_hash.h / .cpp     ← HASH_PREIMAGE + HASH160_PREIMAGE + TAGGED_HASH
    block_anchor.h / .cpp   ← ANCHOR + ANCHOR_CHANNEL + ANCHOR_POOL +
                               ANCHOR_RESERVE + ANCHOR_SEAL + ANCHOR_ORACLE
                               (Phase 2 — stub only in Phase 1, return UNSATISFIED)
    block_covenant.h / .cpp ← CTV + VAULT_LOCK (Phase 2 — stub, return UNSATISFIED)
    block_recurse.h / .cpp  ← RECURSE_* (Phase 3 — stub, return UNSATISFIED)
```

### Files To Modify (surgical changes only)

```
src/primitives/transaction.h   ← add RUNG_TX_VERSION
src/script/interpreter.cpp     ← route version 4 to VerifyRungTx
src/policy/policy.cpp          ← add IsStandardRungTx
src/consensus/tx_verify.cpp    ← RUNG_TX consensus validation
src/rpc/rawtransaction.cpp     ← new RPC commands
src/Makefile.am / CMakeLists   ← add rung/ sources
```

---

## Implementation Requirements

### 1. Deserializer — The Spam Barrier (`rung_serialize.cpp`)

This is the most critical function in the entire implementation. Type enforcement happens here, before any cryptographic operation, before mempool, before anything.

```cpp
RungTypedParam DeserializeTypedParam(Stream& is) {
    RungTypedParam param;
    uint8_t type_byte;
    is >> type_byte;

    // Unknown type = immediate parse error
    // This is what makes spam structurally impossible
    if (!IsKnownRungDataType(type_byte))
        throw std::ios_base::failure(
            strprintf("LADDER SCRIPT: Unknown RungDataType 0x%02x — "
                      "no untyped data exists in this format", type_byte));

    param.type = static_cast<RungDataType>(type_byte);
    uint64_t length = ReadCompactSize(is);

    // Enforce exact size constraints per type
    auto limits = RUNG_TYPE_LIMITS.at(param.type);
    if (length < limits.first || length > limits.second)
        throw std::ios_base::failure(
            strprintf("LADDER SCRIPT: %s param length %d out of bounds [%d,%d]",
                      RungDataTypeName(param.type), length,
                      limits.first, limits.second));

    param.data.resize(length);
    is.read(reinterpret_cast<char*>(param.data.data()), length);
    return param;
}

RungBlock DeserializeRungBlock(Stream& is) {
    RungBlock block;
    uint16_t block_type_raw;
    is >> block_type_raw;
    block.block_type = static_cast<RungBlockType>(block_type_raw);

    uint8_t inverted_byte;
    is >> inverted_byte;
    block.inverted = (inverted_byte == 0x01);

    uint64_t param_count = ReadCompactSize(is);
    block.params.reserve(param_count);
    for (uint64_t i = 0; i < param_count; ++i)
        block.params.push_back(DeserializeTypedParam(is));

    return block;
}
```

### 2. Evaluation Engine (`rung_eval.cpp`)

```cpp
enum class EvalResult {
    SATISFIED,
    UNSATISFIED,
    ERROR,
    UNKNOWN_BLOCK_TYPE,  // future block type — treated as UNSATISFIED
    ANCHOR_SEQUENCE_VIOLATION,  // Phase 2 — sequence number rollback
};

// Main consensus entry point
bool VerifyRungTx(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    unsigned int flags,
    CValidationState& state);

// Evaluate all rungs for one input — first satisfied wins
EvalResult EvaluateRungSet(
    const std::vector<Rung>& rungs,
    const CTxIn& input,
    const RungOutput& prev_output,
    const BaseSignatureChecker& checker,
    const TxContext& ctx);

// Evaluate one rung — all contacts must satisfy
EvalResult EvaluateRung(
    const Rung& rung,
    const CTxIn& input,
    const BaseSignatureChecker& checker,
    const TxContext& ctx);

// Evaluate one block — apply inversion after raw evaluation
EvalResult EvaluateBlock(
    const RungBlock& block,
    const CTxIn& input,
    const BaseSignatureChecker& checker,
    const TxContext& ctx)
{
    EvalResult raw = EvaluateBlockRaw(block, input, checker, ctx);
    return ApplyInversion(raw, block.inverted);
}
```

**Evaluation rules (non-negotiable):**
- Iterate rungs 0, 1, 2... top to bottom
- First rung where ALL contacts return `SATISFIED` → execute coil → return true
- Unknown block type → `UNKNOWN_BLOCK_TYPE` → treated as `UNSATISFIED` (NOT error — forward compat)
- Unknown scheme → `UNSATISFIED` (NOT error — forward compat)
- Any contact returning `ERROR` → entire rung is `ERROR` → propagates up
- No rung satisfied → transaction is invalid

### 3. Block Evaluators — Phase 1

#### SIG block

```cpp
// blocks/block_sig.cpp
// Params: [SCHEME, PUBKEY]
// Witness: [SIGNATURE]
// Satisfies when: signature verifies against pubkey under scheme
EvalResult EvalSigBlock(
    const RungBlock& block,
    const CTxIn& input,
    const BaseSignatureChecker& checker);
```

- Extract SCHEME param → route to Schnorr or ECDSA
- Extract PUBKEY param
- Get signature from witness at input's witness stack
- Use `checker.CheckSchnorrSignature()` or existing ECDSA checker
- Do NOT bypass `BaseSignatureChecker`

#### MULTISIG block

```cpp
// Params: [NUMERIC(n), NUMERIC(m), PUBKEY×m, SCHEME]
// Witness: [SIGNATURE×n]
// Satisfies when: n valid signatures from the m keys
EvalResult EvalMultisigBlock(
    const RungBlock& block,
    const CTxIn& input,
    const BaseSignatureChecker& checker);
```

- Same semantics as OP_CHECKMULTISIG but typed
- Keys and n,m are in params — not in witness
- Only signatures come from witness

#### CSV block

```cpp
// Params: [NUMERIC(blocks)]
// Satisfies when: input.nSequence >= required_blocks
// Identical logic to OP_CHECKSEQUENCEVERIFY — reference src/script/interpreter.cpp
EvalResult EvalCSVBlock(
    const RungBlock& block,
    const CTxIn& input,
    const TxContext& ctx);
```

When `inverted = true`: satisfies when `input.nSequence < required_blocks` — "spend BEFORE N blocks". This is a new Bitcoin primitive with no current equivalent.

#### CLTV block

```cpp
// Params: [NUMERIC(height)]
// Satisfies when: tx.nLockTime >= required_height
// Identical logic to OP_CHECKLOCKTIMEVERIFY — reference src/script/interpreter.cpp
EvalResult EvalCLTVBlock(
    const RungBlock& block,
    const CTxIn& input,
    const TxContext& ctx);
```

When `inverted = true`: satisfies when `tx.nLockTime < required_height` — "spend BEFORE this block". Dead man's switch primitive.

#### HASH_PREIMAGE block

```cpp
// Params: [HASH256(expected_hash)]
// Witness: [PREIMAGE(preimage)]
// Satisfies when: SHA256(preimage) == expected_hash
EvalResult EvalHashPreimageBlock(
    const RungBlock& block,
    const CTxIn& input);
```

When `inverted = true`: satisfies when preimage has NOT been provided or does not match — "spend only if secret was never revealed". HTLC refund path becomes explicit.

#### ADAPTOR_SIG block (stub for DLC support)

```cpp
// Params: [PUBKEY(adaptor_point), PUBKEY(signing_key), SCHEME]
// Witness: [SIGNATURE(adapted_sig)]
// Phase 1: implement basic structure, full DLC validation in Phase 2
EvalResult EvalAdaptorSigBlock(
    const RungBlock& block,
    const CTxIn& input,
    const BaseSignatureChecker& checker);
```

### 4. ANCHOR Block Family — Stub in Phase 1

Create `blocks/block_anchor.cpp` with the full enum and parameter structure defined but returning `UNSATISFIED` for all ANCHOR blocks in Phase 1. The structure must be correct so Phase 2 can implement without changing interfaces.

```cpp
// Phase 1 stub — Phase 2 implements full evaluation
EvalResult EvalAnchorBlock(
    const RungBlock& block,
    const CTxIn& input,
    const CCoinsViewCache& inputs,
    const TxContext& ctx)
{
    // TODO Phase 2: implement sequence number monotonicity check
    // TODO Phase 2: implement state root commitment verification
    // TODO Phase 2: implement protocol-specific validation per ANCHOR_* type
    //
    // ANCHOR block params standard structure:
    //   [0] HASH256: state_root       — L2 state commitment (opaque to L1)
    //   [1] HASH256: protocol_id      — which L2 protocol (standardised hash)
    //   [2] NUMERIC: sequence_number  — monotonically increasing, anti-rollback
    //   [3+] protocol-specific params
    //
    // ANCHOR_CHANNEL adds:
    //   [3] PUBKEY:  local_funding_key
    //   [4] PUBKEY:  remote_funding_key
    //   [5] NUMERIC: to_self_delay
    //   [6] HASH256: payment_hash (current HTLC)
    //
    // ANCHOR_POOL adds:
    //   [3] HASH256: vtxo_tree_root   — merkle root of all VTXOs
    //   [4] NUMERIC: participant_count
    //   [5] NUMERIC: expiry_height
    //   [6] PUBKEY:  asp_key
    //
    // ANCHOR_RESERVE adds:
    //   [3] NUMERIC: threshold_n
    //   [4] NUMERIC: threshold_m
    //   [5] HASH256: guardian_set_hash
    //   [6] NUMERIC: emergency_height
    //
    // ANCHOR_SEAL adds:
    //   [3] HASH256: asset_id
    //   (replaces OP_RETURN for RGB-style commitments)
    //
    // ANCHOR_ORACLE adds:
    //   [3] PUBKEY:  oracle_key
    //   [4] HASH256: event_id
    //   [5] NUMERIC: expiry_height
    //   [6] NUMERIC: outcome_count

    LogPrint(BCLog::RUNG, "ANCHOR block type 0x%04x — Phase 2 not yet implemented\n",
             static_cast<uint16_t>(block.block_type));
    return EvalResult::UNSATISFIED;
}
```

**Why ANCHOR blocks matter (context for Phase 2 implementer):**

ANCHOR blocks solve the L2 anchor standardisation problem. Currently every L2 protocol (Lightning, Ark, Fedimint, RGB, DLCs) anchors to L1 with bespoke script constructions. ANCHOR blocks provide:

1. **Universal watchtower support** — any watchtower can watch any L2 protocol by understanding ANCHOR block types rather than protocol-specific script
2. **Sequence number anti-rollback** — monotonic sequence_number checked at consensus level, making state rollback attacks consensus-invalid not just detectable
3. **Cross-protocol composability** — ANCHOR_CHANNEL + ANCHOR_SEAL in same output = Lightning channel carrying RGB assets
4. **L2 visibility at L1** — block explorers can identify L2 anchor UTXOs and show L2 activity without trusting L2 operators
5. **Transaction size reduction** — ANCHOR blocks with state_root replace large bespoke witness scripts, reducing L2 anchor tx sizes 50-86%

Lightning commitment transactions drop from ~300 vB to ~100 vB. Breach remedies drop from ~170 vB to ~50 vB — 71% smaller, critically improving Lightning security under high fee conditions (smaller = faster confirmation = breach remedy beats CSV timeout more reliably).

### 5. Recursive Covenant Blocks — Stub Only

```cpp
// blocks/block_recurse.cpp
// Phase 3 — stub only, return UNSATISFIED
//
// SAFETY PROPERTIES (for Phase 3 implementer):
// ALL recursive blocks MUST enforce these four properties at consensus level:
//
// 1. EXPLICIT TERMINATION — every recursive block requires a termination
//    condition as a mandatory typed param. Parser rejects without one.
//    A covenant that recurses forever is a parse error.
//
// 2. VALUE CONSERVATION — recursive blocks must prove value is conserved
//    or strictly decreasing. Covenant amplification is consensus-invalid.
//
// 3. TYPED MUTATION — RECURSE_MODIFIED carries explicit typed mutation spec.
//    What changes between recursion levels is a typed, auditable parameter.
//
// 4. NO WHITELIST COVENANTS — there is no ADDRESS_WHITELIST block type.
//    Cannot be constructed. Adding one requires explicit softfork.
//    This specifically addresses the government whitelist concern.
//
// RECURSE_UNTIL  — recurse until block height or depth limit (REQUIRED param)
// RECURSE_COUNT  — recurse exactly N times then free (N is REQUIRED param)
// RECURSE_SPLIT  — split value, each piece re-encumbers (enables Ark, streaming)
// RECURSE_DECAY  — each recursion relaxes one constraint (inheritance with decay)
// RECURSE_SAME   — output inherits identical rung set
// RECURSE_MODIFIED — output inherits rung set with typed mutations
//
// USE CASES:
// Vaults:      UTXO → hot wallet path → RECURSE_UNTIL(expiry) → free
// Streaming:   RECURSE_SPLIT(100 iterations) → salary streaming
// Inheritance: RECURSE_DECAY(remove 1 sig per year) → dead man's switch
// Ark pools:   RECURSE_SPLIT → participant exit, remainder re-encumbers
// Payment channels: RECURSE_SAME + ANCHOR_CHANNEL → self-sustaining channel

EvalResult EvalRecurseBlock(const RungBlock& block, ...) {
    LogPrint(BCLog::RUNG, "RECURSE block — Phase 3 not yet implemented\n");
    return EvalResult::UNSATISFIED;
}
```

### 6. Policy (`rung_policy.cpp`)

```cpp
bool IsStandardRungTx(const CTransaction& tx, std::string& reason) {
    // Type validation already enforced at deserialization
    // Policy adds structural limits on top

    for (const auto& output : GetRungOutputs(tx)) {
        if (output.rungs.size() > 16) {
            reason = "rung-count-too-high";
            return false;
        }
        for (const auto& rung : output.rungs) {
            if (rung.contacts.size() > 8) {
                reason = "block-count-too-high";
                return false;
            }
            // Unknown block types are policy-nonstandard
            // but NOT consensus-invalid (forward compat)
            for (const auto& block : rung.contacts) {
                if (!IsKnownPhase1BlockType(block.block_type)) {
                    reason = "unknown-block-type";
                    return false;
                }
            }
        }
    }
    // No inscription check needed — type system makes it impossible
    return true;
}
```

### 7. RPC Commands

Add to `src/rpc/rawtransaction.cpp`:

#### `createrungtx`

```json
Input:
{
  "inputs": [
    { "txid": "hex", "vout": 0, "sequence": 4294967295 }
  ],
  "outputs": [
    {
      "value": 100000,
      "rungs": [
        {
          "rung_id": 0,
          "contacts": [
            {
              "block": "SIG",
              "inverted": false,
              "params": { "scheme": "SCHNORR", "key": "03abc..." }
            },
            {
              "block": "CSV",
              "inverted": false,
              "params": { "blocks": 144 }
            }
          ],
          "coil": { "type": "UNLOCK", "attestation": "INLINE", "scheme": "SCHNORR" }
        },
        {
          "rung_id": 1,
          "contacts": [
            {
              "block": "CSV",
              "inverted": true,
              "params": { "blocks": 144 }
            },
            {
              "block": "SIG",
              "inverted": false,
              "params": { "scheme": "SCHNORR", "key": "03def..." }
            }
          ],
          "coil": { "type": "UNLOCK", "attestation": "INLINE", "scheme": "SCHNORR" }
        }
      ]
    }
  ]
}
```

Note the `inverted` field on each contact. The second rung uses `[/CSV: 144]` — the breach remedy path that's only valid BEFORE the timeout. This is a real Lightning-equivalent breach remedy in native Ladder Script.

Returns: raw hex unsigned RUNG_TX

#### `decoderung`
Input: raw hex
Returns: full JSON with all rungs, blocks, `inverted` flags, params, coils

#### `signrungtx`
Input: raw hex RUNG_TX + signing key  
Returns: signed RUNG_TX ready for broadcast

#### `validaterungtx`
Input: raw hex RUNG_TX  
Returns: per-rung evaluation results + overall validity + reason for any failure

#### `listrungblocktypes`
No input  
Returns: all known block types, their phase, param schemas, and whether `inverted` changes semantics

---

## Signet Configuration

```bash
mkdir -p ~/.ghost/signet

cat > ~/.ghost/signet/ghost.conf << EOF
signet=1
signetchallenge=51
daemon=1
txindex=1
server=1
rpcuser=ghostrpc
rpcpassword=laddersignet2026
rpcport=38332
rpcallowip=127.0.0.1
fallbackfee=0.0001
debug=rung
EOF
```

Add `BCLog::RUNG` to the logging system so all Ladder Script evaluation steps are traceable.

Create utility scripts:

```bash
#!/bin/bash
# faucet.sh
ghost-cli -signet sendtoaddress $1 1.0

# mine.sh
N=${1:-1}
ghost-cli -signet generateblock $(ghost-cli -signet getnewaddress) $N

# rung-demo.sh — demonstrates a 2-rung tx with breach remedy path
# Creates a channel-like output, spends via primary path, shows breach remedy
```

---

## Test Suite

### `src/test/rung/rung_serialize_tests.cpp`

- Round-trip for every Phase 1 block type
- Every type size limit: at limit = pass, one over = parse error
- Unknown type byte 0xFF = parse error with descriptive message
- `inverted` byte 0x00 = normal, 0x01 = inverted, 0x02 = parse error
- Empty rung set = rejected
- Max 16 rungs enforced
- Max 8 blocks per rung enforced

### `src/test/rung/rung_eval_tests.cpp`

**SIG block:**
- Valid Schnorr sig + correct key = SATISFIED
- Invalid sig = UNSATISFIED
- Wrong key = UNSATISFIED
- `inverted=true` + valid sig = UNSATISFIED
- `inverted=true` + no sig = SATISFIED

**MULTISIG block:**
- 2-of-3, exactly 2 valid sigs = SATISFIED
- 2-of-3, only 1 valid sig = UNSATISFIED
- `inverted=true` + 2 valid sigs = UNSATISFIED (governance veto)

**CSV block:**
- Sequence >= required = SATISFIED
- Sequence < required = UNSATISFIED
- `inverted=true` + sequence < required = SATISFIED (spend before timeout)
- `inverted=true` + sequence >= required = UNSATISFIED

**CLTV block:**
- Locktime >= required = SATISFIED
- Locktime < required = UNSATISFIED
- `inverted=true` + locktime < required = SATISFIED (dead man's switch)

**HASH_PREIMAGE block:**
- Correct preimage = SATISFIED
- Wrong preimage = UNSATISFIED
- `inverted=true` + no preimage = SATISFIED (HTLC refund path)
- `inverted=true` + correct preimage = UNSATISFIED

**Multi-rung:**
- Rung 0 fails, Rung 1 satisfies = overall SATISFIED (fallback works)
- All rungs fail = overall UNSATISFIED
- Rung 0 satisfies = Rung 1 never evaluated

**Unknown block type:**
- Unknown block type = UNSATISFIED (not ERROR — forward compat)
- Unknown block type + `inverted=true` = SATISFIED (absence passes when inverted)

**ANCHOR blocks (Phase 1 stub):**
- Any ANCHOR block = UNSATISFIED with log message

### `src/test/rung/rung_inversion_tests.cpp`

Full test matrix of every block type × normal/inverted × satisfied/unsatisfied inputs. Verify inversion always flips SATISFIED↔UNSATISFIED and leaves ERROR unchanged.

### `src/test/rung/rung_policy_tests.cpp`

- Valid RUNG_TX with known block types = accepted
- 17 rungs = rejected, reason "rung-count-too-high"
- 9 blocks per rung = rejected, reason "block-count-too-high"
- Unknown block type = rejected as non-standard (but consensus-valid)
- RUNG_TX version 4 with version 1/2 outputs = rejected

### `test/functional/rung_basic.py`

```python
#!/usr/bin/env python3
"""
Ladder Script Phase 1 functional test.
Tests: create → sign → broadcast → confirm for all Phase 1 block types.
Tests: inverted contacts (normally closed) for CSV and HASH_PREIMAGE.
Tests: multi-rung fallback paths.
Tests: malformed RUNG_TX rejection.
"""

class LadderScriptPhase1Test(BitcoinTestFramework):
    def run_test(self):
        node = self.nodes[0]
        node.generate(101)

        # Test 1: Simple SIG rung
        self._test_sig_rung(node)

        # Test 2: 2-of-3 MULTISIG rung
        self._test_multisig_rung(node)

        # Test 3: CSV timelock rung
        self._test_csv_rung(node)

        # Test 4: CLTV rung
        self._test_cltv_rung(node)

        # Test 5: HASH_PREIMAGE rung
        self._test_hash_preimage_rung(node)

        # Test 6: Inverted CSV — spend BEFORE timeout
        self._test_inverted_csv(node)

        # Test 7: Inverted HASH_PREIMAGE — spend if secret NOT revealed
        self._test_inverted_preimage(node)

        # Test 8: Multi-rung — primary fails, fallback succeeds
        self._test_multirung_fallback(node)

        # Test 9: Lightning-equivalent breach remedy
        # RUNG 0: [SIG: local] [CSV: 144] UNLOCK
        # RUNG 1: [SIG: remote] [/CSV: 144] UNLOCK  ← breach remedy
        self._test_breach_remedy_pattern(node)

        # Test 10: Malformed RUNG_TX rejection
        self._test_malformed_rejection(node)
```

### `test/functional/rung_l2_patterns.py`

```python
"""
Tests L2 anchor patterns using Phase 1 blocks.
ANCHOR blocks return UNSATISFIED in Phase 1 — test the rung structure
by falling through to non-anchor rungs.
Verifies the rung structure that Phase 2 will activate.
"""

class LadderScriptL2PatternsTest(BitcoinTestFramework):
    def run_test(self):
        # Lightning channel open pattern
        self._test_channel_open_rung_structure()

        # HTLC pattern with inverted preimage (refund path)
        self._test_htlc_pattern()

        # DLC-style pattern with adaptor sig stub
        self._test_dlc_pattern()

        # Dead man's switch: /CLTV + CSV
        self._test_dead_mans_switch()

        # Governance veto: /MULTISIG(board) + SIG(CEO) + CSV
        self._test_governance_veto()
```

---

## Build System

```makefile
RUNG_SOURCES = \
  rung/rung_types.cpp \
  rung/rung_serialize.cpp \
  rung/rung_eval.cpp \
  rung/rung_policy.cpp \
  rung/rung_rpc.cpp \
  rung/blocks/block_sig.cpp \
  rung/blocks/block_csv.cpp \
  rung/blocks/block_hash.cpp \
  rung/blocks/block_anchor.cpp \
  rung/blocks/block_covenant.cpp \
  rung/blocks/block_recurse.cpp
```

---

## What NOT To Do

- Do NOT touch version 1 or 2 transaction consensus rules
- Do NOT implement AGGREGATE or DEFERRED attestation (Phase 4)
- Do NOT implement PQ signature schemes (Phase 4)
- Do NOT implement STEALTH or CONFIDENTIAL outputs (Phase 4)
- Do NOT implement ANCHOR block evaluation logic (Phase 2 — stub only)
- Do NOT implement RECURSE blocks (Phase 3 — stub only)
- Do NOT implement CTV or VAULT_LOCK (Phase 2 — stub only)
- Do NOT break any existing Bitcoin Core unit or functional tests
- Do NOT bypass BaseSignatureChecker for any signature verification
- Do NOT reimplement CSV/CLTV logic — reference existing interpreter.cpp exactly

---

## Success Criteria

```
Phase 1 complete when ALL of the following pass:

COMPILATION
☐ Ghost Core builds cleanly, zero warnings, on feature/ladder-script branch
☐ All existing Bitcoin Core tests pass unmodified

SERIALIZATION
☐ rung_serialize_tests: round-trip for all Phase 1 block types
☐ rung_serialize_tests: every type size violation → parse error
☐ rung_serialize_tests: unknown type byte → parse error with message
☐ rung_serialize_tests: inverted flag serializes/deserializes correctly

EVALUATION
☐ rung_eval_tests: all Phase 1 block types — satisfied/unsatisfied cases
☐ rung_inversion_tests: every block × normal/inverted — correct flip
☐ rung_eval_tests: multi-rung fallback — first satisfied rung wins
☐ rung_eval_tests: unknown block type → UNSATISFIED (not ERROR)
☐ rung_eval_tests: unknown block type inverted → SATISFIED

POLICY
☐ rung_policy_tests: valid RUNG_TX accepted
☐ rung_policy_tests: >16 rungs rejected
☐ rung_policy_tests: >8 blocks per rung rejected

RPC
☐ createrungtx: builds RUNG_TX from JSON including inverted contacts
☐ decoderung: round-trips JSON with inverted flags correct
☐ signrungtx: produces valid signed RUNG_TX
☐ validaterungtx: correctly evaluates each rung, reports reason for failure
☐ listrungblocktypes: lists all known types with phase and inversion semantics

SIGNET END-TO-END
☐ Ghost Signet running with BCLog::RUNG enabled
☐ Simple SIG rung: create → sign → broadcast → confirm
☐ 2-of-3 MULTISIG rung: confirm
☐ CSV timelock: confirm after sequence satisfied
☐ Inverted CSV: confirm BEFORE timeout (new primitive working)
☐ HASH_PREIMAGE: confirm with correct preimage
☐ Inverted HASH_PREIMAGE: confirm without preimage (refund path)
☐ Multi-rung fallback: primary rung fails, secondary confirms
☐ Breach remedy pattern: /CSV rung confirms before timeout
☐ Malformed RUNG_TX: rejected at mempool with descriptive error

FUNCTIONAL TESTS
☐ rung_basic.py: all tests pass
☐ rung_l2_patterns.py: all structural tests pass
```

---

## Phase Roadmap (context only — do not implement)

```
Phase 1 (THIS):   Core format, basic blocks, contact inversion, Signet
Phase 2:          ANCHOR blocks (L2 anchor standardisation)
                  Full ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE,
                  ANCHOR_SEAL, ANCHOR_ORACLE with sequence number consensus
                  STEALTH + CONFIDENTIAL output types
                  CTV + VAULT_LOCK covenants
Phase 3:          Recursive covenants (RECURSE_* blocks)
                  Bounded recursion with mandatory termination
                  Enables: vaults, streaming, inheritance, Ark-style pools
Phase 4:          PQ signatures via liboqs (FALCON512, DILITHIUM3)
                  AGGREGATE attestation mode (block-level proof aggregation)
                  4-5× block capacity within existing 4MB weight limit
```

---

## Reference Documents

The full specification is in `doc/ladder-script/spec_v0.3.md`. Create this file. Key design decisions that must be preserved:

1. **Type system enforced at parse layer** — before crypto, before mempool, before everything
2. **Unknown block types are UNSATISFIED not ERROR** — forward compatibility is non-negotiable
3. **First satisfied rung wins** — deterministic, top-to-bottom, no ambiguity
4. **Coil declares, doesn't carry** — attestation mode in coil, proof data minimal in witness
5. **Inversion is a contact modifier** — not a separate block type, one flag on any block
6. **All new code in `src/rung/`** — clean boundary, easy to review, easy to rebase
7. **ANCHOR blocks are Phase 2** — stub now, structure must be correct for Phase 2 without interface changes

---

## Notes For Claude Code

- Read `src/primitives/transaction.h`, `src/script/interpreter.cpp`, and `src/policy/policy.cpp` before writing anything — understand existing patterns first
- `BaseSignatureChecker` in `src/script/interpreter.h` is mandatory for all sig verification
- Schnorr: use `XOnlyPubKey::VerifySchnorr()` — already in Ghost Core via secp256k1
- ECDSA: use existing `CheckECDSASignature` in interpreter
- CSV/CLTV: copy the exact logic from `src/script/interpreter.cpp` — do not reimplement
- `SERIALIZE_METHODS` macro in `src/primitives/transaction.h` is the serialization pattern
- Add `BCLog::RUNG` log category so every evaluation step is traceable
- Write defensive deserialization — assume hostile input at every boundary
- Every public function: doc comment explaining inputs, outputs, and failure return values
- The `inverted` flag is the most novel feature — test it exhaustively, it enables primitives Bitcoin has never had
- Phase 2+ stubs must have detailed comments explaining what they will do — the next implementer needs this context
