# Ladder Script Block Library

Complete reference for all 53 Ladder Script block types. Each block evaluates a single
spending condition within a rung. Blocks are combined with AND logic within a rung and
OR logic across rungs (first satisfied rung wins).

**Wire encoding:** Block types use micro-header encoding (1-byte slot for known types,
escape byte for others). See the wire format v3 specification.

**Source of truth:** `src/rung/types.h` (type definitions), `src/rung/evaluator.cpp`
(evaluation logic), `src/rung/evaluator.h` (`RungEvalContext` struct).

---

## Table of Contents

1. [Signature Family (0x00xx)](#signature-family)
2. [Timelock Family (0x01xx)](#timelock-family)
3. [Hash Family (0x02xx)](#hash-family)
4. [Covenant Family (0x03xx)](#covenant-family)
5. [Anchor Family (0x05xx)](#anchor-family)
6. [Recursion Family (0x04xx)](#recursion-family)
7. [PLC Family (0x06xx)](#plc-family)
8. [Compound Family (0x07xx)](#compound-family)
9. [Governance Family (0x08xx)](#governance-family)

---

## Signature Family

### 1. SIG (0x0001)

**Family:** Signature

**Purpose:** Verify a single cryptographic signature against a public key. Supports
Schnorr (BIP-340), ECDSA, and post-quantum schemes via the SCHEME field.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 1-2048 B | Yes | Signing public key (32B x-only, 33B compressed, or PQ) |
| PUBKEY_COMMIT | PUBKEY_COMMIT (0x02) | 32 B | No | SHA-256 commitment to the public key. When present, PUBKEY must hash to this value. |
| SCHEME | SCHEME (0x09) | 1 B | No | Signature algorithm selector (SCHNORR=0x01, ECDSA=0x02, FALCON512=0x10, FALCON1024=0x11, DILITHIUM3=0x12). If absent, determined by signature size. |
| SIGNATURE | SIGNATURE (0x06) | 1-50000 B | Yes (witness) | The signature. Schnorr: 64-65 B. ECDSA: 8-72 B. PQ: up to ~3300 B. |

**Evaluation logic:**

```
if PUBKEY_COMMIT present and PUBKEY absent:
    return ERROR
if PUBKEY_COMMIT present:
    if SHA256(PUBKEY.data) != PUBKEY_COMMIT.data:
        return UNSATISFIED
if PUBKEY absent or SIGNATURE absent:
    return ERROR
if SCHEME present and IsPQScheme(SCHEME):
    sighash = ComputeLadderSighash(tx, input_index, SIGHASH_DEFAULT)
    return VerifyPQSignature(SCHEME, SIGNATURE, sighash, PUBKEY) ? SATISFIED : UNSATISFIED
if SIGNATURE.size in [64, 65]:
    // Schnorr path
    xonly = strip_prefix_if_33B(PUBKEY)
    return CheckSchnorrSignature(SIGNATURE, xonly, SigVersion::LADDER) ? SATISFIED : UNSATISFIED
if SIGNATURE.size in [8, 72]:
    // ECDSA path
    return CheckECDSASignature(SIGNATURE, PUBKEY) ? SATISFIED : UNSATISFIED
return ERROR
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid signature verifies against PUBKEY | SATISFIED |
| Signature does not verify | UNSATISFIED |
| Missing required fields, invalid PUBKEY_COMMIT, or unrecognised signature size | ERROR |

**Context requirements:** BaseSignatureChecker, SigVersion, ScriptExecutionData. No
RungEvalContext fields needed.

**Example:**

```json
{
  "type": "SIG",
  "fields": [
    { "type": "PUBKEY", "data": "a]b5c9e3...32_bytes_hex" },
    { "type": "SIGNATURE", "data": "d4f8a1...64_bytes_hex" }
  ]
}
```

**Common patterns:** Standalone in a rung for simple P2PK spend. Paired with CSV or
CLTV for timelocked spending paths. Combined with HASH_PREIMAGE for HTLC patterns.

---

### 2. MULTISIG (0x0002)

**Family:** Signature

**Purpose:** M-of-N threshold signature verification. Requires M valid signatures from
a set of N public keys, where each signature must correspond to a distinct key.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Threshold M (minimum valid signatures required) |
| PUBKEY (x N) | PUBKEY (0x01) | 1-2048 B each | Yes | N public keys in the signing set |
| SCHEME | SCHEME (0x09) | 1 B | No | Signature algorithm selector. Applies to all sigs uniformly. |
| SIGNATURE (x M) | SIGNATURE (0x06) | 1-50000 B each | Yes (witness) | M signatures. Order need not match key order. |

**Evaluation logic:**

```
M = ReadNumeric(NUMERIC)
if M <= 0: return ERROR
pubkeys = FindAllFields(PUBKEY)
sigs = FindAllFields(SIGNATURE)
if pubkeys.empty() or M > pubkeys.size(): return ERROR
if sigs.size() < M: return UNSATISFIED

if SCHEME present and IsPQScheme(SCHEME):
    sighash = ComputeLadderSighash(tx, input_index, SIGHASH_DEFAULT)
    // Each sig verified against unused pubkeys
    valid_count = 0
    for each sig in sigs:
        for each unused pubkey:
            if VerifyPQSignature(SCHEME, sig, sighash, pubkey):
                mark pubkey used; valid_count++; break
    return (valid_count >= M) ? SATISFIED : UNSATISFIED

// Schnorr/ECDSA path: same greedy matching
valid_count = 0
for each sig in sigs:
    for each unused pubkey:
        if verify(sig, pubkey): mark used; valid_count++; break
return (valid_count >= M) ? SATISFIED : UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| At least M signatures verify against distinct keys | SATISFIED |
| Fewer than M valid signatures | UNSATISFIED |
| M <= 0, no pubkeys, or M > N | ERROR |

**Context requirements:** BaseSignatureChecker, SigVersion, ScriptExecutionData.

**Example:**

```json
{
  "type": "MULTISIG",
  "fields": [
    { "type": "NUMERIC", "data": "02" },
    { "type": "PUBKEY", "data": "aa11...32B" },
    { "type": "PUBKEY", "data": "bb22...32B" },
    { "type": "PUBKEY", "data": "cc33...32B" },
    { "type": "SIGNATURE", "data": "...64B" },
    { "type": "SIGNATURE", "data": "...64B" }
  ]
}
```

**Common patterns:** 2-of-3 custody. Paired with CSV for recovery paths (2-of-3 OR
recovery_key + CSV(144)).

---

### 3. ADAPTOR_SIG (0x0003)

**Family:** Signature

**Purpose:** Verify an adaptor signature for atomic swap and PTLC (point-timelocked
contract) protocols. The adapted signature (with the adaptor secret already applied)
verifies as a standard Schnorr signature against the signing key.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY[0] | PUBKEY (0x01) | 32-33 B | Yes | Signing public key |
| PUBKEY[1] | PUBKEY (0x01) | 32 B | Yes | Adaptor point (x-only, 32 bytes exactly) |
| SIGNATURE | SIGNATURE (0x06) | 64-65 B | Yes (witness) | The adapted signature (full Schnorr sig after secret application) |

**Evaluation logic:**

```
pubkeys = FindAllFields(PUBKEY)
if pubkeys.size() < 2 or SIGNATURE absent: return ERROR
signing_key = pubkeys[0]
adaptor_point = pubkeys[1]
if adaptor_point.size() != 32: return ERROR

if SIGNATURE.size in [64, 65]:
    xonly = strip_prefix_if_33B(signing_key)
    return CheckSchnorrSignature(SIGNATURE, xonly, SigVersion::LADDER) ? SATISFIED : UNSATISFIED
return ERROR
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Adapted sig verifies against signing key | SATISFIED |
| Adapted sig fails verification | UNSATISFIED |
| Missing fields or adaptor point not 32 bytes | ERROR |

**Context requirements:** BaseSignatureChecker, SigVersion, ScriptExecutionData.

**Example:**

```json
{
  "type": "ADAPTOR_SIG",
  "fields": [
    { "type": "PUBKEY", "data": "signing_key_32B" },
    { "type": "PUBKEY", "data": "adaptor_point_32B" },
    { "type": "SIGNATURE", "data": "adapted_sig_64B" }
  ]
}
```

**Common patterns:** Cross-chain atomic swaps. PTLC constructions. Paired with CSV
for timeout refund paths.

---

### 4. MUSIG_THRESHOLD (0x0004)

**Family:** Signature

**Purpose:** MuSig2/FROST aggregate threshold signature verification. On-chain, this
looks identical to a single-sig spend: one aggregate public key and one aggregate
Schnorr signature, regardless of the threshold M or group size N. The FROST/MuSig2
key generation and signing ceremony happen entirely off-chain. The block type only
validates the final aggregate result using standard Schnorr verification.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY_COMMIT | PUBKEY_COMMIT (0x02) | 32 B | Yes (conditions) | SHA-256 commitment to the aggregate public key |
| NUMERIC (M) | NUMERIC (0x08) | varint | Yes (conditions) | Threshold M (policy/display only, not used in verification) |
| NUMERIC (N) | NUMERIC (0x08) | varint | Yes (conditions) | Group size N (policy/display only, not used in verification) |
| PUBKEY | PUBKEY (0x01) | 33 B | Yes (witness) | The aggregate public key (compressed) |
| SIGNATURE | SIGNATURE (0x06) | 64 B | Yes (witness) | The aggregate Schnorr signature |

**Evaluation logic:**

```
if PUBKEY absent or SIGNATURE absent:
    return ERROR
if PUBKEY_COMMIT present:
    if SHA256(PUBKEY.data) != PUBKEY_COMMIT.data:
        return UNSATISFIED
if two NUMERIC fields present:
    M = ReadNumeric(NUMERIC[0])
    N = ReadNumeric(NUMERIC[1])
    if M <= 0 or N <= 0 or M > N:
        return ERROR
if SIGNATURE.size not in [64, 65]:
    return ERROR
xonly = strip_prefix_if_33B(PUBKEY)
return CheckSchnorrSignature(SIGNATURE, xonly, SigVersion::LADDER) ? SATISFIED : UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid aggregate signature verifies against aggregate PUBKEY | SATISFIED |
| Signature does not verify or PUBKEY_COMMIT mismatch | UNSATISFIED |
| Missing required fields, invalid M/N, or wrong signature size | ERROR |

**Context requirements:** BaseSignatureChecker, SigVersion, ScriptExecutionData. No
RungEvalContext fields needed. Schnorr-only — no PQ path (aggregate signatures
rely on Schnorr's linear aggregation property).

**Example:**

```json
{
  "type": "MUSIG_THRESHOLD",
  "fields": [
    { "type": "PUBKEY_COMMIT", "data": "a1b2c3...32_bytes_hex" },
    { "type": "NUMERIC", "data": "02" },
    { "type": "NUMERIC", "data": "03" },
    { "type": "PUBKEY", "data": "02d4f8...33_bytes_hex" },
    { "type": "SIGNATURE", "data": "e5f6a7...64_bytes_hex" }
  ]
}
```

**Wire size:** ~131 bytes total (conditions ~36B + witness ~100B), constant regardless
of M and N. Compared to MULTISIG: 2-of-3 saves 43%, 5-of-9 saves 80%, 11-of-15 saves 88%.

**Common patterns:** Any M-of-N threshold custody where privacy is desired (the
blockchain cannot distinguish MUSIG_THRESHOLD from a single-sig SIG spend). Corporate
treasury management, multisig wallets, federated protocols.

---

### 5. KEY_REF_SIG (0x0005)

**Family:** Signature

**Purpose:** Signature verification using a key commitment referenced from a relay block, enabling cross-rung key sharing without duplicating pubkey commitments.

**Conditions Fields:**
| Field | Type | Encoding | Description |
|-------|------|----------|-------------|
| relay_index | NUMERIC | uint32 LE | Index into the relay array |
| block_index | NUMERIC | uint32 LE | Index of the target block within the relay |

**Witness Fields:**
| Field | Type | Encoding | Description |
|-------|------|----------|-------------|
| pubkey | PUBKEY | 33 bytes compressed | Full public key (verified against relay's PUBKEY_COMMIT) |
| signature | SIGNATURE | 64-65 bytes Schnorr / variable PQ | Signature over the ladder sighash |

**Evaluation Logic:**
1. Extract relay_index and block_index from conditions NUMERIC fields
2. Validate relay_index is in the current rung's relay_refs
3. Resolve target relay block at relays[relay_index].blocks[block_index]
4. Extract PUBKEY_COMMIT and SCHEME from the target block
5. Verify SHA256(witness PUBKEY) == target PUBKEY_COMMIT
6. Verify SIGNATURE against the resolved scheme (Schnorr, ECDSA, or PQ)

**Wire Size:** Conditions: ~12 bytes (2 NUMERIC fields). Witness: ~99 bytes (PUBKEY + SIGNATURE). Saves ~30 bytes per rung vs duplicating PUBKEY_COMMIT.

**Use Cases:**
- Multi-path spending with shared key commitment (e.g., same key in hot path and timelocked recovery)
- Reducing witness size in MLSC trees where the same signer appears in multiple rungs
- Relay-based key management where a single relay defines the authorized signer

---

## Timelock Family

### 6. CSV (0x0101)

**Family:** Timelock

**Purpose:** Enforce a relative block-height timelock using BIP68 sequence numbers. The
input can only be spent after the specified number of blocks have elapsed since the
UTXO was confirmed.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Required relative block delay (BIP68 sequence value) |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
sequence_val = ReadNumeric(NUMERIC)
if sequence_val < 0: return ERROR
if (sequence_val & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0:
    return SATISFIED  // disable flag set, lock is unconditionally satisfied
return CheckSequence(CScriptNum(sequence_val)) ? SATISFIED : UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Sequence lock satisfied or disable flag set | SATISFIED |
| Sequence lock not yet met | UNSATISFIED |
| Missing or invalid NUMERIC | ERROR |

**Context requirements:** BaseSignatureChecker (provides CheckSequence via input
nSequence).

**Example:**

```json
{
  "type": "CSV",
  "fields": [
    { "type": "NUMERIC", "data": "90000000" }
  ]
}
```

The value `0x00000090` = 144 blocks (approximately 1 day).

**Common patterns:** Recovery path timelocks (SIG + CSV). Vault hot-spend delays.
Lightning HTLC timeout paths.

---

### 7. CSV_TIME (0x0102)

**Family:** Timelock

**Purpose:** Enforce a relative time-based lock using BIP68 time-based sequence
encoding. The input can only be spent after the specified number of seconds have
elapsed (in units of 512-second intervals per BIP68).

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Required relative time delay (BIP68 time-encoded sequence value) |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
sequence_val = ReadNumeric(NUMERIC)
if sequence_val < 0: return ERROR
if (sequence_val & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0:
    return SATISFIED
return CheckSequence(CScriptNum(sequence_val)) ? SATISFIED : UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Time-based sequence lock satisfied or disable flag set | SATISFIED |
| Time lock not yet met | UNSATISFIED |
| Missing or invalid NUMERIC | ERROR |

**Context requirements:** BaseSignatureChecker (CheckSequence).

**Example:**

```json
{
  "type": "CSV_TIME",
  "fields": [
    { "type": "NUMERIC", "data": "00400018" }
  ]
}
```

BIP68 time flag is bit 22. The value encodes a time-based relative lock.

**Common patterns:** Time-based recovery paths as alternatives to block-based CSV locks.

---

### 8. CLTV (0x0103)

**Family:** Timelock

**Purpose:** Enforce an absolute block-height lock. The input cannot be spent until the
blockchain has reached the specified block height (via `nLockTime`).

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Target block height |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
locktime_val = ReadNumeric(NUMERIC)
if locktime_val < 0: return ERROR
return CheckLockTime(CScriptNum(locktime_val)) ? SATISFIED : UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Current block height >= locktime_val | SATISFIED |
| Block height not yet reached | UNSATISFIED |
| Missing or invalid NUMERIC | ERROR |

**Context requirements:** BaseSignatureChecker (CheckLockTime, which compares against
tx nLockTime and block height).

**Example:**

```json
{
  "type": "CLTV",
  "fields": [
    { "type": "NUMERIC", "data": "40420f00" }
  ]
}
```

The value `0x000f4240` = block 1,000,000.

**Common patterns:** Time-locked vesting. Future-dated spending conditions. Combined
with SIG for "key OR timelock" patterns.

---

### 9. CLTV_TIME (0x0104)

**Family:** Timelock

**Purpose:** Enforce an absolute timestamp lock. The input cannot be spent until the
median time past (MTP) reaches the specified Unix timestamp.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Target Unix timestamp |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
locktime_val = ReadNumeric(NUMERIC)
if locktime_val < 0: return ERROR
return CheckLockTime(CScriptNum(locktime_val)) ? SATISFIED : UNSATISFIED
```

Note: Values >= 500,000,000 are interpreted as Unix timestamps by consensus (the
LOCKTIME_THRESHOLD). Values below that threshold are block heights.

**Return values:**

| Condition | Result |
|-----------|--------|
| MTP >= timestamp | SATISFIED |
| Timestamp not yet reached | UNSATISFIED |
| Missing or invalid NUMERIC | ERROR |

**Context requirements:** BaseSignatureChecker (CheckLockTime).

**Example:**

```json
{
  "type": "CLTV_TIME",
  "fields": [
    { "type": "NUMERIC", "data": "00e1f505" }
  ]
}
```

**Common patterns:** Calendar-based vesting. Insurance claim windows.

---

## Hash Family

### 10. HASH_PREIMAGE (0x0201)

**Family:** Hash

**Purpose:** Verify that a witness preimage hashes to the committed SHA-256 digest.
The preimage is revealed in the witness; the hash is committed in the scriptPubKey
conditions.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256 | HASH256 (0x03) | 32 B | Yes | Expected SHA-256 hash digest |
| PREIMAGE | PREIMAGE (0x05) | 1-252 B | Yes (witness) | Hash preimage to be revealed |

**Evaluation logic:**

```
if PREIMAGE absent: return ERROR
if HASH256 absent: return ERROR
computed = SHA256(PREIMAGE.data)
if computed == HASH256.data: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| SHA256(preimage) matches hash | SATISFIED |
| Hash mismatch | UNSATISFIED |
| Missing PREIMAGE or HASH256 | ERROR |

**Context requirements:** None (pure hash computation).

**Example:**

```json
{
  "type": "HASH_PREIMAGE",
  "fields": [
    { "type": "HASH256", "data": "e3b0c44298fc1c...32B_hash" },
    { "type": "PREIMAGE", "data": "secret_bytes" }
  ]
}
```

**Common patterns:** HTLC (Hash Time-Locked Contract): HASH_PREIMAGE + CSV on
alternative rung. Payment channel routing secrets.

---

### 11. HASH160_PREIMAGE (0x0202)

**Family:** Hash

**Purpose:** Verify a witness preimage against a RIPEMD160(SHA256()) digest. This is
the same hash construction used by P2PKH and P2SH addresses.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH160 | HASH160 (0x04) | 20 B | Yes | Expected HASH160 digest |
| PREIMAGE | PREIMAGE (0x05) | 1-252 B | Yes (witness) | Hash preimage to be revealed |

**Evaluation logic:**

```
if PREIMAGE absent: return ERROR
if HASH160 absent: return ERROR
computed = RIPEMD160(SHA256(PREIMAGE.data))
if computed == HASH160.data: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| HASH160(preimage) matches | SATISFIED |
| Hash mismatch | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "HASH160_PREIMAGE",
  "fields": [
    { "type": "HASH160", "data": "89abcdef...20B_hash" },
    { "type": "PREIMAGE", "data": "secret_bytes" }
  ]
}
```

**Common patterns:** Compatible with existing Bitcoin HASH160 patterns. Shorter
commitment (20 bytes vs 32 bytes) for space-constrained conditions.

---

### 12. TAGGED_HASH (0x0203)

**Family:** Hash

**Purpose:** Verify a BIP-340 tagged hash. Computes
`SHA256(SHA256(tag) || SHA256(tag) || preimage)` and compares against the expected
digest. The tag hash field contains the pre-computed `SHA256(tag)`.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256[0] | HASH256 (0x03) | 32 B | Yes | SHA-256 of the tag string (pre-computed) |
| HASH256[1] | HASH256 (0x03) | 32 B | Yes | Expected tagged hash result |
| PREIMAGE | PREIMAGE (0x05) | 1-252 B | Yes (witness) | Message/preimage to hash with the tag |

**Evaluation logic:**

```
hashes = FindAllFields(HASH256)
if hashes.size() < 2 or PREIMAGE absent: return ERROR
tag_hash = hashes[0]  // SHA256(tag)
expected = hashes[1]   // expected result
if tag_hash.size() != 32 or expected.size() != 32: return ERROR

computed = SHA256(tag_hash || tag_hash || PREIMAGE.data)
if computed == expected.data: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Tagged hash matches expected | SATISFIED |
| Hash mismatch | UNSATISFIED |
| Fewer than 2 HASH256 fields or missing PREIMAGE | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "TAGGED_HASH",
  "fields": [
    { "type": "HASH256", "data": "sha256_of_tag_32B" },
    { "type": "HASH256", "data": "expected_result_32B" },
    { "type": "PREIMAGE", "data": "message_bytes" }
  ]
}
```

**Common patterns:** Domain-separated hash commitments. Protocol-specific commitment
schemes using BIP-340 tagged hash convention.

---

## Covenant Family

### 13. CTV (0x0301)

**Family:** Covenant

**Purpose:** BIP-119 CheckTemplateVerify. Constrains the spending transaction to match
a pre-committed template hash. Commits to transaction version, locktime, scriptSigs
hash, input count, sequences hash, output count, outputs hash, and input index.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256 | HASH256 (0x03) | 32 B | Yes | Pre-committed BIP-119 template hash |

**Evaluation logic:**

```
if HASH256 absent or HASH256.size() != 32: return ERROR
if ctx.tx is null: return UNSATISFIED

computed = ComputeCTVHash(ctx.tx, ctx.input_index)
// CTV hash = SHA256(version || locktime || scriptsigs_hash || num_inputs ||
//                   sequences_hash || num_outputs || outputs_hash || input_index)
if computed == HASH256.data: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Transaction matches template hash | SATISFIED |
| Template mismatch or no tx context | UNSATISFIED |
| Missing or invalid HASH256 | ERROR |

**Context requirements:** `ctx.tx` (spending transaction), `ctx.input_index`.

**Example:**

```json
{
  "type": "CTV",
  "fields": [
    { "type": "HASH256", "data": "template_hash_32B" }
  ]
}
```

**Common patterns:** Congestion control (pre-committed payout trees). Vault
constructions. Non-interactive channel opens. Pairs with AMOUNT_LOCK for value-guarded
templates.

---

### 14. VAULT_LOCK (0x0302)

**Family:** Covenant

**Purpose:** Two-path vault construction. A recovery key can sweep funds immediately
(cold sweep). A hot key can spend only after a CSV delay has elapsed. This provides a
cancellation window for unauthorised hot-key spends.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY[0] | PUBKEY (0x01) | 32-33 B | Yes | Recovery key (cold storage, immediate sweep) |
| PUBKEY[1] | PUBKEY (0x01) | 32-33 B | Yes | Hot key (requires CSV delay) |
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | CSV delay in blocks for the hot-key path |
| SIGNATURE | SIGNATURE (0x06) | 64-65 B | Yes (witness) | Signature from either recovery or hot key |

**Evaluation logic:**

```
pubkeys = FindAllFields(PUBKEY)
if pubkeys.size() < 2 or SIGNATURE absent or NUMERIC absent: return ERROR
recovery_key = pubkeys[0]
hot_key = pubkeys[1]
hot_delay = ReadNumeric(NUMERIC)
if hot_delay < 0: return ERROR

if SIGNATURE.size in [64, 65]:
    // Try recovery key first (no delay required)
    if CheckSchnorrSignature(SIGNATURE, recovery_key): return SATISFIED
    // Try hot key (delay required)
    if CheckSchnorrSignature(SIGNATURE, hot_key):
        if CheckSequence(CScriptNum(hot_delay)): return SATISFIED
        return UNSATISFIED  // delay not met
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Recovery key sig valid | SATISFIED |
| Hot key sig valid AND CSV delay elapsed | SATISFIED |
| Hot key sig valid but delay not met | UNSATISFIED |
| No valid sig or missing fields | UNSATISFIED or ERROR |

**Context requirements:** BaseSignatureChecker (CheckSchnorrSignature, CheckSequence),
SigVersion, ScriptExecutionData.

**Example:**

```json
{
  "type": "VAULT_LOCK",
  "fields": [
    { "type": "PUBKEY", "data": "recovery_key_32B" },
    { "type": "PUBKEY", "data": "hot_key_32B" },
    { "type": "NUMERIC", "data": "90000000" },
    { "type": "SIGNATURE", "data": "sig_64B" }
  ]
}
```

The NUMERIC value 144 (0x90) gives a 1-day cancellation window on hot-key spends.

**Common patterns:** Self-custodial vaults. Institutional custody with watchtower
monitoring. Pairs with CTV for vault re-encumbrance.

---

### 15. AMOUNT_LOCK (0x0303)

**Family:** Covenant

**Purpose:** Constrain the output amount to a specific range. SATISFIED when the output
value falls within `[min_sats, max_sats]` inclusive.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Minimum output value in satoshis |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Maximum output value in satoshis |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
min_sats = ReadNumeric(numerics[0])
max_sats = ReadNumeric(numerics[1])
if min_sats < 0 or max_sats < 0: return ERROR

if ctx.output_amount >= min_sats and ctx.output_amount <= max_sats:
    return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| min_sats <= output_amount <= max_sats | SATISFIED |
| Output outside range | UNSATISFIED |
| Fewer than 2 NUMERICs or negative values | ERROR |

**Context requirements:** `ctx.output_amount`.

**Example:**

```json
{
  "type": "AMOUNT_LOCK",
  "fields": [
    { "type": "NUMERIC", "data": "e8030000" },
    { "type": "NUMERIC", "data": "a0860100" }
  ]
}
```

Enforces outputs between 1,000 sats (0x03e8) and 100,000 sats (0x0186a0).

**Common patterns:** Dust prevention. Withdrawal limits. Pairs with CTV or recursion
blocks for value-constrained covenant chains.

---

## Anchor Family

All anchor blocks are structural metadata blocks. Their evaluation checks field
presence and validity but does not verify spending conditions in the traditional sense.
When fields are valid, evaluation returns SATISFIED.

### 16. ANCHOR (0x0501)

**Family:** Anchor

**Purpose:** Generic anchor block for attaching typed metadata to a UTXO. Requires at
least one field to be present.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| (any) | (any) | varies | Yes (at least 1) | At least one typed field must be present |

**Evaluation logic:**

```
if block.fields.empty(): return ERROR
return SATISFIED
```

**Return values:** SATISFIED if at least one field present; ERROR if empty.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR",
  "fields": [
    { "type": "HASH256", "data": "metadata_hash_32B" }
  ]
}
```

**Common patterns:** Application-specific metadata anchoring. L2 protocol tagging.

---

### 17. ANCHOR_CHANNEL (0x0502)

**Family:** Anchor

**Purpose:** Lightning-style channel anchor. Records local and remote channel keys and
a commitment number.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY[0] | PUBKEY (0x01) | 32-33 B | Yes | Local channel key |
| PUBKEY[1] | PUBKEY (0x01) | 32-33 B | Yes | Remote channel key |
| NUMERIC | NUMERIC (0x08) | 1-4 B | No | Commitment number (must be > 0 if present) |

**Evaluation logic:**

```
if pubkey count < 2: return ERROR
if NUMERIC present and ReadNumeric(NUMERIC) <= 0: return UNSATISFIED
return SATISFIED
```

**Return values:** SATISFIED if 2+ pubkeys present and commitment > 0 (or absent);
ERROR if fewer than 2 pubkeys.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR_CHANNEL",
  "fields": [
    { "type": "PUBKEY", "data": "local_key_32B" },
    { "type": "PUBKEY", "data": "remote_key_32B" },
    { "type": "NUMERIC", "data": "01" }
  ]
}
```

**Common patterns:** Lightning channel opens. State channel metadata.

---

### 18. ANCHOR_POOL (0x0503)

**Family:** Anchor

**Purpose:** Pool anchor for VTXO (virtual transaction output) tree roots. Records a
Merkle root of the VTXO tree and participant count.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256 | HASH256 (0x03) | 32 B | Yes | VTXO tree root hash |
| NUMERIC | NUMERIC (0x08) | 1-4 B | No | Participant count (must be > 0 if present) |

**Evaluation logic:**

```
if HASH256 count < 1: return ERROR
if NUMERIC present and ReadNumeric(NUMERIC) <= 0: return UNSATISFIED
return SATISFIED
```

**Return values:** SATISFIED if hash present and count valid; ERROR if no hash.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR_POOL",
  "fields": [
    { "type": "HASH256", "data": "vtxo_tree_root_32B" },
    { "type": "NUMERIC", "data": "0a" }
  ]
}
```

**Common patterns:** Ark-style VTXO pools. Joinpool constructions.

---

### 19. ANCHOR_RESERVE (0x0504)

**Family:** Anchor

**Purpose:** Reserve anchor for guardian set management. Records threshold parameters
and a guardian set hash. Verifies that threshold_n <= threshold_m.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Threshold N (required signers) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Threshold M (total guardians) |
| HASH256 | HASH256 (0x03) | 32 B | Yes | Guardian set commitment hash |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2 or HASH256 count < 1: return ERROR
threshold_n = ReadNumeric(numerics[0])
threshold_m = ReadNumeric(numerics[1])
if threshold_n < 0 or threshold_m < 0 or threshold_n > threshold_m:
    return UNSATISFIED
return SATISFIED
```

**Return values:** SATISFIED if thresholds valid; UNSATISFIED if N > M or negative;
ERROR if missing fields.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR_RESERVE",
  "fields": [
    { "type": "NUMERIC", "data": "03" },
    { "type": "NUMERIC", "data": "05" },
    { "type": "HASH256", "data": "guardian_set_hash_32B" }
  ]
}
```

**Common patterns:** Federated sidechain reserves. Multisig federation management.

---

### 20. ANCHOR_SEAL (0x0505)

**Family:** Anchor

**Purpose:** Seal anchor for client-side-validated asset protocols. Records an asset
identifier and a state transition hash.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256[0] | HASH256 (0x03) | 32 B | Yes | Asset identifier |
| HASH256[1] | HASH256 (0x03) | 32 B | Yes | State transition hash |

**Evaluation logic:**

```
if HASH256 count < 2: return ERROR
return SATISFIED
```

**Return values:** SATISFIED if 2+ hashes present; ERROR otherwise.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR_SEAL",
  "fields": [
    { "type": "HASH256", "data": "asset_id_32B" },
    { "type": "HASH256", "data": "state_transition_32B" }
  ]
}
```

**Common patterns:** RGB-style asset issuance and transfer. Single-use seal protocols.

---

### 21. ANCHOR_ORACLE (0x0506)

**Family:** Anchor

**Purpose:** Oracle anchor for DLC (Discreet Log Contract) constructions. Records an
oracle public key and outcome count.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 32-33 B | Yes | Oracle signing key |
| NUMERIC | NUMERIC (0x08) | 1-4 B | No | Outcome count (must be > 0 if present) |

**Evaluation logic:**

```
if pubkey count < 1: return ERROR
if NUMERIC present and ReadNumeric(NUMERIC) <= 0: return UNSATISFIED
return SATISFIED
```

**Return values:** SATISFIED if oracle key present and outcome count valid.

**Context requirements:** None.

**Example:**

```json
{
  "type": "ANCHOR_ORACLE",
  "fields": [
    { "type": "PUBKEY", "data": "oracle_key_32B" },
    { "type": "NUMERIC", "data": "04" }
  ]
}
```

**Common patterns:** DLC oracle attestation metadata. Prediction market outcomes.

---

## Recursion Family

Recursion blocks enforce output condition continuity: the spending transaction's
outputs must carry forward the same (or specifically mutated) rung conditions as the
input. This creates covenant chains where UTXOs are re-encumbered across multiple
spends.

### 22. RECURSE_SAME (0x0401)

**Family:** Recursion

**Purpose:** Enforce identical re-encumbrance. The spending transaction's output must
carry exactly the same rung conditions as the input being spent, preserving the full
ladder structure across spends.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Maximum recursion depth (must be > 0) |

**Evaluation logic:**

```
max_depth = ReadNumeric(NUMERIC)
if NUMERIC absent: return ERROR
if max_depth <= 0: return UNSATISFIED

if ctx.input_conditions and ctx.spending_output:
    output_conds = DeserializeRungConditions(spending_output.scriptPubKey)
    if deserialization fails: return UNSATISFIED
    if FullConditionsEqual(input_conditions, output_conds):
        return SATISFIED
    return UNSATISFIED
return SATISFIED  // no context to verify against
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Output conditions identical to input conditions | SATISFIED |
| Output conditions differ or cannot be deserialised | UNSATISFIED |
| max_depth <= 0 | UNSATISFIED |
| Missing NUMERIC | ERROR |

**Context requirements:** `ctx.input_conditions`, `ctx.spending_output`.

**Example:**

```json
{
  "type": "RECURSE_SAME",
  "fields": [
    { "type": "NUMERIC", "data": "0a000000" }
  ]
}
```

Maximum depth of 10 recursive spends.

**Common patterns:** Perpetual vaults. Persistent spending policies. Combine with SIG
for key-gated recursive vaults.

---

### 23. RECURSE_MODIFIED (0x0402)

**Family:** Recursion

**Purpose:** Mutation covenant. Enforces re-encumbrance where specific NUMERIC fields
in specific blocks are allowed to change by an exact additive delta. All other fields
must remain identical. Used to implement state machines, counters, and accumulators
on-chain.

**Fields:**

Legacy format (single mutation at rung 0):

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Maximum recursion depth |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Block index within the target rung |
| NUMERIC[2] | NUMERIC (0x08) | 1-4 B | Yes | Parameter index within the target block |
| NUMERIC[3] | NUMERIC (0x08) | 1-4 B | Yes | Delta (additive change per spend) |

New format (multiple mutations):

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Maximum recursion depth |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Number of mutations (K) |
| NUMERIC[2..2+4K] | NUMERIC (0x08) | 1-4 B each | Yes | K groups of (rung_idx, block_idx, param_idx, delta) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 4: return ERROR
max_depth = ReadNumeric(numerics[0])
if max_depth <= 0: return UNSATISFIED

mutations = ParseMutationSpecs(numerics)  // legacy or new format
// For each mutation: target (rung_idx, block_idx, param_idx, delta)

if ctx.input_conditions and ctx.spending_output:
    output_conds = DeserializeRungConditions(spending_output.scriptPubKey)
    if fail: return UNSATISFIED
    // Verify rung count matches
    // For each rung/block pair:
    //   If targeted by a mutation: verify output_value == input_value + delta
    //     (only NUMERIC fields may be mutated)
    //   Else: verify block conditions are identical
    return SATISFIED or UNSATISFIED
return SATISFIED
```

The delta enforcement rule is: `output_value = input_value + delta`.

**Return values:**

| Condition | Result |
|-----------|--------|
| All mutations correct, all other fields identical | SATISFIED |
| Any mutation incorrect or non-NUMERIC field mutated | UNSATISFIED |
| Fewer than 4 NUMERICs or max_depth <= 0 | ERROR or UNSATISFIED |

**Context requirements:** `ctx.input_conditions`, `ctx.spending_output`.

**Example:**

```json
{
  "type": "RECURSE_MODIFIED",
  "fields": [
    { "type": "NUMERIC", "data": "64000000" },
    { "type": "NUMERIC", "data": "00000000" },
    { "type": "NUMERIC", "data": "00000000" },
    { "type": "NUMERIC", "data": "01000000" }
  ]
}
```

Max depth 100, block 0 of rung 0, parameter 0, delta +1 per spend.

**Common patterns:** State machine transitions (paired with LATCH_SET/LATCH_RESET).
Counter increments (paired with COUNTER_UP). Timer accumulation (paired with
TIMER_CONTINUOUS). Any PLC block that needs tracked state changes.

---

### 24. RECURSE_UNTIL (0x0403)

**Family:** Recursion

**Purpose:** Height-terminated covenant. Before the target height, the UTXO must
re-encumber with identical conditions. At or after the target height, the covenant
terminates and the funds can be spent freely (this block returns SATISFIED without
re-encumbrance checks).

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Target termination block height |

**Evaluation logic:**

```
until_height = ReadNumeric(NUMERIC)
if NUMERIC absent: return ERROR
if until_height < 0: return ERROR

effective_height = ctx.block_height
if ctx.tx and tx.nLockTime < LOCKTIME_THRESHOLD:
    effective_height = max(effective_height, tx.nLockTime)

if effective_height >= until_height:
    return SATISFIED  // covenant terminates

// Before target: must re-encumber
if ctx.input_conditions and ctx.spending_output:
    output_conds = DeserializeRungConditions(spending_output.scriptPubKey)
    if fail or not FullConditionsEqual(input_conditions, output_conds):
        return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Block height >= until_height (termination) | SATISFIED |
| Before target, output re-encumbered correctly | SATISFIED |
| Before target, re-encumbrance missing or incorrect | UNSATISFIED |
| Missing NUMERIC | ERROR |

**Context requirements:** `ctx.block_height`, `ctx.tx`, `ctx.input_conditions`,
`ctx.spending_output`.

**Example:**

```json
{
  "type": "RECURSE_UNTIL",
  "fields": [
    { "type": "NUMERIC", "data": "40420f00" }
  ]
}
```

Covenant active until block 1,000,000.

**Common patterns:** Time-bounded spending policies. Vesting schedules that expire.
Governance periods with fixed end dates.

---

### 25. RECURSE_COUNT (0x0404)

**Family:** Recursion

**Purpose:** Countdown covenant. Each spend must decrement the counter by exactly 1 in
the output. When the counter reaches 0, the covenant terminates and funds can be spent
freely.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Remaining spend count |

**Evaluation logic:**

```
count = ReadNumeric(NUMERIC)
if NUMERIC absent: return ERROR
if count < 0: return ERROR
if count == 0: return SATISFIED  // countdown done, covenant terminates

// count > 0: output must have RECURSE_COUNT with count-1
if ctx.input_conditions and ctx.spending_output:
    output_conds = DeserializeRungConditions(spending_output.scriptPubKey)
    found = false
    for each rung in output_conds:
        for each block in rung:
            if block.type == RECURSE_COUNT:
                out_count = ReadNumeric(block's NUMERIC)
                if out_count == count - 1: found = true
    if not found: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| count == 0 (terminal) | SATISFIED |
| count > 0 and output has count-1 | SATISFIED |
| count > 0 and output missing or wrong count | UNSATISFIED |
| Missing NUMERIC or count < 0 | ERROR |

**Context requirements:** `ctx.input_conditions`, `ctx.spending_output`.

**Example:**

```json
{
  "type": "RECURSE_COUNT",
  "fields": [
    { "type": "NUMERIC", "data": "05" }
  ]
}
```

Five remaining spends before termination.

**Common patterns:** Limited-use spending tickets. N-step protocol sequences. Rate-
limited withdrawal (spend once per block, N times total).

---

### 26. RECURSE_SPLIT (0x0405)

**Family:** Recursion

**Purpose:** UTXO splitting covenant. Allows a single UTXO to be split into multiple
outputs, each carrying the same covenant with a decremented split counter. Enforces
minimum output sizes and total value conservation.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Maximum splits remaining |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Minimum split output value (satoshis) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
max_splits = ReadNumeric(numerics[0])
min_split_sats = ReadNumeric(numerics[1])
if max_splits <= 0 or min_split_sats < 0: return UNSATISFIED

if ctx.tx and ctx.input_conditions:
    total_output = 0
    for each output in tx:
        if output.value < min_split_sats: return UNSATISFIED
        total_output += output.value
        // Each output's RECURSE_SPLIT must have max_splits - 1
        out_conds = DeserializeRungConditions(output.scriptPubKey)
        for RECURSE_SPLIT blocks in out_conds:
            if out_splits != max_splits - 1: return UNSATISFIED
    if total_output > ctx.input_amount: return UNSATISFIED  // value conservation
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| All outputs valid, value conserved, split counter decremented | SATISFIED |
| Any output below minimum, value exceeds input, or counter wrong | UNSATISFIED |
| Missing NUMERICs | ERROR |

**Context requirements:** `ctx.tx`, `ctx.input_conditions`, `ctx.input_amount`.

**Example:**

```json
{
  "type": "RECURSE_SPLIT",
  "fields": [
    { "type": "NUMERIC", "data": "03" },
    { "type": "NUMERIC", "data": "e8030000" }
  ]
}
```

Up to 3 levels of splitting, minimum 1,000 sats per output.

**Common patterns:** CoinPool exit trees. Scalable payout distributions. Binary tree
UTXO expansion.

---

### 27. RECURSE_DECAY (0x0406)

**Family:** Recursion

**Purpose:** Progressive relaxation covenant. Identical to RECURSE_MODIFIED except all
deltas are negated: `output_value = input_value - delta`. This causes parameter values
to decrease over successive spends, progressively relaxing conditions (e.g., lowering
thresholds, reducing delays).

**Fields:** Same as RECURSE_MODIFIED (both legacy and new format).

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Maximum recursion depth |
| NUMERIC[1+] | NUMERIC (0x08) | 1-4 B | Yes | Mutation specs (same format as RECURSE_MODIFIED) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
max_depth, mutations = ParseMutationSpecs(numerics)
if parse fails: return ERROR
if max_depth <= 0: return UNSATISFIED

// Negate all deltas
for each mutation: mutation.delta = -mutation.delta
return VerifyMutatedConditions(ctx, mutations)
```

**Return values:** Same as RECURSE_MODIFIED.

**Context requirements:** `ctx.input_conditions`, `ctx.spending_output`.

**Example:**

```json
{
  "type": "RECURSE_DECAY",
  "fields": [
    { "type": "NUMERIC", "data": "0a000000" },
    { "type": "NUMERIC", "data": "00000000" },
    { "type": "NUMERIC", "data": "00000000" },
    { "type": "NUMERIC", "data": "0a000000" }
  ]
}
```

Max depth 10, decays parameter 0 of block 0 in rung 0 by 10 each spend.

**Common patterns:** Decaying timelocks (CSV delay reduces over time). Diminishing
multisig thresholds. Gradually relaxing spending constraints.

---

## PLC Family

The PLC (Programmable Logic Controller) family models on-chain spending conditions
using industrial automation primitives. PLC blocks typically track state via NUMERIC
fields that are modified across covenant spends using RECURSE_MODIFIED.

### 28. HYSTERESIS_FEE (0x0601)

**Family:** PLC

**Purpose:** Fee rate band (hysteresis). SATISFIED only when the spending transaction's
fee rate (sat/vB) falls within the specified band `[low, high]`.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | High fee rate threshold (sat/vB) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Low fee rate threshold (sat/vB) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
high = ReadNumeric(numerics[0])
low = ReadNumeric(numerics[1])
if high < 0 or low < 0 or low > high: return UNSATISFIED

if ctx.tx is null or ctx.spent_outputs is null:
    return SATISFIED  // structural-only mode

fee = sum(spent_output.values) - sum(tx.output.values)
if fee < 0: return UNSATISFIED
vsize = GetVirtualTransactionSize(tx)
if vsize <= 0: return ERROR
fee_rate = fee / vsize
if low <= fee_rate <= high: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Fee rate within [low, high] | SATISFIED |
| Fee rate outside band, negative fee, or invalid band | UNSATISFIED |
| No tx context (structural mode) | SATISFIED |
| vsize <= 0 | ERROR |

**Context requirements:** `ctx.tx`, `ctx.spent_outputs`.

**Example:**

```json
{
  "type": "HYSTERESIS_FEE",
  "fields": [
    { "type": "NUMERIC", "data": "32000000" },
    { "type": "NUMERIC", "data": "01000000" }
  ]
}
```

Allows spending only when fee rate is between 1 and 50 sat/vB.

**Common patterns:** Fee-sensitive covenants. DCA bots that only execute in low-fee
environments. Rate-limiting high-fee spending.

---

### 29. HYSTERESIS_VALUE (0x0602)

**Family:** PLC

**Purpose:** Value band (hysteresis). SATISFIED only when the input UTXO amount falls
within the specified satoshi band `[low, high]`.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | High value threshold (satoshis) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Low value threshold (satoshis) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
high_sats = ReadNumeric(numerics[0])
low_sats = ReadNumeric(numerics[1])
if high_sats < 0 or low_sats < 0 or low_sats > high_sats: return UNSATISFIED

if ctx.input_amount >= low_sats and ctx.input_amount <= high_sats:
    return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| input_amount within [low, high] | SATISFIED |
| Outside band or invalid parameters | UNSATISFIED |
| Fewer than 2 NUMERICs | ERROR |

**Context requirements:** `ctx.input_amount`.

**Example:**

```json
{
  "type": "HYSTERESIS_VALUE",
  "fields": [
    { "type": "NUMERIC", "data": "a0860100" },
    { "type": "NUMERIC", "data": "e8030000" }
  ]
}
```

Only spendable when UTXO value is between 1,000 and 100,000 sats.

**Common patterns:** Value-gated spending tiers. Conditional logic based on UTXO size.

---

### 30. TIMER_CONTINUOUS (0x0611)

**Family:** PLC

**Purpose:** Elapsed timer. Tracks accumulated time units across covenant spends.
SATISFIED when accumulated >= target (timer has fully elapsed). Pair with
RECURSE_MODIFIED to increment the accumulated value each spend.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Accumulated count |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Target count (timer goal) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2:
    // Single-field backward compat: treat as target
    if numerics.empty(): return ERROR
    if ReadNumeric(numerics[0]) <= 0: return UNSATISFIED
    return SATISFIED
accumulated = ReadNumeric(numerics[0])
target = ReadNumeric(numerics[1])
if accumulated < 0 or target < 0: return ERROR
if accumulated >= target: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| accumulated >= target | SATISFIED |
| accumulated < target | UNSATISFIED |
| Negative values | ERROR |

**Context requirements:** None (state tracked in NUMERIC fields).

**Example:**

```json
{
  "type": "TIMER_CONTINUOUS",
  "fields": [
    { "type": "NUMERIC", "data": "03" },
    { "type": "NUMERIC", "data": "0a" }
  ]
}
```

3 of 10 time units accumulated. 7 more covenant spends needed.

**Common patterns:** Paired with RECURSE_MODIFIED (delta=+1 on accumulated field) to
create spend-counted timers.

---

### 31. TIMER_OFF_DELAY (0x0612)

**Family:** PLC

**Purpose:** Hold-off timer. SATISFIED while the remaining count is positive (still in
the hold-off period). UNSATISFIED when remaining reaches 0 (delay expired). Pair with
RECURSE_MODIFIED (delta=-1) to decrement each spend.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Remaining hold-off count |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
remaining = ReadNumeric(NUMERIC)
if remaining < 0: return ERROR
if remaining > 0: return SATISFIED   // still in hold-off
return UNSATISFIED                    // remaining == 0, delay expired
```

**Return values:**

| Condition | Result |
|-----------|--------|
| remaining > 0 (hold-off active) | SATISFIED |
| remaining == 0 (delay expired) | UNSATISFIED |
| Missing or negative NUMERIC | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "TIMER_OFF_DELAY",
  "fields": [
    { "type": "NUMERIC", "data": "05" }
  ]
}
```

5 spend-steps of hold-off remaining.

**Common patterns:** Delayed deactivation. Cooling-off periods that count down via
covenant spends.

---

### 32. LATCH_SET (0x0621)

**Family:** PLC

**Purpose:** Latch activation. A bistable state element that is SATISFIED when the
state is 0 (unset), allowing the latch to be set. Pair with RECURSE_MODIFIED to
enforce state transition from 0 to 1 in the output.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 32-33 B | Yes | Setter key (authorised to set the latch) |
| NUMERIC | NUMERIC (0x08) | 1-4 B | No | State (0=unset, 1=set). If absent, structural-only mode returns SATISFIED. |

**Evaluation logic:**

```
if pubkey count < 1: return ERROR
numerics = FindAllFields(NUMERIC)
if numerics.empty(): return SATISFIED  // backward compat
state = ReadNumeric(numerics[0])
if state == 0: return SATISFIED   // unset, can be set
return UNSATISFIED                // already set
```

**Return values:**

| Condition | Result |
|-----------|--------|
| state == 0 (unset) | SATISFIED |
| state != 0 (already set) | UNSATISFIED |
| No PUBKEY | ERROR |
| No NUMERIC (structural mode) | SATISFIED |

**Context requirements:** None.

**Example:**

```json
{
  "type": "LATCH_SET",
  "fields": [
    { "type": "PUBKEY", "data": "setter_key_32B" },
    { "type": "NUMERIC", "data": "00" }
  ]
}
```

**Common patterns:** Paired with LATCH_RESET on a separate rung. Combined with
RECURSE_MODIFIED (delta=+1) to enforce 0-to-1 transition. Enable/disable toggles for
spending paths.

---

### 33. LATCH_RESET (0x0622)

**Family:** PLC

**Purpose:** Latch reset. SATISFIED when the state is >= 1 (set), allowing the latch
to be reset. Includes a delay parameter for timed reset windows. Pair with
RECURSE_MODIFIED to enforce state transition from 1 to 0.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 32-33 B | Yes | Resetter key |
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | State (0=unset, >=1=set) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Delay blocks (informational, not enforced by evaluator directly) |

**Evaluation logic:**

```
if pubkey count < 1: return ERROR
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR  // need state + delay
state = ReadNumeric(numerics[0])
delay = ReadNumeric(numerics[1])
if delay < 0: return ERROR
if state >= 1: return SATISFIED   // set, can be reset
return UNSATISFIED                // already unset
```

**Return values:**

| Condition | Result |
|-----------|--------|
| state >= 1 (set) | SATISFIED |
| state == 0 (already unset) | UNSATISFIED |
| Missing PUBKEY or fewer than 2 NUMERICs | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "LATCH_RESET",
  "fields": [
    { "type": "PUBKEY", "data": "resetter_key_32B" },
    { "type": "NUMERIC", "data": "01" },
    { "type": "NUMERIC", "data": "06" }
  ]
}
```

State is 1 (set), 6-block delay parameter.

**Common patterns:** Paired with LATCH_SET on a separate rung. Combined with
RECURSE_MODIFIED (delta=-1) to enforce 1-to-0 transition.

---

### 34. COUNTER_DOWN (0x0631)

**Family:** PLC

**Purpose:** Down counter. SATISFIED while count > 0 (can still decrement). Pair with
RECURSE_MODIFIED (delta=-1) to decrement each spend.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 32-33 B | Yes | Event signer key |
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | Current count |

**Evaluation logic:**

```
if pubkey count < 1: return ERROR
if NUMERIC absent: return ERROR
count = ReadNumeric(NUMERIC)
if count < 0: return ERROR
if count > 0: return SATISFIED
return UNSATISFIED  // countdown done
```

**Return values:**

| Condition | Result |
|-----------|--------|
| count > 0 | SATISFIED |
| count == 0 | UNSATISFIED |
| Missing fields or count < 0 | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "COUNTER_DOWN",
  "fields": [
    { "type": "PUBKEY", "data": "event_key_32B" },
    { "type": "NUMERIC", "data": "05" }
  ]
}
```

**Common patterns:** Limited-use authorisation tokens. Countdown to unlock. Similar to
RECURSE_COUNT but operates as a PLC contact for complex ladder logic.

---

### 35. COUNTER_PRESET (0x0632)

**Family:** PLC

**Purpose:** Preset counter (approval accumulator). SATISFIED while current < preset
(still accumulating). UNSATISFIED when current >= preset (target reached). Pair with
RECURSE_MODIFIED (delta=+1 on current) to increment.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Current count |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Preset (target count) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
current = ReadNumeric(numerics[0])
preset = ReadNumeric(numerics[1])
if current < 0 or preset < 0: return ERROR
if current < preset: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| current < preset | SATISFIED |
| current >= preset | UNSATISFIED |
| Fewer than 2 NUMERICs or negative values | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "COUNTER_PRESET",
  "fields": [
    { "type": "NUMERIC", "data": "02" },
    { "type": "NUMERIC", "data": "05" }
  ]
}
```

2 of 5 approvals collected.

**Common patterns:** Multi-party approval accumulation. Quorum collection over time.

---

### 36. COUNTER_UP (0x0633)

**Family:** PLC

**Purpose:** Up counter with target. SATISFIED while current < target (still counting
up). UNSATISFIED when current >= target. Requires a PUBKEY for authorisation.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| PUBKEY | PUBKEY (0x01) | 32-33 B | Yes | Event signer key |
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Current count |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Target count |

**Evaluation logic:**

```
if pubkey count < 1: return ERROR
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
current = ReadNumeric(numerics[0])
target = ReadNumeric(numerics[1])
if current < 0 or target < 0: return ERROR
if current < target: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| current < target | SATISFIED |
| current >= target | UNSATISFIED |
| Missing PUBKEY, fewer than 2 NUMERICs, or negative values | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "COUNTER_UP",
  "fields": [
    { "type": "PUBKEY", "data": "event_key_32B" },
    { "type": "NUMERIC", "data": "00" },
    { "type": "NUMERIC", "data": "0a" }
  ]
}
```

0 of 10 events counted.

**Common patterns:** Event counting with authorisation. Similar to COUNTER_PRESET but
with a PUBKEY requirement for spending authorisation.

---

### 37. COMPARE (0x0641)

**Family:** PLC

**Purpose:** Amount comparator. Compares the input UTXO amount against threshold values
using a specified comparison operator.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Operator code (1=EQ, 2=NEQ, 3=GT, 4=LT, 5=GTE, 6=LTE, 7=IN_RANGE) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Comparison value B (satoshis) |
| NUMERIC[2] | NUMERIC (0x08) | 1-4 B | Required for IN_RANGE | Upper bound C (satoshis) for IN_RANGE operator |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
op = ReadNumeric(numerics[0])
value_b = ReadNumeric(numerics[1])
if value_b < 0: return ERROR
amount = ctx.input_amount

switch op:
    0x01 (EQ):       return (amount == value_b) ? SATISFIED : UNSATISFIED
    0x02 (NEQ):      return (amount != value_b) ? SATISFIED : UNSATISFIED
    0x03 (GT):       return (amount > value_b) ? SATISFIED : UNSATISFIED
    0x04 (LT):       return (amount < value_b) ? SATISFIED : UNSATISFIED
    0x05 (GTE):      return (amount >= value_b) ? SATISFIED : UNSATISFIED
    0x06 (LTE):      return (amount <= value_b) ? SATISFIED : UNSATISFIED
    0x07 (IN_RANGE):
        if numerics.size() < 3: return ERROR
        value_c = ReadNumeric(numerics[2])
        if value_c < 0: return ERROR
        return (amount >= value_b and amount <= value_c) ? SATISFIED : UNSATISFIED
    default: return ERROR
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Comparison is true | SATISFIED |
| Comparison is false | UNSATISFIED |
| Unknown operator, missing fields, or negative values | ERROR |

**Context requirements:** `ctx.input_amount`.

**Example:**

```json
{
  "type": "COMPARE",
  "fields": [
    { "type": "NUMERIC", "data": "05" },
    { "type": "NUMERIC", "data": "e8030000" }
  ]
}
```

Operator GTE (0x05): SATISFIED if input_amount >= 1,000 sats.

**Common patterns:** Value guards on spending paths. Conditional routing based on UTXO
size. Pairs with AMOUNT_LOCK for comprehensive value constraints.

---

### 38. SEQUENCER (0x0651)

**Family:** PLC

**Purpose:** Step sequencer. SATISFIED when the current step index is valid (within
bounds). Pair with RECURSE_MODIFIED (delta=+1 on current_step) to advance the sequence
each spend.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Current step index (0-based) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Total number of steps |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 2: return ERROR
current = ReadNumeric(numerics[0])
total = ReadNumeric(numerics[1])
if current < 0 or total <= 0 or current >= total: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| 0 <= current < total | SATISFIED |
| current < 0, total <= 0, or current >= total | UNSATISFIED |
| Fewer than 2 NUMERICs | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "SEQUENCER",
  "fields": [
    { "type": "NUMERIC", "data": "02" },
    { "type": "NUMERIC", "data": "05" }
  ]
}
```

Step 2 of 5 (steps 0-4).

**Common patterns:** Multi-phase protocol execution. Ordered workflow enforcement.
State machine step tracking.

---

### 39. ONE_SHOT (0x0661)

**Family:** PLC

**Purpose:** Single-fire activation. SATISFIED only if state is 0 (unfired). Once
fired, the state is set to 1 via RECURSE_MODIFIED and the block becomes permanently
UNSATISFIED. The HASH256 commitment provides a unique identity for the one-shot event.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC | NUMERIC (0x08) | 1-4 B | Yes | State (0=unfired, nonzero=fired) |
| HASH256 | HASH256 (0x03) | 32 B | Yes | Event commitment hash (unique identifier) |

**Evaluation logic:**

```
if NUMERIC absent: return ERROR
if HASH256 count < 1: return ERROR
state = ReadNumeric(NUMERIC)
if state == 0: return SATISFIED   // can fire
return UNSATISFIED                // already fired
```

**Return values:**

| Condition | Result |
|-----------|--------|
| state == 0 (unfired) | SATISFIED |
| state != 0 (already fired) | UNSATISFIED |
| Missing NUMERIC or HASH256 | ERROR |

**Context requirements:** None.

**Example:**

```json
{
  "type": "ONE_SHOT",
  "fields": [
    { "type": "NUMERIC", "data": "00" },
    { "type": "HASH256", "data": "event_commitment_32B" }
  ]
}
```

**Common patterns:** Single-use spending authorisation. Emergency kill switches. One-
time claim tickets.

---

### 40. RATE_LIMIT (0x0671)

**Family:** PLC

**Purpose:** Per-block rate limiter. Constrains the output amount to not exceed
max_per_block in a single transaction. Accumulation cap and refill parameters are
available for UTXO-chain tracking.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| NUMERIC[0] | NUMERIC (0x08) | 1-4 B | Yes | Maximum amount per block (satoshis) |
| NUMERIC[1] | NUMERIC (0x08) | 1-4 B | Yes | Accumulation cap (satoshis) |
| NUMERIC[2] | NUMERIC (0x08) | 1-4 B | Yes | Refill interval (blocks) |

**Evaluation logic:**

```
numerics = FindAllFields(NUMERIC)
if numerics.size() < 3: return ERROR
max_per_block = ReadNumeric(numerics[0])
if max_per_block < 0: return ERROR

if ctx.output_amount > max_per_block: return UNSATISFIED
return SATISFIED
```

Note: Full accumulation tracking across multiple spends requires UTXO-chain state and
is not enforced within a single block evaluation.

**Return values:**

| Condition | Result |
|-----------|--------|
| output_amount <= max_per_block | SATISFIED |
| output_amount > max_per_block | UNSATISFIED |
| Fewer than 3 NUMERICs or negative max | ERROR |

**Context requirements:** `ctx.output_amount`.

**Example:**

```json
{
  "type": "RATE_LIMIT",
  "fields": [
    { "type": "NUMERIC", "data": "e8030000" },
    { "type": "NUMERIC", "data": "10270000" },
    { "type": "NUMERIC", "data": "06000000" }
  ]
}
```

Max 1,000 sats per block, 10,000 sat accumulation cap, 6-block refill interval.

**Common patterns:** Withdrawal rate limiting. Drip-feed spending. Anti-drain
protection on hot wallets.

---

### 41. COSIGN (0x0681)

**Family:** PLC

**Purpose:** Co-spend contact. Requires that another input in the same transaction
has a spent output whose scriptPubKey hashes to the committed value. This creates a
dependency between inputs, ensuring two specific UTXOs are spent atomically together.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| HASH256 | HASH256 (0x03) | 32 B | Yes | SHA-256 of the required co-input's scriptPubKey |

**Evaluation logic:**

```
if HASH256 absent or HASH256.size() != 32: return ERROR

if ctx.tx is null or ctx.spent_outputs is null:
    return SATISFIED  // structural-only mode

for each input i in tx (skip self):
    other_spk = spent_outputs[i].scriptPubKey
    if SHA256(other_spk) == HASH256.data: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Another input's spent scriptPubKey matches hash | SATISFIED |
| No matching co-input found | UNSATISFIED |
| No tx context (structural mode) | SATISFIED |
| Missing or invalid HASH256 | ERROR |

**Context requirements:** `ctx.tx`, `ctx.spent_outputs`, `ctx.input_index`.

**Example:**

```json
{
  "type": "COSIGN",
  "fields": [
    { "type": "HASH256", "data": "sha256_of_partner_scriptpubkey_32B" }
  ]
}
```

**Common patterns:** Atomic multi-UTXO operations. Paired-UTXO spending policies.
Authorisation tokens that must be co-spent with a target UTXO.

---

## Compound Family

Compound blocks combine multiple spending conditions (signature, timelock, hash) into a
single block. They are semantically equivalent to placing the individual blocks in the
same rung, but save wire bytes and simplify common patterns like HTLCs and timelocked
signatures.

### 42. TIMELOCKED_SIG (0x0701)

**Family:** Compound

**Purpose:** SIG + CSV in one block. Requires a valid signature AND a relative timelock
(CSV) to be satisfied. Equivalent to placing SIG and CSV blocks in the same rung.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| pubkey | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Signing public key (or commitment in conditions) |
| scheme | SCHEME (0x09) | 1 B | No | Signature scheme (default: Schnorr). Enables PQ routing. |
| csv_delay | NUMERIC (0x08) | varint | Yes | Relative timelock in blocks (BIP-68 sequence value) |
| signature | SIGNATURE (0x06) | 64--65 B | Yes | Schnorr signature (witness only) |

**Evaluation logic:**

```
if PUBKEY_COMMIT present: verify SHA256(PUBKEY) == PUBKEY_COMMIT
if SCHEME is PQ: route to VerifyPQSignature()
else: verify Schnorr/ECDSA signature against PUBKEY
if CSV disable flag set: return SATISFIED
if CheckSequence(csv_delay) fails: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid signature + CSV delay met | SATISFIED |
| Valid signature + CSV delay not met | UNSATISFIED |
| Invalid signature | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** Signature checker, sequence enforcement.

**Example:**

```json
{
  "type": "TIMELOCKED_SIG",
  "fields": [
    { "type": "PUBKEY", "hex": "02abc..." },
    { "type": "NUMERIC", "value": 144 }
  ]
}
```

**Common patterns:** Time-delayed single-sig spending. Recovery paths with mandatory
waiting periods. Staged withdrawal from vaults.

---

### 43. HTLC (0x0702)

**Family:** Compound

**Purpose:** Hash Time-Locked Contract. Requires a valid signature, a hash preimage
reveal, AND a relative timelock. The standard Lightning Network HTLC pattern in a
single block.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| sender_key | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Sender's public key (refund path) |
| receiver_key | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Receiver's public key (claim path) |
| hash_lock | HASH256 (0x03) | 32 B | Yes | SHA-256 hash that the preimage must match |
| csv_delay | NUMERIC (0x08) | varint | Yes | Relative timelock for the refund path |
| signature | SIGNATURE (0x06) | 64--65 B | Yes | Schnorr/ECDSA signature (witness only) |
| preimage | PREIMAGE (0x05) | 1--252 B | Yes | Hash preimage (witness only) |

**Evaluation logic:**

```
if SHA256(preimage) != hash_lock: return UNSATISFIED
if CheckSequence(csv_delay) fails: return UNSATISFIED
resolve PUBKEY_COMMITs, verify signature against first matched pubkey
if signature invalid: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid preimage + valid sig + CSV met | SATISFIED |
| Wrong preimage | UNSATISFIED |
| Invalid signature | UNSATISFIED |
| CSV not met | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** Signature checker, sequence enforcement.

**Example:**

```json
{
  "type": "HTLC",
  "fields": [
    { "type": "PUBKEY", "hex": "02sender..." },
    { "type": "PUBKEY", "hex": "02receiver..." },
    { "type": "HASH256", "hex": "sha256_hash_32B" },
    { "type": "NUMERIC", "value": 144 }
  ]
}
```

**Common patterns:** Lightning Network payment channels. Cross-chain atomic swaps.
Conditional payments with timeout refund.

---

### 44. HASH_SIG (0x0703)

**Family:** Compound

**Purpose:** HASH_PREIMAGE + SIG in one block. Requires both a valid hash preimage
and a valid signature. Used for atomic swap claim paths where no timelock is needed.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| pubkey | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Signing public key |
| hash_lock | HASH256 (0x03) | 32 B | Yes | SHA-256 hash the preimage must match |
| scheme | SCHEME (0x09) | 1 B | No | Signature scheme. Enables PQ routing. |
| signature | SIGNATURE (0x06) | 64--65 B | Yes | Schnorr signature (witness only) |
| preimage | PREIMAGE (0x05) | 1--252 B | Yes | Hash preimage (witness only) |

**Evaluation logic:**

```
if SHA256(preimage) != hash_lock: return UNSATISFIED
resolve PUBKEY_COMMITs, verify signature (PQ if SCHEME indicates)
if signature invalid: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid preimage + valid signature | SATISFIED |
| Wrong preimage | UNSATISFIED |
| Invalid signature | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** Signature checker.

**Example:**

```json
{
  "type": "HASH_SIG",
  "fields": [
    { "type": "PUBKEY", "hex": "02abc..." },
    { "type": "HASH256", "hex": "sha256_hash_32B" }
  ]
}
```

**Common patterns:** Atomic swap claim (no timeout). Hash-gated signature verification.

---

### 45. PTLC (0x0704)

**Family:** Compound

**Purpose:** Point Time-Locked Contract. ADAPTOR_SIG + CSV in one block. Requires an
adapted Schnorr signature (where the adaptor secret has been applied off-chain) and a
relative timelock. The next-generation replacement for HTLCs in payment channels.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| signing_key | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Signing public key |
| adaptor_point | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32 B | Yes | Adaptor point (committed, not revealed in witness) |
| csv_delay | NUMERIC (0x08) | varint | Yes | Relative timelock in blocks |
| signature | SIGNATURE (0x06) | 64--65 B | Yes | Adapted Schnorr signature (witness only) |

**Evaluation logic:**

```
resolve signing_key from PUBKEY_COMMIT
verify adapted Schnorr signature against signing_key
(adaptor_point is committed but not needed for on-chain verification)
if signature invalid: return UNSATISFIED
if CheckSequence(csv_delay) fails: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid adapted sig + CSV met | SATISFIED |
| Invalid signature | UNSATISFIED |
| CSV not met | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** Signature checker, sequence enforcement. Schnorr only (no ECDSA/PQ).

**Example:**

```json
{
  "type": "PTLC",
  "fields": [
    { "type": "PUBKEY", "hex": "02signing_key..." },
    { "type": "PUBKEY", "hex": "adaptor_point_32B_xonly" },
    { "type": "NUMERIC", "value": 144 }
  ]
}
```

**Common patterns:** PTLC payment channels. Conditional payments without hash preimage
revelation (superior privacy to HTLCs). Adaptor signature constructions.

---

### 46. CLTV_SIG (0x0705)

**Family:** Compound

**Purpose:** SIG + CLTV in one block. Requires a valid signature AND an absolute
timelock (by block height). Equivalent to placing SIG and CLTV blocks in the same rung.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| pubkey | PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B | Yes | Signing public key |
| scheme | SCHEME (0x09) | 1 B | No | Signature scheme. Enables PQ routing. |
| cltv_height | NUMERIC (0x08) | varint | Yes | Absolute block height (nLockTime minimum) |
| signature | SIGNATURE (0x06) | 64--65 B | Yes | Schnorr signature (witness only) |

**Evaluation logic:**

```
resolve PUBKEY_COMMITs, verify signature (PQ if SCHEME indicates)
if signature invalid: return UNSATISFIED
if CheckLockTime(cltv_height) fails: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid signature + CLTV met | SATISFIED |
| Invalid signature | UNSATISFIED |
| CLTV height not reached | UNSATISFIED |
| Missing fields | ERROR |

**Context requirements:** Signature checker, locktime enforcement.

**Example:**

```json
{
  "type": "CLTV_SIG",
  "fields": [
    { "type": "PUBKEY", "hex": "02abc..." },
    { "type": "NUMERIC", "value": 850000 }
  ]
}
```

**Common patterns:** Time-locked inheritance. Absolute-time vesting schedules.

---

### 47. TIMELOCKED_MULTISIG (0x0706)

**Family:** Compound

**Purpose:** MULTISIG + CSV in one block. Requires M-of-N threshold signatures AND a
relative timelock. Used for time-delayed multisig governance.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| threshold | NUMERIC (0x08) | varint | Yes | M (minimum signatures required) |
| pubkeys | N x PUBKEY (0x01) / PUBKEY_COMMIT (0x02) | 32--2048 B each | Yes | N public keys |
| csv_delay | NUMERIC (0x08) | varint | Yes | Relative timelock in blocks |
| signatures | M x SIGNATURE (0x06) | 64--65 B each | Yes | M Schnorr signatures (witness only) |
| scheme | SCHEME (0x09) | 1 B | No | Signature scheme. Enables PQ routing. |

**Evaluation logic:**

```
read threshold M from first NUMERIC
resolve PUBKEY_COMMITs (need >= M matching PUBKEYs)
verify M-of-N signatures (each sig must match a distinct pubkey)
if fewer than M valid signatures: return UNSATISFIED
if CheckSequence(csv_delay) fails: return UNSATISFIED
return SATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| M valid sigs + CSV met | SATISFIED |
| Fewer than M valid sigs | UNSATISFIED |
| CSV not met | UNSATISFIED |
| Missing fields or bad threshold | ERROR |

**Context requirements:** Signature checker, sequence enforcement.

**Example:**

```json
{
  "type": "TIMELOCKED_MULTISIG",
  "fields": [
    { "type": "NUMERIC", "value": 2 },
    { "type": "PUBKEY", "hex": "02key1..." },
    { "type": "PUBKEY", "hex": "02key2..." },
    { "type": "PUBKEY", "hex": "02key3..." },
    { "type": "NUMERIC", "value": 144 }
  ]
}
```

**Common patterns:** DAO governance with mandatory cooling-off period. Time-delayed
corporate treasury spending. Staged release mechanisms.

---

## Governance Family

Governance blocks enforce transaction-level constraints that are independent of
cryptographic signatures. They restrict the structure, timing, or economic properties
of the spending transaction itself.

### 48. EPOCH_GATE (0x0801)

**Family:** Governance

**Purpose:** Restricts spending to periodic windows based on block height. The UTXO can
only be spent during the first `window_size` blocks of each `epoch_size`-block epoch.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| epoch_size | NUMERIC (0x08) | varint | Yes | Length of each epoch in blocks (must be > 0) |
| window_size | NUMERIC (0x08) | varint | Yes | Spending window within each epoch (must be <= epoch_size) |

**Evaluation logic:**

```
if epoch_size <= 0 or window_size <= 0 or window_size > epoch_size: return ERROR
position = block_height % epoch_size
if position < window_size: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Within spending window | SATISFIED |
| Outside spending window | UNSATISFIED |
| Invalid parameters | ERROR |

**Context requirements:** `ctx.block_height`.

**Example:**

```json
{
  "type": "EPOCH_GATE",
  "fields": [
    { "type": "NUMERIC", "value": 144 },
    { "type": "NUMERIC", "value": 72 }
  ]
}
```

**Common patterns:** Daily spending windows (epoch=144, window=72). Weekly distribution
schedules. Rate-limited governance operations.

---

### 49. WEIGHT_LIMIT (0x0802)

**Family:** Governance

**Purpose:** Constrains the maximum weight of the spending transaction. Prevents
fee-siphon attacks by limiting transaction complexity.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| max_weight | NUMERIC (0x08) | varint | Yes | Maximum transaction weight in weight units |

**Evaluation logic:**

```
if ctx.tx is null: return SATISFIED  // structural validation only
if GetTransactionWeight(tx) <= max_weight: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Transaction weight within limit | SATISFIED |
| Transaction too heavy | UNSATISFIED |
| No tx context | SATISFIED |

**Context requirements:** `ctx.tx`.

**Example:**

```json
{
  "type": "WEIGHT_LIMIT",
  "fields": [
    { "type": "NUMERIC", "value": 4000 }
  ]
}
```

**Common patterns:** Anti-bloat constraint on covenant outputs. Fee control for
automated spending paths.

---

### 50. INPUT_COUNT (0x0803)

**Family:** Governance

**Purpose:** Constrains the number of inputs in the spending transaction to a range
[min, max]. Enforces transaction structure requirements.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| min_inputs | NUMERIC (0x08) | varint | Yes | Minimum number of inputs (inclusive) |
| max_inputs | NUMERIC (0x08) | varint | Yes | Maximum number of inputs (inclusive) |

**Evaluation logic:**

```
if min_inputs > max_inputs: return ERROR
if ctx.tx is null: return SATISFIED
count = tx.vin.size()
if count >= min_inputs AND count <= max_inputs: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Input count within range | SATISFIED |
| Input count outside range | UNSATISFIED |
| Invalid range | ERROR |
| No tx context | SATISFIED |

**Context requirements:** `ctx.tx`.

**Example:**

```json
{
  "type": "INPUT_COUNT",
  "fields": [
    { "type": "NUMERIC", "value": 1 },
    { "type": "NUMERIC", "value": 5 }
  ]
}
```

**Common patterns:** Singleton-input covenants. Batching constraints.

---

### 51. OUTPUT_COUNT (0x0804)

**Family:** Governance

**Purpose:** Constrains the number of outputs in the spending transaction to a range
[min, max]. Symmetric to INPUT_COUNT.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| min_outputs | NUMERIC (0x08) | varint | Yes | Minimum number of outputs (inclusive) |
| max_outputs | NUMERIC (0x08) | varint | Yes | Maximum number of outputs (inclusive) |

**Evaluation logic:**

```
if min_outputs > max_outputs: return ERROR
if ctx.tx is null: return SATISFIED
count = tx.vout.size()
if count >= min_outputs AND count <= max_outputs: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Output count within range | SATISFIED |
| Output count outside range | UNSATISFIED |
| Invalid range | ERROR |
| No tx context | SATISFIED |

**Context requirements:** `ctx.tx`.

**Example:**

```json
{
  "type": "OUTPUT_COUNT",
  "fields": [
    { "type": "NUMERIC", "value": 2 },
    { "type": "NUMERIC", "value": 2 }
  ]
}
```

**Common patterns:** Exactly-2-output covenant enforcement. Anti-fan-out constraints.

---

### 52. RELATIVE_VALUE (0x0805)

**Family:** Governance

**Purpose:** Enforces that the output value is at least a given fraction of the input
value. Prevents fee-siphon attacks where a malicious spender routes most value to fees.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| numerator | NUMERIC (0x08) | varint | Yes | Numerator of the minimum ratio |
| denominator | NUMERIC (0x08) | varint | Yes | Denominator of the minimum ratio (must be > 0) |

**Evaluation logic:**

```
if denominator == 0: return ERROR
// Satisfied when: output_amount / input_amount >= numerator / denominator
// Computed as: output_amount * denominator >= input_amount * numerator
// Uses 128-bit arithmetic to prevent overflow
if output_amount * denominator >= input_amount * numerator: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Value ratio sufficient | SATISFIED |
| Value ratio too low | UNSATISFIED |
| Zero denominator | ERROR |

**Context requirements:** `ctx.input_amount`, `ctx.output_amount`.

**Example:**

```json
{
  "type": "RELATIVE_VALUE",
  "fields": [
    { "type": "NUMERIC", "value": 9 },
    { "type": "NUMERIC", "value": 10 }
  ]
}
```

**Common patterns:** Anti-fee-siphon (output >= 90% of input). Value preservation in
recursive covenants. DCA covenant minimum re-encumbrance.

---

### 53. ACCUMULATOR (0x0806)

**Family:** Governance

**Purpose:** Merkle accumulator set membership proof. Verifies that a leaf value is
included in a Merkle tree with a committed root hash. Enables scalable set membership
checks without enumerating all elements on-chain.

**Fields:**

| Name | Data Type | Size | Required | Description |
|------|-----------|------|----------|-------------|
| root | HASH256 (0x03) | 32 B | Yes | Merkle root hash (conditions) |
| siblings | N x HASH256 (0x03) | 32 B each | Yes | Proof path sibling hashes (witness) |
| leaf | HASH256 (0x03) | 32 B | Yes | Leaf hash to verify (witness) |

**Evaluation logic:**

```
if fewer than 3 HASH256 fields: return ERROR
root = hashes[0], leaf = hashes[last]
current = leaf
for each sibling in hashes[1..N-1]:
    if current < sibling: current = SHA256(current || sibling)
    else: current = SHA256(sibling || current)
if current == root: return SATISFIED
return UNSATISFIED
```

**Return values:**

| Condition | Result |
|-----------|--------|
| Valid Merkle proof to root | SATISFIED |
| Proof does not verify | UNSATISFIED |
| Fewer than 3 hashes | ERROR |

**Context requirements:** None (self-contained verification).

**Example:**

```json
{
  "type": "ACCUMULATOR",
  "fields": [
    { "type": "HASH256", "hex": "merkle_root_32B" },
    { "type": "HASH256", "hex": "sibling1_32B" },
    { "type": "HASH256", "hex": "sibling2_32B" },
    { "type": "HASH256", "hex": "leaf_hash_32B" }
  ]
}
```

**Common patterns:** Allowlist/blocklist enforcement. Scalable whitelist covenants.
Commitment set proofs. Accumulator-based spending authorisation.

---

## Compact Encodings

Compact encodings are not block types — they are space-optimised wire representations that resolve to standard blocks at deserialisation time. The block count remains 53.

### COMPACT_SIG

A compact rung encoding for the common case of a single-signer key commitment. Uses the `n_blocks == 0` sentinel within a rung to signal compact mode. The rung body contains only:

- `pubkey_commit` (32 bytes) — SHA-256 commitment to the signing public key
- `scheme` (1 byte) — signature scheme selector

At deserialisation, a COMPACT_SIG rung is expanded into a standard rung containing a single SIG block with PUBKEY_COMMIT and SCHEME fields. The evaluator never sees the compact form; it evaluates the resolved SIG block using the normal code path.

Wire savings: a COMPACT_SIG rung is 34 bytes versus 36+ bytes for an explicitly encoded SIG block with micro-header and implicit fields.

---

## Appendix: Data Type Reference

| Type Code | Name | Min Size | Max Size | Description |
|-----------|------|----------|----------|-------------|
| 0x01 | PUBKEY | 1 B | 2048 B | Public key (compressed, x-only, or PQ) |
| 0x02 | PUBKEY_COMMIT | 32 B | 32 B | SHA-256 commitment to a public key |
| 0x03 | HASH256 | 32 B | 32 B | SHA-256 hash digest |
| 0x04 | HASH160 | 20 B | 20 B | RIPEMD160(SHA256()) hash digest |
| 0x05 | PREIMAGE | 1 B | 252 B | Hash preimage (witness only) |
| 0x06 | SIGNATURE | 1 B | 50000 B | Cryptographic signature (witness only) |
| 0x07 | SPEND_INDEX | 4 B | 4 B | Spend index reference |
| 0x08 | NUMERIC | 1 B | 4 B | Numeric value (wire: varint; memory: 4-byte LE unsigned) |
| 0x09 | SCHEME | 1 B | 1 B | Signature scheme selector |

Condition data types (allowed in scriptPubKey): PUBKEY, PUBKEY_COMMIT, HASH256,
HASH160, NUMERIC, SCHEME, SPEND_INDEX.

Witness-only data types (not allowed in scriptPubKey conditions): SIGNATURE, PREIMAGE.

## Appendix: Signature Schemes

| Code | Name | Sig Size | Key Size | Type |
|------|------|----------|----------|------|
| 0x01 | SCHNORR | 64-65 B | 32 B (x-only) | Classical |
| 0x02 | ECDSA | 8-72 B | 33 B (compressed) | Classical |
| 0x10 | FALCON512 | varies | varies | Post-quantum |
| 0x11 | FALCON1024 | varies | varies | Post-quantum |
| 0x12 | DILITHIUM3 | varies | varies | Post-quantum |

Post-quantum schemes (code >= 0x10) are routed through `VerifyPQSignature()` and
use `ComputeLadderSighash()` with `SIGHASH_DEFAULT`.
