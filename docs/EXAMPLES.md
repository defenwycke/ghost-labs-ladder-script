# Ladder Script -- Worked Examples

This document presents detailed, end-to-end examples of Ladder Script transactions.
Each example includes the scenario rationale, an ASCII ladder diagram showing the
rung layout, the `createrungtx` JSON wire representation, and a step-by-step
walkthrough of how the evaluator processes the transaction.

All examples use transaction version 4 (v4 RUNG_TX). Public keys, hashes, and
transaction IDs shown here are illustrative placeholders.

**Note on PUBKEY in conditions:** The `createrungtx` RPC auto-hashes any PUBKEY
field to PUBKEY_COMMIT (SHA-256) when building output conditions. Users provide
pubkey hex as `"type": "PUBKEY"` in the JSON and the RPC performs the conversion.
The on-chain conditions contain PUBKEY_COMMIT (32 bytes); the raw PUBKEY is
provided in the witness at spend time.

---

## Conventions

- **Rung numbering** follows the PLC convention: R000, R001, R002, etc.
- **AND logic** applies within a rung: every block in the rung must evaluate to
  SATISFIED for the rung to pass.
- **OR logic** applies across rungs: the first satisfied rung wins; remaining
  rungs are not evaluated.
- **Power rails** in the ASCII diagrams represent the left (L+) and right (L-)
  rails of a PLC ladder. Power flows left to right through contacts (blocks)
  to reach the coil (output action).
- **Coil notation**: `( )` = standard unlock, `(R)` = recursive re-encumbrance,
  `(C)` = covenant constraint.

---

## 1. Simple P2PKH (Single Signature)

### Scenario

The simplest possible Ladder Script transaction: a single output encumbered by
a single signature verification block. Functionally equivalent to Pay-to-Public-Key-Hash,
but expressed as a typed, structured condition rather than a Bitcoin Script opcode sequence.

### Ladder Diagram

```
     L+                                              L-
     |                                                |
R000 +--[ SIG: 02a1b2...f0a1 ]----------------------( )--+
     |                                                |
     +------------------------------------------------+
```

One rung, one block, one coil. The `SIG` block contains a single PUBKEY field.
To spend, the witness must contain a valid Schnorr signature for that public key.

### Wire Representation (createrungtx JSON)

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 0 }
  ],
  "outputs": [
    {
      "amount": 0.001,
      "conditions": [
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Evaluation Walkthrough

1. The node receives a spending transaction referencing this UTXO.
2. The scriptPubKey begins with `0xc1` (RUNG_CONDITIONS_PREFIX), so the node
   deserializes it as rung conditions rather than interpreting Bitcoin Script.
3. The evaluator calls `EvalLadder`, which iterates over rungs in order.
4. **Rung 0**: Contains one block of type `SIG` (0x0001).
   - `EvalSigBlock` extracts the PUBKEY field from the conditions.
   - The witness provides a SIGNATURE field.
   - The evaluator computes `SignatureHashLadder` (tagged hash: `"LadderSighash"`),
     which commits to the transaction version, locktime, prevouts, amounts,
     sequences, outputs, input index, and the serialized conditions hash.
   - Schnorr signature verification is performed against the pubkey.
   - Result: **SATISFIED**.
5. All blocks in rung 0 are SATISFIED, so the rung passes.
6. The coil type is UNLOCK (standard spend). No further constraints.
7. Transaction is valid.

---

## 2. 2-of-3 Multisig Vault with Recovery

### Scenario

A corporate treasury UTXO with two spending paths on the same output:

- **Rung 0 (SPEND)**: Requires 2-of-3 multisig signatures from the board of
  directors. This is the normal spending path.
- **Rung 1 (RECOVER)**: After approximately one year (52,560 blocks), a single
  backup key can recover the funds. This is the emergency path for lost keys.

Both rungs are assigned to the same transaction input.

### Ladder Diagram

```
     L+                                                          L-
     |                                                            |
R000 +--[ MULTISIG: 2-of-3 {pk1, pk2, pk3} ]-------------------( )--+
     |                                                            |
R001 +--[ CSV: 52560 blocks ]---[ SIG: 03c6d7...b600 ]----------( )--+
     |                                                            |
     +------------------------------------------------------------+
```

Rung 0 provides immediate spending with quorum approval. Rung 1 provides
time-delayed recovery. The evaluator tries rung 0 first; if it fails (fewer
than 2 valid signatures), it falls through to rung 1, which additionally
requires the CSV relative timelock to have matured.

### Wire Representation

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 0 }
  ],
  "outputs": [
    {
      "amount": 0.05,
      "conditions": [
        {
          "blocks": [
            {
              "type": "MULTISIG",
              "fields": [
                { "type": "NUMERIC", "hex": "02000000" },
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" },
                { "type": "PUBKEY", "hex": "03f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a3928170605f4e3d2c1b0" },
                { "type": "PUBKEY", "hex": "02b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081920a" }
              ]
            }
          ]
        },
        {
          "blocks": [
            {
              "type": "CSV",
              "fields": [
                { "type": "NUMERIC", "hex": "50cd0000" }
              ]
            },
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "03c6d7e8f90a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b600" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

Note: The NUMERIC field `50cd0000` is 52560 encoded as a 4-byte little-endian integer.

### Evaluation Walkthrough

**Path A -- Normal spend (rung 0):**

1. The witness contains 2 signatures and identifies rung 0.
2. `EvalMultisigBlock` reads the threshold (NUMERIC field: 2) and the 3 PUBKEY fields.
3. It iterates the witness signatures, matching each against the pubkey set.
4. If 2 or more signatures verify, result: **SATISFIED**.
5. Rung 0 passes. Transaction is valid.

**Path B -- Recovery spend (rung 1):**

1. The witness contains 1 signature and identifies rung 1.
2. `EvalCSVBlock` reads the NUMERIC field (52,560 blocks) and checks the input's
   nSequence against BIP 68 relative timelock rules.
   - If the UTXO has not matured for 52,560 blocks: **UNSATISFIED**. Rung 1 fails.
   - If matured: **SATISFIED**.
3. `EvalSigBlock` verifies the backup key's signature.
   - If valid: **SATISFIED**.
4. Both blocks in rung 1 are SATISFIED (AND logic). Rung 1 passes.
5. Transaction is valid.

---

## 3. Hash Time-Locked Contract (HTLC)

### Scenario

A cross-chain atomic swap between Alice and Bob. The UTXO has two spending paths:

- **Rung 0 (CLAIM)**: Alice reveals a hash preimage and provides her signature.
  This is the happy path for completing the swap.
- **Rung 1 (REFUND)**: After 144 blocks (~1 day), Bob can reclaim the funds
  with his signature alone. This is the safety net if Alice never claims.

### Ladder Diagram

```
     L+                                                              L-
     |                                                                |
R000 +--[ HASH_PREIMAGE: a1b2...b2 ]---[ SIG: 02a1b2...f0a1 ]-----( )--+
     |         (ALICE CLAIM)                                          |
R001 +--[ CSV: 144 blocks ]---[ SIG: 03f9e8...c1b0 ]-----------( )--+
     |         (BOB REFUND)                                           |
     +----------------------------------------------------------------+
```

### Wire Representation

```json
{
  "inputs": [
    { "txid": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", "vout": 1 }
  ],
  "outputs": [
    {
      "amount": 0.01,
      "conditions": [
        {
          "blocks": [
            {
              "type": "HASH_PREIMAGE",
              "fields": [
                { "type": "HASH256", "hex": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" }
              ]
            },
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            }
          ]
        },
        {
          "blocks": [
            {
              "type": "CSV",
              "fields": [
                { "type": "NUMERIC", "hex": "90000000" }
              ]
            },
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "03f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a3928170605f4e3d2c1b0" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Evaluation Walkthrough

**Path A -- Alice claims (rung 0):**

1. Alice's witness provides a PREIMAGE field and a SIGNATURE field.
2. `EvalHashPreimageBlock`: computes `SHA256(preimage)` and compares it to the
   HASH256 field in the conditions.
   - Match: **SATISFIED**.
3. `EvalSigBlock`: verifies Alice's Schnorr signature against her PUBKEY.
   - Valid: **SATISFIED**.
4. Both blocks pass (AND). Rung 0 wins. Alice receives the funds.

**Path B -- Bob refunds (rung 1):**

1. Bob's witness provides a SIGNATURE field and identifies rung 1.
2. `EvalCSVBlock`: checks nSequence >= 144 blocks relative to the UTXO's
   confirmation height.
   - If matured: **SATISFIED**.
3. `EvalSigBlock`: verifies Bob's signature.
   - Valid: **SATISFIED**.
4. Both blocks pass (AND). Rung 1 wins. Bob recovers the funds.

**Atomicity**: When Alice claims on this chain by revealing the preimage, the
preimage becomes public on-chain. Bob (or anyone) can extract it from the
witness data and use it to claim the corresponding HTLC on the other chain.

---

## 4. Countdown Vault (3-Step Deliberation)

### Scenario

A corporate treasury vault that requires 3 separate signed transactions,
each confirmed in a separate block, before funds can be freely spent. This
prevents impulsive or coerced single-transaction withdrawals.

The UTXO contains: `SIG(vault_key)` + `RECURSE_COUNT(3)`.

### Ladder Diagram

```
     L+                                                          L-
     |                                                            |
R000 +--[ SIG: 02a1b2...f0a1 ]---[ RECURSE_COUNT: 3 ]---------( R )--+
     |                                                            |
     +------------------------------------------------------------+

     (R) = Recursive coil: output must re-encumber with identical conditions,
           except RECURSE_COUNT is decremented by 1.
```

### Wire Representation (Initial UTXO)

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 0 }
  ],
  "outputs": [
    {
      "amount": 1.0,
      "conditions": [
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            },
            {
              "type": "RECURSE_COUNT",
              "fields": [
                { "type": "NUMERIC", "hex": "03000000" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### The 4-Step Spend Chain

**Spend 1 (count 3 -> 2):**

1. The vault key signs the spending transaction.
2. `EvalRecurseCountBlock` reads the count value (3). Since count > 0, the
   block enforces that the spending transaction's output contains identical
   conditions with count decremented to 2.
3. The evaluator compares the output's serialized conditions against the input's
   conditions, verifying that only the RECURSE_COUNT NUMERIC field changed and
   that the new value is exactly `input_count - 1`.
4. Result: **SATISFIED**. The output is now encumbered with count=2.

**Spend 2 (count 2 -> 1):**

Same process. The output is re-encumbered with count=1.

**Spend 3 (count 1 -> 0):**

Same process. The output is re-encumbered with count=0.

**Spend 4 (count 0 -- covenant terminates):**

1. The vault key signs the spending transaction.
2. `EvalRecurseCountBlock` reads the count value (0). Since count == 0, the
   covenant constraint terminates. The block returns **SATISFIED** without
   enforcing any output structure.
3. The funds can now be sent to any destination freely.

### State Progression

```
UTXO_0: SIG + RECURSE_COUNT(3)   --sign-->  UTXO_1: SIG + RECURSE_COUNT(2)
UTXO_1: SIG + RECURSE_COUNT(2)   --sign-->  UTXO_2: SIG + RECURSE_COUNT(1)
UTXO_2: SIG + RECURSE_COUNT(1)   --sign-->  UTXO_3: SIG + RECURSE_COUNT(0)
UTXO_3: SIG + RECURSE_COUNT(0)   --sign-->  Any destination (covenant expired)
```

---

## 5. DCA (Dollar-Cost Averaging) Covenant

### Scenario

A self-enforcing dollar-cost averaging contract. A user locks 1,000,000 sats
into a covenant that allows exactly 12 purchases of 50,000-100,000 sats each.
On each spend:

1. The COUNTER_DOWN block decrements from 12 toward 0.
2. The AMOUNT_LOCK block constrains the buy output to 50,000-100,000 sats.
3. The RECURSE_MODIFIED block re-encumbers the remainder with the updated counter.

When the counter reaches 0, a second rung (SWEEP) allows the owner to collect
any remaining dust.

### Ladder Diagram

```
     L+                                                                              L-
     |                                                                                |
R000 +--[ COUNTER_DOWN: 12 ]--[ AMOUNT_LOCK: 50k-100k ]--[ RECURSE_MODIFIED ]------( R )--+
     |         (BUY)                                                                  |
R001 +--[ COUNTER_DOWN: 0 ]--[ SIG: 02a1b2...f0a1 ]--------------------------------( )--+
     |         (SWEEP)                                                                |
     +--------------------------------------------------------------------------------+
```

### Wire Representation

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 2 }
  ],
  "outputs": [
    {
      "amount": 0.00083333,
      "conditions": [
        {
          "blocks": [
            {
              "type": "COUNTER_DOWN",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" },
                { "type": "NUMERIC", "hex": "0c000000" }
              ]
            },
            {
              "type": "AMOUNT_LOCK",
              "fields": [
                { "type": "NUMERIC", "hex": "50c30000" },
                { "type": "NUMERIC", "hex": "a0860100" }
              ]
            },
            {
              "type": "RECURSE_MODIFIED",
              "fields": [
                { "type": "NUMERIC", "hex": "00000000" },
                { "type": "NUMERIC", "hex": "00000000" },
                { "type": "NUMERIC", "hex": "01000000" },
                { "type": "NUMERIC", "hex": "ffffffff" }
              ]
            }
          ]
        },
        {
          "blocks": [
            {
              "type": "COUNTER_DOWN",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" },
                { "type": "NUMERIC", "hex": "00000000" }
              ]
            },
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Evaluation Walkthrough (Buy Spend)

The RECURSE_MODIFIED fields encode: target rung 0, target block 0 (COUNTER_DOWN),
target parameter 1 (the count NUMERIC), delta -1.

1. `EvalCounterDownBlock`: reads the count field (12). Since count > 0, the
   block is **SATISFIED** (the counter can still fire).
2. `EvalAmountLockBlock`: checks that the output amount falls within the
   [50,000, 100,000] satoshi range. If the buy output is 83,333 sats:
   **SATISFIED**.
3. `EvalRecurseModifiedBlock`: verifies that the spending transaction's output
   contains conditions identical to the input, except that rung 0, block 0,
   field 1 (the COUNTER_DOWN count) has been decremented by exactly 1
   (from 12 to 11).
   **SATISFIED**.
4. All three blocks pass (AND). The transaction must produce:
   - One output to the buy address (50,000-100,000 sats)
   - One output re-encumbered with the same conditions but counter=11

### Spend Sequence

```
Spend  1: counter 12 -> 11, buy 83,333 sats, remainder re-encumbered
Spend  2: counter 11 -> 10, buy 83,333 sats, remainder re-encumbered
  ...
Spend 12: counter  1 ->  0, buy 83,333 sats, remainder re-encumbered
Spend 13: counter  0, rung 0 UNSATISFIED (COUNTER_DOWN at 0),
          falls through to rung 1 (SWEEP), owner signs to collect remainder
```

---

## 6. Fee-Gated Treasury

### Scenario

A treasury covenant that only permits spending when the network fee rate is
between 5 and 50 sat/vB. This prevents panic-spending during fee spikes and
disincentivizes unnecessarily cheap transactions that might be vulnerable to
replacement attacks.

The UTXO contains: `SIG` + `HYSTERESIS_FEE(5, 50)` + `RECURSE_SAME`.

### Ladder Diagram

```
     L+                                                                          L-
     |                                                                            |
R000 +--[ SIG: 02a1b2...f0a1 ]--[ HYST_FEE: 5-50 ]--[ AMOUNT_LOCK: 10k-500k ]--( )--+
     |         (FEE-GATED SEND)                                                   |
R001 +--[ SIG: 02a1b2...f0a1 ]--[ SIG: 02b4c5...920a ]-------------------------( )--+
     |         (EMERGENCY 2-of-2)                                                 |
     +----------------------------------------------------------------------------+
```

### Wire Representation

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 1 }
  ],
  "outputs": [
    {
      "amount": 0.0325,
      "conditions": [
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            },
            {
              "type": "HYSTERESIS_FEE",
              "fields": [
                { "type": "NUMERIC", "hex": "32000000" },
                { "type": "NUMERIC", "hex": "05000000" }
              ]
            },
            {
              "type": "AMOUNT_LOCK",
              "fields": [
                { "type": "NUMERIC", "hex": "10270000" },
                { "type": "NUMERIC", "hex": "20a10700" }
              ]
            }
          ]
        },
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            },
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081920a" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Evaluation Walkthrough

1. `EvalSigBlock`: verifies the key holder's signature. **SATISFIED**.
2. `EvalHysteresisFeeBlock`: computes the spending transaction's fee rate:
   `fee = sum(input_values) - sum(output_values)`, then `fee_rate = fee / vsize`.
   - If fee_rate < 5 sat/vB: **UNSATISFIED** (too cheap).
   - If fee_rate > 50 sat/vB: **UNSATISFIED** (too expensive).
   - If 5 <= fee_rate <= 50: **SATISFIED**.
3. `EvalAmountLockBlock`: verifies the output amount is within [10,000, 500,000]
   sats. **SATISFIED** if within range.
4. All three blocks pass. Transaction is valid.

If fee conditions are unfavorable, the emergency rung (rung 1) allows a 2-of-2
multisig override that bypasses the fee gate entirely.

---

## 7. PQ Anchor + COSIGN Children

### Scenario

Post-quantum protection for multiple UTXOs using a single, perpetual FALCON-512
anchor. The anchor UTXO carries the expensive PQ key commitment and re-encumbers
itself on every spend. Child UTXOs use lightweight Schnorr signatures but require
co-spending with the anchor, ensuring that no child can be spent without the
anchor's PQ signature in the same transaction.

This pattern amortizes the cost of PQ signatures: 1 anchor protects unlimited
children. At 10 children per batch, witness data is 5.3x smaller than individual
PQ signatures on each UTXO.

### Ladder Diagram

**Anchor UTXO:**

```
     L+                                                                                  L-
     |                                                                                    |
R000 +--[ SIG: FALCON512 ]--[ PUBKEY_COMMIT: 7f3a...9e ]--[ RECURSE_SAME: depth=1000 ]--( R )--+
     |                                                                                    |
     +------------------------------------------------------------------------------------+
```

**Child UTXO:**

```
     L+                                                                  L-
     |                                                                    |
R000 +--[ SIG: 02a1b2...f0a1 ]--[ COSIGN: hash=b4c5...0f ]------------( )--+
     |                                                                    |
     +--------------------------------------------------------------------+
```

The COSIGN block's HASH256 field contains `SHA256(anchor_scriptPubKey)`. At spend
time, the evaluator scans all other inputs in the transaction looking for one whose
spent scriptPubKey hashes to this value.

### Wire Representation

**Anchor output conditions:**

```json
{
  "inputs": [
    { "txid": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "vout": 0 }
  ],
  "outputs": [
    {
      "amount": 0.0001,
      "conditions": [
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "SCHEME", "hex": "10" },
                { "type": "PUBKEY_COMMIT", "hex": "7f3a8b2c9d0e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e9e" }
              ]
            },
            {
              "type": "RECURSE_SAME",
              "fields": [
                { "type": "NUMERIC", "hex": "e8030000" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

**Child output conditions:**

```json
{
  "inputs": [
    { "txid": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", "vout": 0 }
  ],
  "outputs": [
    {
      "amount": 0.005,
      "conditions": [
        {
          "blocks": [
            {
              "type": "SIG",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" }
              ]
            },
            {
              "type": "COSIGN",
              "fields": [
                { "type": "HASH256", "hex": "b4c5d6e7f8091a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f70819a0f" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

### Co-Spend Transaction

The spending transaction includes both inputs:
- Input 0: the anchor UTXO (provides FALCON-512 signature + full PQ pubkey in witness)
- Input 1: the child UTXO (provides Schnorr signature)

### Evaluation Walkthrough

**Anchor input (input 0):**

1. `EvalSigBlock`: the SCHEME field (0x10 = FALCON512) selects PQ verification.
   The PUBKEY_COMMIT field contains a 32-byte SHA-256 commitment. The witness
   provides the full 897-byte FALCON-512 public key via `pq_pubkey`.
   - The evaluator computes `SHA256(witness_pubkey)` and compares it to the
     PUBKEY_COMMIT value. Match: proceed.
   - The evaluator computes `SignatureHashLadder` and verifies the FALCON-512
     signature against the full public key.
   - **SATISFIED**.
2. `EvalRecurseSameBlock`: verifies that one of the spending transaction's outputs
   contains a scriptPubKey byte-identical to the input's scriptPubKey.
   The depth counter (1000) is decremented; at depth 0 the covenant would expire.
   - **SATISFIED** (output re-encumbers with identical conditions).

**Child input (input 1):**

1. `EvalSigBlock`: standard Schnorr verification. **SATISFIED**.
2. `EvalCosignBlock`: computes `SHA256(spent_scriptPubKey)` for every other input
   in the transaction (skipping self at index 1). For input 0 (the anchor),
   `SHA256(anchor_scriptPubKey)` matches the HASH256 field.
   - **SATISFIED**.

Both inputs valid. The anchor re-encumbers itself. The child's value is freed.

---

## 8. State Machine (Latch + Sequencer)

### Scenario

A state machine where a control rung (rung 0) gates transitions on a separate
state rung (rung 1). This pattern cleanly separates the authorization logic
(who can trigger transitions) from the state storage (what step the machine is on).

- **Rung 0**: `LATCH_SET(state=0)` + `RECURSE_MODIFIED(target=rung1, block0, param0, delta=+1)`
- **Rung 1**: `SEQUENCER(step=0, total=5)`

The latch on rung 0 acts as a gate: it only allows the transition when its
state is 0 (unlatched). The RECURSE_MODIFIED block on rung 0 targets rung 1's
SEQUENCER, incrementing the step counter.

### Ladder Diagram

```
     L+                                                                              L-
     |                                                                                |
R000 +--[ LATCH_SET: state=0 ]--[ RECURSE_MODIFIED: target=R001.B0.P0, delta=+1 ]--( R )--+
     |         (CONTROL)                                                              |
R001 +--[ SEQUENCER: step=0, total=5 ]----------------------------------------------( )--+
     |         (STATE)                                                                |
     +--------------------------------------------------------------------------------+
```

### Wire Representation

```json
{
  "inputs": [
    { "txid": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", "vout": 1 }
  ],
  "outputs": [
    {
      "amount": 0.01,
      "conditions": [
        {
          "blocks": [
            {
              "type": "LATCH_SET",
              "fields": [
                { "type": "PUBKEY", "hex": "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" },
                { "type": "NUMERIC", "hex": "00000000" }
              ]
            },
            {
              "type": "RECURSE_MODIFIED",
              "fields": [
                { "type": "NUMERIC", "hex": "01000000" },
                { "type": "NUMERIC", "hex": "00000000" },
                { "type": "NUMERIC", "hex": "00000000" },
                { "type": "NUMERIC", "hex": "01000000" }
              ]
            }
          ]
        },
        {
          "blocks": [
            {
              "type": "SEQUENCER",
              "fields": [
                { "type": "NUMERIC", "hex": "00000000" },
                { "type": "NUMERIC", "hex": "05000000" }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

The RECURSE_MODIFIED fields encode: target rung index 1, target block index 0,
target parameter index 0 (the SEQUENCER's current_step field), delta +1.

### Evaluation Walkthrough

**Spend 1 (step 0 -> 1):**

1. The spender satisfies rung 0 (provides appropriate witness data).
2. `EvalLatchSetBlock`: reads the state field (0). Since state == 0, the latch
   is unset and can fire. **SATISFIED**.
3. `EvalRecurseModifiedBlock`: verifies that the spending transaction's output
   conditions are identical to the input, except that rung 1, block 0, parameter 0
   (the SEQUENCER's current_step) has increased by exactly +1.
   - Input: `SEQUENCER(step=0, total=5)` in rung 1
   - Required output: `SEQUENCER(step=1, total=5)` in rung 1
   - All other conditions (rung 0's LATCH_SET and RECURSE_MODIFIED) unchanged.
   - **SATISFIED**.
4. The output is re-encumbered with step=1.

**Subsequent spends** increment through steps 1, 2, 3, 4. When step reaches 5
(equal to total), the SEQUENCER on rung 1 transitions to its terminal state.

### State Progression

```
UTXO_0: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(0/5)]   -->  step 0 -> 1
UTXO_1: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(1/5)]   -->  step 1 -> 2
UTXO_2: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(2/5)]   -->  step 2 -> 3
UTXO_3: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(3/5)]   -->  step 3 -> 4
UTXO_4: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(4/5)]   -->  step 4 -> 5
UTXO_5: R0=[LATCH(0), RECURSE_MOD] | R1=[SEQ(5/5)]   -->  sequencer complete
```

This pattern is the Ladder Script equivalent of a programmable logic controller's
scan cycle: the control rung evaluates conditions and triggers state transitions
on a separate state rung, with each UTXO spend representing one scan cycle.

---

## Summary of Evaluation Rules

| Rule | Scope | Behavior |
|------|-------|----------|
| AND | Within a rung | All blocks must be SATISFIED |
| OR | Across rungs | First satisfied rung wins |
| Inversion | Per block | `inverted=true` flips SATISFIED to UNSATISFIED and vice versa |
| Fail-closed | Unknown blocks | Unknown block types return UNSATISFIED (not ERROR) |
| Covenants | Per output | Recursion blocks constrain the spending transaction's outputs |
| State | Per UTXO | PLC blocks carry state in their NUMERIC fields across covenant spends |

---

## Appendix: NUMERIC Field Encoding

All NUMERIC values in the wire format are 4-byte little-endian unsigned integers.

| Decimal | Hex (LE) | Field |
|---------|----------|-------|
| 2 | `02000000` | MULTISIG threshold |
| 3 | `03000000` | RECURSE_COUNT remaining |
| 5 | `05000000` | HYSTERESIS_FEE low bound |
| 50 | `32000000` | HYSTERESIS_FEE high bound |
| 144 | `90000000` | CSV 144 blocks |
| 1000 | `e8030000` | RECURSE_SAME depth |
| 10,000 | `10270000` | AMOUNT_LOCK min |
| 50,000 | `50c30000` | AMOUNT_LOCK min (DCA) |
| 52,560 | `50cd0000` | CSV ~1 year in blocks |
| 100,000 | `a0860100` | AMOUNT_LOCK max (DCA) |
| 500,000 | `20a10700` | AMOUNT_LOCK max |
