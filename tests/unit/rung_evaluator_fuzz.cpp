// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <rung/conditions.h>
#include <rung/evaluator.h>
#include <rung/serialize.h>
#include <rung/sighash.h>
#include <rung/types.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>

#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

/** Fuzz the ladder evaluator: deserialize conditions + witness, build a
 *  minimal transaction context, and run EvalLadder. Must never crash,
 *  assert-fail, or invoke undefined behavior regardless of input. */
FUZZ_TARGET(rung_evaluator)
{
    if (buffer.size() < 4) return;

    // Split buffer: first half = conditions (for MLSC proof), second half = witness
    size_t split = buffer.size() / 2;
    std::vector<uint8_t> wit_data(buffer.begin(), buffer.begin() + split);
    std::vector<uint8_t> proof_data(buffer.begin() + split, buffer.end());

    // Deserialize witness
    rung::LadderWitness witness;
    std::string wit_error;
    if (!rung::DeserializeLadderWitness(wit_data, witness, wit_error)) {
        return; // Invalid witness — not interesting for evaluator fuzz
    }

    // Deserialize MLSC proof
    rung::MLSCProof proof;
    std::string proof_error;
    if (!rung::DeserializeMLSCProof(proof_data, proof, proof_error)) {
        return; // Invalid proof — not interesting
    }

    // Build minimal conditions from proof
    rung::RungConditions conditions;
    if (!proof.revealed_rung.blocks.empty()) {
        conditions.rungs.push_back(proof.revealed_rung);
    }
    for (const auto& [idx, relay] : proof.revealed_relays) {
        conditions.relays.push_back(relay);
    }

    // Build a minimal dummy transaction for context
    CMutableTransaction mtx;
    mtx.version = CTransaction::RUNG_TX_VERSION;
    mtx.vin.emplace_back();
    mtx.vout.emplace_back();
    mtx.vout[0].nValue = 50000;

    // Build evaluation context
    CTransaction tx_ref(mtx);
    rung::RungEvalContext ctx;
    ctx.input_index = 0;
    ctx.input_amount = 50000;
    ctx.block_height = 1000;
    ctx.tx = &tx_ref;
    ctx.input_conditions = &conditions;

    // Run evaluation — must not crash
    if (!conditions.rungs.empty()) {
        ScriptExecutionData execdata;
        BaseSignatureChecker checker;
        rung::EvalLadder(witness, checker,
                         SigVersion::LADDER, execdata, ctx);
    }
}
