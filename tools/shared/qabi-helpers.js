// QABIO helper wrappers — thin layer over the ladder proxy endpoints.
// Depends on window.LadderAPI (ladder-api.js must load first).
// Exposes window.QABI.

(function(){
  if (!window.LadderAPI) {
    throw new Error('qabi-helpers.js requires ladder-api.js to load first.');
  }
  const { apiCallBase } = window.LadderAPI;

  const FALCON512_PUBKEY_SIZE = 897;
  const FALCON512_SIG_SIZE = 666;
  const QABI_BLOCK_MAX_SOFT = 65536;
  const QABI_BLOCK_MAX_HARD = 262144;
  const BYTES_PER_INPUT = 432;
  const VBYTES_PER_INPUT = 162;
  const STANDARD_RELAY_MAX_N = 618;

  // Proxy endpoint expects auth_seed + chain_length (not seed/length).
  async function authchain(authSeed, chainLength, depth) {
    const body = { auth_seed: authSeed, chain_length: chainLength };
    if (depth !== undefined) body.depth = depth;
    return apiCallBase('/api/ladder/qabi/authchain', body);
  }

  async function buildBlock({ coordinatorPubkey, primeExpiryHeight, entries, outputs }) {
    return apiCallBase('/api/ladder/qabi/buildblock', {
      coordinator_pubkey: coordinatorPubkey,
      prime_expiry_height: primeExpiryHeight,
      entries,
      outputs,
    });
  }

  async function blockInfo(qabiBlockHex) {
    return apiCallBase('/api/ladder/qabi/blockinfo', { qabi_block: qabiBlockHex });
  }

  async function sighash(hexTx) {
    return apiCallBase('/api/ladder/qabi/sighash', { hex_tx: hexTx });
  }

  async function signQabo(hexTx, privkey) {
    return apiCallBase('/api/ladder/qabi/signqabo', { hex_tx: hexTx, privkey });
  }

  async function generateKeypair(scheme) {
    // FALCON/Dilithium/SPHINCS+ keygen lives under /pq/, not /qabi/.
    return apiCallBase('/api/ladder/pq/keypair', { scheme: scheme || 'FALCON512' });
  }

  // Closed-form amortised batch size estimate, from QABIO.md §8.
  // Used for live metrics before the batch tx is actually built.
  function estimateBatchVsize(n, outputs) {
    const perInput = VBYTES_PER_INPUT;
    const fixedOverhead = 180;
    const perOutput = 31;
    const outs = Math.max(1, outputs || n);
    return fixedOverhead + perInput * n + perOutput * outs;
  }

  function estimatePerInputCostSavings(n, singleTxVsize) {
    const batch = estimateBatchVsize(n, n);
    const individual = (singleTxVsize || 150) * n;
    return {
      batch,
      individual,
      savedVbytes: individual - batch,
      savedPct: individual > 0 ? ((individual - batch) / individual) * 100 : 0,
    };
  }

  window.QABI = {
    FALCON512_PUBKEY_SIZE,
    FALCON512_SIG_SIZE,
    QABI_BLOCK_MAX_SOFT,
    QABI_BLOCK_MAX_HARD,
    BYTES_PER_INPUT,
    VBYTES_PER_INPUT,
    STANDARD_RELAY_MAX_N,
    authchain,
    buildBlock,
    blockInfo,
    sighash,
    signQabo,
    generateKeypair,
    estimateBatchVsize,
    estimatePerInputCostSavings,
  };
})();
