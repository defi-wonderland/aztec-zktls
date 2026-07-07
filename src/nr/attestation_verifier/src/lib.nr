//! Primus zkTLS attestation verifier - three Noir cryptographic primitives.
//! Based on primus-labs/zktls-verification-noir @ `65496b7`. See README for
//! divergences (key one: in-circuit `keccak256(envelope)` reconstruction
//! closing upstream issue #9). Compose in canonical order: derive -> ECDSA
//! -> bind; see `examples/quote_verifier`.

use keccak256::keccak256;
use sha256::sha256_var;

/// Reconstruct `keccak256(encodePacked(envelope))` byte-for-byte - what the
/// Primus attestor signed. Pair with `verify_ecdsa_over_hash` to bind the
/// signature to specific envelope contents (closes upstream issue #9).
///
/// `request_urls` is fixed at length 1: Primus's protocol unit is
/// `(1 URL -> 1 reveal)`.
pub fn derive_envelope_hash<let MAX_URL_LEN: u32, let MAX_HMB_LEN: u32, let N: u32, let MAX_RR_LEN: u32, let MAX_DATA_LEN: u32, let MAX_COND_LEN: u32, let MAX_PARAMS_LEN: u32>(
    recipient: [u8; 20],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 1],
    request_hmb: BoundedVec<u8, MAX_HMB_LEN>,
    response_resolves: [BoundedVec<u8, MAX_RR_LEN>; N],
    data: BoundedVec<u8, MAX_DATA_LEN>,
    att_conditions: BoundedVec<u8, MAX_COND_LEN>,
    timestamp: u64,
    addition_params: BoundedVec<u8, MAX_PARAMS_LEN>,
) -> [u8; 32] {
    // Inner keccak 1: request concat (one URL).
    let mut req_buf: [u8; MAX_URL_LEN + MAX_HMB_LEN] = [0; MAX_URL_LEN + MAX_HMB_LEN];
    let mut req_len: u32 = 0;
    for j in 0..MAX_URL_LEN {
        if j < request_urls[0].len() {
            req_buf[req_len + j] = request_urls[0].storage()[j];
        }
    }
    req_len += request_urls[0].len();
    for j in 0..MAX_HMB_LEN {
        if j < request_hmb.len() {
            req_buf[req_len + j] = request_hmb.storage()[j];
        }
    }
    req_len += request_hmb.len();
    let request_hash = keccak256(req_buf, req_len);

    // Inner keccak 2: response_resolves concat (N entries).
    let mut resp_buf: [u8; MAX_RR_LEN * N] = [0; MAX_RR_LEN * N];
    let mut resp_len: u32 = 0;
    for i in 0..N {
        for j in 0..MAX_RR_LEN {
            if j < response_resolves[i].len() {
                resp_buf[resp_len + j] = response_resolves[i].storage()[j];
            }
        }
        resp_len += response_resolves[i].len();
    }
    let response_hash = keccak256(resp_buf, resp_len);

    // Outer keccak: full envelope.
    let mut env_buf: [u8; 20 + 32 + 32 + MAX_DATA_LEN + MAX_COND_LEN + 8 + MAX_PARAMS_LEN] =
        [0; 20 + 32 + 32 + MAX_DATA_LEN + MAX_COND_LEN + 8 + MAX_PARAMS_LEN];
    let mut env_len: u32 = 0;
    for j in 0..20 {
        env_buf[env_len + j] = recipient[j];
    }
    env_len += 20;
    for j in 0..32 {
        env_buf[env_len + j] = request_hash[j];
    }
    env_len += 32;
    for j in 0..32 {
        env_buf[env_len + j] = response_hash[j];
    }
    env_len += 32;
    for j in 0..MAX_DATA_LEN {
        if j < data.len() {
            env_buf[env_len + j] = data.storage()[j];
        }
    }
    env_len += data.len();
    for j in 0..MAX_COND_LEN {
        if j < att_conditions.len() {
            env_buf[env_len + j] = att_conditions.storage()[j];
        }
    }
    env_len += att_conditions.len();
    // Timestamp BE - u64 in the low 8 of the 32-byte Field representation.
    let ts_be: [u8; 32] = (timestamp as Field).to_be_bytes();
    for i in 0..8 {
        env_buf[env_len + i] = ts_be[24 + i];
    }
    env_len += 8;
    for j in 0..MAX_PARAMS_LEN {
        if j < addition_params.len() {
            env_buf[env_len + j] = addition_params.storage()[j];
        }
    }
    env_len += addition_params.len();

    keccak256(env_buf, env_len)
}

/// ECDSA-secp256k1 check. Caller must ensure `hash` is derived, not witnessed
/// - pair with `derive_envelope_hash` over the same envelope.
pub fn verify_ecdsa_over_hash(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    hash: [u8; 32],
) {
    assert(
        std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash),
        "ECDSA verification failed",
    );
}

/// For each content, assert `sha256(content)`'s 64-char lowercase hex appears
/// at `data_hash_offsets[i]` inside `data`.
///
/// SOUNDNESS: `data` is unverified from this function's perspective. Caller
/// MUST pass `envelope.data` AFTER `verify_ecdsa_over_hash` against a hash
/// derived from that same envelope. Otherwise this function proves nothing.
pub fn bind_content_hashes<let N: u32, let MAX_CONTENT_LEN: u32, let MAX_DATA_LEN: u32>(
    contents: [BoundedVec<u8, MAX_CONTENT_LEN>; N],
    data: BoundedVec<u8, MAX_DATA_LEN>,
    data_hash_offsets: [u32; N],
) {
    for i in 0..N {
        let computed = sha256_var(contents[i].storage(), contents[i].len() as u32);
        let off = data_hash_offsets[i];
        assert(off + 64 <= data.len(), "data hash offset out of range");
        for j in 0..32 {
            let b = computed[j];
            let hi = b >> 4;
            let lo = b & 0x0f;
            let hi_char: u8 = if hi < 10 { hi + 48 } else { hi + 87 };
            let lo_char: u8 = if lo < 10 { lo + 48 } else { lo + 87 };
            assert_eq(data.storage()[off + j * 2], hi_char, "data hash hex mismatch (high)");
            assert_eq(data.storage()[off + j * 2 + 1], lo_char, "data hash hex mismatch (low)");
        }
    }
}
