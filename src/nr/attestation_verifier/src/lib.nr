//! Primus zkTLS attestation verifier - Noir building blocks.
//!
//! Originally based on primus-labs/zktls-verification-noir (commit
//! `65496b7b99879fc108b68bd7f08296225786a40c`). See README for the rationale
//! on each local divergence (the in-circuit `keccak256(envelope)`
//! reconstruction that closes upstream issue #9 is the main soundness fix).

use aztec::protocol::hash::poseidon2_hash;
use keccak256::keccak256;
use sha256::sha256_var;

// =============================================================================
// Building blocks
// =============================================================================
//
// Each function does ONE thing. Consumers compose them depending on their use
// case (e.g. an oracle with a single pinned URL prefix skips
// `match_url_against_allowlist` and does its own URL check). The composition
// order matters for soundness - see each function's doc comment.

/// Reconstruct `keccak256(encodePacked(envelope))` byte-for-byte. The output
/// is what the Primus attestor signed; pair this with `verify_ecdsa_over_hash`
/// to bind the signature to a specific envelope without trusting a witnessed
/// hash (closes upstream issue #9).
///
/// Byte layout (matches Primus's `encodePacked`):
///   recipient(20)
///   || keccak256(request_urls[0] || request_hmb)
///   || keccak256(response_resolves concat)
///   || data
///   || att_conditions
///   || timestamp_be(8)
///   || addition_params
///
/// `request_urls` is fixed at length 1 because Primus's `(1 URL -> 1 reveal)`
/// unit means real attestations always carry exactly one request. The array
/// shape is preserved for compatibility with the upstream lib and any future
/// multi-request extension.
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
    // Timestamp as 8-byte big-endian. Field::to_be_bytes returns the BE bytes
    // of a Field; the u64 fits in the low 8 of the 32-byte representation.
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

/// Verify an ECDSA-secp256k1 signature over `hash`. JUST the ECDSA check -
/// the caller is responsible for ensuring `hash` came from a derived (not
/// witnessed) source. Pair with `derive_envelope_hash` to bind the signature
/// to specific envelope contents.
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

/// Find the entry of `allowed_urls` that is a byte-prefix of `request_url`,
/// constrain the prefix match, and return the Poseidon2 hash of the matched
/// entry. Reverts if no entry matches.
///
/// Generic over `NUM_ALLOWED_URLS` so consumers pick the number of allowed
/// slots; the upstream lib hardcoded it at 3.
///
/// The returned Poseidon2 hash is computed over `MAX_URL_LEN` bytes of the
/// matched URL (zero-padded), so two consumers with different `MAX_URL_LEN`s
/// will get different hashes for the same URL - callers comparing hashes
/// off-circuit must agree on the bound.
pub fn match_url_against_allowlist<let MAX_URL_LEN: u32, let NUM_ALLOWED_URLS: u32>(
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
) -> Field {
    // Safety: locate the matching slot unconstrained, then constrain the prefix
    // byte-by-byte. The unconstrained helper is a witness-gen hint with no
    // soundness role.
    let (found, url_index) = unsafe { get_allowed_url_index(request_url, allowed_urls) };
    assert(found, "No allowed URL matches the request URL");
    let allowed_url = allowed_urls[url_index];

    for j in 0..MAX_URL_LEN {
        if j < allowed_url.len() {
            assert_eq(request_url.storage()[j], allowed_url.storage()[j], "URL check failed");
        }
    }

    let mut hash_input: [Field; MAX_URL_LEN] = [0; MAX_URL_LEN];
    for j in 0..MAX_URL_LEN {
        if j < allowed_url.len() {
            hash_input[j] = allowed_url.storage()[j] as Field;
        }
    }
    poseidon2_hash(hash_input)
}

/// For each content, compute `sha256(content)` and assert its 64-char lowercase
/// hex representation appears at `data_hash_offsets[i]` inside `data`.
///
/// SOUNDNESS: `data` is unverified bytes from the caller's perspective. The
/// caller MUST have established that `data` came from a signature-bound
/// envelope (typically: pass `envelope.data` after `verify_ecdsa_over_hash`
/// against a hash derived from that same envelope). Without that, this
/// function proves nothing - the prover can choose any `data` and any
/// `contents` whose hashes happen to match at the offsets.
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

// =============================================================================
// Convenience wrapper
// =============================================================================
//
// Most consumers want the full canonical flow (envelope hash + ECDSA + URL
// allow-list + content binding). This wraps the building blocks above in the
// correct order. Consumers with a different composition (e.g. a single pinned
// URL prefix without an allow-list) should call the building blocks directly.

/// Verify a Primus zkTLS hashing-mode attestation end-to-end:
///   1. Reconstruct `keccak256(envelope)` from envelope fields.
///   2. ECDSA-verify the signature over the derived hash.
///   3. Match the request URL against `allowed_urls`.
///   4. SHA256_EX-bind each `content` to the signed `data` string.
///
/// Returns the Poseidon2 hash of the matched allowed URL, useful for consumers
/// who pin a different URL per provider/symbol and want to know which slot was
/// hit.
///
/// `NUM_ALLOWED_URLS` is generic - the upstream lib hardcoded it at 3.
pub fn verify_attestation_hashing<let MAX_URL_LEN: u32, let NUM_ALLOWED_URLS: u32, let N: u32, let MAX_CONTENT_LEN: u32, let MAX_HMB_LEN: u32, let MAX_RR_LEN: u32, let MAX_DATA_LEN: u32, let MAX_COND_LEN: u32, let MAX_PARAMS_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 1],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
    contents: [BoundedVec<u8, MAX_CONTENT_LEN>; N],
    recipient: [u8; 20],
    request_hmb: BoundedVec<u8, MAX_HMB_LEN>,
    response_resolves: [BoundedVec<u8, MAX_RR_LEN>; N],
    data: BoundedVec<u8, MAX_DATA_LEN>,
    att_conditions: BoundedVec<u8, MAX_COND_LEN>,
    timestamp: u64,
    addition_params: BoundedVec<u8, MAX_PARAMS_LEN>,
    data_hash_offsets: [u32; N],
) -> [Field; 1] {
    let derived_hash = derive_envelope_hash(
        recipient,
        request_urls,
        request_hmb,
        response_resolves,
        data,
        att_conditions,
        timestamp,
        addition_params,
    );

    verify_ecdsa_over_hash(public_key_x, public_key_y, signature, derived_hash);

    let matched_url_hash = match_url_against_allowlist(request_urls[0], allowed_urls);

    bind_content_hashes(contents, data, data_hash_offsets);

    [matched_url_hash]
}

// =============================================================================
// Unconstrained URL helpers
// =============================================================================
//
// `unconstrained` functions run as witness-generation hints. Their assertions
// are runtime-only and never enter the proof. Soundness is enforced by the
// constrained byte-equality loop in `match_url_against_allowlist`.

unconstrained fn starts_with<let MAX_URL_LEN: u32>(
    haystack: BoundedVec<u8, MAX_URL_LEN>,
    needle: BoundedVec<u8, MAX_URL_LEN>,
) -> bool {
    let needle_length = needle.len();
    assert(needle_length > 0, "needle length of size 0 not supported");
    // LOCAL PATCH (vs primus-labs/zktls-verification-noir @ 65496b7): `>` -> `>=`
    // to accept `haystack == needle` (allowed URL == request URL, our exact use
    // case). Safe because this fn is `unconstrained` (witness-gen hint, no
    // soundness role); the real prefix check is the `assert_eq` loop in
    // `match_url_against_allowlist`, which handles equal-length inputs
    // correctly. Drop this patch once upstream merges.
    assert(haystack.len() >= needle_length, "haystack shorter than needle");

    let mut matched = true;
    for j in 0..needle_length {
        if haystack.get(j) != needle.get(j) {
            matched = false;
            break;
        }
    }
    matched
}

unconstrained fn get_allowed_url_index<let MAX_URL_LEN: u32, let NUM_ALLOWED_URLS: u32>(
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
) -> (bool, u32) {
    let mut found = false;
    let mut index: u32 = 3050913689; // sentinel for "not found"
    for i in 0..allowed_urls.len() {
        let allowed_url = allowed_urls[i];
        if (allowed_url.len() <= request_url.len()) {
            let result = starts_with(request_url, allowed_url);
            if result & !found {
                found = true;
                index = i;
            }
        }
    }
    (found, index)
}
