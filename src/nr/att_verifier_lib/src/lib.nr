use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use keccak256::keccak256;

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------
//
// LOCAL DIVERGENCE FROM UPSTREAM (primus-labs/zktls-verification-noir @ 65496b7):
// the upstream lib also ships Pedersen-commitment paths (`verify_commitment_group`,
// `verify_attestation_comm`) plus their Grumpkin imports. Removed here because we
// only consume hashing-mode envelopes (op = "SHA256" / "SHA256_EX"); the
// commitment path was never exercised. Restore from upstream if commitment mode
// becomes needed (e.g. to attest sensitive values with unconditional hiding).

// Verifies the secp256k1 signature and checks that each request URL starts with
// one of the allowed URLs. Returns the Poseidon2 hash of each matched allowed URL.
fn verify_sig_and_urls<let MAX_URL_LEN: u32, let NUM_REQUEST_URLS: u32, let NUM_ALLOWED_URLS: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_REQUEST_URLS],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
) -> [Field; NUM_REQUEST_URLS] {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    let mut allowed_url_matches: [Field; NUM_REQUEST_URLS] = [0; NUM_REQUEST_URLS];
    for i in 0..NUM_REQUEST_URLS {
        // Safety: find the allowed_url index unconstrained, then constrain it.
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        let allowed_url = allowed_urls[url_index];
        for j in 0..MAX_URL_LEN {
            if j < allowed_url.len() {
                assert_eq(request_urls[i].storage()[j], allowed_url.storage()[j], "URL check failed");
            }
        }
        let mut hash_input: [Field; MAX_URL_LEN] = [0; MAX_URL_LEN];
        for j in 0..MAX_URL_LEN {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, MAX_URL_LEN);
    }
    allowed_url_matches
}

// -----------------------------------------------------------------------------
// Public API - hash-based, envelope-bound
// -----------------------------------------------------------------------------

// SOUNDNESS NOTE (LOCAL CHANGE vs upstream): upstream takes `hash` as a witness
// and only verifies the ECDSA signature over it - never tying `hash` to the
// envelope fields. A prover could pair a real signed `hash` with `data_hashes`
// of their choosing. See primus-labs/zktls-verification-noir#9. Closed here by
// taking the envelope fields directly, reconstructing
// keccak256(encodePacked(envelope)) inside the circuit, verifying ECDSA over
// the derived hash, and binding each content's SHA256 hex to the signed `data`
// string at a witness-provided offset.
//
// LOCAL PATCH (carried from before): NUM_REQUEST_URLS dropped from upstream's
// hardcoded 2 to 1 (one HTTP request per attestation).
//
// N = number of responseResolves.
pub fn verify_attestation_hashing<
    let MAX_URL_LEN: u32,
    let N: u32,
    let MAX_CONTENT_LEN: u32,
    let MAX_HMB_LEN: u32,
    let MAX_RR_LEN: u32,
    let MAX_DATA_LEN: u32,
    let MAX_COND_LEN: u32,
    let MAX_PARAMS_LEN: u32,
>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 1],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    contents: [BoundedVec<u8, MAX_CONTENT_LEN>; N],
    // ----- Envelope fields (see att_verifier_parsing/src/utils.ts::encodePacked) -----
    recipient: [u8; 20],
    request_hmb: BoundedVec<u8, MAX_HMB_LEN>,
    response_resolves: [BoundedVec<u8, MAX_RR_LEN>; N],
    data: BoundedVec<u8, MAX_DATA_LEN>,
    att_conditions: BoundedVec<u8, MAX_COND_LEN>,
    timestamp: u64,
    addition_params: BoundedVec<u8, MAX_PARAMS_LEN>,
    // ----- Per-content binding into `data` (the offset where each SHA256 hex begins) -----
    data_hash_offsets: [u32; N],
) -> [Field; 1] {
    // 1. Reconstruct keccak256(envelope) inside the circuit.
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

    // 2. Verify ECDSA over the DERIVED hash + URL allow-list match.
    let allowed_url_matches = verify_sig_and_urls(
        public_key_x, public_key_y, derived_hash, signature, request_urls, allowed_urls
    );

    // 3. Bind each content to the (now signature-bound) `data` string: compute
    //    sha256(content), then assert its 64-char lowercase hex appears at the
    //    claimed offset inside `data`.
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

    allowed_url_matches
}

// Internal helper: rebuild keccak256(encodePacked(envelope)) byte-for-byte.
// Matches att_verifier_parsing/src/utils.ts::encodePacked:
//   recipient(20) || keccak256(request_concat) || keccak256(response_concat)
//     || data || attConditions || timestamp_be(8) || additionParams
// where request_concat = (url || header+method+body) for the one request, and
// response_concat = (keyName || parseType || parsePath) per resolve, flat-mapped.
fn derive_envelope_hash<
    let MAX_URL_LEN: u32,
    let MAX_HMB_LEN: u32,
    let N: u32,
    let MAX_RR_LEN: u32,
    let MAX_DATA_LEN: u32,
    let MAX_COND_LEN: u32,
    let MAX_PARAMS_LEN: u32,
>(
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

    // Inner keccak 2: response concat (N resolves).
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
    for j in 0..20 { env_buf[env_len + j] = recipient[j]; }
    env_len += 20;
    for j in 0..32 { env_buf[env_len + j] = request_hash[j]; }
    env_len += 32;
    for j in 0..32 { env_buf[env_len + j] = response_hash[j]; }
    env_len += 32;
    for j in 0..MAX_DATA_LEN {
        if j < data.len() { env_buf[env_len + j] = data.storage()[j]; }
    }
    env_len += data.len();
    for j in 0..MAX_COND_LEN {
        if j < att_conditions.len() { env_buf[env_len + j] = att_conditions.storage()[j]; }
    }
    env_len += att_conditions.len();
    // timestamp as 8-byte big-endian
    env_buf[env_len + 0] = ((timestamp >> 56) & 0xff) as u8;
    env_buf[env_len + 1] = ((timestamp >> 48) & 0xff) as u8;
    env_buf[env_len + 2] = ((timestamp >> 40) & 0xff) as u8;
    env_buf[env_len + 3] = ((timestamp >> 32) & 0xff) as u8;
    env_buf[env_len + 4] = ((timestamp >> 24) & 0xff) as u8;
    env_buf[env_len + 5] = ((timestamp >> 16) & 0xff) as u8;
    env_buf[env_len + 6] = ((timestamp >> 8) & 0xff) as u8;
    env_buf[env_len + 7] = (timestamp & 0xff) as u8;
    env_len += 8;
    for j in 0..MAX_PARAMS_LEN {
        if j < addition_params.len() { env_buf[env_len + j] = addition_params.storage()[j]; }
    }
    env_len += addition_params.len();

    keccak256(env_buf, env_len)
}

// -----------------------------------------------------------------------------
// Unconstrained URL helpers
// -----------------------------------------------------------------------------

unconstrained fn starts_with<let MAX_URL_LEN: u32>(
    haystack: BoundedVec<u8, MAX_URL_LEN>,
    needle: BoundedVec<u8, MAX_URL_LEN>,
) -> bool {
    let needle_length = needle.len();
    assert(needle_length > 0, "needle length of size 0 not supported");
    // LOCAL PATCH (vs primus-labs/zktls-verification-noir @ 65496b7): `>` -> `>=`
    // to accept `haystack == needle` (allowed URL == request URL, our exact use case).
    // Safe because this fn is `unconstrained` (witness-gen hint, no soundness role);
    // the real prefix check is the `assert_eq` loop in `verify_sig_and_urls` above,
    // which handles equal-length inputs correctly. Drop this patch once upstream merges.
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
