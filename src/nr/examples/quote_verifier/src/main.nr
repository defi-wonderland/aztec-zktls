mod types;

use aztec::macros::aztec;

/**
 * Quote verifier - verifies Primus zkTLS attestations of a single price field
 * from a supported exchange ticker endpoint (Binance, OKX, Coinbase).
 *
 * Trust model: signatures are accepted only from the single attestor pubkey
 * pinned at deploy. The set of allowed request URLs is also pinned at deploy
 * as a map keyed by `poseidon2_hash(zero-padded URL bytes)`; the URL check is
 * exact byte equality (different URL bytes => different hash => not in map).
 * Both the URL allow-list and the attestor pubkey are immutable for the PoC;
 * redeploy to change either.
 */
#[aztec]
pub contract QuoteVerifier {
    use crate::types::{Envelope, PublicKey};
    use attestation_verifier::verify_attestation;
    use aztec::{
        macros::{events::event, functions::{external, initializer}, storage::storage},
        protocol::{address::AztecAddress, hash::poseidon2_hash},
        state_vars::{Map, PublicImmutable},
    };

    // Ticker URLs across Binance/OKX/Coinbase fit in 96 bytes after the query string.
    global MAX_URL_LEN: u32 = 96;
    // Crypto price strings ("104231.50000000" = 15 bytes). 32 covers fiat + headroom.
    global MAX_PLAINTEXT_LEN: u32 = 32;
    // One field per quote: the price. The (provider, symbol) pair is committed via
    // the URL allow-list: each allowed URL hash in the map represents one full
    // symbol-bearing URL.
    global NUM_RESPONSE_RESOLVE: u32 = 1;
    // Hardcoded by attestation_verifier's signature.
    global NUM_REQUEST_URLS: u32 = 1;
    // Number of URL hashes seeded into the allow-list map at deploy. Only used
    // by the constructor; verify() does an O(1) map lookup and doesn't care.
    global NUM_ALLOWED_URLS_AT_DEPLOY: u32 = 3;
    // Bounds on per-attestation envelope fields used to drive the in-circuit
    // keccak256(envelope) reconstruction. Values below are "observed length on
    // real Primus envelopes for our ticker endpoints, rounded up with headroom":
    //   - HMB: per-request `header + method + body` concat. "GET" + empty header/body = 3 bytes -> 16.
    //   - RR:  per-resolve `keyName + parseType + parsePath` concat. "SHA256($.price)json$.price" ~30 bytes -> 48.
    //   - DATA:  envelope.data JSON. `{"SHA256($.price)":"<64hex>"}` = 86 bytes -> 128.
    //   - COND:  envelope.attConditions JSON. `[{"op":"SHA256","field":"$.price"}]` = 35 bytes -> 64.
    //   - PARAMS: envelope.additionParams JSON. `{"algorithmType":"mpctls"}` = 26 bytes -> 32.
    global MAX_HMB_LEN: u32 = 16;
    global MAX_RR_LEN: u32 = 48;
    global MAX_DATA_LEN: u32 = 128;
    global MAX_COND_LEN: u32 = 64;
    global MAX_PARAMS_LEN: u32 = 32;

    #[event]
    struct QuoteVerified {
        sender: AztecAddress,
        provider_url_hash: Field,
    }

    #[storage]
    struct Storage<Context> {
        // Allow-list of permitted request URLs, keyed by the Poseidon2 hash of
        // the URL bytes zero-padded to MAX_URL_LEN. A key present in the map
        // (initialized to `true`) means that exact URL is accepted. Lookups
        // from private context will revert with "Trying to read from
        // uninitialized PublicImmutable" if the URL hash isn't in the map.
        allowed_url_hashes: Map<Field, PublicImmutable<bool, Context>, Context>,
        // The single attestor whose signatures we accept. Stored as a packed PublicKey (4 Fields).
        allowed_attestor: PublicImmutable<PublicKey, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(
        allowed_url_hashes: [Field; NUM_ALLOWED_URLS_AT_DEPLOY],
        initial_attestor: PublicKey,
    ) {
        for i in 0..NUM_ALLOWED_URLS_AT_DEPLOY {
            self.storage.allowed_url_hashes.at(allowed_url_hashes[i]).initialize(true);
        }
        self.storage.allowed_attestor.initialize(initial_attestor);
    }

    /// Verify a hash-based Primus attestation of a single price field.
    ///
    /// All cryptographic checks (envelope hash reconstruction, ECDSA signature,
    /// SHA256 content binding) run in `attestation_verifier::verify_attestation`.
    /// The URL allow-list check is this contract's policy: hash the request URL
    /// from the verified envelope and require its hash to be in storage.
    ///
    /// The public callback only emits the event.
    #[external("private")]
    fn verify(
        signature: [u8; 64],
        envelope: Envelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
    ) {
        // Read trusted attestor pubkey from storage.
        let attestor: PublicKey = self.storage.allowed_attestor.read();

        // Cryptographic checks (all in-circuit): reconstruct keccak256(envelope),
        // verify ECDSA against the derived hash, and bind each content's SHA256
        // hex to the signed `data` string. After this returns, every envelope
        // field is provably what the attestor signed.
        verify_attestation(
            attestor.x,
            attestor.y,
            signature,
            envelope.recipient,
            [envelope.request_url],
            envelope.request_hmb,
            envelope.response_resolves,
            envelope.data,
            envelope.att_conditions,
            envelope.timestamp,
            envelope.addition_params,
            contents,
            data_hash_offsets,
        );

        // Compute the request URL's identity hash. Zero-pad explicitly to
        // MAX_URL_LEN because BoundedVec's storage() can contain unconstrained
        // bytes beyond len(); the off-chain hasher uses the same zero-padding.
        let mut hash_input: [Field; MAX_URL_LEN] = [0; MAX_URL_LEN];
        for j in 0..MAX_URL_LEN {
            if j < envelope.request_url.len() {
                hash_input[j] = envelope.request_url.storage()[j] as Field;
            }
        }
        let request_url_hash = poseidon2_hash(hash_input);

        // Allow-list check: read() panics with "Trying to read from
        // uninitialized PublicImmutable" if the URL hash isn't in the map.
        let _allowed: bool = self.storage.allowed_url_hashes.at(request_url_hash).read();

        // Public-context emit, since QuoteVerified is a public unencrypted log.
        self.enqueue_self.emit_verified(self.msg_sender(), request_url_hash);
    }

    #[external("public")]
    fn emit_verified(sender: AztecAddress, provider_url_hash: Field) {
        self.emit(QuoteVerified { sender, provider_url_hash });
    }
}
