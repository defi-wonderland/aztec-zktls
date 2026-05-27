mod types;

use aztec::macros::aztec;

/**
 * Quote verifier - verifies Primus zkTLS attestations of a single price field
 * from a supported exchange ticker endpoint (Binance, OKX, Coinbase).
 *
 * Trust model: signatures are accepted only from the single attestor pubkey
 * pinned at deploy. Both the URL allow-list and the attestor pubkey are
 * immutable for the PoC; redeploy to change either.
 */
#[aztec]
pub contract QuoteVerifier {
    use crate::types::{Envelope, PublicKey};
    use att_verifier_lib::verify_attestation_hashing;
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::PublicImmutable;

    // Ticker URLs across Binance/OKX/Coinbase fit in 96 bytes after the query string.
    global MAX_URL_LEN: u32 = 96;
    // Crypto price strings ("104231.50000000" = 15 bytes). 32 covers fiat + headroom.
    global MAX_PLAINTEXT_LEN: u32 = 32;
    // One field per quote: the price. The (provider, symbol) pair is committed via
    // the URL allow-list - each allowed URL contains the full symbol-bearing URL,
    // byte-identical to the claim's request URL. This relies on a one-character
    // patch to the local att_verifier_lib (`>` -> `>=` in `starts_with`) so the
    // unconstrained URL-matching helper accepts equal-length inputs; see
    // `nr/att_verifier_lib/src/lib.nr` for the justification.
    global NUM_RESPONSE_RESOLVE: u32 = 1;
    // Hardcoded by att_verifier_lib's signature.
    global NUM_REQUEST_URLS: u32 = 1;
    global NUM_ALLOWED_URLS: u32 = 3;
    // Bounds on per-attestation envelope fields used to drive the in-circuit
    // keccak256(envelope) reconstruction (att_verifier_lib::verify_attestation_hashing).
    // Sized to fit real Primus envelopes for our ticker endpoints with headroom.
    //   - HMB: per-request `header + method + body` concat. "GET" + empty header/body = 3 bytes.
    //   - RR:  per-resolve `keyName + parseType + parsePath` concat. "SHA256($.price)json$.price" ~30 bytes.
    //   - DATA:  envelope.data JSON. `{"SHA256($.price)":"<64hex>"}` = 86 bytes.
    //   - COND:  envelope.attConditions JSON. `[{"op":"SHA256","field":"$.price"}]` = 35 bytes.
    //   - PARAMS: envelope.additionParams JSON. `{"algorithmType":"mpctls"}` = 26 bytes.
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
        // Poseidon2 hashes of allowed provider ticker URLs. With NUM_ALLOWED_URLS = 3,
        // one slot per provider (Binance, OKX, Coinbase) in the canonical PoC deployment.
        allowed_url_hashes: PublicImmutable<[Field; NUM_ALLOWED_URLS], Context>,
        // The single attestor whose signatures we accept. Stored as a packed PublicKey (4 Fields).
        allowed_attestor: PublicImmutable<PublicKey, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(
        allowed_url_hashes: [Field; NUM_ALLOWED_URLS],
        initial_attestor: PublicKey,
    ) {
        self.storage.allowed_url_hashes.initialize(allowed_url_hashes);
        self.storage.allowed_attestor.initialize(initial_attestor);
    }

    /// Verify a hash-based Primus attestation of a single price field.
    /// All checks (envelope hash reconstruction, signature, URL allow-list,
    /// SHA256 binding) run in the private circuit. The trusted attestor pubkey
    /// is read from storage and passed directly to the ECDSA check.
    /// The public callback only emits the event.
    #[external("private")]
    fn verify(
        signature: [u8; 64],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
        envelope: Envelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
    ) {
        // Read trusted attestor pubkey from storage.
        let attestor: PublicKey = self.storage.allowed_attestor.read();

        // Cryptographic checks (all in-circuit): reconstruct keccak256(envelope),
        // verify ECDSA against the derived hash, URL prefix match, and bind each
        // content's SHA256 hex to the signed `data` string.
        let matched_url_hashes: [Field; NUM_REQUEST_URLS] = verify_attestation_hashing(
            attestor.x,
            attestor.y,
            signature,
            [envelope.request_url],
            allowed_urls,
            contents,
            envelope.recipient,
            envelope.request_hmb,
            envelope.response_resolves,
            envelope.data,
            envelope.att_conditions,
            envelope.timestamp,
            envelope.addition_params,
            data_hash_offsets,
        );

        // URL allow-list check: the matched URL hash must be in storage.
        let allowed: [Field; NUM_ALLOWED_URLS] = self.storage.allowed_url_hashes.read();
        let mut found = false;
        for j in 0..NUM_ALLOWED_URLS {
            if allowed[j] == matched_url_hashes[0] {
                found = true;
            }
        }
        assert(found, "url not in allow-list");

        // Public-context emit, since QuoteVerified is a public unencrypted log.
        self.enqueue_self.emit_verified(self.msg_sender(), matched_url_hashes[0]);
    }

    #[external("public")]
    fn emit_verified(sender: AztecAddress, provider_url_hash: Field) {
        self.emit(QuoteVerified { sender, provider_url_hash });
    }
}
