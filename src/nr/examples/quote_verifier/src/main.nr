mod types;

use aztec::macros::aztec;

/// QuoteVerifier - verifies Primus zkTLS price attestations and records the
/// normalized price into `historical_quotes`. See `src/nr/examples/README.md`
/// for the trust model and design notes.
#[aztec]
pub contract QuoteVerifier {
    use crate::types::{Envelope, PublicKey, Quote};
    use attestation_verifier::{bind_content_hashes, derive_envelope_hash, verify_ecdsa_over_hash};
    use aztec::{
        macros::{
            events::event,
            functions::{external, initializer, only_self, view},
            storage::storage,
        },
        protocol::hash::poseidon2_hash,
        state_vars::{Map, PublicImmutable},
    };

    /// Public event: emitted by `record_quote` on each new historical slot init
    /// (skipped on duplicate-timestamp re-submissions). The canonical
    /// off-chain "latest quote" signal.
    #[event]
    struct QuoteRecorded {
        price: u128,
        timestamp: u64,
    }

    global MAX_URL_LEN: u32 = 96;
    global MAX_PLAINTEXT_LEN: u32 = 32;
    global NUM_RESPONSE_RESOLVE: u32 = 1;
    global NUM_REQUEST_URLS: u32 = 1;
    global NUM_ALLOWED_URLS_AT_DEPLOY: u32 = 3;
    // Envelope-field bounds: observed lengths on real Primus ticker envelopes,
    // rounded up with headroom. See examples README for the full table.
    global MAX_HMB_LEN: u32 = 16;
    global MAX_RR_LEN: u32 = 48;
    global MAX_DATA_LEN: u32 = 128;
    global MAX_COND_LEN: u32 = 64;
    global MAX_PARAMS_LEN: u32 = 32;
    global PRICE_DECIMALS: u32 = 8;

    #[storage]
    struct Storage<Context> {
        // Allow-listed (request_url, response_resolve) pairs, keyed by
        // poseidon2_hash([url_hash, rr_hash]). Uninitialized slot read in
        // verify() reverts -> (URL, parsePath) not allowed.
        allowed_attestation_hashes: Map<Field, PublicImmutable<bool, Context>, Context>,
        allowed_attestor: PublicImmutable<PublicKey, Context>,
        // Per-attestation immutable record, keyed by envelope.timestamp.
        historical_quotes: Map<Field, PublicImmutable<Quote, Context>, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(
        allowed_attestation_hashes: [Field; NUM_ALLOWED_URLS_AT_DEPLOY],
        initial_attestor: PublicKey,
    ) {
        for i in 0..NUM_ALLOWED_URLS_AT_DEPLOY {
            self.storage.allowed_attestation_hashes.at(allowed_attestation_hashes[i]).initialize(
                true,
            );
        }
        self.storage.allowed_attestor.initialize(initial_attestor);
    }

    #[external("private")]
    fn verify(
        signature: [u8; 64],
        envelope: Envelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
    ) {
        let attestor: PublicKey = self.storage.allowed_attestor.read();

        // Canonical lib composition: derive -> ECDSA -> bind. After bind,
        // every envelope field is signature-bound.
        let envelope_hash = derive_envelope_hash(
            envelope.recipient,
            [envelope.request_url],
            envelope.request_hmb,
            envelope.response_resolves,
            envelope.data,
            envelope.att_conditions,
            envelope.timestamp,
            envelope.addition_params,
        );
        verify_ecdsa_over_hash(attestor.x, attestor.y, signature, envelope_hash);
        bind_content_hashes(contents, envelope.data, data_hash_offsets);

        // (URL, response_resolve) pair-hash allow-list lookup. Zero-pad
        // explicitly - BoundedVec.storage() bytes beyond len() are unconstrained.
        let mut url_input: [Field; MAX_URL_LEN] = [0; MAX_URL_LEN];
        for j in 0..MAX_URL_LEN {
            if j < envelope.request_url.len() {
                url_input[j] = envelope.request_url.storage()[j] as Field;
            }
        }
        let request_url_hash = poseidon2_hash(url_input);

        let mut rr_input: [Field; MAX_RR_LEN] = [0; MAX_RR_LEN];
        for j in 0..MAX_RR_LEN {
            if j < envelope.response_resolves[0].len() {
                rr_input[j] = envelope.response_resolves[0].storage()[j] as Field;
            }
        }
        let response_resolve_hash = poseidon2_hash(rr_input);

        let attestation_hash = poseidon2_hash([request_url_hash, response_resolve_hash]);
        let _allowed: bool = self.storage.allowed_attestation_hashes.at(attestation_hash).read();

        let price = parse_decimal_price(contents[0]);
        self.enqueue_self.record_quote(price, envelope.timestamp);
    }

    /// `only_self`: callable only via verify()'s enqueued path. Idempotent on
    /// duplicate timestamps (no write, no event).
    #[external("public")]
    #[only_self]
    fn record_quote(price: u128, timestamp: u64) {
        let slot = self.storage.historical_quotes.at(timestamp as Field);
        if !slot.is_initialized() {
            slot.initialize(Quote { price, timestamp });
            self.emit(QuoteRecorded { price, timestamp });
        }
    }

    #[external("public")]
    #[view]
    fn get_quote_at(timestamp: u64) -> pub Quote {
        self.storage.historical_quotes.at(timestamp as Field).read()
    }

    /// @notice Parse a decimal price string into a `u128` mantissa scaled to
    ///         `PRICE_DECIMALS`.
    /// @dev    Reverts on: empty/dot-only input, multiple decimal points,
    ///         non-digit bytes, or more than `PRICE_DECIMALS` fractional digits.
    ///         Only the first `bytes.len()` entries are read; trailing storage is
    ///         unconstrained and ignored.
    /// @param  bytes The revealed response plaintext (`contents[0]`) holding the
    ///         price as ASCII decimal digits with an optional single `.`, e.g.
    ///         `"1234.56"`.
    /// @return The price as a `u128` mantissa scaled to `PRICE_DECIMALS`
    ///         (e.g. `"1234.56"` with `PRICE_DECIMALS == 4` yields `12345600`).
    #[contract_library_method]
    fn parse_decimal_price(bytes: BoundedVec<u8, MAX_PLAINTEXT_LEN>) -> u128 {
        let mut value: u128 = 0;
        let mut decimals_seen: u32 = 0;
        let mut digits_seen: u32 = 0;
        let mut seen_dot: bool = false;
        for i in 0..MAX_PLAINTEXT_LEN {
            if i < bytes.len() {
                let b = bytes.storage()[i];
                if b == 0x2e {
                    assert(!seen_dot, "multiple decimal points in price");
                    seen_dot = true;
                } else {
                    assert((b >= 0x30) & (b <= 0x39), "non-digit byte in price");
                    value = value * 10 + ((b - 0x30) as u128);
                    digits_seen += 1;
                    if seen_dot {
                        decimals_seen += 1;
                    }
                }
            }
        }
        assert(digits_seen > 0, "price must contain at least one digit");
        assert(decimals_seen <= PRICE_DECIMALS, "price has more decimals than PRICE_DECIMALS");
        // Scale up with a compile-time-bounded loop (Noir requires static bounds).
        let scale_up = PRICE_DECIMALS - decimals_seen;
        let mut multiplier: u128 = 1;
        for i in 0..PRICE_DECIMALS {
            if i < scale_up {
                multiplier *= 10;
            }
        }
        value * multiplier
    }
}
