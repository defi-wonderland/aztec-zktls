mod types;

use aztec::macros::aztec;

/**
 * Quote verifier - verifies Primus zkTLS attestations of a single price field
 * from a supported exchange ticker endpoint (Binance, OKX, Coinbase) and
 * records the normalized price into on-chain storage.
 *
 * Trust model: signatures are accepted only from the single attestor pubkey
 * pinned at deploy. The set of allowed (request_url, response_resolve) PAIRS
 * is also pinned at deploy as a map keyed by
 * `poseidon2_hash([url_hash, rr_hash])` where each inner hash is over the
 * field's bytes zero-padded to its bound. Different URL or parsePath bytes
 * yield a different pair-hash, so any (URL, parsePath) not in the map gets
 * rejected on map read.
 *
 * Storage shape: every verified attestation creates an immutable entry in
 * `historical_quotes`, keyed by the attestor-signed `envelope.timestamp`.
 * Entries are readable from both public and private context with no delay.
 * There is intentionally no "latest" view - consumers wanting the most
 * recent quote should track timestamps off-chain (indexer / event log) and
 * query the specific historical slot. This avoids the staleness/privacy
 * trade-off a DelayedPublicMutable-based latest view would force.
 *
 * Both URL allow-list and attestor pubkey are immutable; redeploy to change.
 */
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

    /// Emitted by `record_quote` whenever a new historical_quotes slot is
    /// initialized. Off-chain indexers can subscribe to this to track "the
    /// latest known quote" without an on-chain `latest_quote` slot.
    /// Re-submissions of an already-recorded `timestamp` do NOT re-emit
    /// (record_quote returns early via the `is_initialized()` guard).
    #[event]
    struct QuoteRecorded {
        price: u128,
        timestamp: u64,
    }

    // Ticker URLs across Binance/OKX/Coinbase fit in 96 bytes after the query string.
    global MAX_URL_LEN: u32 = 96;
    // Crypto price strings ("104231.50000000" = 15 bytes). 32 covers fiat + headroom.
    global MAX_PLAINTEXT_LEN: u32 = 32;
    // One field per quote: the price. The (provider, symbol) pair is committed
    // via the (URL, response_resolve) pair-hash allow-list: each slot binds
    // both the full symbol-bearing URL AND its canonical parsePath bytes.
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

    // Canonical decimal precision for stored prices (matches Binance native).
    global PRICE_DECIMALS: u32 = 8;

    #[storage]
    struct Storage<Context> {
        // Allow-list of permitted (request_url, response_resolve) PAIRS,
        // keyed by `poseidon2_hash([url_hash, rr_hash])` where each inner
        // hash is over the field's bytes zero-padded to its MAX_*_LEN. A key
        // present in the map (initialized to `true`) means that exact
        // (URL, parsePath) pair is accepted. Binding both prevents a
        // submitter from requesting a different parsePath against an
        // allow-listed URL and having it recorded as the canonical price.
        // Lookups from private context revert with "Trying to read from
        // uninitialized PublicImmutable" if the pair isn't in the map.
        allowed_attestation_hashes: Map<Field, PublicImmutable<bool, Context>, Context>,
        // The single attestor whose signatures we accept. Stored as a packed PublicKey (4 Fields).
        allowed_attestor: PublicImmutable<PublicKey, Context>,
        // Per-attestation historical record, keyed by envelope.timestamp.
        // Each slot is initialized once and is immediately readable from
        // both public and private context (PublicImmutable has no delay).
        // Duplicate-timestamp submissions are silently skipped via the
        // is_initialized() guard in record_quote.
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

    /// Verify a hash-based Primus attestation of a single price field and
    /// record the normalized price.
    ///
    /// Cryptographic checks (envelope hash reconstruction, ECDSA signature,
    /// SHA256 content binding) compose the three `attestation_verifier`
    /// primitives in canonical order. Allow-list check is this contract's
    /// policy: hash the (request_url, response_resolve) pair from the
    /// verified envelope and require its pair-hash to be in storage. Binding
    /// the response_resolve alongside the URL prevents a submitter from
    /// requesting a different parsePath against an allow-listed URL.
    ///
    /// On success, enqueues a public call to `record_quote` which initializes
    /// the `historical_quotes` slot keyed by `envelope.timestamp`.
    #[external("private")]
    fn verify(
        signature: [u8; 64],
        envelope: Envelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
    ) {
        // Read trusted attestor pubkey from storage.
        let attestor: PublicKey = self.storage.allowed_attestor.read();

        // Cryptographic checks (all in-circuit), in the canonical order:
        //   1. Reconstruct keccak256(envelope) from the witnessed fields.
        //   2. ECDSA-verify the signature against the *derived* hash (binds
        //      envelope fields to what the attestor actually signed).
        //   3. Bind each content's SHA256 hex into the now-signature-bound
        //      `data` string.
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

        // Compute the (url, response_resolve) pair-hash that identifies this
        // attestation in the allow-list. Zero-pad explicitly to each bound
        // because BoundedVec's storage() can contain unconstrained bytes
        // beyond len(); the off-chain hasher uses the same zero-padding.
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

        // Allow-list check: read() panics with "Trying to read from
        // uninitialized PublicImmutable" if the pair isn't in the map.
        let _allowed: bool = self.storage.allowed_attestation_hashes.at(attestation_hash).read();

        // Parse the signature-bound price string into a u128 fixed-point with
        // PRICE_DECIMALS precision.
        let price = parse_decimal_price(contents[0]);

        // Write the quote to public storage via enqueued public call.
        // historical_quotes[envelope.timestamp] gets initialized to
        // Quote { price, timestamp }; duplicate timestamps are skipped.
        self.enqueue_self.record_quote(price, envelope.timestamp);
    }

    /// Record a verified quote into public storage. Only callable by `verify`
    /// (via `enqueue_self`); the `only_self` guard prevents anyone from
    /// stamping unverified quotes through this entry point.
    ///
    /// Writes `historical_quotes[timestamp].initialize(...)` only if that
    /// timestamp slot was never written before, and in that case also emits
    /// a `QuoteRecorded` event. Duplicate timestamps from replayed witnesses
    /// are silently skipped (no storage write, no event).
    #[external("public")]
    #[only_self]
    fn record_quote(price: u128, timestamp: u64) {
        let slot = self.storage.historical_quotes.at(timestamp as Field);
        if !slot.is_initialized() {
            slot.initialize(Quote { price, timestamp });
            self.emit(QuoteRecorded { price, timestamp });
        }
    }

    /// Returns the historical quote at `timestamp`. Reverts if no quote was
    /// recorded at that timestamp. Works from both public and private context.
    #[external("public")]
    #[view]
    fn get_quote_at(timestamp: u64) -> pub Quote {
        self.storage.historical_quotes.at(timestamp as Field).read()
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Parse a decimal-string price (e.g., "104231.50000000") into a u128
    /// mantissa scaled to `PRICE_DECIMALS` precision. Reverts on:
    ///   - non-digit / non-dot bytes,
    ///   - more than one decimal point,
    ///   - more fractional digits than `PRICE_DECIMALS` (would lose precision).
    ///
    /// The input is the signature-bound `contents[i]` from `verify_attestation`;
    /// trailing bytes beyond `bytes.len()` are not read.
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
                    // '.'
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
        // Reject malformed inputs like "." or empty content that would otherwise
        // pass through with value = 0.
        assert(digits_seen > 0, "price must contain at least one digit");
        assert(decimals_seen <= PRICE_DECIMALS, "price has more decimals than PRICE_DECIMALS");
        let scale_up = PRICE_DECIMALS - decimals_seen;
        // Loop up to PRICE_DECIMALS (compile-time bound); multiply only the first
        // `scale_up` iterations. Noir requires statically-known loop bounds.
        let mut multiplier: u128 = 1;
        for i in 0..PRICE_DECIMALS {
            if i < scale_up {
                multiplier *= 10;
            }
        }
        value * multiplier
    }
}
