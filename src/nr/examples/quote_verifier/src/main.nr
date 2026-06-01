mod types;

use aztec::macros::aztec;

/**
 * Quote verifier - verifies Primus zkTLS attestations of a single price field
 * from a supported exchange ticker endpoint (Binance, OKX, Coinbase) and
 * records the normalized price into on-chain storage.
 *
 * Trust model: signatures are accepted only from the single attestor pubkey
 * pinned at deploy. The set of allowed request URLs is also pinned at deploy
 * as a map keyed by `poseidon2_hash(zero-padded URL bytes)`; the URL check is
 * exact byte equality (different URL bytes => different hash => not in map).
 *
 * Storage shape: `latest_quote` is a `DelayedPublicMutable<Quote>` (writable
 * from public via enqueued call, readable from both public and private with a
 * delay). `historical_quotes` is a `Map<Field, PublicImmutable<Quote>>` keyed
 * by the attestor-signed `envelope.timestamp`; each slot is initialized once
 * and readable from both contexts (no delay, since immutable).
 *
 * Both URL allow-list and attestor pubkey are immutable; redeploy to change.
 */
#[aztec]
pub contract QuoteVerifier {
    use crate::types::{Envelope, PublicKey, Quote};
    use attestation_verifier::verify_attestation;
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::hash::poseidon2_hash,
        state_vars::{DelayedPublicMutable, Map, PublicImmutable},
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

    // Canonical decimal precision for stored prices (matches Binance native).
    global PRICE_DECIMALS: u32 = 8;

    // DelayedPublicMutable's privacy guarantees scale with this delay. 60s is
    // the PoC floor: short enough to show fresh prices in demos, long enough
    // that *some* prover hardware can prove and include a tx in time. For prod
    // use, bump to several hours (or MAX_TX_LIFETIME = 1 day) to maximize the
    // reader privacy set. See examples README for the trade-off discussion.
    global QUOTE_DELAY: u64 = 60;

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
        // The most recent successfully-verified quote. Reads from private
        // context are subject to QUOTE_DELAY. Reads of a never-written slot
        // return the default Quote { price: 0, timestamp: 0 }.
        latest_quote: DelayedPublicMutable<Quote, QUOTE_DELAY, Context>,
        // Per-attestation historical record, keyed by envelope.timestamp.
        // Initialized once per successful verify(); reverts on duplicate
        // timestamp init via `is_initialized()` guard in `record_quote`.
        historical_quotes: Map<Field, PublicImmutable<Quote, Context>, Context>,
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

    /// Verify a hash-based Primus attestation of a single price field and
    /// record the normalized price.
    ///
    /// Cryptographic checks (envelope hash reconstruction, ECDSA signature,
    /// SHA256 content binding) run in `attestation_verifier::verify_attestation`.
    /// URL allow-list check is this contract's policy: hash the request URL
    /// from the verified envelope and require its hash to be in storage.
    ///
    /// On success, enqueues a public call to `record_quote` which writes
    /// to both `latest_quote` (scheduled change with QUOTE_DELAY) and
    /// `historical_quotes` (immutable, keyed by envelope.timestamp).
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

        // Parse the signature-bound price string into a u128 fixed-point with
        // PRICE_DECIMALS precision.
        let price = parse_decimal_price(contents[0]);

        // Write the quote to public storage via enqueued public call. Both
        // latest_quote (scheduled change) and historical_quotes (one-shot
        // immutable slot) get the same Quote value.
        self.enqueue_self.record_quote(price, envelope.timestamp);
    }

    /// Record a verified quote into public storage. Only callable by `verify`
    /// (via `enqueue_self`); the `only_self` guard prevents anyone from
    /// stamping unverified quotes through this entry point.
    ///
    /// Writes:
    ///   - `latest_quote.schedule_value_change(...)` (delayed write, takes
    ///     effect after QUOTE_DELAY for private readers).
    ///   - `historical_quotes[timestamp].initialize(...)` only if that
    ///     timestamp slot was never written before. Duplicate timestamps from
    ///     replayed witnesses are silently skipped (the latest_quote still
    ///     gets refreshed, just no new historical entry).
    #[external("public")]
    #[only_self]
    fn record_quote(price: u128, timestamp: u64) {
        let q = Quote { price, timestamp };
        self.storage.latest_quote.schedule_value_change(q);

        let slot = self.storage.historical_quotes.at(timestamp as Field);
        if !slot.is_initialized() {
            slot.initialize(q);
        }
    }

    /// Returns the current value of `latest_quote` as seen by a public reader.
    /// Private readers should use the storage-level read directly so the
    /// expiration-timestamp constraint is set correctly.
    #[external("public")]
    #[view]
    fn get_latest_quote() -> pub Quote {
        self.storage.latest_quote.get_current_value()
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
                    if seen_dot {
                        decimals_seen += 1;
                    }
                }
            }
        }
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
