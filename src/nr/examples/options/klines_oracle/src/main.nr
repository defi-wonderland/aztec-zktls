use aztec::macros::aztec;
pub mod types;

/// Admin-managed verifier for Primus zkTLS klines attestations. Pins
/// (attestor pubkey, base URL) at deploy; consumers commit a per-call
/// `query_prefix` (symbol+interval). Returns a parsed `KlinesCandle`.
///
/// Uses the `attestation_verifier` lib for crypto. URL policy is local:
/// `request_url` must start with `base_url_prefix || query_prefix`. This
/// is structurally a prefix match - variable suffixes like `startTime` /
/// `endTime` are not bound. Soundness depends on the consumer pinning the
/// right query_prefix off-chain; see examples README.
#[aztec]
pub contract KlinesOracle {
    use crate::types::base_url_prefix::{BaseUrlPrefix, MAX_BASE_URL_LEN};
    use crate::types::envelope::Envelope;
    use crate::types::klines_candle::KlinesCandle;
    use crate::types::{parse_u64_decimal, parse_u64_price_8dp};
    use crate::types::public_key::PublicKey;
    use attestation_verifier::{bind_content_hashes, derive_envelope_hash, verify_ecdsa_over_hash};

    use aztec::{
        macros::{functions::{external, initializer, view}, storage::storage},
        state_vars::PublicImmutable,
    };

    // ---------------------------- Bounds ----------------------------
    /// Tight enough to fit any Binance klines request URL we'd emit.
    /// `https://api.binance.com/api/v3/klines?symbol=XXXXXXXXXX&interval=1m&startTime=NNNNNNNNNNNNN&endTime=NNNNNNNNNNNNN`
    /// ~= 128 bytes. 160 leaves headroom.
    global MAX_URL_LEN: u32 = 160;
    /// `query_prefix` example: `?symbol=ETHUSDT&interval=1m&` = 27 bytes.
    /// 96 covers longer symbols (futures pairs etc.) with margin.
    global MAX_QUERY_PREFIX_LEN: u32 = 96;
    /// Decimal price strings ("104231.50000000") fit in <32 bytes; integer ms
    /// timestamps ("1704067200000") fit too. 32 covers all six fields.
    global MAX_CONTENT_LEN: u32 = 32;
    /// Six numeric fields per candle: openTime, open, high, low, close, closeTime.
    global NUM_RESPONSE_RESOLVE: u32 = 6;

    // Per-attestation envelope-field bounds. Sized for klines responses with
    // six SHA256_EX bindings (each binding ~85 bytes inside `data`).
    global MAX_HMB_LEN: u32 = 16;
    global MAX_RR_LEN: u32 = 64;
    global MAX_DATA_LEN: u32 = 640;
    global MAX_COND_LEN: u32 = 320;
    global MAX_PARAMS_LEN: u32 = 32;

    // ---------------------------- Storage ----------------------------
    #[storage]
    struct Storage<Context> {
        /// Primus klines attestor pubkey. Any signature accepted by the
        /// oracle must be from this attestor.
        attestor: PublicImmutable<PublicKey, Context>,
        /// `https://api.binance.com/api/v3/klines` (or equivalent). The
        /// oracle's identity pin - what endpoint family it speaks for.
        base_url_prefix: PublicImmutable<BaseUrlPrefix, Context>,
    }

    /// @dev Initialize the contract.
    /// @param initial_attestor The Primus klines attestor public key (secp256k1).
    /// @param initial_base_url_prefix The Binance klines base URL prefix.
    #[external("public")]
    #[initializer]
    fn constructor(initial_attestor: PublicKey, initial_base_url_prefix: BaseUrlPrefix) {
        self.storage.attestor.initialize(initial_attestor);
        self.storage.base_url_prefix.initialize(initial_base_url_prefix);
    }

    /// Verify a Primus zkTLS klines attestation and return the parsed candle.
    /// Crypto via `attestation_verifier` lib; URL prefix-match + content parse
    /// are contract-local. Symbol/interval/timing semantics are the consumer's
    /// job - this oracle just returns the bound data.
    #[external("private")]
    fn verify_klines_attestation(
        signature: [u8; 64],
        envelope: Envelope<MAX_URL_LEN, MAX_HMB_LEN, NUM_RESPONSE_RESOLVE, MAX_RR_LEN, MAX_DATA_LEN, MAX_COND_LEN, MAX_PARAMS_LEN>,
        contents: [BoundedVec<u8, MAX_CONTENT_LEN>; NUM_RESPONSE_RESOLVE],
        data_hash_offsets: [u32; NUM_RESPONSE_RESOLVE],
        query_prefix: BoundedVec<u8, MAX_QUERY_PREFIX_LEN>,
    ) -> pub KlinesCandle {
        let attestor: PublicKey = self.storage.attestor.read();
        let base_prefix: BaseUrlPrefix = self.storage.base_url_prefix.read();

        // Canonical lib composition: derive -> ECDSA -> bind.
        let derived_hash = derive_envelope_hash(
            envelope.recipient,
            [envelope.request_url],
            envelope.request_hmb,
            envelope.response_resolves,
            envelope.data,
            envelope.att_conditions,
            envelope.timestamp,
            envelope.addition_params,
        );
        verify_ecdsa_over_hash(attestor.x, attestor.y, signature, derived_hash);
        bind_content_hashes(contents, envelope.data, data_hash_offsets);

        // URL prefix policy (contract-local): request_url must start with
        // `base_prefix || query_prefix`. Variable suffixes (startTime,
        // endTime) are deliberately unbound - consumers pin query_prefix
        // off-chain.
        assert_url_prefix(envelope.request_url, base_prefix, query_prefix);

        // Bound fields in order:
        //   contents[0] = openTime (ms), [1..5] = open/high/low/close (8dp), [5] = closeTime (ms).
        let open_time = parse_u64_decimal(contents[0]);
        let open_price = parse_u64_price_8dp(contents[1]);
        let high_price = parse_u64_price_8dp(contents[2]);
        let low_price = parse_u64_price_8dp(contents[3]);
        let close_price = parse_u64_price_8dp(contents[4]);
        let close_time = parse_u64_decimal(contents[5]);

        KlinesCandle { open_time, open_price, high_price, low_price, close_price, close_time }
    }

    #[external("private")]
    #[view]
    fn get_attestor() -> pub PublicKey {
        self.storage.attestor.read()
    }

    #[external("private")]
    #[view]
    fn get_base_url_prefix() -> pub BaseUrlPrefix {
        self.storage.base_url_prefix.read()
    }

    /// `request_url[0..base.len + query.len]` byte-equal `base || query`.
    /// Bytes past that boundary (variable suffixes) are NOT constrained.
    #[contract_library_method]
    fn assert_url_prefix(
        request_url: BoundedVec<u8, MAX_URL_LEN>,
        base: BaseUrlPrefix,
        query: BoundedVec<u8, MAX_QUERY_PREFIX_LEN>,
    ) {
        let base_len = base.len;
        let query_len = query.len();
        assert(base_len + query_len <= request_url.len(), "url shorter than base+query prefix");

        for j in 0..MAX_BASE_URL_LEN {
            if j < base_len {
                assert_eq(request_url.storage()[j], base.bytes[j], "base prefix mismatch");
            }
        }
        for j in 0..MAX_QUERY_PREFIX_LEN {
            if j < query_len {
                assert_eq(
                    request_url.storage()[base_len + j],
                    query.storage()[j],
                    "query prefix mismatch",
                );
            }
        }
    }
}
