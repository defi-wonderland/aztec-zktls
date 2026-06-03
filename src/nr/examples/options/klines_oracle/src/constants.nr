//! Per-attestation envelope-field bounds. Sized for Binance klines responses
//! with six SHA256_EX bindings (each ~85 bytes inside `data`).
//!
//! Consumers MUST instantiate the oracle's `Envelope<...>` type with these
//! same constants. Importing from this module rather than redeclaring them
//! keeps the consumer in lockstep with the oracle byte-for-byte.

/// Binance klines URL: `https://api.binance.com/api/v3/klines?symbol=...&interval=...&startTime=...&endTime=...`
/// fits in ~128 bytes. 160 leaves headroom.
pub global MAX_URL_LEN: u32 = 160;
/// Caller-pinned prefix, e.g. `?symbol=ETHUSDT&interval=1m&` (~27 bytes). 96 fits longer pairs.
pub global MAX_QUERY_PREFIX_LEN: u32 = 96;
/// Each candle field as a string: prices up to "104231.50000000" (~16 bytes);
/// ms timestamps "1704067200000" (13 bytes). 32 covers all six.
pub global MAX_CONTENT_LEN: u32 = 32;
/// Six numeric fields: openTime, open, high, low, close, closeTime.
pub global NUM_RESPONSE_RESOLVE: u32 = 6;

pub global MAX_HMB_LEN: u32 = 16;
pub global MAX_RR_LEN: u32 = 64;
pub global MAX_DATA_LEN: u32 = 640;
pub global MAX_COND_LEN: u32 = 320;
pub global MAX_PARAMS_LEN: u32 = 32;
