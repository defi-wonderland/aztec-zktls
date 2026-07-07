use aztec::protocol::traits::{Deserialize, Packable, Serialize};

/// A canonicalized price quote.
///
/// `price` is the spot price normalized to 8 decimal fixed-point (e.g.,
/// "1234.5" -> 123450000000). Providers return prices with varying decimals
/// (Binance: 8, Coinbase: 2, OKX: variable); the contract's in-circuit
/// parser scales them all to 8 decimals before storing.
///
/// `timestamp` is `envelope.timestamp` from the Primus-signed attestation -
/// the attestor's view of when the data was observed. Signature-bound by the
/// `verify_attestation` call, so trusted by construction.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Quote {
    pub price: u128,
    pub timestamp: u64,
}
