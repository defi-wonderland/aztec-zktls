use aztec::protocol::traits::{Deserialize, Serialize};

/// Parsed Binance klines candle as returned by `verify_klines_attestation`.
/// Prices are scaled to 10^8 (Binance's 8-decimal-places convention); timestamps
/// are unix epoch milliseconds. Consumers apply their own pricing semantics on
/// top - e.g. `(open_price + close_price) / 2`, or a range-midpoint, etc.
#[derive(Deserialize, Eq, Serialize)]
pub struct KlinesCandle {
    pub open_time: u64, // ms
    pub open_price: u64, // 8dp-scaled
    pub high_price: u64, // 8dp-scaled
    pub low_price: u64, // 8dp-scaled
    pub close_price: u64, // 8dp-scaled
    pub close_time: u64, // ms
}
