use aztec::{macros::notes::note, protocol::traits::{Packable, Serialize}};

/// Per-option pricing + feed-pin terms.
///
/// `pinned_query_prefix_hash` is the Poseidon2 hash of the URL query prefix
/// (e.g. "?symbol=ETHUSDT&interval=1m&") committed at quote time. At exercise
/// the buyer supplies the prefix bytes; we hash them and check against this
/// pin, so a buyer can't swap symbols or intervals after the option is active.
#[derive(Eq, Packable, Serialize)]
#[note]
pub struct EscrowQuoteNote {
    pub premium_amount: u128,
    pub strike: u64,
    pub is_call: bool,
    pub is_american: bool,
    pub pinned_query_prefix_hash: Field,
}
