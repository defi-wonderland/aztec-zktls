use aztec::protocol::{address::AztecAddress, traits::{Deserialize, Serialize}};

/// Sub-struct passed to `quote_option` for the Core note fields the proposer
/// pins at quote time.
#[derive(Deserialize, Serialize)]
pub struct CoreTerms {
    pub deadline: u64,
    pub base_token: AztecAddress,
    pub base_amount: u128,
    pub quote_token: AztecAddress,
    pub quote_amount: u128,
}

/// Sub-struct passed to `quote_option` for the Quote note fields.
#[derive(Deserialize, Serialize)]
pub struct QuoteTerms {
    pub premium_amount: u128,
    pub strike: u64,
    pub is_call: bool,
    pub is_american: bool,
    pub pinned_query_prefix_hash: Field,
}
