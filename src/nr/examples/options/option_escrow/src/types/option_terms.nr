use aztec::protocol::{address::AztecAddress, traits::{Deserialize, Serialize}};

/// Parameters the proposer pins at `offer` time. Buyer/seller addresses are
/// derived from the caller's `my_role` + counterparty, so they're not here.
#[derive(Deserialize, Serialize)]
pub struct OptionTerms {
    pub deadline: u64,
    pub base_token: AztecAddress,
    pub base_amount: u128,
    pub quote_token: AztecAddress,
    pub quote_amount: u128,
    pub premium_amount: u128,
    pub strike: u64,
    pub is_call: bool,
    pub is_american: bool,
    pub pinned_query_prefix_hash: Field,
}
