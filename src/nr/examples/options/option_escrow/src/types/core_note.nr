use aztec::{macros::notes::note, protocol::{address::AztecAddress, traits::{Packable, Serialize}}};

/// Per-option core terms.
///
/// Stored once at offer time, read at exercise and recover. Captures the
/// parties, the expiry, and the two-token movement amounts.
///
/// We use a base/quote naming convention (base = underlying asset like ETH,
/// quote = cash currency like USDC) rather than locked/settlement, because
/// the "locked" side flips with is_call. Premium is always paid in
/// quote_token; that's enforced by convention in the contract.
#[derive(Eq, Packable, Serialize)]
#[note]
pub struct EscrowCoreNote {
    pub buyer: AztecAddress,
    pub seller: AztecAddress,
    pub deadline: u64,
    pub base_token: AztecAddress,
    pub base_amount: u128,
    pub quote_token: AztecAddress,
    pub quote_amount: u128,
}
