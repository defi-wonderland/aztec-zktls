use aztec::{macros::notes::note, protocol::{address::AztecAddress, traits::{Packable, Serialize}}};

/// Per-option proposal-state marker.
///
/// Written at quote time and nullified at subscribe. While this note exists,
/// the option is "pending" (waiting for the counterparty to subscribe). Once
/// nullified, the option is "active" (both sides committed, premium released).
///
/// `missing_side` is 0 (buyer needs to subscribe) or 1 (seller needs to).
/// `proposer` is who put up the initial deposit.
#[derive(Eq, Packable, Serialize)]
#[note]
pub struct EscrowProposalNote {
    pub proposer: AztecAddress,
    pub missing_side: u8,
}
