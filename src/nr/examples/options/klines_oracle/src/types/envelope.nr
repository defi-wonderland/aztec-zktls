use aztec::protocol::traits::{Deserialize, Serialize};

/// Signed Primus attestation payload. Fields match the byte layout the
/// `attestation_verifier` lib's `derive_envelope_hash` expects.
#[derive(Deserialize, Serialize)]
pub struct Envelope<let MAX_URL_LEN: u32, let MAX_HMB_LEN: u32, let N: u32, let MAX_RR_LEN: u32, let MAX_DATA_LEN: u32, let MAX_COND_LEN: u32, let MAX_PARAMS_LEN: u32> {
    pub recipient: [u8; 20],
    pub request_url: BoundedVec<u8, MAX_URL_LEN>,
    pub request_hmb: BoundedVec<u8, MAX_HMB_LEN>,
    pub response_resolves: [BoundedVec<u8, MAX_RR_LEN>; N],
    pub data: BoundedVec<u8, MAX_DATA_LEN>,
    pub att_conditions: BoundedVec<u8, MAX_COND_LEN>,
    pub timestamp: u64,
    pub addition_params: BoundedVec<u8, MAX_PARAMS_LEN>,
}
