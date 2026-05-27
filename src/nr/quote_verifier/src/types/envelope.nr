use aztec::protocol::traits::Serialize;

/// The signed Primus attestation payload, grouped into one struct for ergonomics.
/// Field byte layout matches `att_verifier_parsing/src/utils.ts::encodePacked`:
///   recipient(20) || keccak256(request_url || request_hmb)
///     || keccak256(response_resolves concat) || data || attConditions
///     || timestamp_be(8) || additionParams
///
/// `request_url` lives in here because it's part of the signed payload; the URL
/// allow-list check pulls it back out for the prefix match.
#[derive(Serialize)]
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
