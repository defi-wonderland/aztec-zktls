use aztec::{
    macros::notes::note,
    protocol::{address::AztecAddress, traits::{FromField, Packable, Serialize, ToField}},
};

/// Per-option full state. Written once at `offer` time; read at every
/// subsequent function (subscribe, exercise, cancel, reclaim).
///
/// Base/quote naming convention: base = underlying asset (e.g. ETH);
/// quote = cash currency (e.g. USDC). The "locked" side flips with `is_call`.
/// Premium is always paid in `quote_token`.
///
/// `pinned_query_prefix_hash` is the Poseidon2 hash of the URL query prefix
/// (e.g. "?symbol=ETHUSDT&interval=1m&") committed at offer time. At exercise
/// the buyer supplies the prefix bytes; we hash them and check against this
/// pin, so the buyer can't swap symbols or intervals after the option is active.
///
/// Custom `Packable` impl: this struct has 12 logical fields but packs into
/// 8 BN254 Fields (Aztec's note cap). 5 of those are Field-sized values
/// (4 AztecAddress + 1 hash). The remaining 3 are bit-packed: each holds a
/// u128 in the low 128 bits and a u64 or 2 bools in the upper bits.
#[derive(Eq, Serialize)]
#[note]
pub struct EscrowOptionNote {
    pub buyer: AztecAddress,
    pub seller: AztecAddress,
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

/// 2^128 as a Field constant (1 followed by 32 hex zeros). Used to lift a
/// u64/bool into the upper 128 bits of a Field when packing alongside a u128.
global TWO_POW_128: Field = 0x100000000000000000000000000000000;
/// 2^129 = 2 * 2^128. Used for the second bool slot (bit 129).
global TWO_POW_129: Field = 0x200000000000000000000000000000000;

impl Packable for EscrowOptionNote {
    let N: u32 = 8;

    fn pack(self) -> [Field; Self::N] {
        let mut packed: [Field; 8] = [0; 8];
        // 4 addresses + 1 hash = 5 Field-sized values, one per slot.
        packed[0] = self.buyer.to_field();
        packed[1] = self.seller.to_field();
        packed[2] = self.base_token.to_field();
        packed[3] = self.quote_token.to_field();
        packed[4] = self.pinned_query_prefix_hash;
        // Slot 5: u128 (lower 128 bits) + u64 (bits 128..191). Max bits used: 192.
        packed[5] = (self.premium_amount as Field) + (self.deadline as Field) * TWO_POW_128;
        packed[6] = (self.base_amount as Field) + (self.strike as Field) * TWO_POW_128;
        // Slot 7: u128 (lower 128 bits) + 2 bools (bits 128, 129). Max bits used: 130.
        let is_call_f: Field = if self.is_call { 1 } else { 0 };
        let is_american_f: Field = if self.is_american { 1 } else { 0 };
        packed[7] =
            (self.quote_amount as Field) + is_call_f * TWO_POW_128 + is_american_f * TWO_POW_129;
        packed
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        // Field-sized slots: trivial.
        let buyer = AztecAddress::from_field(packed[0]);
        let seller = AztecAddress::from_field(packed[1]);
        let base_token = AztecAddress::from_field(packed[2]);
        let quote_token = AztecAddress::from_field(packed[3]);
        let pinned_query_prefix_hash = packed[4];

        // Bit-packed slots: extract via 32-byte BE representation.
        //   bytes[16..32] = lower 128 bits (the u128)
        //   bytes[8..16]  = bits 128..191  (the u64)
        //   bytes[15] bit 0,1 = bits 128, 129 (the bools for slot 7)
        let (premium_amount, deadline) = unpack_u128_and_u64(packed[5]);
        let (base_amount, strike) = unpack_u128_and_u64(packed[6]);

        let bytes_7: [u8; 32] = packed[7].to_be_bytes();
        let mut quote_amount: u128 = 0;
        for i in 0..16 {
            quote_amount = quote_amount * 256 + bytes_7[16 + i] as u128;
        }
        let is_call = (bytes_7[15] & 0x01) != 0;
        let is_american = (bytes_7[15] & 0x02) != 0;

        Self {
            buyer,
            seller,
            deadline,
            base_token,
            base_amount,
            quote_token,
            quote_amount,
            premium_amount,
            strike,
            is_call,
            is_american,
            pinned_query_prefix_hash,
        }
    }
}

/// Extract a (u128, u64) pair from a Field packed as `u128 + (u64 << 128)`.
/// Lives in this module rather than as an impl method so it can be shared
/// between the two packed slots without re-deriving.
fn unpack_u128_and_u64(packed: Field) -> (u128, u64) {
    let bytes: [u8; 32] = packed.to_be_bytes();
    let mut lo: u128 = 0;
    for i in 0..16 {
        lo = lo * 256 + bytes[16 + i] as u128;
    }
    let mut hi: u64 = 0;
    for i in 0..8 {
        hi = hi * 256 + bytes[8 + i] as u64;
    }
    (lo, hi)
}
