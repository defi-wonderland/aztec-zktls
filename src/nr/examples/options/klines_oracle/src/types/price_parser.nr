/// Parse an unsigned decimal integer (e.g. b"1704067200000") into a `u64`.
/// All bytes within `len` must be ASCII digits - no decimal point, no sign,
/// no whitespace. Used for openTime and closeTime fields in klines responses.
pub fn parse_u64_decimal<let MAX_LEN: u32>(content: BoundedVec<u8, MAX_LEN>) -> u64 {
    let mut result: u64 = 0;
    let content_len = content.len();

    for i in 0..MAX_LEN {
        if i < content_len {
            let b = content.storage()[i];
            assert((b >= 0x30) & (b <= 0x39), "non-digit byte in integer");
            let digit = (b - 0x30) as u64;
            result = result * 10 + digit;
        }
    }

    result
}

/// Parse a decimal price string (e.g. b"2281.87000000") into a `u64` scaled
/// by 10^8 - Binance's 8dp convention. Constraints:
///   - All bytes within `len` are ASCII digits OR exactly one '.'.
///   - At most 8 digits after the decimal point. Fewer is fine; we scale up.
///   - No sign or whitespace.
pub fn parse_u64_price_8dp<let MAX_LEN: u32>(content: BoundedVec<u8, MAX_LEN>) -> u64 {
    let mut result: u64 = 0;
    let mut seen_point = false;
    let mut decimals_after_point: u32 = 0;
    let content_len = content.len();

    for i in 0..MAX_LEN {
        if i < content_len {
            let b = content.storage()[i];
            if b == 0x2E {
                // '.'
                assert(!seen_point, "duplicate decimal point");
                seen_point = true;
            } else {
                assert((b >= 0x30) & (b <= 0x39), "non-digit byte in price");
                let digit = (b - 0x30) as u64;
                result = result * 10 + digit;
                if seen_point {
                    decimals_after_point += 1;
                }
            }
        }
    }

    assert(decimals_after_point <= 8, "more than 8 decimal places");
    let powers_of_10: [u64; 9] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];
    let adjustment = powers_of_10[8 - decimals_after_point];
    result * adjustment
}
