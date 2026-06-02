use aztec::protocol::traits::{Deserialize, Packable, Serialize};

/// Admin-pinned base URL prefix (e.g. `https://api.binance.com/api/v3/klines`).
/// Fixed-length byte buffer + length so it's `Packable` for `PublicImmutable`.
pub global MAX_BASE_URL_LEN: u32 = 64;

#[derive(Deserialize, Eq, Serialize)]
pub struct BaseUrlPrefix {
    pub bytes: [u8; MAX_BASE_URL_LEN],
    pub len: u32,
}

impl Packable for BaseUrlPrefix {
    // 64 bytes packed as 31+31+2 across 3 Fields, plus 1 Field for `len`.
    let N: u32 = 4;

    fn pack(self) -> [Field; Self::N] {
        let mut packed: [Field; 4] = [0; 4];
        for i in 0..31 {
            packed[0] = packed[0] * 256 + (self.bytes[i] as Field);
        }
        for i in 31..62 {
            packed[1] = packed[1] * 256 + (self.bytes[i] as Field);
        }
        for i in 62..64 {
            packed[2] = packed[2] * 256 + (self.bytes[i] as Field);
        }
        packed[3] = self.len as Field;
        packed
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        let mut bytes = [0u8; MAX_BASE_URL_LEN];
        let f0_be: [u8; 32] = packed[0].to_be_bytes();
        for i in 0..31 {
            bytes[i] = f0_be[i + 1];
        }
        let f1_be: [u8; 32] = packed[1].to_be_bytes();
        for i in 0..31 {
            bytes[31 + i] = f1_be[i + 1];
        }
        let f2_be: [u8; 32] = packed[2].to_be_bytes();
        bytes[62] = f2_be[30];
        bytes[63] = f2_be[31];
        let len_be: [u8; 32] = packed[3].to_be_bytes();
        let len = len_be[31] as u32;
        BaseUrlPrefix { bytes, len }
    }
}
