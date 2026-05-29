use aztec::protocol::traits::{Deserialize, Packable, Serialize};

// A secp256k1 public key, stored packed in 4 Fields.
//
// BN254 Field holds 31 bytes safely, so each 32-byte coord splits across two
// Fields: 31 high bytes + 1 low byte. Pattern lifted from
// aztec-passkey-wallet's WebAuthnPublicKeyNote; we additionally derive
// Serialize/Deserialize so PublicKey can be passed as a public function arg.
#[derive(Deserialize, Eq, Serialize)]
pub struct PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Packable for PublicKey {
    // [0,1] = x  (31 high bytes, 1 low byte)
    // [2,3] = y  (31 high bytes, 1 low byte)
    let N: u32 = 4;

    fn pack(self) -> [Field; Self::N] {
        let (x_hi, x_lo) = pack_bytes32(self.x);
        let (y_hi, y_lo) = pack_bytes32(self.y);
        [x_hi, x_lo, y_hi, y_lo]
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        PublicKey {
            x: unpack_bytes32(packed[0], packed[1]),
            y: unpack_bytes32(packed[2], packed[3]),
        }
    }
}

fn pack_bytes32(bytes: [u8; 32]) -> (Field, Field) {
    let mut high: Field = 0;
    let mut mul: Field = 1;
    for i in 1..32 {
        high = high + ((bytes[31 - i] as Field) * mul);
        mul *= 256;
    }
    (high, bytes[31] as Field)
}

fn unpack_bytes32(high: Field, low: Field) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let part: [u8; 32] = high.to_be_bytes();
    for i in 0..31 {
        bytes[i] = part[i + 1];
    }
    bytes[31] = low.to_be_bytes::<32>()[31];
    bytes
}
