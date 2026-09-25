/// Build the 41-byte `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX` ETS
/// label code from a 6-byte serial and a 16-byte FDSK.
///
/// Construction (matches what ETS accepts; the spec leaves the label
/// format unspecified):
///
/// 1. Concatenate `[serial(6) || fdsk(16) || 0x00]` → 23 bytes.
/// 2. CRC-4 over the first 22 bytes; high nibble of byte 22.
/// 3. Base32-encode the first 180 bits (36 symbols).
/// 4. Insert `-` after every 6 chars.
pub fn fdsk_string(serial: &[u8; 6], fdsk: &[u8; 16]) -> [u8; 41] {
    let mut buf = [0u8; 23];
    buf[0..6].copy_from_slice(serial);
    buf[6..22].copy_from_slice(fdsk);
    let crc = fdsk_crc4(&buf[..22]);
    buf[22] = (crc << 4) & 0xF0;

    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut encoded = [0u8; 36];
    for (i, out) in encoded.iter_mut().enumerate() {
        let bit_pos = i * 5;
        let byte = bit_pos / 8;
        let shift = bit_pos & 7;
        let first = (buf[byte] as u16) << 8;
        let second = if byte + 1 < buf.len() { buf[byte + 1] as u16 } else { 0 };
        let combined = first | second;
        let idx = ((combined >> (11 - shift)) & 0x1F) as usize;
        *out = ALPHABET[idx];
    }

    let mut out = [0u8; 41];
    let mut dst = 0;

    for (i, &c) in encoded.iter().enumerate() {
        if i != 0 && i % 6 == 0 {
            out[dst] = b'-';
            dst += 1;
        }
        out[dst] = c;
        dst += 1;
    }

    debug_assert!(dst == 41);
    out
}

// ================================================================================
// CRC-4 (generator polynomial x⁴+x+1), nibble-wise
// ================================================================================

const FDSK_CRC4_TAB: [u8; 16] = [0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0xb, 0x8, 0xd, 0xe, 0x7, 0x4, 0x1, 0x2];

/// CRC-4 over a byte slice, high nibble first then low. Used to compute the
/// check nibble in the FDSK ETS label string.
pub fn fdsk_crc4(bytes: &[u8]) -> u8 {
    let mut c: u8 = 0;

    for &b in bytes {
        // High nibble first, then low — order matters; the swap
        // produces a different (wrong) CRC.
        c = FDSK_CRC4_TAB[(c ^ (b >> 4)) as usize];
        c = FDSK_CRC4_TAB[(c ^ (b & 0x0F)) as usize];
    }

    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdsk_string_known_vectors() {
        let cases: [([u8; 6], [u8; 16], &[u8; 41]); 2] = [
            (
                [0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF],
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                b"AD5N5L-N654AA-CAQDAQ-CQMBYI-BEFAWD-ANBYHX",
            ),
            (
                [0x00, 0xFA, 0x01, 0x02, 0x03, 0x04],
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
                b"AD5ACA-QDAQAA-CAQDAQ-CQMBYI-BEFAWD-ANBYHV",
            ),
        ];
        for (serial, fdsk, expected) in cases {
            assert_eq!(&fdsk_string(&serial, &fdsk), expected);
        }
    }
}
