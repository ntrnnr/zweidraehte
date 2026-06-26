pub fn crc16_ccitt(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0x1d0f;

    for b in buf {
        crc = crc >> 8 | (crc & 0xff) << 8;
        crc ^= *b as u16;
        crc ^= (crc >> 4) & 0xF;
        crc ^= crc << 12;
        crc ^= (crc & 0xff) << 5;
        crc &= 0xffff;
    }

    crc
}

// ================================================================================
// CRC-32 (IEEE 802.3, reflected, init=0xFFFFFFFF, xorout=0xFFFFFFFF)
// ================================================================================

const CRC32_TABLE: [u32; 256] = build_crc32_table();

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let poly: u32 = 0xEDB8_8320;
    let mut i = 0;

    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;

        while j < 8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            j += 1;
        }

        table[i] = c;
        i += 1;
    }

    table
}

/// Reflected CRC-32 / IEEE 802.3 — same polynomial as zlib / Ethernet.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;

    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }

    c ^ 0xFFFF_FFFF
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
    use super::crc32;

    /// Sanity check: the published reflected CRC-32 of the ASCII string
    /// "123456789" is 0xCBF43926. If this drifts we have broken either the
    /// table generator or the update step.
    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}