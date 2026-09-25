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
