//! CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), table-free.
//!
//! The log checks every record and bank header with it. A table would cost
//! 512 bytes of flash for a checksum that runs once per append and once per
//! record at boot, so the bitwise form is the better trade on small parts.
//! Kept here rather than borrowed from `zweidraehte-proto` so this crate stays
//! a leaf dependency.

/// CRC over a contiguous slice. Records are staged in one buffer before
/// they are programmed, so there is no need for an incremental form.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_ccitt_false_check_value() {
        // The standard check input for every CRC catalogue entry.
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }
}
