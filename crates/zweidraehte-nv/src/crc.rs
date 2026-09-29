//! CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), table-free.
//!
//! The log checks every record and bank header with it. A table would cost
//! 512 bytes of flash for a checksum that runs once per append and once per
//! record at boot, so the bitwise form is the better trade on small parts.
//! Kept here rather than borrowed from `zweidraehte-proto` so this crate stays
//! a leaf dependency.

/// CRC over a contiguous slice.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc = Crc16::new();
    crc.update(data);
    crc.finish()
}

/// Incremental CRC, for a section image checked chunk by chunk rather than
/// staged whole in RAM.
#[derive(Clone, Copy)]
pub(crate) struct Crc16(u16);

impl Crc16 {
    pub(crate) const fn new() -> Self {
        Self(0xFFFF)
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.0 ^= u16::from(byte) << 8;
            for _ in 0..8 {
                self.0 = if self.0 & 0x8000 != 0 { (self.0 << 1) ^ 0x1021 } else { self.0 << 1 };
            }
        }
    }

    pub(crate) const fn finish(self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_ccitt_false_check_value() {
        // The standard check input for every CRC catalogue entry.
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let mut crc = Crc16::new();
        crc.update(b"1234");
        crc.update(b"56789");
        assert_eq!(crc.finish(), 0x29B1);
    }
}
