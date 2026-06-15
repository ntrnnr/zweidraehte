//! The minimal flash interface the persistence backends depend on.

/// The slice of flash behaviour the wear-levelled / verbatim backends need,
/// kept separate from any specific HAL so the log logic is unit-testable against
/// an in-memory buffer (see `MockFlash` in the backend test modules).
///
/// Offsets are absolute from the start of flash, matching `embassy_rp` /
/// `embassy_stm32` `blocking_*` APIs. `erase` takes a `[start, end)` byte range
/// aligned to the device's sector/page size.
pub trait FlashIo {
    type Error;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
}

/// CRC-8 (poly 0x07, init 0x00) — small, table-free, enough to spot torn writes.
pub(crate) fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}
