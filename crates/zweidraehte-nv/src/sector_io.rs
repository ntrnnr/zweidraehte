//! The minimal flash interface the persistence backends depend on.

/// The slice of flash behaviour the append log needs, kept separate from any
/// specific HAL so the log logic is unit-testable against an in-memory buffer
/// (see [`MockFlash`](crate::mock::MockFlash)).
///
/// Offsets are absolute from the start of flash, matching `embassy_rp` /
/// `embassy_stm32` `blocking_*` APIs. `erase` takes a `[start, end)` byte range
/// aligned to the device's sector/page size.
pub trait SectorIo {
    type Error;

    /// The medium's write granularity in bytes — a fact of the flash
    /// controller, not of any store: writes must land as whole
    /// `WRITE_ALIGN`-sized units (STM32G0 doubleword = 8; RP2040 and mock
    /// media are byte-granular = 1, the default). Stores pad their payloads
    /// up to it with `0xFF`, the erased value.
    const WRITE_ALIGN: usize = 1;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
}
