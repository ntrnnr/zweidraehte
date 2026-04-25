//! Infineon FM25L16B 16 kbit SPI FRAM driver (blocking).
//!
//! 2 KiB byte-addressable FRAM, no write cycle time, unlimited
//! endurance. Used to persist KNX Data Secure sequence numbers across
//! power cycles so replay protection survives reboots (see
//! [`FramSeqStorage`](super::fram_seq::FramSeqStorage)).
//!
//! The driver is deliberately minimal: WREN / READ / WRITE only. The
//! chip's protection registers (BP0/BP1/WPEN) default to "no
//! protection" on power-up and we never touch WRSR, which means the
//! `~WP` pin is irrelevant to data writes and can be tied high in
//! hardware or driven high by a GPIO held for the lifetime of the
//! firmware.
//!
//! # Wire protocol (datasheet §6)
//!
//! Each transaction is framed by `~CS`:
//!
//! ```text
//! WREN : [0x06]
//! READ : [0x03, addr_hi, addr_lo, <data out>...]
//! WRITE: [0x02, addr_hi, addr_lo, <data in>...]
//! ```
//!
//! The chip uses a 16-bit address field of which the upper 5 bits are
//! ignored (the FRAM is 2 KiB = 11-bit address space). The driver
//! range-checks every access against [`CAPACITY`] and returns
//! [`FramError::AddressOutOfRange`] for overflows — catching
//! off-by-one bugs at the driver boundary rather than silently
//! wrapping around in hardware.
//!
//! WRITE is auto-incrementing and rolls over at the top of the array;
//! we could exploit that to chain arbitrary-length writes in a single
//! CS cycle. Every WRITE must be preceded by a WREN in its **own**
//! CS-framed transaction — the chip latches WEL on the WREN's rising
//! CS edge and clears WEL on the WRITE's rising CS edge.
//!
//! SPI mode 0 (CPOL=0, CPHA=0). Max clock 20 MHz; 4 MHz gives plenty
//! of margin and keeps the blocking-SPI cost of a ~20-byte write at
//! well under 100 µs.

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

/// Usable FRAM capacity in bytes (2 KiB = 11-bit address space).
pub const CAPACITY: u16 = 2048;

// ============================================================================
// Opcodes (datasheet Table 4)
// ============================================================================

const OP_WREN: u8 = 0x06;
// WRDI / RDSR / WRSR are intentionally unused — see module docs.
const OP_READ: u8 = 0x03;
const OP_WRITE: u8 = 0x02;

// ============================================================================
// Error type
// ============================================================================

/// Errors surfaced by the FRAM driver.
///
/// Parameterised over the underlying bus error `E` so the driver stays
/// generic over `SpiBus` implementations without committing to a
/// specific HAL's error type.
#[derive(Debug)]
pub enum FramError<E> {
    /// The requested address range `[addr, addr + len)` extends past
    /// [`CAPACITY`]. The hardware would silently wrap — we fail loud
    /// instead so caller bugs show up immediately.
    AddressOutOfRange { addr: u16, len: usize },
    /// SPI bus transfer failed.
    Spi(E),
    /// Chip-select GPIO failed to toggle. Only reported on HALs where
    /// `OutputPin::set_high`/`set_low` can fail (most can't).
    Cs,
}

impl<E> defmt::Format for FramError<E>
where
    E: defmt::Format,
{
    fn format(&self, f: defmt::Formatter) {
        match self {
            FramError::AddressOutOfRange { addr, len } => {
                defmt::write!(f, "FramError::AddressOutOfRange {{ addr: {=u16:#x}, len: {=usize} }}", addr, len);
            }
            FramError::Spi(e) => defmt::write!(f, "FramError::Spi({})", e),
            FramError::Cs => defmt::write!(f, "FramError::Cs"),
        }
    }
}

// ============================================================================
// Driver
// ============================================================================

/// Blocking driver for the FM25L16B SPI FRAM.
///
/// Holds ownership of both the SPI bus and the chip-select pin. For
/// shared-bus scenarios, wrap the bus in `embedded-hal-bus`'s
/// `SpiDevice` machinery at the call site and adapt — this driver
/// assumes sole ownership because the firmware currently has no other
/// SPI peripheral.
pub struct Fm25l16b<BUS, CS> {
    bus: BUS,
    cs: CS,
}

impl<BUS, CS, E> Fm25l16b<BUS, CS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    /// Wrap an already-configured SPI bus and CS pin.
    ///
    /// The caller is responsible for configuring SPI mode 0 and a
    /// clock frequency ≤20 MHz. The CS pin must start high (inactive)
    /// — a standard `Output::new(pin, Level::High, …)` does the right
    /// thing.
    pub fn new(bus: BUS, cs: CS) -> Self {
        Self { bus, cs }
    }

    /// Borrow the underlying SPI bus for diagnostics.
    pub fn bus(&mut self) -> &mut BUS {
        &mut self.bus
    }

    /// Read `buf.len()` bytes starting at `addr` into `buf`.
    pub fn read(&mut self, addr: u16, buf: &mut [u8]) -> Result<(), FramError<E>> {
        self.check_range(addr, buf.len())?;

        // Datasheet §6.4: [opcode][addr_hi][addr_lo] then shift data
        // out for as long as CS stays low. `transfer_in_place` would
        // need a prefix-then-receive split we don't have; writing the
        // header and reading the payload as separate bus ops inside a
        // single CS frame works on every `SpiBus` impl.
        let header = [OP_READ, (addr >> 8) as u8, addr as u8];
        self.transaction(|bus| {
            bus.write(&header)?;
            bus.read(buf)?;
            Ok(())
        })
    }

    /// Write `data.len()` bytes starting at `addr` from `data`.
    pub fn write(&mut self, addr: u16, data: &[u8]) -> Result<(), FramError<E>> {
        self.check_range(addr, data.len())?;
        if data.is_empty() {
            return Ok(());
        }

        // Two CS-framed transactions: WREN first (the chip latches
        // WEL on the WREN's rising CS edge and clears it on the
        // WRITE's rising CS edge), then the actual WRITE.
        self.transaction(|bus| bus.write(&[OP_WREN]))?;

        let header = [OP_WRITE, (addr >> 8) as u8, addr as u8];
        self.transaction(|bus| {
            bus.write(&header)?;
            bus.write(data)?;
            Ok(())
        })
    }

    /// Run `f` with `CS` asserted, flush, then release `CS`
    /// regardless of whether `f` returned an error.
    ///
    /// Inlined into `read` and `write` rather than exposed — the
    /// driver has no third protocol op that would benefit.
    fn transaction(&mut self, f: impl FnOnce(&mut BUS) -> Result<(), E>) -> Result<(), FramError<E>> {
        self.cs.set_low().map_err(|_| FramError::Cs)?;
        let bus_result = f(&mut self.bus);
        // Flush before releasing CS so the last byte has clocked out.
        // `SpiBus::flush` uses the same error channel as the transfer,
        // so preserve the first error if both fire.
        let flush_result = self.bus.flush();
        // Always release CS, even on error. Leaving CS asserted
        // would block all subsequent transactions against the chip.
        let cs_result = self.cs.set_high();
        bus_result.map_err(FramError::Spi)?;
        flush_result.map_err(FramError::Spi)?;
        cs_result.map_err(|_| FramError::Cs)?;
        Ok(())
    }

    /// Range-check `[addr, addr + len)` against [`CAPACITY`].
    fn check_range(&self, addr: u16, len: usize) -> Result<(), FramError<E>> {
        // Compute end address as usize to avoid wraparound inside u16.
        let end = addr as usize + len;
        if end > CAPACITY as usize {
            return Err(FramError::AddressOutOfRange { addr, len });
        }
        Ok(())
    }
}
