//! Semtech SX1211 sub-GHz transceiver driver, generic over the `embedded-hal`
//! `SpiBus` and two `OutputPin` chip-selects.
//!
//! The SX1211 has two chip-selects sharing one SPI bus: `NSS_CONFIG` for
//! register access and `NSS_DATA` for the FIFO. `SpiBus` carries no CS, so the
//! driver drives the appropriate pin low around each transfer (the other pin
//! must stay high). All methods are blocking and synchronous; the firmware
//! that owns the IRQ lines does the `async` waiting around them.
//!
//! # Receive flow (buffered mode)
//!
//! [`Sx1211::init`] loads the default register image, [`Sx1211::set_channel_ready`]
//! applies the KNX-RF "Ready" parameters (868.300 MHz, 32.931 kbit/s on-air),
//! and [`Sx1211::start_rx`] arms 24-bit sync detection and enters RX. The chip
//! then raises IRQ0 on sync detection and IRQ1 on FIFO threshold; the firmware
//! drains the FIFO with [`Sx1211::read_fifo`] (gated by [`Sx1211::fifo_has_data`]),
//! Manchester-decodes the bytes and verifies the block CRCs.
//!
//! # Transmit (not yet wired)
//!
//! The on-air TX path is deliberately not implemented in this first cut. The
//! frame-building half (block CRCs + Manchester encoding) is real and tested —
//! see [`crate::frame::prepare_tx_buf`]. Wiring TX will need, roughly: enter
//! `MODE_SYNTH`, wait for PLL lock, set buffered mode, prime the FIFO with the
//! preamble (18×`0x55`) and sync word, enter `MODE_TRANSMIT`, then feed the
//! prepared on-air bytes from [`crate::frame::prepare_tx_buf`] whenever IRQ0
//! signals "FIFO not full", append the postamble (`0x55, 0x40`), and return to
//! standby when IRQ1 signals Tx-done.

pub mod config;
pub mod regs;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use config::{DEFAULT_CONFIG, RPS_PARAM};
use regs::*;

/// SX1211 driver errors, generic over the underlying SPI error type `E`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Sx1211Error<E> {
    /// The SPI bus reported an error.
    Spi(E),
    /// A chip-select GPIO could not be driven.
    Cs,
    /// A register written during [`Sx1211::init`] (or the RX-arming readback)
    /// did not read back as written — almost always an SPI wiring or
    /// chip-select polarity problem.
    SpiVerify { reg: u8, expected: u8, got: u8 },
}

/// Driver for an SX1211 wired with separate `NSS_CONFIG` / `NSS_DATA`
/// chip-selects on a shared SPI bus.
pub struct Sx1211<SPI, NCFG, NDATA> {
    spi: SPI,
    nss_cfg: NCFG,
    nss_data: NDATA,
}

impl<SPI, NCFG, NDATA> Sx1211<SPI, NCFG, NDATA>
where
    SPI: SpiBus,
    NCFG: OutputPin,
    NDATA: OutputPin,
{
    /// Wrap an SPI bus and the two chip-select pins. Both pins are expected to
    /// start high (inactive).
    pub fn new(spi: SPI, nss_cfg: NCFG, nss_data: NDATA) -> Self {
        Self { spi, nss_cfg, nss_data }
    }

    /// Release the SPI bus and pins.
    pub fn release(self) -> (SPI, NCFG, NDATA) {
        (self.spi, self.nss_cfg, self.nss_data)
    }

    // ---- Low-level register / FIFO access ---------------------------------

    /// Write one config register. Address byte is `reg << 1` (R/W = 0).
    pub fn write_reg(&mut self, reg: u8, val: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.nss_cfg.set_low().map_err(|_| Sx1211Error::Cs)?;
        let res = self.spi.write(&[(reg & 0x7F) << 1, val]).map_err(Sx1211Error::Spi);
        let _ = self.spi.flush();
        let cs = self.nss_cfg.set_high().map_err(|_| Sx1211Error::Cs);
        res.and(cs)
    }

    /// Read one config register. Address byte is `(reg << 1) | 0x40` (R/W = 1)
    /// followed by a dummy byte clocked to sample the value.
    pub fn read_reg(&mut self, reg: u8) -> Result<u8, Sx1211Error<SPI::Error>> {
        let mut buf = [((reg & 0x7F) << 1) | 0x40, 0x00];
        self.nss_cfg.set_low().map_err(|_| Sx1211Error::Cs)?;
        let res = self.spi.transfer_in_place(&mut buf).map_err(Sx1211Error::Spi);
        let _ = self.spi.flush();
        let cs = self.nss_cfg.set_high().map_err(|_| Sx1211Error::Cs);
        res.and(cs)?;
        Ok(buf[1])
    }

    /// Write one byte to the FIFO over `NSS_DATA` (one CS pulse per byte, as
    /// the SX1211 requires).
    pub fn write_fifo(&mut self, byte: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.nss_data.set_low().map_err(|_| Sx1211Error::Cs)?;
        let res = self.spi.write(&[byte]).map_err(Sx1211Error::Spi);
        let _ = self.spi.flush();
        let cs = self.nss_data.set_high().map_err(|_| Sx1211Error::Cs);
        res.and(cs)
    }

    /// Write bytes from `buf` into the FIFO until it reports full or `buf` is
    /// exhausted, returning the number of bytes written.
    ///
    /// This is the transmit feed primitive: the FIFO drains on air far slower
    /// than SPI fills it, so a long frame is pushed across several calls. The
    /// caller yields between calls (after the chip has sent a byte or two) and
    /// re-invokes with the remaining slice. The per-byte `Fifofull` check keeps
    /// the FIFO from overrunning without needing exact free-space accounting.
    pub fn write_fifo_chunk(&mut self, buf: &[u8]) -> Result<usize, Sx1211Error<SPI::Error>> {
        for (i, &b) in buf.iter().enumerate() {
            if self.fifo_full()? {
                return Ok(i);
            }
            self.write_fifo(b)?;
        }
        Ok(buf.len())
    }

    /// Read one byte from the FIFO over `NSS_DATA`.
    pub fn read_fifo(&mut self) -> Result<u8, Sx1211Error<SPI::Error>> {
        let mut buf = [0x00u8];
        self.nss_data.set_low().map_err(|_| Sx1211Error::Cs)?;
        let res = self.spi.transfer_in_place(&mut buf).map_err(Sx1211Error::Spi);
        let _ = self.spi.flush();
        let cs = self.nss_data.set_high().map_err(|_| Sx1211Error::Cs);
        res.and(cs)?;
        Ok(buf[0])
    }

    // ---- Status -----------------------------------------------------------

    /// Returns `true` while the FIFO holds at least one byte (the `/Fifoempty`
    /// status bit of `REG_IRQ_PARAM0`).
    pub fn fifo_has_data(&mut self) -> Result<bool, Sx1211Error<SPI::Error>> {
        Ok(self.read_reg(REG_IRQ_PARAM0)? & FIFO_NOT_EMPTY != 0)
    }

    /// Returns `true` while the FIFO is full (the `Fifofull` status bit of
    /// `REG_IRQ_PARAM0`). The transmit feed loop uses this to pace itself.
    pub fn fifo_full(&mut self) -> Result<bool, Sx1211Error<SPI::Error>> {
        Ok(self.read_reg(REG_IRQ_PARAM0)? & FIFO_FULL != 0)
    }

    /// Read the raw RSSI register (0.5 dB/LSB).
    pub fn get_rssi(&mut self) -> Result<u8, Sx1211Error<SPI::Error>> {
        self.read_reg(REG_RSSI)
    }

    // ---- Mode / channel setup ---------------------------------------------

    /// Set the chip operating mode (one of the `MODE_*` constants) via a
    /// read-modify-write of the mode bits [7:5] of `REG_MC_PARAM`.
    pub fn set_mode(&mut self, mode: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        let prev = self.read_reg(REG_MC_PARAM)?;
        self.write_reg(REG_MC_PARAM, (prev & 0x1F) | ((mode & 0x07) << 5))
    }

    /// Select continuous / buffered / packet data mode (`DATA_MODE_*`).
    pub fn set_data_mode(&mut self, mode: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        // Bit 7 (FSK select) is always set.
        self.write_reg(REG_DATA_MODUL, (mode & 0x24) | 0x80)
    }

    /// Program one of the four KNX-RF carrier frequencies (index into
    /// [`config::RPS_PARAM`]). Writes the inactive PLL bank, then flips
    /// `RPS_SELECT` so the change is glitch-free.
    pub fn set_frequency(&mut self, channel: usize) -> Result<(), Sx1211Error<SPI::Error>> {
        let prev = self.read_reg(REG_MC_PARAM)?;
        let rps = &RPS_PARAM[channel * 3..channel * 3 + 3];
        let (r, f, g) = if prev & 1 == 0 {
            (REG_RPS_B_R, REG_RPS_B_F, REG_RPS_B_G)
        } else {
            (REG_RPS_A_R, REG_RPS_A_F, REG_RPS_A_G)
        };
        self.write_reg(r, rps[0])?;
        self.write_reg(f, rps[1])?;
        self.write_reg(g, rps[2])?;
        self.write_reg(REG_MC_PARAM, ((prev & 0x3F) | 0x40) ^ 1)
    }

    /// Set FSK frequency deviation (a `DEV_*` register value).
    pub fn set_deviation(&mut self, dev: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.write_reg(REG_FDEV, dev)
    }

    /// Set the bit rate (a `BR_*` register value).
    pub fn set_bitrate(&mut self, br: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.write_reg(REG_BITRATE, br)
    }

    /// Set the RX filter bandwidths (passive in the high nibble, active in the
    /// low nibble).
    pub fn set_rx_filter(&mut self, passive: u8, active: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.write_reg(REG_RX_PARAM0, (active & 0x0F) | (passive & 0xF0))
    }

    /// Set the TX filter bandwidth (high nibble) and output power (low nibble).
    pub fn set_tx_filter(&mut self, bandwidth: u8, power: u8) -> Result<(), Sx1211Error<SPI::Error>> {
        self.write_reg(REG_TX_PARAM, (power & 0x0E) | (bandwidth & 0xF0))
    }

    /// Apply the KNX-RF "Ready" physical-layer parameters (868.300 MHz, 58 kHz
    /// deviation, 32.931 kbit/s on-air, 184/144 kHz RX filter, 115 kHz TX
    /// filter at +10 dBm).
    pub fn set_channel_ready(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_frequency(CHANNEL_868_300)?;
        self.set_deviation(DEV_58KHZ)?;
        self.set_bitrate(BR_32_931)?;
        self.set_rx_filter(RXPBW_184KHZ, RXABW_144KHZ)?;
        self.set_tx_filter(TXBW_115KHZ, PWR_10DB)
    }

    // ---- High-level lifecycle ---------------------------------------------

    /// Load the power-on register image and verify SPI integrity.
    ///
    /// Writes register 0 first to force a known mode, then registers `1..=0x1E`
    /// from [`config::DEFAULT_CONFIG`], reading each back. Registers carrying
    /// live status (FIFO / PLL / RSSI) are excluded from the readback check
    /// because they do not read back as written. Finally programs
    /// `REG_IRQ_PARAM1` to enable the PLL-lock pin.
    pub fn init(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.write_reg(REG_MC_PARAM, DEFAULT_CONFIG[0])?;

        for reg in 1u8..=REG_LAST_CONFIG {
            let expected = DEFAULT_CONFIG[reg as usize];
            self.write_reg(reg, expected)?;
            if matches!(reg, REG_IRQ_PARAM0 | REG_IRQ_PARAM1 | REG_RSSI) {
                continue;
            }
            let got = self.read_reg(reg)?;
            if got != expected {
                return Err(Sx1211Error::SpiVerify { reg, expected, got });
            }
        }

        self.write_reg(REG_IRQ_PARAM1, IRQ_PARAM1_INIT)
    }

    /// Arm the receiver: buffered mode, 24-bit sync detection, KNX-RF sync
    /// word, IRQ0→sync / IRQ1→FIFO-threshold mapping, then enter RX mode.
    pub fn start_rx(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_data_mode(DATA_MODE_BUFFERED)?;

        // The chip needs a moment to accept the RX-ready value; read it back.
        let mut tries = 0u8;
        loop {
            self.write_reg(REG_RX_PARAM2, RX_PARAM2_RX_READY)?;
            let got = self.read_reg(REG_RX_PARAM2)?;
            if got == RX_PARAM2_RX_READY {
                break;
            }
            tries += 1;
            if tries >= 100 {
                return Err(Sx1211Error::SpiVerify { reg: REG_RX_PARAM2, expected: RX_PARAM2_RX_READY, got });
            }
        }

        self.write_reg(REG_SYNC0, SYNC_WORD[0])?;
        self.write_reg(REG_SYNC1, SYNC_WORD[1])?;
        self.write_reg(REG_SYNC2, SYNC_WORD[2])?;
        self.write_reg(REG_IRQ_PARAM0, IRQ_PARAM0_RX)?;
        self.set_mode(MODE_RECEIVE)
    }

    /// Arm the transmitter and begin sending. Switches to buffered mode, primes
    /// the FIFO with [`TX_PRIME_BYTE`] — which starts transmission immediately
    /// because `Tx_start_irq_0` (set by [`IRQ_PARAM1_INIT`] at init) keys up as
    /// soon as the FIFO is non-empty — then enters transmit mode.
    ///
    /// After this returns the chip is already transmitting the prime byte, so
    /// the caller must feed the on-air buffer (preamble first) with
    /// [`Self::write_fifo_chunk`] without delay. Tx-done is signalled on the
    /// IRQ1 pin: [`IRQ_PARAM0_RX`] already sets `Tx_irq_1` so no IRQ
    /// reprogramming is needed.
    pub fn arm_tx(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_data_mode(DATA_MODE_BUFFERED)?;
        self.write_fifo(TX_PRIME_BYTE)?;
        self.set_mode(MODE_TRANSMIT)
    }

    /// Arm the receiver for a carrier-sense (listen-before-talk) measurement:
    /// continuous mode (so the raw demodulated transitions reach the DATA pin
    /// for edge counting), the narrower CCA RX filter, the RSSI block enabled
    /// via [`RX_PARAM2_CCA`], then enter RX.
    ///
    /// The caller counts DATA-pin edges over its listen window, reads
    /// [`Self::get_rssi`], classifies the channel, then calls [`Self::stop`].
    pub fn prepare_cca(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_data_mode(DATA_MODE_CONTINUOUS)?;
        self.set_rx_filter(RXPBW_137KHZ, RXABW_115KHZ)?;

        // The chip needs a moment to accept the RX-control value; read it back.
        let mut tries = 0u8;
        loop {
            self.write_reg(REG_RX_PARAM2, RX_PARAM2_CCA)?;
            let got = self.read_reg(REG_RX_PARAM2)?;
            if got == RX_PARAM2_CCA {
                break;
            }
            tries += 1;
            if tries >= 100 {
                return Err(Sx1211Error::SpiVerify { reg: REG_RX_PARAM2, expected: RX_PARAM2_CCA, got });
            }
        }

        self.set_mode(MODE_RECEIVE)
    }

    /// Arm the receiver in **continuous** mode for the DATA+DCLK diagnostic.
    ///
    /// In continuous Rx the demodulated, bit-synchronised NRZ chips appear on
    /// the DATA pin with a recovered clock on DCLK (the IRQ1 pin, output
    /// automatically when BitSync is on), and IRQ0 carries Sync
    /// (`Rx_stby_irq_0 = 00`). This bypasses the FIFO entirely, so the firmware
    /// samples DATA on each DCLK rising edge instead of reading the FIFO.
    pub fn start_rx_continuous(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_data_mode(DATA_MODE_CONTINUOUS)?; // reg1 = 0x80 (FSK, continuous)

        let mut tries = 0u8;
        loop {
            self.write_reg(REG_RX_PARAM2, RX_PARAM2_RX_READY)?;
            let got = self.read_reg(REG_RX_PARAM2)?;
            if got == RX_PARAM2_RX_READY {
                break;
            }
            tries += 1;
            if tries >= 100 {
                return Err(Sx1211Error::SpiVerify { reg: REG_RX_PARAM2, expected: RX_PARAM2_RX_READY, got });
            }
        }

        self.write_reg(REG_SYNC0, SYNC_WORD[0])?;
        self.write_reg(REG_SYNC1, SYNC_WORD[1])?;
        self.write_reg(REG_SYNC2, SYNC_WORD[2])?;
        // IRQ0 = Sync (Rx_stby_irq_0 = 00); IRQ1 auto-drives DCLK in continuous
        // Rx with BitSync enabled. Reserved bit 3 kept set.
        self.write_reg(REG_IRQ_PARAM0, 0x08)?;
        self.set_mode(MODE_RECEIVE)
    }

    /// Enter frequency-synthesizer mode (used to let the PLL settle before RX).
    pub fn enter_synth(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_mode(MODE_SYNTH)
    }

    /// Return to standby, halting FIFO fill.
    pub fn stop(&mut self) -> Result<(), Sx1211Error<SPI::Error>> {
        self.set_mode(MODE_STANDBY)
    }
}
