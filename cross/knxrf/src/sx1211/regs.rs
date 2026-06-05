//! SX1211 register numbers and the field constants we use.
//!
//! Register *numbers* are as addressed by the config SPI interface; the driver
//! turns a number `r` into the wire address byte `(r << 1)` for a write or
//! `(r << 1) | 0x40` for a read. For example, the deviation setter writes
//! wire byte `0x04`, i.e. register `2`.

// ---- Register numbers -----------------------------------------------------

/// Main config: chip mode in bits [7:5], RPS bank select in bit 0.
pub const REG_MC_PARAM: u8 = 0x00;
/// Data/modulation mode. Written as `(mode & 0x24) | 0x80`.
pub const REG_DATA_MODUL: u8 = 0x01;
/// FSK frequency deviation.
pub const REG_FDEV: u8 = 0x02;
/// Bit rate.
pub const REG_BITRATE: u8 = 0x03;
/// PLL R/F/G divider triplet, bank A.
pub const REG_RPS_A_R: u8 = 0x06;
pub const REG_RPS_A_F: u8 = 0x07;
pub const REG_RPS_A_G: u8 = 0x08;
/// PLL R/F/G divider triplet, bank B.
pub const REG_RPS_B_R: u8 = 0x09;
pub const REG_RPS_B_F: u8 = 0x0A;
pub const REG_RPS_B_G: u8 = 0x0B;
/// IRQ source mapping byte 0 (IRQ0/IRQ1 in RX/standby, FIFO status bits).
pub const REG_IRQ_PARAM0: u8 = 0x0D;
/// IRQ source mapping byte 1 (PLL-lock pin enable, Tx start/done).
pub const REG_IRQ_PARAM1: u8 = 0x0E;
/// RX filter: `(active & 0x0F) | (passive & 0xF0)`.
pub const REG_RX_PARAM0: u8 = 0x10;
/// RX control: sync-word enable / size / tolerance.
pub const REG_RX_PARAM2: u8 = 0x12;
/// RSSI value (read-only), 0.5 dB/LSB.
pub const REG_RSSI: u8 = 0x14;
/// 24-bit sync word, most-significant byte first.
pub const REG_SYNC0: u8 = 0x16;
pub const REG_SYNC1: u8 = 0x17;
pub const REG_SYNC2: u8 = 0x18;
/// TX filter / power: `(power & 0x0E) | (bandwidth & 0xF0)`.
pub const REG_TX_PARAM: u8 = 0x1A;

/// Highest register written by [`super::Sx1211::init`] (registers `1..=0x1E`).
pub const REG_LAST_CONFIG: u8 = 0x1E;

// ---- Chip modes (bits [7:5] of REG_MC_PARAM) ------------------------------

pub const MODE_SLEEP: u8 = 0x00;
pub const MODE_STANDBY: u8 = 0x01;
pub const MODE_SYNTH: u8 = 0x02;
pub const MODE_RECEIVE: u8 = 0x03;
pub const MODE_TRANSMIT: u8 = 0x04;

// ---- Data modes (argument to set_data_mode) -------------------------------

pub const DATA_MODE_CONTINUOUS: u8 = 0x00;
pub const DATA_MODE_BUFFERED: u8 = 0x20;
pub const DATA_MODE_PACKET: u8 = 0x24;

// ---- REG_IRQ_PARAM0 fields ------------------------------------------------

/// IRQ mapping written before RX (`0x0D = 0xF9`):
/// `Rx_stby_irq_0 = 11` → IRQ0 = Sync detected,
/// `Rx_stby_irq_1 = 11` → IRQ1 = Fifo_threshold; reserved bit 3 set;
/// FIFO-overrun cleared.
///
/// The firmware waits for IRQ0 (sync), then reads exactly two FIFO bytes each
/// time IRQ1 (Fifo_threshold) indicates a byte pair is ready. Reading in
/// byte-commit-synchronised pairs is
/// what keeps the Manchester stream aligned; polling `/Fifoempty` and reading
/// single bytes at arbitrary times corrupts it.
pub const IRQ_PARAM0_RX: u8 = 0xF9;
/// Read-back status bit: FIFO is full.
pub const FIFO_FULL: u8 = 0x04;
/// Read-back status bit: `/Fifoempty` — set (1) when the FIFO holds data.
pub const FIFO_NOT_EMPTY: u8 = 0x02;

// ---- REG_IRQ_PARAM1 value -------------------------------------------------

/// Enables the PLL-lock pin, clears the sticky PLL/RSSI flags and sets
/// Tx_start_irq_0 so TX begins once the FIFO is non-empty (`0x0E = 0x1B`).
pub const IRQ_PARAM1_INIT: u8 = 0x1B;

// ---- REG_RX_PARAM2 values -------------------------------------------------

/// Arm RX with 24-bit sync-word detection (`Sync_on`, `Sync_size = 10`).
pub const RX_PARAM2_RX_READY: u8 = 0x30;

// ---- 24-bit KNX-RF sync word ----------------------------------------------

/// The 24-bit pattern the SX1211 hunts for. It is the tail of the preheader as
/// defined in KNX 03/02/05 §5.1.2.1: preamble tail `010101` + Manchester
/// violation `000111` + sync word `011010010110`, which packs to
/// `0x54, 0x76, 0x96` (MSB first).
pub const SYNC_WORD: [u8; 3] = [0x54, 0x76, 0x96];

// ---- KNX-RF "Ready" channel parameters (from SetChannelReady) -------------

/// 868.300 MHz — KNX-RF F0. Index into [`super::config::RPS_PARAM`].
pub const CHANNEL_868_300: usize = 0;
/// 58 kHz FSK deviation.
pub const DEV_58KHZ: u8 = 0x07;
/// 32.931 kbit/s on-air (≈16.4 kbit/s after Manchester).
pub const BR_32_931: u8 = 0x06;
/// 184 kHz passive RX bandwidth.
pub const RXPBW_184KHZ: u8 = 0x50;
/// 144 kHz active RX bandwidth.
pub const RXABW_144KHZ: u8 = 0x04;
/// 115 kHz TX bandwidth.
pub const TXBW_115KHZ: u8 = 0x30;
/// +10 dBm output power.
pub const PWR_10DB: u8 = 0x02;

// ---- Transmit framing -----------------------------------------------------

/// Preamble byte streamed before the sync word; `0x55` is the on-air chip pair
/// `01` repeated.
pub const TX_PREAMBLE_BYTE: u8 = 0x55;
/// Number of preamble bytes sent (`0x12`).
pub const TX_PREAMBLE_LEN: usize = 18;
/// Postamble streamed after the Manchester data: a `0x55` chip pair plus the
/// `0x40` end marker. Not checked by receivers but
/// mandatory on transmit.
pub const TX_POSTAMBLE: [u8; 2] = [0x55, 0x40];
/// Byte written to the FIFO immediately before entering transmit mode. With
/// `Tx_start_irq_0` (set by [`IRQ_PARAM1_INIT`]) the chip begins transmitting
/// as soon as the FIFO is non-empty, so this byte both triggers TX and is sent
/// ahead of the preamble; receivers ignore it and lock on the following `0x55`
/// run. The FIFO is primed with `0x00` then `0x55`.
pub const TX_PRIME_BYTE: u8 = 0x00;

// ---- Listen-before-talk / carrier sense -----------------------------------

/// `REG_RX_PARAM2` value for the carrier-sense window: like
/// [`RX_PARAM2_RX_READY`] but with `Bitsync_off` set (bit 6), so the
/// demodulator's raw transitions reach the DATA pin for edge counting rather
/// than being bit-synchronised (`0x12 = 0x70`).
pub const RX_PARAM2_CCA: u8 = 0x70;
/// Passive RX filter bandwidth used during carrier sense
/// (137 kHz), one step narrower than the 184 kHz data-RX value.
pub const RXPBW_137KHZ: u8 = 0x30;
/// Active RX filter bandwidth used during carrier sense (115 kHz).
pub const RXABW_115KHZ: u8 = 0x03;
/// Raw RSSI register value at or above which the channel counts as occupied by
/// non-KNX energy. With a free level of `0x3C`, the channel is busy at
/// `>= 0x3D`.
pub const LBT_RSSI_THRESHOLD: u8 = 0x3D;
/// Lower bound (inclusive) of the DATA-edge count band that indicates a KNX
/// transmission in progress (`8`).
pub const LBT_EDGE_LOW: u32 = 8;
/// Upper bound (exclusive) of the KNX edge-count band (`0x1F`).
pub const LBT_EDGE_HIGH: u32 = 31;
