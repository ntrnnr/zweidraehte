#![no_std]
//! KNX-RF physical layer for the Semtech SX1211 transceiver.
//!
//! This crate is split into two halves:
//!
//! - A **pure codec** ([`manchester`], [`crc`], [`frame`]) that turns the raw
//!   bytes shuffled through the SX1211 FIFO into a decoded KNX-RF data-link
//!   frame and back. It has no hardware or `embassy` dependency and is
//!   exercised by host round-trip property tests.
//! - A **chip driver** ([`sx1211`]) generic over the `embedded-hal` `SpiBus`
//!   and two `OutputPin` chip-selects. It owns register/FIFO access, mode
//!   control and the receive-arming sequence, but does *not* do any `async`
//!   waiting — that lives in the firmware binary that drives the IRQ lines.
//!
//! # Why software Manchester + software block CRC
//!
//! KNX-RF inserts a CRC-16 after every block (the first block is 10 bytes,
//! every following block 16), which the SX1211's single-trailing-CRC packet
//! engine cannot produce. We therefore run the chip in *buffered* mode and do
//! Manchester coding and the block CRC in software. See [`crc`] for the block
//! layout.

pub mod crc;
pub mod frame;
pub mod manchester;
pub mod sx1211;
