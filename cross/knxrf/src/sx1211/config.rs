//! SX1211 power-on register image and PLL frequency table.

/// Power-on default register image. [`super::Sx1211::init`] writes registers
/// `1..=0x1E` from this table (register 0 is written separately first), then
/// reads each back to confirm SPI integrity.
pub const DEFAULT_CONFIG: [u8; 32] = [
    0x12, 0xA0, 0x06, 0x06, 0x0C, 0xC1, 0x59, 0x3D,
    0x3D, 0x59, 0x3D, 0x3D, 0x20, 0xF9, 0x19, 0x00,
    0x75, 0x38, 0x70, 0x07, 0x00, 0x00, 0x54, 0x76,
    0x96, 0x00, 0x40, 0x1C, 0x00, 0x00, 0x40, 0x00,
];

/// PLL R/F/G divider triplets for the four KNX-RF carriers, three bytes per
/// channel.
///
/// Note: these dividers are tied to a particular SX1211 reference-crystal
/// frequency. A board with a different crystal needs recomputed values for the
/// 868.300 MHz centre frequency.
pub const RPS_PARAM: [u8; 12] = [
    0x59, 0x3D, 0x3D, // 868.300 MHz
    0x7F, 0x65, 0x4A, // 868.950 MHz
    0xA6, 0x85, 0x27, // 869.850 MHz
    0x9E, 0x7F, 0x01, // 869.525 MHz
];
