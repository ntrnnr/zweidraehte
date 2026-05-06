//! Helper functions for schema types.

use super::com_objects::ComObjectPriority;

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert object size in bits to ETS string format
pub fn object_size_to_string(size_bits: u8) -> &'static str {
    match size_bits {
        1 => "1 Bit",
        2 => "2 Bit",
        3 => "3 Bit",
        4 => "4 Bit",
        5 => "5 Bit",
        6 => "6 Bit",
        7 => "7 Bit",
        8 => "1 Byte",
        16 => "2 Bytes",
        24 => "3 Bytes",
        32 => "4 Bytes",
        40 => "5 Bytes",
        48 => "6 Bytes",
        56 => "7 Bytes",
        64 => "8 Bytes",
        72 => "9 Bytes",
        80 => "10 Bytes",
        88 => "11 Bytes",
        96 => "12 Bytes",
        104 => "13 Bytes",
        112 => "14 Bytes",
        _ => {
            // Default to bytes calculation
            let bytes = size_bits.div_ceil(8);
            match bytes {
                1 => "1 Byte",
                2 => "2 Bytes",
                3 => "3 Bytes",
                4 => "4 Bytes",
                5 => "5 Bytes",
                6 => "6 Bytes",
                7 => "7 Bytes",
                8 => "8 Bytes",
                _ => "14 Bytes",
            }
        }
    }
}

/// Convert DPT main/sub to ETS string format
pub fn dpt_to_string(dpt_main: u16, dpt_sub: u16) -> String {
    if dpt_sub == 0 { format!("DPT-{}", dpt_main) } else { format!("DPST-{}-{}", dpt_main, dpt_sub) }
}

/// Convert priority flags to ComObjectPriority
///
/// KNX priority values (from flags bits 0-1):
/// - 0 = System (NOT supported in ETS - will panic!)
/// - 1 = High (urgent)
/// - 2 = Alert (alarm)
/// - 3 = Low (normal)
///
/// # Panics
/// Panics if System priority (0) is specified, as it cannot be set in ETS.
pub fn priority_from_flags(flags: u8) -> ComObjectPriority {
    match flags & 0x03 {
        0 => panic!("System priority (0) cannot be used in ETS. Use Low (3), High (1), or Alert (2)."),
        1 => ComObjectPriority::High,
        2 => ComObjectPriority::Alert,
        _ => ComObjectPriority::Low,
    }
}
