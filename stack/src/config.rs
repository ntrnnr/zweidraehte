//! KNX Stack Configuration
//!
//! This module provides:
//! - Constants for APDU sizes and buffer configuration
//! - Ergonomic macros to define static KNX device configurations
//!
//! # APDU Size: Compile-Time vs Runtime
//!
//! The stack uses a two-tier approach for APDU sizes:
//!
//! 1. **Compile-time allocation** ([`StackDefinition::MAX_APDU_LENGTH`]):
//!    Determines the buffer size allocated in [`StackResources`](crate::StackResources).
//!    This is the maximum APDU size that can ever be handled by the stack.
//!
//! 2. **Runtime limit** ([`StackState::max_apdu_length()`](crate::StackState::max_apdu_length)):
//!    The actual limit reported via PID 56 (MAX_APDU_LENGTH) in the Device Object.
//!    This can be dynamically adjusted based on the detected link layer (e.g., USB
//!    interface capabilities, TP1 MAC type).
//!
//! The runtime limit must always be ≤ the compile-time allocation.
//!
//! # APDU Size Constants
//!
//! The APDU (Application Protocol Data Unit) is the payload portion of a KNX message.
//! Different KNX mediums support different maximum APDU sizes:
//!
//! - **Standard TP1** (no Extended Frame Format): 15 bytes
//! - **TP1 with EFF**: up to 255 bytes
//! - **KNX/IP**: up to 255 bytes
//!
//! Note: The APDU size is just the payload. The full buffer also needs space for
//! the frame header (ctrl, addresses, npdu) and headroom for protocol encapsulation.
//! Use [`buffer_size_for_apdu()`] to calculate the required buffer size.
//!
//! The [`MaxApduLength`] enum provides common configurations.
//!
//! # Buffer Size Calculation
//!
//! Use [`buffer_size_for_apdu`] to calculate the required buffer size
//! for a given maximum APDU length. The buffer must accommodate:
//! - Control byte (1)
//! - Source address (2)
//! - Destination address (2)
//! - NPDU/hop count (1)
//! - APDU (variable)
//! - Headroom for protocol headers (16 bytes)
//!
//! # Configuration Macros
//!
//! Provides ergonomic macros to define static KNX device configurations including:
//! - Group address table (GAT/ADT7)
//! - Association table (ASSO6)
//! - Communication object table (CO7)
//!
//! ## Example
//!
//! ```ignore
//! use zweidraehte::config::knx_stack_config;
//!
//! knx_stack_config! {
//!     name: LightingController,
//!     individual_address: "1.1.5",
//!
//!     group_addresses: {
//!         1 => "1/0/1",
//!         2 => "1/0/2",
//!     },
//!
//!     comm_objects: {
//!         1 => (1, CE | TE | WE),
//!         2 => (2, CE | RE | UE),
//!     },
//!
//!     associations: {
//!         1 => [1, 2],
//!         2 => [1],
//!     },
//! }
//! ```

// ============================================================================
// APDU Size Constants
// ============================================================================

/// Maximum APDU length for standard TP1 without Extended Frame Format.
///
/// This is the baseline APDU size supported by all TP1 devices.
/// Standard frames can carry TPCI (1 byte) + up to 14 bytes of payload = 15 bytes.
pub const MAX_APDU_LENGTH_TP1_STANDARD: u16 = 15;

/// Maximum APDU length for TP1 with Extended Frame Format (EFF).
///
/// The NPDU length byte (1 byte) encodes TPCI + APDU. Maximum NPDU length
/// is 255 (= 1 byte TPCI + 254 bytes APDU), so the maximum APDU is 254.
/// This is also the maximum for KNX/IP devices.
pub const MAX_APDU_LENGTH_EXTENDED: u16 = 254;

/// Frame overhead in bytes.
///
/// This is the maximum overhead for any KNX frame format that may be stored
/// in a buffer. We use the cEMI header size since that's the largest:
///
/// **Internal format (6 bytes):**
/// - Control byte: 1
/// - Source address: 2
/// - Destination address: 2
/// - NPDU (hop count): 1
///
/// **cEMI format (9 bytes, without additional info):**
/// - Message code: 1
/// - Additional info length: 1 (value 0)
/// - Control field 1: 1
/// - Control field 2: 1
/// - Source address: 2
/// - Destination address: 2
/// - NPDU length: 1
///
/// **Extended TP1 format (7 bytes):**
/// - Control byte: 1
/// - Extended control: 1
/// - Source address: 2
/// - Destination address: 2
/// - Length: 1
///
/// Since received cEMI frames are copied into the buffer before conversion
/// to internal format (which happens in-place), the buffer capacity must
/// be able to hold the full cEMI frame.
pub const FRAME_OVERHEAD: usize = 9;

/// Default headroom for protocol headers.
///
/// This headroom is used for zero-copy prepending of headers:
/// - cEMI expansion: 3 bytes (msg_code + add_info_len + ctrl2)
/// - KNXnet/IP header: 6 bytes
/// - Extra margin: 7 bytes
pub const DEFAULT_HEADROOM: usize = 16;

/// Calculate the required buffer size for a given maximum APDU length.
///
/// The buffer must be large enough to hold:
/// - Frame overhead (9 bytes for cEMI compatibility)
/// - Maximum APDU
/// - Headroom for protocol headers (16 bytes)
///
/// # Example
///
/// ```
/// use zweidraehte::config::{buffer_size_for_apdu, MAX_APDU_LENGTH_EXTENDED};
///
/// // For a device supporting 254-byte APDUs
/// const BUFFER_SIZE: usize = buffer_size_for_apdu(MAX_APDU_LENGTH_EXTENDED);
/// assert_eq!(BUFFER_SIZE, 279); // 254 + 9 + 16
/// ```
pub const fn buffer_size_for_apdu(max_apdu_length: u16) -> usize {
    max_apdu_length as usize + FRAME_OVERHEAD + DEFAULT_HEADROOM
}

/// Common maximum APDU length configurations.
///
/// Use this enum to select a standard APDU size configuration for your device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MaxApduLength {
    /// Standard TP1 without EFF: 15 bytes (TPCI + 14 bytes payload)
    Tp1Standard = MAX_APDU_LENGTH_TP1_STANDARD,
    /// TP1 with EFF or KNX/IP: 254 bytes
    Extended = MAX_APDU_LENGTH_EXTENDED,
}

impl MaxApduLength {
    /// Get the maximum APDU length as a u16.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Calculate the required buffer size for this APDU length.
    pub const fn buffer_size(self) -> usize {
        buffer_size_for_apdu(self as u16)
    }
}

impl From<MaxApduLength> for u16 {
    fn from(len: MaxApduLength) -> Self {
        len as u16
    }
}

// ============================================================================
// Configuration Macros
// ============================================================================

// Re-export ComObjectFlags and Priority for use in macros
pub use crate::messages::knx::Priority;
pub use crate::objects::tables::ComObjectFlags;

// Re-export communication object flag constants from ComObjectFlags
pub const UE: u8 = ComObjectFlags::UE_FLAG_MASK; // Update Enable
pub const TE: u8 = ComObjectFlags::TE_FLAG_MASK; // Transmission Enable
pub const ROI: u8 = ComObjectFlags::ROI_FLAG_MASK; // Read on Init
pub const WE: u8 = ComObjectFlags::WE_FLAG_MASK; // Write Enable
pub const RE: u8 = ComObjectFlags::RE_FLAG_MASK; // Read Enable
pub const CE: u8 = ComObjectFlags::CE_FLAG_MASK; // Communication Enable

/// Macro to define a complete KNX stack configuration
///
/// This generates const-compatible data structures for all KNX tables
/// that can be loaded into a stack at runtime.
///
/// ## Flag Constants
/// - `CE`: Communication Enable
/// - `RE`: Read Enable
/// - `WE`: Write Enable
/// - `TE`: Transmission Enable
/// - `UE`: Update Enable
/// - `ROI`: Read on Init
///
/// ## Priority (optional, defaults to Low)
/// Add priority with `@priority(System|High|Alarm|Low)` after flags
///
/// ## Common Patterns
/// - `CONFIG_T`: Transmit (CE | TE)
/// - `CONFIG_RT`: Read & Transmit (CE | TE | RE)
/// - `CONFIG_WU`: Write & Update (CE | WE | UE)
/// - `CONFIG_RTWU`: Full capability (CE | TE | WE | UE | RE)
#[macro_export]
macro_rules! knx_stack_config {
    (
        name: $name:ident,
        individual_address: $addr:expr,

        group_addresses: {
            $($tsap:expr => $group_addr:expr),* $(,)?
        },

        comm_objects: {
            $($asap:expr => ($size:expr, $flags:expr $(, @priority($prio:ident))?)),* $(,)?
        },

        associations: {
            $($assoc_tsap:expr => [$($assoc_asap:expr),* $(,)?]),* $(,)?
        } $(,)?
    ) => {
        pub struct $name {
            pub individual_address: $crate::address::IndividualAddress,
            addr7_data: [u8; Self::ADDR7_SIZE],
            asso6_data: [u8; Self::ASSO6_SIZE],
            co7_data: [u8; Self::CO7_SIZE],
        }

        // Type aliases for the table types using MAX_ENTRIES.
        // All tables use a 2-byte count header followed by entries:
        //   AddrTab7: 2 + MAX_ENTRIES * 2 bytes (2 bytes per group address)
        //   AssoTab6: 2 + MAX_ENTRIES * 4 bytes (4 bytes per entry: TSAP u16 + ASAP u16)
        //   CoTab7:   2 + MAX_ENTRIES * 2 bytes (2 bytes per comm object)
        pub type AddrTab = $crate::objects::tables::addr7::AddrTab7<{ $name::NUM_GROUP_ADDRS }>;
        pub type AssoTab = $crate::objects::tables::asso6::AssoTab6<{ $name::NUM_ASSOCIATIONS }>;
        pub type CoTab = $crate::objects::tables::co7::CoTab7<{ $name::NUM_COMM_OBJECTS }>;

        impl $name {
            // Calculate sizes at compile time
            pub const NUM_GROUP_ADDRS: usize = $crate::knx_stack_config!(@count $($tsap)*);
            pub const NUM_COMM_OBJECTS: usize = $crate::knx_stack_config!(@count $($asap)*);
            pub const NUM_ASSOCIATIONS: usize = $crate::knx_stack_config!(@count_assocs $($assoc_tsap => [$($assoc_asap)*])*);


            pub const ADDR7_SIZE: usize = 2 + Self::NUM_GROUP_ADDRS * 2;
            pub const ASSO6_SIZE: usize = 2 + Self::NUM_ASSOCIATIONS * 4;  // Each association is 4 bytes: TSAP (2) + ASAP (2)
            pub const CO7_SIZE: usize = 2 + Self::NUM_COMM_OBJECTS * 2;

            pub const fn new() -> Self {
                // Parse individual address at compile time
                let individual_address = {
                    let addr_str = $addr;
                    let bytes = addr_str.as_bytes();
                    let mut area = 0u8;
                    let mut line = 0u8;
                    let mut device = 0u8;
                    let mut i = 0;
                    let mut part = 0; // 0=area, 1=line, 2=device

                    while i < bytes.len() {
                        let b = bytes[i];
                        if b == b'.' {
                            part += 1;
                        } else if b >= b'0' && b <= b'9' {
                            let digit = b - b'0';
                            if part == 0 {
                                area = area * 10 + digit;
                            } else if part == 1 {
                                line = line * 10 + digit;
                            } else if part == 2 {
                                device = device * 10 + digit;
                            }
                        }
                        i += 1;
                    }

                    $crate::address::IndividualAddress::new(area, line, device)
                };

                // Build address table
                let mut addr7_data = [0u8; Self::ADDR7_SIZE];
                addr7_data[0] = (Self::NUM_GROUP_ADDRS >> 8) as u8;
                addr7_data[1] = (Self::NUM_GROUP_ADDRS & 0xFF) as u8;

                let mut addr_idx = 2;
                $(
                    // Parse group address at compile time
                    let ga = {
                        let addr_str = $group_addr;
                        let bytes = addr_str.as_bytes();
                        let mut main = 0u16;
                        let mut middle = 0u16;
                        let mut sub = 0u16;
                        let mut i = 0;
                        let mut part = 0;
                        let mut slash_count = 0;

                        while i < bytes.len() {
                            let b = bytes[i];
                            if b == b'/' {
                                slash_count += 1;
                                part += 1;
                            } else if b >= b'0' && b <= b'9' {
                                let digit = (b - b'0') as u16;
                                if part == 0 {
                                    main = main * 10 + digit;
                                } else if part == 1 {
                                    middle = middle * 10 + digit;
                                } else if part == 2 {
                                    sub = sub * 10 + digit;
                                }
                            }
                            i += 1;
                        }

                        // Encode as 3-level or 2-level
                        let encoded = if slash_count == 2 {
                            ((main & 0x1F) << 11) | ((middle & 0x07) << 8) | (sub & 0xFF)
                        } else {
                            ((main & 0x1F) << 11) | (middle & 0x7FF)
                        };

                        [(encoded >> 8) as u8, (encoded & 0xFF) as u8]
                    };
                    addr7_data[addr_idx] = ga[0];
                    addr7_data[addr_idx + 1] = ga[1];
                    addr_idx += 2;
                )*

                // Build association table
                let mut asso6_data = [0u8; Self::ASSO6_SIZE];
                asso6_data[0] = (Self::NUM_ASSOCIATIONS >> 8) as u8;
                asso6_data[1] = (Self::NUM_ASSOCIATIONS & 0xFF) as u8;

                let mut asso_idx = 2;
                $(
                    $(
                        // Each entry: TSAP (2 bytes) + ASAP (2 bytes)
                        asso6_data[asso_idx] = 0;                    // TSAP high byte
                        asso6_data[asso_idx + 1] = $assoc_tsap;      // TSAP low byte
                        asso6_data[asso_idx + 2] = 0;                // ASAP high byte
                        asso6_data[asso_idx + 3] = $assoc_asap;      // ASAP low byte
                        asso_idx += 4;
                    )*
                )*

                // Build communication object table
                let mut co7_data = [0u8; Self::CO7_SIZE];
                co7_data[0] = (Self::NUM_COMM_OBJECTS >> 8) as u8;
                co7_data[1] = (Self::NUM_COMM_OBJECTS & 0xFF) as u8;

                let mut co_idx = 2;
                $(
                    // Default priority is Low (3) if not specified
                    let priority = $crate::knx_stack_config!(@get_priority $($prio)?);
                    co7_data[co_idx] = $size;
                    co7_data[co_idx + 1] = $flags | priority;
                    co_idx += 2;
                )*

                Self {
                    individual_address,
                    addr7_data,
                    asso6_data,
                    co7_data,
                }
            }

            /// Get references to the table data
            pub const fn addr7_data(&self) -> &[u8] {
                &self.addr7_data
            }

            pub const fn asso6_data(&self) -> &[u8] {
                &self.asso6_data
            }

            pub const fn co7_data(&self) -> &[u8] {
                &self.co7_data
            }

            /// Create table instances with the configuration data loaded.
            ///
            /// # Arguments
            /// * `adt_address` - Base address for the Address Table in the KNX device's virtual address space
            /// * `ast_address` - Base address for the Association Table
            /// * `cot_address` - Base address for the Communication Object Table
            ///
            /// These addresses are used by management clients for memory-mapped access to the tables.
            pub fn create_tables(adt_address: u32, ast_address: u32, cot_address: u32) -> (AddrTab, AssoTab, CoTab) {
                use $crate::objects::tables::Table;

                const CONFIG: $name = $name::new();

                // Create tables with pre-loaded data and their virtual addresses
                let addr_tab = Table::with_data(CONFIG.addr7_data(), adt_address);
                let asso_tab = Table::with_data(CONFIG.asso6_data(), ast_address);
                let co_tab = Table::with_data(CONFIG.co7_data(), cot_address);

                (addr_tab, asso_tab, co_tab)
            }
        }
    };

    // Helper: Count items (using tt instead of expr for proper recursion)
    (@count) => { 0 };
    (@count $head:tt $($tail:tt)*) => { 1 + $crate::knx_stack_config!(@count $($tail)*) };

    // Helper: Count associations (each ASAP can have multiple TSAPs)
    (@count_assocs) => { 0 };
    (@count_assocs $tsap:expr => [$($asap:expr)*] $($rest:tt)*) => {
        $crate::knx_stack_config!(@count $($asap)*) + $crate::knx_stack_config!(@count_assocs $($rest)*)
    };

    // Helper: Get priority value (defaults to Low = 3)
    // These match the Priority enum values from messages::knx::Priority
    (@get_priority) => { 3u8 }; // Low priority (default)
    (@get_priority System) => { 0u8 };
    (@get_priority High) => { 1u8 };
    (@get_priority Alarm) => { 2u8 };
    (@get_priority Low) => { 3u8 };
}

// Re-export flag constants for convenience
pub use ComObjectFlags as Flags;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asso_buffer_format() {
        mod test_config {
            use crate::config::{CE, RE, TE, WE};
            use crate::knx_stack_config;

            knx_stack_config! {
                name: TestConfig,
                individual_address: "1.1.0",

                group_addresses: {
                    1 => "1/0/1",
                    2 => "1/0/2",
                },

                comm_objects: {
                    1 => (0, CE | TE | RE | WE),
                    2 => (0, CE | TE | RE | WE),
                },

                associations: {
                    1 => [1],
                    2 => [1, 2],
                },
            }
        }

        // 3 associations total: 2 + 3*4 = 14 bytes
        const CONFIG: test_config::TestConfig = test_config::TestConfig::new();
        assert_eq!(CONFIG.asso6_data().len(), 14);

        // Verify structure:
        // Bytes 0-1: count = 3
        assert_eq!(CONFIG.asso6_data()[0], 0);
        assert_eq!(CONFIG.asso6_data()[1], 3);

        // Entry 1: TSAP=1, ASAP=1
        assert_eq!(CONFIG.asso6_data()[2], 0); // TSAP high
        assert_eq!(CONFIG.asso6_data()[3], 1); // TSAP low
        assert_eq!(CONFIG.asso6_data()[4], 0); // ASAP high
        assert_eq!(CONFIG.asso6_data()[5], 1); // ASAP low

        // Entry 2: TSAP=2, ASAP=1
        assert_eq!(CONFIG.asso6_data()[6], 0); // TSAP high
        assert_eq!(CONFIG.asso6_data()[7], 2); // TSAP low
        assert_eq!(CONFIG.asso6_data()[8], 0); // ASAP high
        assert_eq!(CONFIG.asso6_data()[9], 1); // ASAP low

        // Entry 3: TSAP=2, ASAP=2
        assert_eq!(CONFIG.asso6_data()[10], 0); // TSAP high
        assert_eq!(CONFIG.asso6_data()[11], 2); // TSAP low
        assert_eq!(CONFIG.asso6_data()[12], 0); // ASAP high
        assert_eq!(CONFIG.asso6_data()[13], 2); // ASAP low
    }

    #[test]
    fn test_basic_config() {
        // Example configuration for a simple lighting controller
        knx_stack_config! {
            name: LightingController,
            individual_address: "1.1.5",

            group_addresses: {
                1 => "1/0/1",
                2 => "1/0/2",
                3 => "1/0/3",
            },

            comm_objects: {
                1 => (1, CE | WE | TE),
                2 => (1, CE | RE | WE | TE),
                3 => (1, CE | TE | UE),
            },

            associations: {
                1 => [1, 3],
                2 => [2],
                3 => [3],
            },
        }

        const CONFIG: LightingController = LightingController::new();

        // Check individual address
        assert_eq!(CONFIG.individual_address.area(), 1);
        assert_eq!(CONFIG.individual_address.line(), 1);
        assert_eq!(CONFIG.individual_address.device(), 5);

        // Check address table size (2 byte header + 3 addresses * 2 bytes)
        assert_eq!(CONFIG.addr7_data().len(), 2 + 3 * 2);

        // Check association table size (2 byte header + 4 associations * 4 bytes)
        assert_eq!(CONFIG.asso6_data().len(), 2 + 4 * 4);

        // Check comm object table size (2 byte header + 3 objects * 2 bytes)
        assert_eq!(CONFIG.co7_data().len(), 2 + 3 * 2);
    }

    #[test]
    fn test_priority_flags() {
        // Test that priority values are correctly encoded in the lower 2 bits
        knx_stack_config! {
            name: PriorityTest,
            individual_address: "1.1.1",

            group_addresses: {
                1 => "0/0/1",
                2 => "0/0/2",
                3 => "0/0/3",
                4 => "0/0/4",
            },

            comm_objects: {
                1 => (1, CE | TE, @priority(System)),  // Priority = 0
                2 => (1, CE | TE, @priority(High)),    // Priority = 1
                3 => (1, CE | TE, @priority(Alarm)),   // Priority = 2
                4 => (1, CE | TE),                     // Priority = 3 (default Low)
            },

            associations: {
                1 => [1],
                2 => [2],
                3 => [3],
                4 => [4],
            },
        }

        const CONFIG: PriorityTest = PriorityTest::new();
        let co_data = CONFIG.co7_data();

        // CO7 format: [header 2 bytes][obj1 2 bytes][obj2 2 bytes][obj3 2 bytes][obj4 2 bytes]
        // Each object: [type (size)][flags]
        // Flags = CE | TE = 0x44, plus priority in bits 0-1

        // Object 1: System priority (0) -> flags should be 0x44 | 0 = 0x44
        assert_eq!(co_data[2 + 0 * 2 + 1], 0x44 | 0, "System priority should be 0");

        // Object 2: High priority (1) -> flags should be 0x44 | 1 = 0x45
        assert_eq!(co_data[2 + 1 * 2 + 1], 0x44 | 1, "High priority should be 1");

        // Object 3: Alarm priority (2) -> flags should be 0x44 | 2 = 0x46
        assert_eq!(co_data[2 + 2 * 2 + 1], 0x44 | 2, "Alarm priority should be 2");

        // Object 4: Low priority (3, default) -> flags should be 0x44 | 3 = 0x47
        assert_eq!(co_data[2 + 3 * 2 + 1], 0x44 | 3, "Low priority (default) should be 3");
    }
}
