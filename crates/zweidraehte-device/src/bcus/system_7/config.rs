//! Compile-time device configuration for System 7 devices.
//!
//! [`system7_stack_config!`](crate::system7_stack_config) is the
//! System 7 twin of [`knx_stack_config!`](crate::knx_stack_config): the
//! same declarative blocks, but building the System 7 table blobs — the
//! individual address embedded in the address table, 1-octet
//! TSAP/ASAP association entries — and pinning the address table to its
//! fixed 4000h home.

/// Generate a compile-time device configuration with System 7 tables.
///
/// Same input blocks as `knx_stack_config!`; differences in what comes
/// out:
///
/// - `AddrTab` / `AssoTab` are the RT8 types
///   ([`AddrTab8`](crate::objects::tables::addr8::AddrTab8) /
///   [`AssoTab8`](crate::objects::tables::asso8::AssoTab8)); `CoTab` is
///   the System 7 memory format
///   ([`System7ComObjectTable`](crate::objects::tables::System7ComObjectTable)) that ETS's
///   System 7 formatter writes. The table is indexed by ASAP, so
///   ASAPs must be contiguous (compile-time checked). Products number
///   from 0 (`FIRST_ASAP = 0`, the System 7 convention); the EITT
///   conformance DUT starts at 1 because the vendor templates pin its
///   ASAPs literally, leaving entry 0 as a zeroed spare.
/// - The parsed `individual_address` is *also* baked into the address
///   table's IA slot — on System 7 that slot is the device's address
///   storage.
/// - Group addresses must be listed in ascending order (RT8 mandates a
///   sorted table; the runtime TSAP lookup is a binary search). `new()`
///   asserts this at compile time.
/// - `create_tables(ast_address, cot_address)` takes no address-table
///   address: RT8 fixes it at 4000h.
/// - No `security:` arm — there is no Data Secure System 7 profile in
///   the stack yet.
///
/// Like `knx_stack_config!`, the `comm_objects` size argument is a
/// [`ComObjectType`](crate::objects::tables::ComObjectType) discriminant
/// (`ComObjectType::Uint1 as u8`, ...), not a bit or byte count.
#[macro_export]
macro_rules! system7_stack_config {
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
            pub individual_address: ::zweidraehte_proto::address::IndividualAddress,
            addr8_data: [u8; Self::ADDR8_SIZE],
            asso8_data: [u8; Self::ASSO8_SIZE],
            cot_data: [u8; Self::COT_SIZE],
        }

        pub type AddrTab = $crate::objects::tables::addr8::AddrTab8<{ $name::NUM_GROUP_ADDRS }>;
        pub type AssoTab = $crate::objects::tables::asso8::AssoTab8<{ $name::NUM_ASSOCIATIONS }>;
        pub type CoTab = $crate::objects::tables::System7ComObjectTable<{ $name::MAX_ASAP }>;

        impl $name {
            pub const NUM_GROUP_ADDRS: usize = $crate::knx_stack_config!(@count $($tsap)*);
            pub const NUM_COMM_OBJECTS: usize = $crate::knx_stack_config!(@count $($asap)*);
            pub const NUM_ASSOCIATIONS: usize =
                $crate::knx_stack_config!(@count_assocs $($assoc_tsap => [$($assoc_asap)*])*);

            pub const ADDR8_SIZE: usize = 3 + Self::NUM_GROUP_ADDRS * 2;
            pub const ASSO8_SIZE: usize = 1 + Self::NUM_ASSOCIATIONS * 2;

            /// Lowest wire ASAP in the `comm_objects` block. 0 for
            /// products (the System 7 numbering convention); 1 for the
            /// EITT conformance DUT, whose ASAPs the vendor templates
            /// pin literally.
            pub const FIRST_ASAP: usize = {
                let mut min = usize::MAX;
                $( { let a = $asap as usize; if a < min { min = a; } } )*
                if min == usize::MAX { 0 } else { min }
            };
            /// Highest wire ASAP in the `comm_objects` block.
            pub const MAX_ASAP: usize = {
                let mut max = 0usize;
                $( { let a = $asap as usize; if a > max { max = a; } } )*
                max
            };

            /// System 7 group object table: header (count + RAM-flags ptr)
            /// plus one 4-octet entry per ASAP `0..=MAX_ASAP` — the
            /// table is indexed directly by ASAP, so a `FIRST_ASAP` of
            /// 1 leaves entry 0 as a zeroed spare.
            pub const COT_SIZE: usize = 3 + (Self::MAX_ASAP + 1) * 4;

            /// The fixed location of the RT8 address table.
            pub const ADT_ADDRESS: u32 = 0x4000;

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

                    ::zweidraehte_proto::address::IndividualAddress::new(area, line, device)
                };

                // Build the RT8 address table: [length][IA][GA...], with
                // the IA included in `length`.
                assert!(
                    Self::NUM_GROUP_ADDRS < u8::MAX as usize,
                    "RT8 length holds at most 254 group addresses"
                );
                let mut addr8_data = [0u8; Self::ADDR8_SIZE];
                addr8_data[0] = 1 + Self::NUM_GROUP_ADDRS as u8;
                let ia = individual_address.as_bytes();
                addr8_data[1] = ia[0];
                addr8_data[2] = ia[1];

                let mut addr_idx = 3;
                $(
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

                        let encoded = if slash_count == 2 {
                            ((main & 0x1F) << 11) | ((middle & 0x07) << 8) | (sub & 0xFF)
                        } else {
                            ((main & 0x1F) << 11) | (middle & 0x7FF)
                        };

                        [(encoded >> 8) as u8, (encoded & 0xFF) as u8]
                    };
                    addr8_data[addr_idx] = ga[0];
                    addr8_data[addr_idx + 1] = ga[1];
                    addr_idx += 2;
                )*
                assert!(addr_idx == Self::ADDR8_SIZE);

                // RT8 mandates ascending group addresses (the TSAP lookup
                // is a binary search over them).
                {
                    let mut i = 3 + 2;
                    while i < Self::ADDR8_SIZE {
                        let prev = ((addr8_data[i - 2] as u16) << 8) | addr8_data[i - 1] as u16;
                        let cur = ((addr8_data[i] as u16) << 8) | addr8_data[i + 1] as u16;
                        assert!(prev < cur, "system7_stack_config!: group addresses must ascend");
                        i += 2;
                    }
                }

                // Build the RT8 association table: [count][TSAP u8, ASAP u8...]
                let mut asso8_data = [0u8; Self::ASSO8_SIZE];
                asso8_data[0] = Self::NUM_ASSOCIATIONS as u8;

                let mut asso_idx = 1;
                $(
                    $(
                        assert!($assoc_tsap as u16 <= 0xFF && $assoc_asap as u16 <= 0xFF,
                            "system7_stack_config!: RT8 caps TSAP/ASAP at 255");
                        asso8_data[asso_idx] = $assoc_tsap as u8;
                        asso8_data[asso_idx + 1] = $assoc_asap as u8;
                        asso_idx += 2;
                    )*
                )*
                assert!(asso_idx == Self::ASSO8_SIZE);

                // Build the group object table in the System 7 memory
                // format: [count][RAM-flags ptr:2] then one
                // [data ptr:2][config][type] entry per ASAP. Entry
                // index = ASAP, so the count covers `0..=MAX_ASAP` and
                // any slot below FIRST_ASAP stays zeroed. The pointers
                // are wire-compat only — this stack keeps the runtime
                // values and flags in the device's `ComObjects` struct.
                let mut cot_data = [0u8; Self::COT_SIZE];
                cot_data[0] = (Self::MAX_ASAP + 1) as u8;

                let mut expected_asap = Self::FIRST_ASAP;
                $(
                    assert!(
                        ($asap as usize) == expected_asap,
                        "system7_stack_config!: ASAPs must be contiguous — the System 7 table is indexed by ASAP"
                    );
                    let priority = $crate::knx_stack_config!(@get_priority $($prio)?);
                    let entry = 3 + ($asap as usize) * 4;
                    cot_data[entry + 2] = $flags | priority;
                    cot_data[entry + 3] = $size;
                    expected_asap += 1;
                )*
                let _ = expected_asap;

                Self {
                    individual_address,
                    addr8_data,
                    asso8_data,
                    cot_data,
                }
            }

            pub const fn addr8_data(&self) -> &[u8] {
                &self.addr8_data
            }

            pub const fn asso8_data(&self) -> &[u8] {
                &self.asso8_data
            }

            pub const fn cot_data(&self) -> &[u8] {
                &self.cot_data
            }

            /// Create pre-loaded table instances.
            ///
            /// The address table sits at its fixed 4000h home; the
            /// association table and communication object table live
            /// wherever the product database placed them.
            pub fn create_tables(ast_address: u32, cot_address: u32) -> (AddrTab, AssoTab, CoTab) {
                use $crate::objects::tables::Table;

                const CONFIG: $name = $name::new();

                let addr_tab = Table::with_data(CONFIG.addr8_data(), Self::ADT_ADDRESS);
                let asso_tab = Table::with_data(CONFIG.asso8_data(), ast_address);
                let co_tab = Table::with_data(CONFIG.cot_data(), cot_address);

                (addr_tab, asso_tab, co_tab)
            }
        }
    };

    // ====================================================================
    // Security-extended arm: base tables + Data Secure configuration
    // ====================================================================
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
        },

        security: {
            p2p_key_capacity: $p2p_cap:expr,
            siat_capacity: $siat_cap:expr,
            tool_key: $tool_key_hex:expr,

            group_keys: {
                $($gk_tsap:expr => $gk_hex:expr),* $(,)?
            },

            go_flags: {
                $($gf_co:expr => $gf_val:expr),* $(,)?
            } $(,)?
        } $(,)?
    ) => {
        // Base tables come from the non-security arm above.
        $crate::system7_stack_config! {
            name: $name,
            individual_address: $addr,
            group_addresses: { $($tsap => $group_addr),* },
            comm_objects: { $($asap => ($size, $flags $(, @priority($prio))?)),* },
            associations: { $($assoc_tsap => [$($assoc_asap),*]),* },
        }

        // Data Secure is a profile module (06 Profiles v02.02.01 §9.1),
        // so the constants and `create_security_config()` come from the
        // same macro System B uses. The one family-specific input is the
        // ASAP base: System 7 numbers communication objects from 0
        // (`StackDefinition::FIRST_ASAP`), and the GO security flags
        // table is positional, so the `go_flags` keys are 0-based here
        // where System B's are 1-based.
        $crate::secure_stack_config! {
            name: $name,
            first_asap: 0,
            p2p_key_capacity: $p2p_cap,
            siat_capacity: $siat_cap,
            tool_key: $tool_key_hex,
            group_keys: { $($gk_tsap => $gk_hex),* },
            go_flags: { $($gf_co => $gf_val),* },
        }
    };
}
