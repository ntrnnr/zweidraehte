//! The mask-fixed System 7 addresses. Everything else about the
//! memory layout is *not* fixed: the association table and application
//! segments live wherever the download's allocation records put them
//! (tracked through each machine's `table_ref`), and the group object
//! table address is a constant of the product database, not of the
//! mask — which is why it is a const parameter of
//! [`super::System7Family`] rather than a value here.

/// The option register. Not inverted on System 7, and outside the
/// user-EEPROM window — the stack keeps it in `ManagementState`.
pub const OPTION_REG_ADDR: u16 = 0x0100;
/// The memory-mapped load-control write window (03/05/02 §3.31.2).
pub const LOAD_CONTROL_ADDR: u16 = 0x0104;
/// Longest record the load-control window accepts.
pub const LOAD_CONTROL_MAX: usize = 12;
/// Read-only load-status bytes, one `LoadState` octet per machine
/// (ADT, AST, application, optional interface program).
pub const LOAD_STATUS_ADDR: u16 = 0xB6EA;
/// The RT8-coded group address table is fixed at 4000h (Resources
/// §4.16.9.2), the start of user EEPROM.
pub const ADT_ADDR: u16 = 0x4000;
