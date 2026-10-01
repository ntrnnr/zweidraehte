//! Device-level vocabulary for System 7 devices: [`System7StateInit`], the
//! constructor-args envelope, and the family's sizing constants.
//!
//! Two deliberate differences from System B:
//!
//! - **No individual-address field.** On System 7 the IA lives inside
//!   the RT8-coded address table (offset 1–2, see
//!   [`addr8`](crate::objects::tables::addr8)) and is persisted as part
//!   of that blob — a separate field could diverge from what ETS
//!   downloads.
//! - **15 settable authorization keys** for the 16-level model
//!   (06 Profiles v02.02.01 §4.2 row 12): levels 0–14 carry keys,
//!   level 15 is "access for everyone" and has none.

/// Number of authorization access levels on System 7 (0–15).
pub const SYSTEM7_MAX_ACCESS_LEVELS: usize = 16;

/// Number of settable authorization keys (levels 0–14). Level 15 is
/// "access for everyone" and has no key — it's what you get when auth
/// fails.
pub const SYSTEM7_NUM_AUTH_KEYS: usize = 15;

/// Standard `StateInit` shape for `System7DeviceState`-based devices.
///
/// Same envelope as System B's `SystemBStateInit`: factory-programmed
/// identity and construction resources that are not configuration (`()`
/// for plain TP1 stacks).
pub struct System7StateInit<I, R = ()> {
    /// Factory-programmed device identity.
    pub identity: I,
    /// Construction inputs for the extension state that are not configuration.
    pub resources: R,
}

impl<I> System7StateInit<I, ()> {
    /// The init envelope for a plain stack (resources defaulted to `()`).
    pub fn new(identity: I) -> Self {
        Self { identity, resources: () }
    }
}

/// Calculate table sizes from max entry counts.
///
/// Returns `(adt_size, ast_size, cot_size)` for use as const generics.
pub const fn table_sizes(max_addr: usize, max_asso: usize, max_co: usize) -> (usize, usize, usize) {
    (
        3 + max_addr * 2, // RT8-coded ADT: 1-byte length + 2-byte IA + 2 bytes per GA
        1 + max_asso * 2, // System 7 AST: 1-byte count + 2 bytes per entry
        3 + max_co * 4,   // System 7 COT: count + RAM-flags ptr + one row per object
    )
}
