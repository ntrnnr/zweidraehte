//! Persistence infrastructure for System 7 devices.
//!
//! Mirrors the System B vocabulary (see [`crate::extension`] for the
//! shared `Config` / `State` / `Resources` suffixes): [`System7DeviceConfig`]
//! is the device-level serialisable form, [`System7StateInit`] the
//! constructor-args envelope.
//!
//! Two deliberate differences from System B's `DeviceConfig`:
//!
//! - **No `individual_address` field.** On System 7 the IA lives inside
//!   the RT8-coded address table (offset 1–2, see
//!   [`addr8`](crate::objects::tables::addr8)) and is persisted as part
//!   of that blob — a separate field could diverge from what ETS
//!   downloads.
//! - **15 settable authorization keys** for the 16-level model
//!   (06 Profiles v02.02.01 §4.2 row 12): levels 0–14 carry keys,
//!   level 15 is "access for everyone" and has none.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::extension::ExtensionConfig;
use crate::objects::tables::{
    AbsoluteAlloc, Application, Table, TableMemory, addr8::AddrTab8Impl, asso8::AssoTab8Impl,
    co_system7::System7ComObjectTableImpl,
};

/// Number of authorization access levels on System 7 (0–15).
pub const SYSTEM7_MAX_ACCESS_LEVELS: usize = 16;

/// Number of settable authorization keys (levels 0–14). Level 15 is
/// "access for everyone" and has no key — it's what you get when auth
/// fails.
pub const SYSTEM7_NUM_AUTH_KEYS: usize = 15;

/// Standard `StateInit` shape for `System7DeviceState`-based devices.
///
/// Same three-part envelope as System B's `SystemBStateInit`:
/// factory-programmed identity, an optional persisted snapshot, and
/// non-serialisable construction resources (`()` for plain TP1 stacks).
pub struct System7StateInit<I, C, R = ()> {
    /// Factory-programmed device identity.
    pub identity: I,
    /// `Some(snapshot)` from a previous boot, or `None` for factory-fresh.
    pub loaded_config: Option<C>,
    /// Non-serialisable construction inputs for the extension state.
    pub resources: R,
}

impl<I, C> System7StateInit<I, C, ()> {
    /// Build an init envelope for a plain stack (resources defaulted to `()`).
    pub fn new(identity: I, loaded_config: Option<C>) -> Self {
        Self { identity, loaded_config, resources: () }
    }
}

/// All state that must survive power cycles — the device-level persisted
/// configuration for a System 7 device.
///
/// # Generic Parameters
///
/// The const generics are the actual byte sizes of each table:
/// - `ADT_SIZE`: RT8-coded address table size (3 + MAX_ADDR * 2)
/// - `AST_SIZE`: System 7 association table size (1 + MAX_ASSO * 2)
/// - `COT_SIZE`: group object table size in the System 7 memory format
///   (3 + MAX_CO * 4)
/// - `P`: Application parameters type
/// - `E`: Extension-specific persistent config
///
/// Use [`table_sizes`] to calculate the const generics from max entry
/// counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: Deserialize<'de>",))]
pub struct System7DeviceConfig<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable = (),
    E: ExtensionConfig = (),
> {
    /// Version of the device config format.
    ///
    /// Increment this when making breaking changes to allow migration.
    pub version: u8,

    /// Authorization keys for levels 0-14.
    ///
    /// Level 15 has no key (it's the fallback when no key matches).
    /// Key value `[0xFF, 0xFF, 0xFF, 0xFF]` is the "default key".
    pub auth_keys: [[u8; 4]; SYSTEM7_NUM_AUTH_KEYS],

    /// Routing count (hop count) for outgoing messages.
    pub routing_count: u8,

    /// OptionReg (03/05/01 Resources §4.25), exposed at memory 0100h.
    pub option_reg: u8,

    /// RT8-coded address table (fixed at 4000h; carries the device IA at
    /// offset 1–2).
    pub address_table: Table<AddrTab8Impl<ADT_SIZE>, AbsoluteAlloc>,

    /// System 7 association table (located via `PID_TABLE_REFERENCE`).
    pub association_table: Table<AssoTab8Impl<AST_SIZE>, AbsoluteAlloc>,

    /// Group object table (CO type + flags). Internal — System 7 exposes
    /// no Group Object Table interface object; ETS writes this data as
    /// part of the application memory segment.
    pub group_object_table: Table<System7ComObjectTableImpl<COT_SIZE>, AbsoluteAlloc>,

    /// Application program data (interface object index 3).
    pub application: Application<P, AbsoluteAlloc>,

    /// Optional Interface Program (interface object index 4). Carries no
    /// device parameters of its own. The field retains its historical name
    /// for configuration-format compatibility.
    pub application2: Application<(), AbsoluteAlloc>,

    /// Application program version (set by ETS during programming).
    pub program_version: [u8; 5],

    /// Interface Program version (set by ETS during programming).
    pub program2_version: [u8; 5],

    /// Extension-specific persistent configuration.
    pub extension_config: E,
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable,
    E: ExtensionConfig,
> System7DeviceConfig<ADT_SIZE, AST_SIZE, COT_SIZE, P, E>
{
    /// Current version of the device config format.
    pub const VERSION: u8 = 1;

    /// Create a new device config with factory defaults.
    ///
    /// The address table's IA slot is seeded with `FF FF` (15.15.255) —
    /// the fresh-device default, matching erased EEPROM on real silicon.
    pub fn factory_default() -> Self {
        let mut address_table = Table::new();
        address_table.write(1, &[0xFF, 0xFF]);

        Self {
            version: Self::VERSION,
            auth_keys: [[0xFF; 4]; SYSTEM7_NUM_AUTH_KEYS], // All keys = default key
            routing_count: 6,                              // Default per KNX spec
            option_reg: 0,
            address_table,
            association_table: Table::new(),
            group_object_table: Table::new(),
            application: Application::new(),
            application2: Application::new(),
            program_version: [0; 5],
            program2_version: [0; 5],
            extension_config: E::default(),
        }
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
