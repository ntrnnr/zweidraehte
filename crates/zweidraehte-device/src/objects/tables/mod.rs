use core::cell::RefCell;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    big_endian::{U16, U32},
};

use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::dpt::PDT_Generic08;
use zweidraehte_proto::messages::knx::Priority;
use zweidraehte_proto::util::{crc::crc16_ccitt, packets::BufferView};

// The load/run-state machine *wire* enums are pure protocol values, so they live
// in `zweidraehte-proto`. The state machines that consume them (`Table<T>`,
// `RunnableApplication<T>`, the `Has*StateMachine` traits, `LoadAction`,
// `RunAction`, `LoadError`) stay here. Re-exported so the device-side and
// downstream `cross/` paths (`objects::tables::LoadState`, the prelude) keep
// working without those crates taking a direct `zweidraehte-proto` dependency.
pub use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadSegment, LoadState, RunEvent, RunState};

// ============================================================================
// Table Accessor Traits
// ============================================================================

/// Trait for types that contain an Address Table.
///
/// Implement this trait on your device state type to enable group object
/// communication in the stack.
pub trait HasAddressTable {
    /// The concrete address table type
    type ADT: AddressTable;
    /// Get a reference to the address table
    fn adt(&self) -> &RefCell<Self::ADT>;
}

/// Trait for types that contain an Association Table.
///
/// Implement this trait on your device state type to enable group object
/// communication in the stack.
pub trait HasAssociationTable {
    /// The concrete association table type
    type AST: AssociationTable;
    /// Get a reference to the association table
    fn ast(&self) -> &RefCell<Self::AST>;
}

/// Trait for types that contain a Communication Object Table.
///
/// Implement this trait on your device state type to enable group object
/// communication in the stack.
pub trait HasCommunicationObjectTable {
    /// The concrete communication object table type
    type COT: CommunicationObjectTable;
    /// Get a reference to the communication object table
    fn cot(&self) -> &RefCell<Self::COT>;
}

/// Trait for types that contain an Application Program.
///
/// This is used by interface objects and the memory map to access
/// the application's load and run state machines.
pub trait HasApplication {
    /// The concrete application type.
    type APP: HasLoadStateMachine + HasRunStateMachine;

    /// Get a reference to the application.
    fn app(&self) -> &RefCell<Self::APP>;
}

/// Trait for types that contain a PEI (Physical External Interface) Program.
///
/// This is used by interface objects to access the PEI's load and run state machines.
/// Required for ETS/spec compliance even though no modern device behavior depends on
/// PEI state. See [`PeiApplication`] for details on why this exists.
pub trait HasPeiApplication {
    /// The concrete PEI application type.
    type PEI: HasLoadStateMachine + HasRunStateMachine;

    /// Get a reference to the PEI application.
    fn pei(&self) -> &RefCell<Self::PEI>;
}

// ============================================================================
// Table Traits
// ============================================================================

pub trait TableMemory: ConstDefault + Sized {
    /// The table's maximum byte capacity. An associated const (not a method)
    /// so it is usable in const contexts and array sizes.
    const MAX_SIZE: usize;
    fn data_ref(&self) -> &[u8];
    fn data_ref_mut(&mut self) -> &mut [u8];

    /// Copy `data.len()` bytes starting at `offset` out of the table.
    ///
    /// The default impl is an **unchecked** `copy_from_slice` and will panic
    /// if `offset + data.len()` exceeds `data_ref().len()`. Table types
    /// whose backing storage has meaningful bounds (e.g.,
    /// [`ApplicationImpl`](super::app::ApplicationImpl) wrapping a typed
    /// struct) override this with a saturating variant.
    fn read(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.data_ref()[offset..offset + data.len()]);
    }

    /// Copy `data.len()` bytes of `data` into the table starting at
    /// `offset`. See [`read`](Self::read) for the bounds-handling contract.
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
    }
}

pub trait HasLoadStateMachine: TableMemory {
    /// Process a load state machine command.
    ///
    /// Returns the [`LoadAction`] that the state machine produced, so the
    /// caller (e.g., `ApplicationProgramObject`) can orchestrate side effects
    /// like signaling the run state machine on `LoadEnd` or `Unload`.
    ///
    /// # Arguments
    /// * `buf` - Load control data (event byte followed by segment data for allocation)
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation.
    fn write_lsm(&mut self, buf: &[u8], alloc_address: Option<u32>) -> LoadAction;
    fn read_lsm(&self) -> [u8; 1];
    fn is_loaded(&self) -> bool;

    /// Get a reference to the MCB (Memory Control Block) data.
    /// The MCB is 8 bytes: `[requested_memory_size:4][mode:1][fill:1][crc:2]`
    fn mcb_bytes(&self) -> &[u8];

    /// Get the table reference (base address in the KNX device's virtual address space).
    ///
    /// Management clients use this for memory-mapped access to the table data.
    /// This is NOT a real memory pointer - it's a virtual address assigned by the
    /// device's memory manager during allocation.
    fn table_reference(&self) -> u32;

    /// Last load error code, surfaced via PID_ERROR_CODE (PID 28).
    ///
    /// Encoded as DPT_ErrorClass_System (20.011); see [`LoadError`] for the
    /// values used by this stack. Returns `0` (no error) when the state
    /// machine is not in `LoadState::Err`. Per Resources spec 4.2.28, the
    /// code is reset to 0 once the state machine transitions out of `Err`.
    fn last_error_code(&self) -> u8;
}

/// Subset of `DPT_ErrorClass_System` (DPT 20.011) used to report load
/// state machine failures via `PID_ERROR_CODE`.
///
/// The full DPT defines codes 0–18; this enum only names the ones the
/// LSM can actually produce. Other codes remain valid `u8` values for
/// callers that need to surface a specific failure outside this list.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum LoadError {
    /// No fault — load state machine is not in `Err`.
    None = 0,
    /// Memory allocation request exceeded the configured table capacity.
    /// Maps to "maximal table length exceeded" in DPT 20.011.
    MaxTableLengthExceeded = 13,
    /// `AdditionalLoadControls` carried an unknown segment type, or some
    /// other malformed load command. Maps to "undefined load command
    /// received" in DPT 20.011.
    UndefinedLoadCommand = 14,
}

pub trait AddressTable: HasLoadStateMachine {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    fn address(&self, tsap: u16) -> Option<GroupAddress>;
    fn tsap(&self, address: GroupAddress) -> Option<u16>;
    fn contains(&self, address: GroupAddress) -> bool;
}

pub trait AssociationTable: HasLoadStateMachine {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    /// Check if the association table is empty
    fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// Gets the sending TSAP for a given ASAP
    fn sending_tsap(&self, asap: u16) -> Option<u16>;

    fn tsaps_for_asap(&self, asap: u16) -> impl Iterator<Item = u16> + '_;
    fn asaps_for_tsap(&self, tsap: u16) -> impl Iterator<Item = u16> + '_;
}

/// Communication object data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComObjectType {
    Uint1 = 0,
    Uint2 = 1,
    Uint3 = 2,
    Uint4 = 3,
    Uint5 = 4,
    Uint6 = 5,
    Uint7 = 6,
    Byte1 = 7,
    Byte2 = 8,
    Byte3 = 9,
    Byte4 = 10,
    Byte6 = 11,
    Byte8 = 12,
    Byte10 = 13,
    Byte14 = 14,
    // New data types only valid for System B
    Byte5 = 15,
    Byte7 = 16,
    Byte9 = 17,
    Byte11 = 18,
    Byte12 = 19,
    Byte13 = 20,
    Byte15 = 21,
    Byte16 = 22,
    Byte17 = 23,
    Byte18 = 24,
    Byte19 = 25,
    Byte20 = 26,
    Byte21 = 27,
    Byte22 = 28,
    Byte23 = 29,
    Byte24 = 30,
    Byte25 = 31,
    Byte26 = 32,
    Byte27 = 33,
    Byte28 = 34,
    Byte29 = 35,
    Byte30 = 36,
    Byte31 = 37,
    Byte32 = 38,
    Byte33 = 39,
    Byte34 = 40,
    Byte35 = 41,
    Byte36 = 42,
    Byte37 = 43,
    Byte38 = 44,
    Byte39 = 45,
    Byte40 = 46,
    Byte41 = 47,
    Byte42 = 48,
    Byte43 = 49,
    Byte44 = 50,
    Byte45 = 51,
    Byte46 = 52,
    Byte47 = 53,
    Byte48 = 54,
    Byte49 = 55,
    Byte50 = 56,
    Byte51 = 57,
    Byte52 = 58,
    Byte53 = 59,
    Byte54 = 60,
    Byte55 = 61,
    Byte56 = 62,
    Byte57 = 63,
    Byte58 = 64,
    Byte59 = 65,
    Byte60 = 66,
    Byte61 = 67,
    Byte62 = 68,
    Byte63 = 69,
    Byte64 = 70,
    Byte65 = 71,
    Byte66 = 72,
    Byte67 = 73,
    Byte68 = 74,
    Byte69 = 75,
    Byte70 = 76,
    Byte71 = 77,
    Byte72 = 78,
    Byte73 = 79,
    Byte74 = 80,
    Byte75 = 81,
    Byte76 = 82,
    Byte77 = 83,
    Byte78 = 84,
    Byte79 = 85,
    Byte80 = 86,
    Byte81 = 87,
    Byte82 = 88,
    Byte83 = 89,
    Byte84 = 90,
    Byte85 = 91,
    Byte86 = 92,
    Byte87 = 93,
    Byte88 = 94,
    Byte89 = 95,
    Byte90 = 96,
    Byte91 = 97,
    Byte92 = 98,
    Byte93 = 99,
    Byte94 = 100,
    Byte95 = 101,
    Byte96 = 102,
    Byte97 = 103,
    Byte98 = 104,
    Byte99 = 105,
    Byte100 = 106,
    Byte101 = 107,
    Byte102 = 108,
    Byte103 = 109,
    Byte104 = 110,
    Byte105 = 111,
    Byte106 = 112,
    Byte107 = 113,
    Byte108 = 114,
    Byte109 = 115,
    Byte110 = 116,
    Byte111 = 117,
    Byte112 = 118,
    Byte113 = 119,
    Byte114 = 120,
    Byte115 = 121,
    Byte116 = 122,
    Byte117 = 123,
    Byte118 = 124,
    Byte119 = 125,
    Byte120 = 126,
    Byte121 = 127,
    Byte122 = 128,
    Byte123 = 129,
    Byte124 = 130,
    Byte125 = 131,
    Byte126 = 132,
    Byte127 = 133,
    Byte128 = 134,
    Byte129 = 135,
    Byte130 = 136,
    Byte131 = 137,
    Byte132 = 138,
    Byte133 = 139,
    Byte134 = 140,
    Byte135 = 141,
    Byte136 = 142,
    Byte137 = 143,
    Byte138 = 144,
    Byte139 = 145,
    Byte140 = 146,
    Byte141 = 147,
    Byte142 = 148,
    Byte143 = 149,
    Byte144 = 150,
    Byte145 = 151,
    Byte146 = 152,
    Byte147 = 153,
    Byte148 = 154,
    Byte149 = 155,
    Byte150 = 156,
    Byte151 = 157,
    Byte152 = 158,
    Byte153 = 159,
    Byte154 = 160,
    Byte155 = 161,
    Byte156 = 162,
    Byte157 = 163,
    Byte158 = 164,
    Byte159 = 165,
    Byte160 = 166,
    Byte161 = 167,
    Byte162 = 168,
    Byte163 = 169,
    Byte164 = 170,
    Byte165 = 171,
    Byte166 = 172,
    Byte167 = 173,
    Byte168 = 174,
    Byte169 = 175,
    Byte170 = 176,
    Byte171 = 177,
    Byte172 = 178,
    Byte173 = 179,
    Byte174 = 180,
    Byte175 = 181,
    Byte176 = 182,
    Byte177 = 183,
    Byte178 = 184,
    Byte179 = 185,
    Byte180 = 186,
    Byte181 = 187,
    Byte182 = 188,
    Byte183 = 189,
    Byte184 = 190,
    Byte185 = 191,
    Byte186 = 192,
    Byte187 = 193,
    Byte188 = 194,
    Byte189 = 195,
    Byte190 = 196,
    Byte191 = 197,
    Byte192 = 198,
    Byte193 = 199,
    Byte194 = 200,
    Byte195 = 201,
    Byte196 = 202,
    Byte197 = 203,
    Byte198 = 204,
    Byte199 = 205,
    Byte200 = 206,
    Byte201 = 207,
    Byte202 = 208,
    Byte203 = 209,
    Byte204 = 210,
    Byte205 = 211,
    Byte206 = 212,
    Byte207 = 213,
    Byte208 = 214,
    Byte209 = 215,
    Byte210 = 216,
    Byte211 = 217,
    Byte212 = 218,
    Byte213 = 219,
    Byte214 = 220,
    Byte215 = 221,
    Byte216 = 222,
    Byte217 = 223,
    Byte218 = 224,
    Byte219 = 225,
    Byte220 = 226,
    Byte221 = 227,
    Byte222 = 228,
    Byte223 = 229,
    Byte224 = 230,
    Byte225 = 231,
    Byte226 = 232,
    Byte227 = 233,
    Byte228 = 234,
    Byte229 = 235,
    Byte230 = 236,
    Byte231 = 237,
    Byte232 = 238,
    Byte233 = 239,
    Byte234 = 240,
    Byte235 = 241,
    Byte236 = 242,
    Byte237 = 243,
    Byte238 = 244,
    Byte239 = 245,
    Byte240 = 246,
    Byte241 = 247,
    Byte242 = 248,
    Byte243 = 249,
    Byte244 = 250,
    Byte245 = 251,
    Byte246 = 252,
    Byte247 = 253,
    Byte248 = 254,
    Byte252 = 255,
}

impl From<u8> for ComObjectType {
    fn from(value: u8) -> Self {
        // SAFETY: `ComObjectType` is `#[repr(u8)]` and covers all 256 discriminants
        // (0-254 are named variants; 255 is `Byte252`). Every `u8` is therefore a
        // valid discriminant. The round-trip test below (`test_com_object_type_roundtrip`)
        // iterates all 256 values and verifies that `u8::from(ComObjectType::from(v)) == v`,
        // which catches any future gap if a variant is removed.
        unsafe { core::mem::transmute(value) }
    }
}

impl From<ComObjectType> for u8 {
    fn from(value: ComObjectType) -> Self {
        value as u8
    }
}

impl ComObjectType {
    /// Get the size in bytes for this object type and whether it's a compact type
    /// that fits in the 6 APCI bits for short APDUs.
    ///
    /// Returns `(size_in_bytes, is_short_format)` where:
    /// - `size_in_bytes` is the number of bytes the value occupies
    /// - `is_short_format` is true if the value can fit in the 6-bit APCI data field
    pub fn size_in_bytes(&self) -> (usize, bool) {
        match *self {
            // Uint types (0-6): All are 1 byte, but only Uint1-Uint6 fit in short format
            Self::Uint1 | Self::Uint2 | Self::Uint3 | Self::Uint4 | Self::Uint5 | Self::Uint6 => (1, true),
            Self::Uint7 | Self::Byte1 => (1, false),
            Self::Byte2 => (2, false),
            Self::Byte3 => (3, false),
            Self::Byte4 => (4, false),
            Self::Byte5 => (5, false),
            Self::Byte6 => (6, false),
            Self::Byte7 => (7, false),
            Self::Byte8 => (8, false),
            Self::Byte9 => (9, false),
            Self::Byte10 => (10, false),
            Self::Byte11 => (11, false),
            Self::Byte12 => (12, false),
            Self::Byte13 => (13, false),
            Self::Byte14 => (14, false),
            Self::Byte15 => (15, false),
            Self::Byte252 => (252, false),
            // For Byte16-Byte248, the value is (enum_value - 6)
            _ => {
                let i: u8 = (*self).into();
                ((i as usize) - 6, false)
            }
        }
    }
}

/// A Communication object flags field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct ComObjectFlags(u8);

impl ComObjectFlags {
    pub const UE_FLAG_MASK: u8 = 0b10000000; // Update Enable flag
    pub const TE_FLAG_MASK: u8 = 0b01000000; // Transmission Enable flag
    pub const ROI_FLAG_MASK: u8 = 0b00100000; // Read on Init flag
    pub const WE_FLAG_MASK: u8 = 0b00010000; // Write Enable flag
    pub const RE_FLAG_MASK: u8 = 0b00001000; // Read Enable flag
    pub const CE_FLAG_MASK: u8 = 0b00000100; // Communication Enable flag

    const P_SHIFT: u8 = 0;
    const P_LEN: u8 = 2;
    const P_MAX: u8 = (1 << Self::P_LEN) - 1; // Max priority value (3)
    const P_MASK: u8 = Self::P_MAX << Self::P_SHIFT;

    /// Common group object configuration: Transmit to bus (T)
    pub const CONFIG_T: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, read from bus (RT)
    pub const CONFIG_RT: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::RE_FLAG_MASK;

    /// Common group object configuration: Receive from bus (WU)
    pub const CONFIG_WU: u8 = Self::CE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, receive, read from bus (RTWU)
    pub const CONFIG_RTWU: u8 =
        Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK | Self::RE_FLAG_MASK;
}

impl Default for ComObjectFlags {
    fn default() -> Self {
        // Default to CONFIG_RTWU - full communication capability
        Self(Self::CONFIG_RTWU | u8::from(Priority::Low))
    }
}

impl ComObjectFlags {
    /// Create ComObjectFlags from a raw byte value.
    #[inline]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Get the raw byte value of the flags.
    #[inline]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    #[inline]
    pub fn transmission_enable(&self) -> bool {
        self.0 & Self::TE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_on_init(&self) -> bool {
        self.0 & Self::ROI_FLAG_MASK != 0
    }

    #[inline]
    pub fn write_enable(&self) -> bool {
        self.0 & Self::WE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_enable(&self) -> bool {
        self.0 & Self::RE_FLAG_MASK != 0
    }

    #[inline]
    pub fn update_enable(&self) -> bool {
        self.0 & Self::UE_FLAG_MASK != 0
    }

    #[inline]
    pub fn communication_enable(&self) -> bool {
        self.0 & Self::CE_FLAG_MASK != 0
    }

    #[inline]
    pub fn priority(&self) -> Priority {
        let p = (self.0 & Self::P_MASK) >> Self::P_SHIFT;
        Priority::from(p)
    }

    /// Check if flags contain a specific flag pattern
    #[inline]
    pub fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) == flag
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ComObjectTableEntry {
    pub object_type: ComObjectType,
    pub flags: ComObjectFlags,
}

pub trait CommunicationObjectTable: HasLoadStateMachine {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    fn object(&self, idx: u16) -> Option<ComObjectTableEntry>;
    fn object_type(&self, idx: u16) -> Option<ComObjectType>;
    fn object_flags(&self, idx: u16) -> Option<ComObjectFlags>;

    /// Set the configuration flags for a communication object at runtime.
    ///
    /// Returns `true` if the flags were successfully set, `false` if the index is invalid.
    fn set_object_flags(&mut self, idx: u16, flags: ComObjectFlags) -> bool;
}

// ============================================================================
// Run State Machine Types
// ============================================================================

/// Lifecycle action produced when the run state machine crosses the
/// running/not-running boundary.
///
/// Sent to the [`DeviceModel`](crate::device_model::DeviceModel) via the
/// DM channel as a [`DeviceModelEvent::RunAction`](crate::device_model::DeviceModelEvent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAction {
    /// Application transitioned to RUNNING.
    Started,
    /// Application transitioned out of RUNNING.
    Stopped,
}

/// Trait for objects that have a run state machine.
///
/// This trait is separate from `HasLoadStateMachine` because the run state machine
/// has different semantics - it controls application execution rather than
/// data loading. The run state depends on the load state (app must be loaded
/// to run), so implementations typically need access to both.
pub trait HasRunStateMachine {
    /// Get the current run state.
    fn run_state(&self) -> RunState;

    /// Process a run state control command.
    ///
    /// The `data` buffer contains the run control event (first byte) followed
    /// by optional additional data (currently unused).
    ///
    /// Returns an optional [`RunAction`] if the transition crossed the
    /// running/not-running boundary.
    fn write_rsm(&mut self, data: &[u8]) -> Option<RunAction>;

    /// Handle an internal run event (Loaded, Unloaded, ReadyToRun).
    ///
    /// Called by the DeviceModel to cascade LSM actions into the RSM
    /// (e.g., `LoadEnd` → `RunEvent::Loaded`) or to fire delayed
    /// transitions (e.g., `ReadyToRun` after init delay).
    ///
    /// Returns an optional [`RunAction`] if the transition crossed the
    /// running/not-running boundary.
    fn handle_run_event(&mut self, event: RunEvent) -> Option<RunAction>;

    /// Read the current run state as a single byte.
    fn read_rsm(&self) -> [u8; 1] {
        [self.run_state().into()]
    }

    /// Check if the application is currently running.
    fn is_running(&self) -> bool {
        self.run_state() == RunState::Running
    }
}

/// Action produced by a load state machine transition.
///
/// Returned by [`HasLoadStateMachine::write_lsm`] so the caller can
/// orchestrate side effects (e.g., signaling the run state machine on
/// `LoadEnd` or `Unload`).
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum LoadAction {
    None,
    LoadStart,
    LoadEnd,
    Unload,
    Alloc,
}

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
pub struct McbData {
    pub requested_memory_size: U32,
    pub mode: u8,
    pub fill: u8,
    pub crc: U16,
}

// TODO: Add trait called InterfaceObject?
//       This can contain all the properties for this object
// TODO: Add trait MemoryAccessible which uses pointers of the objects and checks bounds when reading/writing raw?
//       Maybe not necessary as w already have TableMemory which could do this

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table<T: TableMemory> {
    // TODO: add alloc() and free() to TableMemory and use these instead of directly filling them? Would allow for Boxed Tables etc.
    pub(super) table: T,
    pub(super) state: LoadState,
    pub(super) mcb_table: PDT_Generic08,
    /// Base address of allocated memory, set during RelativeData allocation, cleared on unload
    pub(super) table_reference: u32,
    /// Last load error code (DPT_ErrorClass_System). Mirrors the LSM Err
    /// state — set when entering `LoadState::Err` and cleared on every
    /// transition out of it (per Resources spec 4.2.28).
    #[serde(default)]
    pub(super) last_error_code: u8,
}

impl<T: TableMemory> ConstDefault for Table<T> {
    const DEFAULT: Self = Table::new();
}

impl<T: TableMemory> Default for Table<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TableMemory> Table<T> {
    pub const fn new() -> Self {
        Self {
            table: T::DEFAULT,
            state: LoadState::Unloaded,
            mcb_table: PDT_Generic08::with_value([0; 8]),
            table_reference: 0,
            last_error_code: 0,
        }
    }

    /// Create a table with pre-loaded data, bypassing the load state machine.
    /// This is useful for compile-time configurations where the data is known at build time.
    ///
    /// # Arguments
    /// * `data` - The table data to preload
    /// * `table_reference` - The base address in the KNX device's virtual address space
    ///   for memory-mapped access by management clients
    pub fn with_data(data: &[u8], table_reference: u32) -> Self {
        let mut table = Self::new();
        table.table.data_ref_mut()[..data.len()].copy_from_slice(data);
        table.state = LoadState::Loaded;
        table.table_reference = table_reference;
        // Initialize MCB with data size and CRC
        let stored_mcb = McbData::mut_from_bytes(table.mcb_table.as_mut_bytes()).unwrap();
        stored_mcb.requested_memory_size.set(data.len() as u32);
        stored_mcb.mode = 0x00;
        stored_mcb.fill = 0xFF;
        stored_mcb.crc.set(crc16_ccitt(data));
        table
    }

    /// Get the current load state.
    pub fn load_state(&self) -> LoadState {
        self.state
    }

    /// Set the load state directly (for persistence restore).
    pub fn set_load_state(&mut self, state: LoadState) {
        self.state = state;
    }

    /// Get a reference to the MCB (Memory Control Block) bytes.
    pub fn mcb_bytes(&self) -> &[u8] {
        self.mcb_table.as_bytes()
    }

    /// Get a mutable reference to the MCB (Memory Control Block) bytes.
    pub fn mcb_bytes_mut(&mut self) -> &mut [u8] {
        self.mcb_table.as_mut_bytes()
    }

    /// Get the table reference (base address in KNX device's virtual address space).
    pub fn table_reference(&self) -> u32 {
        self.table_reference
    }

    /// Set the table reference (for persistence restore).
    pub fn set_table_reference(&mut self, reference: u32) {
        self.table_reference = reference;
    }

    fn next_state(event: LoadEvent, cur_state: LoadState) -> (LoadState, LoadAction) {
        match event {
            LoadEvent::NoOp => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Loaded, LoadAction::None),
                LoadState::Loading => (LoadState::Loading, LoadAction::None),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::StartLoading => match cur_state {
                LoadState::Unloaded => (LoadState::Loading, LoadAction::LoadStart),
                LoadState::Loaded => (LoadState::Loading, LoadAction::LoadStart),
                LoadState::Loading => (LoadState::Loading, LoadAction::None),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::LoadCompleted => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Loaded, LoadAction::None),
                LoadState::Loading => (LoadState::Loaded, LoadAction::LoadEnd),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::AdditionalLoadControls => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Err, LoadAction::None),
                LoadState::Loading => (LoadState::Loading, LoadAction::Alloc),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::Unload => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Loaded => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Loading => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Err => (LoadState::Unloaded, LoadAction::Unload),
            },
            // Unknown load events are ignored - state remains unchanged
            _ => (cur_state, LoadAction::None),
        }
    }
}

impl<T: TableMemory> HasLoadStateMachine for Table<T> {
    fn write_lsm(&mut self, mut buf: &[u8], alloc_address: Option<u32>) -> LoadAction {
        let mut buf = &mut buf;
        // An empty LOAD_STATE_CONTROL write carries no event — treat as a no-op.
        let event_byte = match buf.take_front(1) {
            Some(b) => b[0],
            None => return LoadAction::None,
        };
        let (mut new_state, action) = Self::next_state(event_byte.into(), self.state);

        match action {
            LoadAction::LoadStart => {}
            LoadAction::Alloc => {
                let mut additional_data = &mut buf.take_rest_front();

                match additional_data.take_byte_front().map(LoadSegment::from) {
                    Some(LoadSegment::RelativeData) => {
                        // Truncated RelativeData payload — the allocation descriptor
                        // is incomplete; treat the command as malformed.
                        let data = match additional_data.take_obj_front::<McbData>() {
                            Some(d) => d,
                            None => {
                                self.last_error_code = LoadError::UndefinedLoadCommand as u8;
                                self.state = LoadState::Err;
                                return LoadAction::None;
                            }
                        };

                        let req_mem_sz = data.requested_memory_size.get() as usize;
                        if req_mem_sz <= T::MAX_SIZE {
                            // Fill requested?
                            if data.mode & 1 != 0 {
                                self.table.data_ref_mut()[..req_mem_sz].fill(data.fill);
                            }

                            // Store the length in the MCB table
                            // CRC will be calculated later on LoadEnd
                            let stored_mcb = McbData::mut_from_bytes(self.mcb_table.as_mut_bytes()).unwrap();
                            stored_mcb.requested_memory_size = data.requested_memory_size;
                            stored_mcb.mode = 0x00;
                            stored_mcb.fill = 0xFF;
                            stored_mcb.crc.set(0xFFFF);

                            if let Some(addr) = alloc_address {
                                self.table_reference = addr;
                            }
                        } else {
                            // Allocation request larger than the table buffer.
                            new_state = LoadState::Err;
                            self.last_error_code = LoadError::MaxTableLengthExceeded as u8;
                        }
                    }
                    // Unknown segment type (or missing segment byte) — the load
                    // command is malformed.
                    _ => {
                        new_state = LoadState::Err;
                        self.last_error_code = LoadError::UndefinedLoadCommand as u8;
                    }
                }
            }
            LoadAction::LoadEnd => {
                let stored_mcb = McbData::mut_from_bytes(self.mcb_table.as_mut_bytes()).unwrap();
                stored_mcb
                    .crc
                    .set(crc16_ccitt(&self.table.data_ref()[0..(stored_mcb.requested_memory_size.get() as usize)]));
            }
            LoadAction::Unload => {
                self.mcb_table.set_value([0; 8]);
                self.table.data_ref_mut().fill(0);
                self.table_reference = 0;
            }
            LoadAction::None => {}
        }

        // Per Resources spec 4.2.28, PID_ERROR_CODE is reset to 0 once the
        // load state machine leaves the Err state. Apply the clear before
        // commit so any new error set in this same call (e.g., a fresh
        // Alloc failure right after Unload) is preserved.
        if self.state == LoadState::Err && new_state != LoadState::Err {
            self.last_error_code = LoadError::None as u8;
        }
        self.state = new_state;
        action
    }

    fn read_lsm(&self) -> [u8; 1] {
        [self.state.into()]
    }

    fn is_loaded(&self) -> bool {
        self.state == LoadState::Loaded
    }

    fn mcb_bytes(&self) -> &[u8] {
        self.mcb_table.as_bytes()
    }

    fn table_reference(&self) -> u32 {
        self.table_reference
    }

    fn last_error_code(&self) -> u8 {
        // Mirror the LSM Err state. The field is set on entry to Err and
        // cleared on every transition out, so a stale code never leaks.
        if self.state == LoadState::Err { self.last_error_code } else { 0 }
    }
}

impl<T: TableMemory> TableMemory for Table<T> {
    fn data_ref(&self) -> &[u8] {
        self.table.data_ref()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        self.table.data_ref_mut()
    }

    const MAX_SIZE: usize = T::MAX_SIZE;

    fn read(&self, offset: usize, data: &mut [u8]) {
        self.table.read(offset, data)
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.table.write(offset, data)
    }
}

// ============================================================================
// Runnable Application Wrapper
// ============================================================================

/// Wrapper that adds a Run State Machine to any HasLoadStateMachine.
///
/// This follows the same pattern as `Table<T>`:
/// - `Table<T>` wraps `TableMemory` and adds Load State Machine
/// - `RunnableApplication<T>` wraps `HasLoadStateMachine` and adds Run State Machine
///
/// The run state machine has the following states:
/// - HALTED (0x00): Application not running
/// - RUNNING (0x01): Application running
/// - READY (0x02): Intermediate state (conditions being checked)
/// - TERMINATED (0x03): Application explicitly stopped
///
/// The run state depends on the load state:
/// - Unloading forces run state to HALTED
/// - RESTART only transitions to RUNNING if loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnableApplication<T: HasLoadStateMachine> {
    /// The underlying loadable table
    pub(super) table: T,
    /// Run state for the application
    pub(super) run_state: RunState,
}

impl<T: HasLoadStateMachine + ConstDefault> ConstDefault for RunnableApplication<T> {
    const DEFAULT: Self = Self::new();
}

impl<T: HasLoadStateMachine + ConstDefault> Default for RunnableApplication<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: HasLoadStateMachine + ConstDefault> RunnableApplication<T> {
    /// Create a new runnable application in unloaded/halted state.
    pub const fn new() -> Self {
        Self { table: T::DEFAULT, run_state: RunState::Halted }
    }
}

impl<T: HasLoadStateMachine> RunnableApplication<T> {
    /// Create a runnable application from an existing loadable table.
    /// The run state will be HALTED initially.
    pub fn from_table(table: T) -> Self {
        Self { table, run_state: RunState::Halted }
    }

    /// Get a reference to the underlying loadable table.
    pub fn inner(&self) -> &T {
        &self.table
    }

    /// Get a mutable reference to the underlying loadable table.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.table
    }

    /// Compute the next run state based on the event.
    ///
    /// |                 | HALTED  | RUNNING | READY   | TERMINATED |
    /// |-----------------|---------|---------|---------|------------|
    /// | Ready (0)       | halted  | running | ready   | terminated |
    /// | Restart (1)     | halted  | ready   | ready   | halted     |
    /// | Stop (2)        | term    | term    | term    | term       |
    /// | Loaded (3)      | ready   | running | ready   | term       |
    /// | Unloaded (4)    | halted  | halted  | halted  | halted     |
    /// | ReadyToRun (5)  | halted  | running | running | term       |
    ///
    /// The spec's transition table additionally annotates some arms with
    /// loadStart/loadEnd actions; those are intentionally not modeled —
    /// the only consumer the stack needs is start/stop notification,
    /// which [`apply_event`](Self::apply_event) derives from the
    /// running/not-running boundary crossing instead.
    fn next_run_state(&self, event: RunEvent) -> RunState {
        match (self.run_state, event) {
            // Ready event - no-op, stay in current state
            (state, RunEvent::Ready) => state,

            // Restart command
            (RunState::Halted, RunEvent::Restart) => RunState::Halted,
            (RunState::Running, RunEvent::Restart) => RunState::Ready,
            (RunState::Ready, RunEvent::Restart) => RunState::Ready,
            (RunState::Terminated, RunEvent::Restart) => RunState::Halted,

            // Stop command
            (_, RunEvent::Stop) => RunState::Terminated,

            // Loaded event (from LSM)
            (RunState::Halted, RunEvent::Loaded) => RunState::Ready,
            (RunState::Running, RunEvent::Loaded) => RunState::Running,
            (RunState::Ready, RunEvent::Loaded) => RunState::Ready,
            (RunState::Terminated, RunEvent::Loaded) => RunState::Terminated,

            // Unloaded event (from LSM)
            (_, RunEvent::Unloaded) => RunState::Halted,

            // ReadyToRun event (startup delay complete)
            (RunState::Halted, RunEvent::ReadyToRun) => RunState::Halted,
            (RunState::Running, RunEvent::ReadyToRun) => RunState::Running,
            (RunState::Ready, RunEvent::ReadyToRun) => RunState::Running,
            (RunState::Terminated, RunEvent::ReadyToRun) => RunState::Terminated,

            // Unknown events - no change
            (state, RunEvent::Other(_)) => state,
        }
    }

    /// Apply a run event and return a [`RunAction`] if the running state
    /// crossed the running/not-running boundary.
    fn apply_event(&mut self, event: RunEvent) -> Option<RunAction> {
        let was_running = self.is_running();
        self.run_state = self.next_run_state(event);
        match (was_running, self.is_running()) {
            (false, true) => Some(RunAction::Started),
            (true, false) => Some(RunAction::Stopped),
            _ => None,
        }
    }
}

// Delegate TableMemory to inner table
impl<T: HasLoadStateMachine + TableMemory> TableMemory for RunnableApplication<T> {
    fn data_ref(&self) -> &[u8] {
        self.table.data_ref()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        self.table.data_ref_mut()
    }

    const MAX_SIZE: usize = T::MAX_SIZE;

    fn read(&self, offset: usize, data: &mut [u8]) {
        self.table.read(offset, data)
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.table.write(offset, data)
    }
}

// Pure delegation — no LSM→RSM cascade. The cascade is orchestrated by
// the ApplicationProgramObject.
impl<T: HasLoadStateMachine> HasLoadStateMachine for RunnableApplication<T> {
    fn write_lsm(&mut self, buf: &[u8], alloc_address: Option<u32>) -> LoadAction {
        self.table.write_lsm(buf, alloc_address)
    }

    fn read_lsm(&self) -> [u8; 1] {
        self.table.read_lsm()
    }

    fn is_loaded(&self) -> bool {
        self.table.is_loaded()
    }

    fn mcb_bytes(&self) -> &[u8] {
        self.table.mcb_bytes()
    }

    fn table_reference(&self) -> u32 {
        self.table.table_reference()
    }

    fn last_error_code(&self) -> u8 {
        self.table.last_error_code()
    }
}

impl<T: HasLoadStateMachine> HasRunStateMachine for RunnableApplication<T> {
    fn run_state(&self) -> RunState {
        self.run_state
    }

    fn write_rsm(&mut self, data: &[u8]) -> Option<RunAction> {
        if data.is_empty() {
            return None;
        }

        let event = RunEvent::from(data[0]);
        self.apply_event(event)
    }

    fn handle_run_event(&mut self, event: RunEvent) -> Option<RunAction> {
        self.apply_event(event)
    }
}

pub mod addr7;
pub mod app;
pub mod asso6;
pub mod co7;

// Re-export commonly-used concrete table types so consumers can write
// `objects::tables::AddrTab7` instead of `objects::tables::addr7::AddrTab7`.
pub use addr7::{AddrTab7, AddrTab7Impl};
pub use app::{Application, PeiApplication};
pub use asso6::{AssoTab6, AssoTab6Impl};
pub use co7::{CoTab7, CoTab7Impl};

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that every `u8` value round-trips through `ComObjectType::from` and
    /// back to `u8`.  This test is the safety guard for the `transmute` in
    /// `From<u8> for ComObjectType`: if a variant is ever removed, the gap will
    /// cause this test to fail rather than silently producing undefined behaviour at
    /// runtime.
    #[test]
    fn test_com_object_type_roundtrip() {
        for v in 0u8..=255 {
            let cot = ComObjectType::from(v);
            let back: u8 = cot.into();
            assert_eq!(back, v, "ComObjectType round-trip failed for value {v}");
        }
    }
}
