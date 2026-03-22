use core::cell::RefCell;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    big_endian::{U16, U32},
};

use crate::{
    address::GroupAddress,
    dpt::PDT_Generic08,
    messages::knx::Priority,
    util::{crc::crc16_ccitt, packets::BufferView},
};

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
    fn max_size() -> usize;
    fn data_ref(&self) -> &[u8];
    fn data_ref_mut(&mut self) -> &mut [u8];
    fn read(&self, offset: usize, data: &mut [u8]);
    fn write(&mut self, offset: usize, data: &[u8]);
}

pub trait HasLoadStateMachine: TableMemory {
    /// Process a load state machine command.
    ///
    /// # Arguments
    /// * `buf` - Load control data (event byte followed by segment data for allocation)
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation.
    fn write_lsm(&mut self, buf: &[u8], alloc_address: Option<u32>);
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
}

pub trait AddressTable: HasLoadStateMachine {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    fn get_address(&self, tsap: u16) -> Option<GroupAddress>;
    fn get_tsap(&self, address: GroupAddress) -> Option<u16>;
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
    fn get_sending_tsap(&self, asap: u16) -> Option<u16>;

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
        // SAFETY: This is safe because the enum is repr(u8) and all values for all variants are defined
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

    fn get_object(&self, idx: u16) -> Option<ComObjectTableEntry>;
    fn object_type(&self, idx: u16) -> Option<ComObjectType>;
    fn object_flags(&self, idx: u16) -> Option<ComObjectFlags>;

    /// Set the configuration flags for a communication object at runtime.
    ///
    /// Returns `true` if the flags were successfully set, `false` if the index is invalid.
    fn set_object_flags(&mut self, idx: u16, flags: ComObjectFlags) -> bool;
}

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum LoadState: u8 {
        Unloaded        , 0x00, "Unloaded";
        Loaded          , 0x01, "Loaded";
        Loading         , 0x02, "Loading";
        Err             , 0x03, "Error";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadEvent: u8 {
        NoOp                    , 0x00, "NoOp";
        StartLoading            , 0x01, "StartLoading";
        LoadCompleted           , 0x02, "LoadCompleted";
        AdditionalLoadControls  , 0x03, "AdditionalLoadControls";
        Unload                  , 0x04, "Unload";
        Err                     , 0x05, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

// ============================================================================
// Run State Machine Types
// ============================================================================

// Run state machine states for the Application Program Object.
//
// The run state machine controls the execution state of the application program.
// It interacts with the load state machine - the application can only run when loaded.
//
// States:
// - `Halted` (0x00): Application is halted (not running). Default state when unloaded.
// - `Running` (0x01): Application is running normally.
// - `Ready` (0x02): Intermediate state - conditions being checked before running.
// - `Terminated` (0x03): Application explicitly stopped via RUNCONTROL_STOP.
create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum RunState: u8 {
        Halted          , 0x00, "Halted";
        Running         , 0x01, "Running";
        Ready           , 0x02, "Ready";
        Terminated      , 0x03, "Terminated";
    }
);

// Run control events for PID_RUN_STATE_CONTROL (0x06).
//
// These events control the run state machine transitions:
// - `Ready` (0x00): No operation - state remains unchanged.
// - `Restart` (0x01): Restart the application.
// - `Stop` (0x02): Stop the application. Transitions to Terminated state.
// - `Loaded` (0x03): Internal event - signaled when load state machine completes loading.
// - `Unloaded` (0x04): Internal event - signaled when load state machine unloads.
// - `ReadyToRun` (0x05): Internal event - startup delay complete, can transition to Running.
create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum RunEvent: u8 {
        Ready           , 0x00, "Ready";
        Restart         , 0x01, "Restart";
        Stop            , 0x02, "Stop";
        Loaded          , 0x03, "Loaded";
        Unloaded        , 0x04, "Unloaded";
        ReadyToRun      , 0x05, "ReadyToRun";
        _,                      "Unknown Run Event 0x{:x}";
    }
);

/// Lifecycle action produced by a run state machine transition.
///
/// Used by the device model to react to application start/stop transitions.
/// The composition layer detects transitions by comparing `is_running()`
/// before and after dispatching messages through the layer stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunAction {
    /// No lifecycle change.
    #[default]
    None,
    /// Application transitioned to RUNNING.
    Started,
    /// Application transitioned out of RUNNING.
    Stopped,
}

impl RunAction {
    /// Derive the lifecycle action from a before/after `is_running()` comparison.
    pub fn from_transition(was_running: bool, is_running: bool) -> Self {
        match (was_running, is_running) {
            (false, true) => RunAction::Started,
            (true, false) => RunAction::Stopped,
            _ => RunAction::None,
        }
    }
}

/// Result of a run state machine transition (internal).
///
/// Used within `RunnableApplication` to track both the new state and
/// the action produced by the transition table. The action is consumed
/// internally by the cascade logic.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RunStateResult {
    /// The new run state.
    pub state: RunState,
    /// The internal action from the transition table.
    pub action: RunStateAction,
}

/// Internal actions from the run state transition table.
///
/// These are consumed by `RunnableApplication`'s cascade logic and
/// are not exposed outside the module. The external-facing lifecycle
/// action is [`RunAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunStateAction {
    /// No action needed.
    None,
    /// App is stopping — set device control bit 0.
    LoadStart,
    /// App initialization complete — ready to run.
    LoadEnd,
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
    /// Returns the resulting run state after processing the event.
    fn write_rsm(&mut self, data: &[u8]) -> RunState;

    /// Read the current run state as a single byte.
    fn read_rsm(&self) -> [u8; 1] {
        [self.run_state().into()]
    }

    /// Check if the application is currently running.
    fn is_running(&self) -> bool {
        self.run_state() == RunState::Running
    }

    /// Initialize the run state machine at startup.
    ///
    /// This should be called when the stack starts up. If the application
    /// is already loaded (from persistent storage), this will transition
    /// the run state machine to RUNNING.
    ///
    /// 1. If app is loaded: HALTED → READY (via Loaded event)
    /// 2. Then immediately: READY → RUNNING (via ReadyToRun event)
    fn init_run_state(&mut self);
}

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadSegment: u8 {
        AbsoluteData            , 0x00, "AbsoluteData";
        AbsoluteStack           , 0x01, "AbsoluteStack";
        AbsoluteTask            , 0x02, "AbsoluteTask";
        AbsolutePointer         , 0x03, "AbsolutePointer";
        TaskCtrl1               , 0x04, "TaskCtrl1";
        TaskCtrl2               , 0x05, "TaskCtrl2";
        RelativeData            , 0x0b, "RelativeData";
        Err                     , 0x0c, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

/// Internal action to perform during load state machine transitions.
/// This is purely internal and never serialized/deserialized from the wire.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LoadAction {
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
    fn write_lsm(&mut self, mut buf: &[u8], alloc_address: Option<u32>) {
        let mut buf = &mut buf;
        let (mut new_state, action) = Self::next_state(buf.take_front(1).unwrap()[0].into(), self.state);

        match action {
            LoadAction::LoadStart => {}
            LoadAction::Alloc => {
                let mut additional_data = &mut buf.take_rest_front();

                match additional_data.take_byte_front().map(LoadSegment::from) {
                    Some(LoadSegment::RelativeData) => {
                        let data = additional_data.take_obj_front::<McbData>().unwrap();

                        let req_mem_sz = data.requested_memory_size.get() as usize;
                        if req_mem_sz <= T::max_size() {
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
                            new_state = LoadState::Err;
                        }
                    }
                    _ => new_state = LoadState::Err,
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

        self.state = new_state;
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
}

impl<T: TableMemory> TableMemory for Table<T> {
    fn data_ref(&self) -> &[u8] {
        self.table.data_ref()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        self.table.data_ref_mut()
    }

    fn max_size() -> usize {
        T::max_size()
    }

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

    /// Compute the next run state and action based on event.
    ///
    /// |                 | HALTED          | RUNNING         | READY           | TERMINATED      |
    /// |-----------------|-----------------|-----------------|-----------------|-----------------|
    /// | Ready (0)       | halted, none    | running, none   | ready, none     | terminated, none|
    /// | Restart (1)     | halted, unload  | ready, loadStart| ready, unload   | halted, unload  |
    /// | Stop (2)        | term, none      | term, loadStart | term, none      | term, none      |
    /// | Loaded (3)      | ready, none     | running, none   | ready, none     | term, none      |
    /// | Unloaded (4)    | halted, none    | halted, loadStart| halted, none   | halted, none    |
    /// | ReadyToRun (5)  | halted, none    | running, none   | running, loadEnd| term, none      |
    fn next_run_state_with_action(&self, event: RunEvent) -> RunStateResult {
        match (self.run_state, event) {
            // Ready event - no-op, stay in current state
            (state, RunEvent::Ready) => RunStateResult { state, action: RunStateAction::None },

            // Restart command
            (RunState::Halted, RunEvent::Restart) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }
            (RunState::Running, RunEvent::Restart) => {
                RunStateResult { state: RunState::Ready, action: RunStateAction::LoadStart }
            }
            (RunState::Ready, RunEvent::Restart) => {
                RunStateResult { state: RunState::Ready, action: RunStateAction::None }
            }
            (RunState::Terminated, RunEvent::Restart) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }

            // Stop command
            (RunState::Halted, RunEvent::Stop) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::None }
            }
            (RunState::Running, RunEvent::Stop) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::LoadStart }
            }
            (RunState::Ready, RunEvent::Stop) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::None }
            }
            (RunState::Terminated, RunEvent::Stop) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::None }
            }

            // Loaded event (from LSM)
            (RunState::Halted, RunEvent::Loaded) => RunStateResult { state: RunState::Ready, action: RunStateAction::None },
            (RunState::Running, RunEvent::Loaded) => {
                RunStateResult { state: RunState::Running, action: RunStateAction::None }
            }
            (RunState::Ready, RunEvent::Loaded) => RunStateResult { state: RunState::Ready, action: RunStateAction::None },
            (RunState::Terminated, RunEvent::Loaded) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::None }
            }

            // Unloaded event (from LSM)
            (RunState::Halted, RunEvent::Unloaded) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }
            (RunState::Running, RunEvent::Unloaded) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::LoadStart }
            }
            (RunState::Ready, RunEvent::Unloaded) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }
            (RunState::Terminated, RunEvent::Unloaded) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }

            // ReadyToRun event (startup delay complete)
            (RunState::Halted, RunEvent::ReadyToRun) => {
                RunStateResult { state: RunState::Halted, action: RunStateAction::None }
            }
            (RunState::Running, RunEvent::ReadyToRun) => {
                RunStateResult { state: RunState::Running, action: RunStateAction::None }
            }
            (RunState::Ready, RunEvent::ReadyToRun) => {
                RunStateResult { state: RunState::Running, action: RunStateAction::LoadEnd }
            }
            (RunState::Terminated, RunEvent::ReadyToRun) => {
                RunStateResult { state: RunState::Terminated, action: RunStateAction::None }
            }

            // Unknown events - no change
            (state, RunEvent::Other(_)) => RunStateResult { state, action: RunStateAction::None },
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

    fn max_size() -> usize {
        T::max_size()
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        self.table.read(offset, data)
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.table.write(offset, data)
    }
}

// Delegate HasLoadStateMachine to inner table, but also signal internal RSM events
impl<T: HasLoadStateMachine> HasLoadStateMachine for RunnableApplication<T> {
    fn write_lsm(&mut self, buf: &[u8], alloc_address: Option<u32>) {
        let was_loaded = self.table.is_loaded();

        // Process the load event on the inner table
        self.table.write_lsm(buf, alloc_address);

        let is_loaded = self.table.is_loaded();

        // Signal internal events to run state machine based on load state change
        if !was_loaded && is_loaded {
            // Just became loaded - signal Loaded event, then immediately ReadyToRun
            let result = self.next_run_state_with_action(RunEvent::Loaded);
            self.run_state = result.state;

            // If now in READY, immediately signal ReadyToRun to start the app
            if self.run_state == RunState::Ready {
                let result = self.next_run_state_with_action(RunEvent::ReadyToRun);
                self.run_state = result.state;
                // Note: result.action would be LoadEnd if app started - caller can check is_running()
            }
        } else if was_loaded && !is_loaded {
            // Just became unloaded - signal Unloaded event
            let result = self.next_run_state_with_action(RunEvent::Unloaded);
            self.run_state = result.state;
        }
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
}

// Implement HasRunStateMachine
impl<T: HasLoadStateMachine> HasRunStateMachine for RunnableApplication<T> {
    fn run_state(&self) -> RunState {
        self.run_state
    }

    fn write_rsm(&mut self, data: &[u8]) -> RunState {
        if data.is_empty() {
            return self.run_state;
        }

        let event = RunEvent::from(data[0]);
        let result = self.next_run_state_with_action(event);
        self.run_state = result.state;
        // Note: result.action contains the side effect to perform (LoadStart, LoadEnd, Unload)
        // The caller can use write_rsm_with_action() if they need the action
        self.run_state
    }

    fn init_run_state(&mut self) {
        // 1. Start with current state (could be HALTED or preserved from storage)
        // 2. If app is loaded: signal Loaded event (HALTED → READY)
        // 3. Immediately signal ReadyToRun (READY → RUNNING)
        if self.table.is_loaded() {
            // Signal Loaded event - transitions HALTED → READY
            let result = self.next_run_state_with_action(RunEvent::Loaded);
            self.run_state = result.state;

            // If now in READY, immediately signal ReadyToRun to start the app
            if self.run_state == RunState::Ready {
                let result = self.next_run_state_with_action(RunEvent::ReadyToRun);
                self.run_state = result.state;
            }
        }
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
