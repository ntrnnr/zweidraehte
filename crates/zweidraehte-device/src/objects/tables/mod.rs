use core::cell::RefCell;
use core::marker::PhantomData;

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    big_endian::{U16, U32},
};

use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::dpt::PDT_Generic08;
use zweidraehte_proto::messages::apdu::load_control::load_control_transition;
use zweidraehte_proto::util::{crc::crc16_ccitt, packets::BufferView};

// The load/run-state machine protocol values and pure load transition live in
// `zweidraehte-proto`. Re-exported so the device-side and downstream
// `firmware/` paths (`objects::tables::LoadState`, the prelude) keep working
// without those crates taking a direct `zweidraehte-proto` dependency. Runtime
// state ownership and the run-state machine remain here.
pub use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
pub use zweidraehte_proto::messages::apdu::load_control::{
    LoadAction, LoadEvent, LoadSegment, LoadState, RunEvent, RunState,
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
    /// [`ApplicationImpl`](crate::objects::tables::app::ApplicationImpl) wrapping a typed
    /// struct) override this with a saturating variant.
    fn read(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.data_ref()[offset..offset + data.len()]);
    }

    /// Copy `data.len()` bytes of `data` into the table starting at
    /// `offset`. See [`read`](Self::read) for the bounds-handling contract.
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.data_ref_mut()[offset..offset + data.len()].copy_from_slice(data);
    }

    /// Whether an absolute-segment allocation of `len` bytes is
    /// acceptable for this table.
    ///
    /// The default bounds segments by the table's own capacity. The
    /// application program overrides this to accept any length: on
    /// System 7 its load state machine owns *all* the application's
    /// segments — the group object table and the parameters — and each
    /// region is bounds-checked by its own memory window at write
    /// time, not by the allocation record.
    fn accepts_segment(len: usize) -> bool {
        len <= Self::MAX_SIZE
    }

    /// Clear the table's payload for a load-state-machine Unload.
    ///
    /// The Unload event only declares the loadable data invalid — "the
    /// data is undefined", and clients "shall not rely on the fact that
    /// the table is erased in memory" (03/05/01 §4.23.2.3.2, §4.5.3) —
    /// so zeroing is our chosen rendering of "undefined", not a spec
    /// obligation. Table types whose memory window co-locates a
    /// *different* resource override this to spare it: the RT8 address
    /// table keeps the device's Individual Address slot.
    fn clear_on_unload(&mut self) {
        self.data_ref_mut().fill(0);
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

    /// Set the virtual base address surfaced through
    /// `PID_TABLE_REFERENCE`.
    fn set_table_reference(&mut self, reference: u32);

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

// ============================================================================
// Load-control policies
// ============================================================================

/// How a [`Table`] answers the `AdditionalLoadControls` (03h) load event.
///
/// The event itself is profile-neutral, but the segment records it carries
/// are not: System B allocates its tables with *Data Relative Allocation*
/// (segment type 0Bh) while System 7 uses the absolute-segment records of
/// the classic BCU2/BIM lineage (types 00h–05h) — 06 Profiles v02.02.01
/// Annex A.2.4.1 Table 7 makes each set mandatory for one family and n/a
/// for the other. The policy is a zero-sized compile-time strategy so a
/// device binary carries only the record handling its profile needs.
pub trait LoadControlPolicy {
    /// Handle the payload following the `AdditionalLoadControls` event
    /// byte: `[segment_type:1][...record...]`.
    ///
    /// On success the policy has updated the MCB (requested size) and,
    /// where the record carries or implies one, the table reference. On
    /// failure the caller moves the load state machine to `Err` with the
    /// returned code.
    fn handle_alloc<T: TableMemory>(
        table: &mut T,
        mcb_table: &mut PDT_Generic08,
        table_reference: &mut u32,
        additional_data: &[u8],
        alloc_address: Option<u32>,
    ) -> Result<(), LoadError>;
}

/// System B allocation: *Data Relative Allocation* (segment type 0Bh,
/// 03/05/01 Resources §4.23.2). The record is an [`McbData`]; the device
/// assigns the virtual address (`alloc_address`) itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativeAlloc;

impl LoadControlPolicy for RelativeAlloc {
    fn handle_alloc<T: TableMemory>(
        table: &mut T,
        mcb_table: &mut PDT_Generic08,
        table_reference: &mut u32,
        mut additional_data: &[u8],
        alloc_address: Option<u32>,
    ) -> Result<(), LoadError> {
        // `BufferView` is implemented on `&mut &[u8]`, so the cursor the
        // take_* methods advance is a mutable borrow of the slice binding.
        let mut additional_data = &mut additional_data;

        match additional_data.take_byte_front().map(LoadSegment::from) {
            Some(LoadSegment::RelativeData) => {
                // Truncated RelativeData payload — the allocation descriptor
                // is incomplete; treat the command as malformed.
                let data = additional_data.take_obj_front::<McbData>().ok_or(LoadError::UndefinedLoadCommand)?;

                let req_mem_sz = data.requested_memory_size.get() as usize;
                if req_mem_sz > T::MAX_SIZE {
                    // Allocation request larger than the table buffer.
                    return Err(LoadError::MaxTableLengthExceeded);
                }

                // Fill requested?
                if data.mode & 1 != 0 {
                    table.data_ref_mut()[..req_mem_sz].fill(data.fill);
                }

                // Store the length in the MCB table
                // CRC will be calculated later on LoadEnd
                let stored_mcb = McbData::mut_from_bytes(mcb_table.as_mut_bytes())
                    .expect("McbData is 8 unaligned bytes, matching PDT_Generic08");
                stored_mcb.requested_memory_size = data.requested_memory_size;
                stored_mcb.mode = 0x00;
                stored_mcb.fill = 0xFF;
                stored_mcb.crc.set(0xFFFF);

                if let Some(addr) = alloc_address {
                    *table_reference = addr;
                }
                Ok(())
            }
            // Unknown segment type (or missing segment byte) — the load
            // command is malformed.
            _ => Err(LoadError::UndefinedLoadCommand),
        }
    }
}

/// System 7 allocation: the absolute-segment records of 03/05/02 §3.31
/// `DM_LoadStateMachineWrite` — mandatory for masks 0701h/0705h per
/// 06 Profiles v02.02.01 Annex A.2.4.1 Table 7.
///
/// `AllocAbsDataSeg` (type 00h) carries, after the type octet
/// (03/05/02 §3.31.3):
///
/// ```text
/// [start_address:2BE][length:2BE][access_attributes:1]
/// [memory_type:1][memory_attributes:1][reserved 00h]
/// ```
///
/// The start address becomes the table reference (the segments are fixed
/// in the profile's absolute memory map, so nothing is allocated — the
/// record is acknowledged and recorded). Access attributes carry the
/// write level in bits 0–3 and the read level in bits 4–7; memory type
/// bits 0–2 name the memory class (3 = EEPROM). The task/pointer records
/// (types 01h–05h) exist for the legacy BCU firmware's entry points and
/// are accepted as no-ops. `RelativeData` (0Bh) is not part of this
/// profile family and is rejected.
// TODO: memory_attributes bit 7 requests checksum control for the
// segment (03/05/02 §3.31.3); ETS sends it set (80h) — wire it to the
// MCB's CRC handling when checksum verification is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsoluteAlloc;

impl LoadControlPolicy for AbsoluteAlloc {
    fn handle_alloc<T: TableMemory>(
        _table: &mut T,
        mcb_table: &mut PDT_Generic08,
        table_reference: &mut u32,
        mut additional_data: &[u8],
        _alloc_address: Option<u32>,
    ) -> Result<(), LoadError> {
        // See `RelativeAlloc::handle_alloc` on the cursor shape.
        let mut additional_data = &mut additional_data;

        match additional_data.take_byte_front().map(LoadSegment::from) {
            Some(LoadSegment::AbsoluteData) => {
                let start_address =
                    additional_data.take_obj_front::<U16>().ok_or(LoadError::UndefinedLoadCommand)?.get();
                let length = additional_data.take_obj_front::<U16>().ok_or(LoadError::UndefinedLoadCommand)?.get();
                // access attributes / memory type / memory attributes /
                // reserved follow; nothing in them changes what this
                // device does with the segment, so they are not decoded.

                if !T::accepts_segment(length as usize) {
                    return Err(LoadError::MaxTableLengthExceeded);
                }

                let stored_mcb = McbData::mut_from_bytes(mcb_table.as_mut_bytes())
                    .expect("McbData is 8 unaligned bytes, matching PDT_Generic08");
                stored_mcb.requested_memory_size.set(length as u32);
                stored_mcb.mode = 0x00;
                stored_mcb.fill = 0xFF;
                stored_mcb.crc.set(0xFFFF);

                *table_reference = start_address as u32;
                Ok(())
            }
            Some(
                LoadSegment::AbsoluteStack
                | LoadSegment::AbsoluteTask
                | LoadSegment::AbsolutePointer
                | LoadSegment::TaskCtrl1
                | LoadSegment::TaskCtrl2,
            ) => Ok(()),
            _ => Err(LoadError::UndefinedLoadCommand),
        }
    }
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

    /// Whether this table requests a read when the application starts.
    ///
    /// Bit 5 has this meaning only in System B's RT7 descriptor. Other
    /// families can still issue startup reads from application code, but
    /// their table implementation must not interpret bit 5 as this flag.
    fn read_on_init(&self, _idx: u16) -> bool {
        false
    }

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
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct Table<T: TableMemory, P: LoadControlPolicy = RelativeAlloc> {
    // TODO: add alloc() and free() to TableMemory and use these instead of directly filling them? Would allow for Boxed Tables etc.
    pub(super) table: T,
    pub(super) state: LoadState,
    pub(super) mcb_table: PDT_Generic08,
    /// Base address of the table in the device's management address space:
    /// assigned by the device during relative allocation, or taken from the
    /// absolute-segment record. Cleared on unload.
    pub(super) table_reference: u32,
    /// Last load error code (DPT_ErrorClass_System). Mirrors the LSM Err
    /// state — set when entering `LoadState::Err` and cleared on every
    /// transition out of it (per Resources spec 4.2.28).
    #[serde(default)]
    pub(super) last_error_code: u8,
    #[serde(skip)]
    pub(super) _policy: PhantomData<P>,
}

impl<T: TableMemory, P: LoadControlPolicy> ConstDefault for Table<T, P> {
    const DEFAULT: Self = Table::new();
}

impl<T: TableMemory, P: LoadControlPolicy> Default for Table<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TableMemory, P: LoadControlPolicy> Table<T, P> {
    pub const fn new() -> Self {
        Self {
            table: T::DEFAULT,
            state: LoadState::Unloaded,
            mcb_table: PDT_Generic08::with_value([0; 8]),
            table_reference: 0,
            last_error_code: 0,
            _policy: PhantomData,
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
        let stored_mcb = McbData::mut_from_bytes(table.mcb_table.as_mut_bytes())
            .expect("McbData is 8 unaligned bytes, matching PDT_Generic08");
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
}

impl<T: TableMemory, P: LoadControlPolicy> HasLoadStateMachine for Table<T, P> {
    fn write_lsm(&mut self, mut buf: &[u8], alloc_address: Option<u32>) -> LoadAction {
        let mut buf = &mut buf;
        // An empty LOAD_STATE_CONTROL write carries no event — treat as a no-op.
        let event_byte = match buf.take_front(1) {
            Some(b) => b[0],
            None => return LoadAction::None,
        };
        let (mut new_state, action) = load_control_transition(self.state, event_byte.into());

        match action {
            LoadAction::LoadStart => {}
            LoadAction::Alloc => {
                let additional_data = buf.take_rest_front();
                if let Err(code) = P::handle_alloc(
                    &mut self.table,
                    &mut self.mcb_table,
                    &mut self.table_reference,
                    additional_data,
                    alloc_address,
                ) {
                    new_state = LoadState::Err;
                    self.last_error_code = code as u8;
                }
            }
            LoadAction::LoadEnd => {
                let stored_mcb = McbData::mut_from_bytes(self.mcb_table.as_mut_bytes())
                    .expect("McbData is 8 unaligned bytes, matching PDT_Generic08");
                // The CRC covers the loaded data, but the allocated
                // length is client-supplied and need not match this
                // table's buffer: `ApplicationImpl` accepts segments of
                // any size because on System 7 its machine allocates
                // the group object table and the parameter segments,
                // which live in other tables' memory windows. Clamping
                // keeps a client from indexing past the buffer (a
                // bus-reachable panic) — the CRC is then over what this
                // table actually holds, which is all it can attest to.
                let data = self.table.data_ref();
                let covered = (stored_mcb.requested_memory_size.get() as usize).min(data.len());
                stored_mcb.crc.set(crc16_ccitt(&data[0..covered]));
            }
            LoadAction::Unload => {
                self.mcb_table.set_value([0; 8]);
                self.table.clear_on_unload();
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

    fn set_table_reference(&mut self, reference: u32) {
        self.table_reference = reference;
    }

    fn last_error_code(&self) -> u8 {
        // Mirror the LSM Err state. The field is set on entry to Err and
        // cleared on every transition out, so a stale code never leaks.
        if self.state == LoadState::Err { self.last_error_code } else { 0 }
    }
}

impl<T: TableMemory, P: LoadControlPolicy> TableMemory for Table<T, P> {
    fn data_ref(&self) -> &[u8] {
        self.table.data_ref()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        self.table.data_ref_mut()
    }

    const MAX_SIZE: usize = T::MAX_SIZE;

    fn accepts_segment(len: usize) -> bool {
        T::accepts_segment(len)
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
    /// Run state for the application.
    ///
    /// Deliberately not persisted: 03/05/01 §4.24.2.2 requires the run state
    /// to live in volatile memory, and Table 97 note d) has every reset start
    /// the machine in `Halted`. Carrying `Terminated` across a device restart
    /// would defeat both, and would block the power-up cascade in
    /// `SystemBDeviceModel::init`. Interface-object writes to PID 6 are
    /// already exempt from `mark_dirty` for the same reason — see the
    /// volatile-PID list in `bcus::system_b::objects::dispatch`.
    #[serde(skip, default = "run_state_at_reset")]
    pub(super) run_state: RunState,
}

/// The run state every device reset starts from (03/05/01 §4.24.2.3.3 note d).
///
/// A `serde` default path rather than `impl Default for RunState`: there is no
/// such thing as a default run state in the protocol, only a state after reset.
fn run_state_at_reset() -> RunState {
    RunState::Halted
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

    /// Compute the next run state, per 03/05/01 §4.24.2.3.3 Table 97.
    ///
    /// | Event                   | HALTED  | RUNNING | READY   | TERMINATED |
    /// |-------------------------|---------|---------|---------|------------|
    /// | NOP (0)                 | halted  | running | ready   | terminated |
    /// | Restart (1), loaded     | running | running | running | running    |
    /// | Restart (1), unloaded   | halted  | halted  | halted  | halted     |
    /// | Stop (2), loaded        | term    | term    | term    | term       |
    /// | Stop (2), unloaded      | halted  | halted  | halted  | halted     |
    /// | Loaded (internal)       | ready   | running | ready   | term       |
    /// | Unloaded (internal)     | halted  | halted  | halted  | halted     |
    /// | ReadyToRun (internal)   | halted  | running | running | term       |
    /// | unknown                 | halted  | running | ready   | terminated |
    ///
    /// Whether the executable part is loaded is not a modifier the spec
    /// bolts on — Table 97 gives Restart and Device-Restart a row each for
    /// loaded and unloaded, with opposite outcomes, and note c) scopes Stop
    /// the same way ("the event Stop shall always lead to the state
    /// Terminated; this shall only be possible if the corresponding Load
    /// State Machine is in the state Loaded"). Vendor conformance case 2.2.4
    /// tests exactly that: STOP against an unloaded application must answer
    /// HALTED, not TERMINATED.
    ///
    /// Restart-when-loaded is spelled `I:Halted → I:Ready → M:Running` in the
    /// table; only `Running` is mandatory, and §4.24.2.4 notes the
    /// intermediates "may never appear". Ours never do — the application has
    /// no start-up work to perform, so collapsing the chain into a single
    /// transition is both simpler and required by case 2.5.2, which pins the
    /// write response to RUNNING with no wildcard.
    ///
    /// `Starting` (04h) and `ShuttingDown` (05h) are unimplemented for the
    /// same reason: Table 95 makes them mandatory only when the executable
    /// part needs more than two seconds to start or stop.
    ///
    /// Table 97 additionally annotates some arms with loadStart/loadEnd
    /// actions; those are intentionally not modeled — the only consumer the
    /// stack needs is start/stop notification, which
    /// [`apply_event`](Self::apply_event) derives instead.
    fn next_run_state(&self, event: RunEvent) -> RunState {
        // One of the run conditions of §4.24.2.3.4: the executable part can
        // only start while its Load State Machine says Loaded.
        let loaded = self.table.is_loaded();

        match (self.run_state, event) {
            // NOP - stay in current state
            (state, RunEvent::Ready) => state,

            // Restart command. Loaded, the application really does stop and
            // start again, from every state including Terminated — Table 95
            // makes Restart one of the two ways out of Terminated.
            (_, RunEvent::Restart) if loaded => RunState::Running,
            (_, RunEvent::Restart) => RunState::Halted,

            // Stop command, see note c) above.
            (_, RunEvent::Stop) if loaded => RunState::Terminated,
            (_, RunEvent::Stop) => RunState::Halted,

            // Loaded event (from LSM). Figure 65 draws this as the
            // Halted → Ready arrow; the onward Ready → Running step is the
            // run-condition check, which arrives as `ReadyToRun`. Starting
            // the application here instead would fire `RunAction::Started`
            // on every segment of an ETS download.
            (RunState::Halted, RunEvent::Loaded) => RunState::Ready,
            (RunState::Running, RunEvent::Loaded) => RunState::Running,
            (RunState::Ready, RunEvent::Loaded) => RunState::Ready,
            (RunState::Terminated, RunEvent::Loaded) => RunState::Terminated,

            // Unloaded event (from LSM)
            (_, RunEvent::Unloaded) => RunState::Halted,

            // ReadyToRun event (run conditions evaluated). Terminated is
            // deliberately sticky: Table 95 says a terminated executable part
            // "shall no longer start automatically".
            (RunState::Halted, RunEvent::ReadyToRun) => RunState::Halted,
            (RunState::Running, RunEvent::ReadyToRun) => RunState::Running,
            (RunState::Ready, RunEvent::ReadyToRun) => RunState::Running,
            (RunState::Terminated, RunEvent::ReadyToRun) => RunState::Terminated,

            // "Unknown events shall be ignored" (§4.24.2.3.3).
            (state, RunEvent::Other(_)) => state,
        }
    }

    /// Apply a run event and return a [`RunAction`] if the application
    /// started or stopped.
    fn apply_event(&mut self, event: RunEvent) -> Option<RunAction> {
        let was_running = self.is_running();
        self.run_state = self.next_run_state(event);
        match (was_running, self.is_running()) {
            (false, true) => Some(RunAction::Started),
            (true, false) => Some(RunAction::Stopped),
            // A Restart that lands in RUNNING from RUNNING crosses no
            // boundary we can observe, but Table 97 routes it through the
            // intermediate Halted and Ready states — the application did stop
            // and start again. Report it, so the device model resets the
            // communication objects and re-arms read-on-init. This is the
            // path an ETS download ends on.
            (true, true) if event == RunEvent::Restart => Some(RunAction::Started),
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

    fn accepts_segment(len: usize) -> bool {
        T::accepts_segment(len)
    }

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

    fn set_table_reference(&mut self, reference: u32) {
        self.table.set_table_reference(reference);
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

        // Only NOP, Restart and Stop can be written to PID_RUN_STATE_CONTROL
        // (03/05/01 §4.24.2.3.2 Table 96). `RunEvent` continues past those to
        // carry the machine's internal events, whose values overlap the same
        // byte space, so decoding the wire byte with `RunEvent::from` would
        // let a management client drive `Loaded`, `Unloaded` or `ReadyToRun`
        // from the bus. Everything outside the three defined writes is an
        // unknown event, and §4.24.2.3.3 says unknown events are ignored.
        let event = match data[0] {
            b @ 0x00..=0x02 => RunEvent::from(b),
            b => RunEvent::Other(b),
        };
        self.apply_event(event)
    }

    fn handle_run_event(&mut self, event: RunEvent) -> Option<RunAction> {
        self.apply_event(event)
    }
}

pub mod addr7;
pub mod addr8;
pub mod app;
pub mod asso6;
pub mod asso8;
pub mod co7;
pub mod co_system7;

// Re-export commonly-used concrete table types so consumers can write
// `objects::tables::AddrTab7` instead of `objects::tables::addr7::AddrTab7`.
pub use addr7::{AddrTab7, AddrTab7Impl};
pub use addr8::{AddrTab8, AddrTab8Impl};
pub use app::{Application, PeiApplication};
pub use asso6::{AssoTab6, AssoTab6Impl};
pub use asso8::{AssoTab8, AssoTab8Impl};
pub use co_system7::{System7ComObjectTable, System7ComObjectTableImpl};
pub use co7::{CoTab7, CoTab7Alloc, CoTab7Impl};

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Load-control policies
    // ------------------------------------------------------------------

    /// 32-byte AddrTab7 buffer as a stand-in table for policy tests.
    type RelTable = Table<AddrTab7Impl<32>, RelativeAlloc>;
    type AbsTable = Table<AddrTab7Impl<32>, AbsoluteAlloc>;

    /// `AllocAbsDataSeg` (03/05/02 §3.31): the start address becomes the
    /// table reference, the length lands in the MCB, and the state
    /// machine stays in `Loading`.
    #[test]
    fn absolute_alloc_records_reference_and_size() {
        let mut table = AbsTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // [event][type 00h][start 4000h][length 0010h][access][memtype][memattr][reserved]
        table.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x40, 0x00, 0x00, 0x10, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        assert_eq!(table.load_state(), LoadState::Loading);
        assert_eq!(table.table_reference(), 0x4000);
        let mcb = McbData::ref_from_bytes(HasLoadStateMachine::mcb_bytes(&table)).expect("MCB is 8 bytes");
        assert_eq!(mcb.requested_memory_size.get(), 0x10);
    }

    /// The application program's load state machine accepts absolute
    /// segments larger than its own params buffer: on System 7 it owns
    /// the group object table and the parameter block together, and the
    /// records only acknowledge the product database's fixed layout.
    /// The reference tracks the last record (our generator emits the
    /// parameter segment last).
    // TODO: record-order independence — match the params segment by
    // its product address instead of relying on emission order, once a
    // second System 7 product exercises a different procedure shape.
    #[test]
    fn application_accepts_multiple_absolute_segments() {
        let mut app = Application::<u64, AbsoluteAlloc>::new();
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // GO table segment: 14 bytes at 4200h — larger than the 8-byte
        // params struct, still accepted.
        app.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x42, 0x00, 0x00, 0x0E, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        assert_eq!(app.read_lsm(), [u8::from(LoadState::Loading)]);
        // Parameter segment: 8 bytes at 4300h.
        app.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x43, 0x00, 0x00, 0x08, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        assert_eq!(app.read_lsm(), [u8::from(LoadState::Loading)]);
        assert_eq!(app.table_reference(), 0x4300, "last record wins");
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(app.read_lsm(), [u8::from(LoadState::Loaded)]);
    }

    /// Completing a load whose last allocation is larger than the
    /// table's own buffer must not panic: the MCB's CRC is computed
    /// over the buffer, and the allocated length is client-supplied.
    ///
    /// Regression — a System 7 download that allocates the group
    /// object table segment (35 bytes) on the application machine of a
    /// product with no parameters (zero-length buffer) used to index
    /// past the slice and take the device down from the bus.
    #[test]
    fn load_completed_clamps_the_crc_to_the_table_buffer() {
        // `()` is a zero-length params struct: no parameters at all.
        let mut app = Application::<(), AbsoluteAlloc>::new();
        app.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // 35 bytes at 4200h — the group object table's segment.
        app.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x42, 0x00, 0x00, 0x23, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        app.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(app.read_lsm(), [u8::from(LoadState::Loaded)]);
    }

    /// Unload zeroes a plain table's whole blob — the default
    /// `clear_on_unload`. (The RT8 address table overrides it to spare
    /// its co-located Individual Address slot; see `addr8`.)
    #[test]
    fn unload_zeroes_plain_table() {
        let mut table = AbsTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        table.write(0, &[0xAA; 8]);
        table.write_lsm(&[LoadEvent::Unload.into()], None);
        assert_eq!(table.load_state(), LoadState::Unloaded);
        assert!(table.data_ref().iter().all(|&b| b == 0));
    }

    /// Task/pointer records only carry the legacy BCU firmware's entry
    /// points — accepted without any state change.
    #[test]
    fn absolute_alloc_accepts_task_records_as_noops() {
        let mut table = AbsTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        for segment_type in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            table.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), segment_type, 0, 0, 0, 0, 0, 0, 0, 0, 0], None);
            assert_eq!(table.load_state(), LoadState::Loading, "segment type {segment_type:#04x}");
        }
        assert_eq!(table.table_reference(), 0);
    }

    /// A RelativeData record under the absolute policy is a foreign
    /// profile's mechanism — undefined load command.
    #[test]
    fn absolute_alloc_rejects_relative_data() {
        let mut table = AbsTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        table.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0, 0, 0, 16, 0, 0, 0xFF, 0xFF], None);
        assert_eq!(table.load_state(), LoadState::Err);
        assert_eq!(table.last_error_code(), LoadError::UndefinedLoadCommand as u8);
    }

    /// The mirror image: an absolute-segment record under the relative
    /// policy (the System B default) stays rejected, as before the
    /// policies were split.
    #[test]
    fn relative_alloc_rejects_absolute_segment() {
        let mut table = RelTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        table.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x40, 0x00, 0x00, 0x10, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        assert_eq!(table.load_state(), LoadState::Err);
        assert_eq!(table.last_error_code(), LoadError::UndefinedLoadCommand as u8);
    }

    /// An absolute allocation larger than the backing buffer must fail
    /// the same way a relative one does.
    #[test]
    fn absolute_alloc_over_capacity_errors() {
        let mut table = AbsTable::new();
        table.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // length 0x0100 > MAX_SIZE 32
        table.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x40, 0x00, 0x01, 0x00, 0xFF, 0x03, 0x80, 0x00],
            None,
        );
        assert_eq!(table.load_state(), LoadState::Err);
        assert_eq!(table.last_error_code(), LoadError::MaxTableLengthExceeded as u8);
    }
}
