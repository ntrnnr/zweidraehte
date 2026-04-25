use core::cell::RefCell;

use zweidraehte_proto::dpt::DatapointType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Status of a communication object
///
/// Defined in KNX 03/04/01 3.2 - Communication flags
///
/// BCU1/BCU2 flag byte format:
/// - Bit 6: Idle indicator (1 = idle, 0 = transmitting)
/// - Bit 3: Update flag
/// - Bit 2: Read request pending
/// - Bit 1: Write/Transmit request pending
/// - Bit 0: Error flag (1 = error, 0 = ok)
#[derive(Default)]
pub enum ComObjectStatus {
    /// Object was updated remotely (0x48)
    Updated,

    /// Read request pending (0x44).
    ///
    /// Set when a read request is issued and after successful L2 transmission.
    /// The object stays in this state until a `GroupValue_Response` arrives
    /// (transitioning to `Updated`) or until the application resets it.
    ReadRequest,

    /// Read request failed (transmission error or disabled) (0x45)
    ReadRequestError,

    /// Write request was issued (0x02)
    WriteRequest,

    /// Write request failed (transmission error or disabled) (0x41)
    WriteRequestError,

    /// Read or Write request is currently handled (0x02)
    Busy,

    /// Object is idle (0x40)
    IdleOk,

    /// Object encountered an error during last requested bus transaction (0x41)
    IdleError,

    /// Object is currently uninitialized
    #[default]
    Uninitialized,
}

impl ComObjectStatus {
    /// Convert status to a BCU1-style flags byte.
    ///
    /// Format (8 bits):
    /// - Bit 6: Idle indicator (1 = idle, 0 = transmitting)
    /// - Bit 3: Update flag
    /// - Bit 2: Read request pending
    /// - Bit 1: Write/Transmit request pending (BCU1 style)
    /// - Bit 0: Error flag (1 = error, 0 = ok)
    ///
    /// Common values:
    /// - 0x40: IdleOk
    /// - 0x41: IdleError
    /// - 0x42: Busy/Transmitting (WriteRequest pending)
    /// - 0x44: ReadRequest pending (idle)
    /// - 0x48: Updated
    pub fn to_flags_byte(&self) -> u8 {
        match self {
            ComObjectStatus::IdleOk => 0x40,            // Idle, OK
            ComObjectStatus::IdleError => 0x41,         // Idle, Error
            ComObjectStatus::Busy => 0x02,              // Transmitting (not idle)
            ComObjectStatus::WriteRequest => 0x02,      // Transmitting (not idle)
            ComObjectStatus::WriteRequestError => 0x41, // Idle, Error (write failed)
            ComObjectStatus::ReadRequest => 0x44,       // Idle + Read request pending
            ComObjectStatus::ReadRequestError => 0x45,  // Idle + Read request pending + Error
            ComObjectStatus::Updated => 0x48,           // Idle + Updated
            ComObjectStatus::Uninitialized => 0x40,     // Treat as IdleOk
        }
    }

    /// Create status from a BCU1-style flags byte.
    ///
    /// Format (8 bits):
    /// - Bit 7: Set command (when writing, 1 = set flags, 0 = clear/read)
    /// - Bit 6: Idle indicator (ignored when parsing)
    /// - Bit 3: Update flag
    /// - Bit 2: Read request pending
    /// - Bit 1: Write/Transmit request pending
    /// - Bit 0: Error flag (1 = error, 0 = ok)
    ///
    /// This is the inverse of `to_flags_byte()`.
    pub fn from_flags_byte(flags: u8) -> Self {
        // Check special flags first (read request and update take priority)
        if flags & 0x04 != 0 {
            ComObjectStatus::ReadRequest
        } else if flags & 0x08 != 0 {
            ComObjectStatus::Updated
        } else if flags & 0x02 != 0 {
            // Write/Transmit request pending
            ComObjectStatus::WriteRequest
        } else if flags & 0x01 != 0 {
            ComObjectStatus::IdleError
        } else {
            ComObjectStatus::IdleOk
        }
    }

    /// Check if the object is idle (not transmitting).
    ///
    /// Returns true if the object can accept a new write/read request.
    /// Returns false if a transmission is in progress.
    pub fn is_idle(&self) -> bool {
        // Bit 6 of the flags byte is the idle indicator (1 = idle, 0 = transmitting)
        self.to_flags_byte() & 0x40 != 0
    }
}

/// A trait for communication object values to abstract over different DatapointTypes
pub trait ComObjectValueType: Clone + Default + AsRef<[u8]> + AsMut<[u8]> + Sized {}

// Implement the trait for all DatapointType instances
impl<T, const MAIN: u16, const SUB: u16> ComObjectValueType for DatapointType<T, MAIN, SUB>
where
    T: Clone + Default,
    DatapointType<T, MAIN, SUB>: Clone + Default + AsRef<[u8]> + AsMut<[u8]>,
{
}

/// Generic communication object with value of type T
pub struct ComObject<T: ComObjectValueType> {
    /// The actual value
    pub value: T,

    /// Status byte containing transmission state and flags
    pub status: ComObjectStatus,
}

impl<T: ComObjectValueType> ComObject<T> {
    pub fn new(value: T) -> Self {
        Self { value, status: ComObjectStatus::default() }
    }
}

pub struct ComObjectInfo<'a> {
    pub status: &'a ComObjectStatus,
    pub value: &'a [u8],
}

// ============================================================================
// Multi-Ref Communication Object Storage
// ============================================================================

/// Raw byte storage for multi-ref communication objects.
///
/// This type is used when a communication object can have multiple DPT interpretations
/// (via ComObjectRefs). The size is auto-derived by the proc macro from the maximum
/// size across all ref DPT types.
///
/// # Example
///
/// A comm object with refs for `DPT_Switch` (1 byte), `DPT_Scaling` (1 byte),
/// `DPT_Value_Temp` (2 bytes), and `DPT_Colour_RGB` (3 bytes) would use
/// `ComObjectStorage<3>` since 3 is the maximum size.
#[derive(Clone, Copy)]
pub struct ComObjectStorage<const SIZE: usize> {
    data: [u8; SIZE],
}

impl<const SIZE: usize> Default for ComObjectStorage<SIZE> {
    fn default() -> Self {
        Self { data: [0u8; SIZE] }
    }
}

impl<const SIZE: usize> AsRef<[u8]> for ComObjectStorage<SIZE> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const SIZE: usize> AsMut<[u8]> for ComObjectStorage<SIZE> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const SIZE: usize> ComObjectValueType for ComObjectStorage<SIZE> {}

impl<const SIZE: usize> ComObjectStorage<SIZE> {
    /// Create a new storage with zeroed data.
    pub const fn new() -> Self {
        Self { data: [0u8; SIZE] }
    }

    /// Get the raw data bytes.
    pub fn data(&self) -> &[u8; SIZE] {
        &self.data
    }

    /// Get the raw data bytes mutably.
    pub fn data_mut(&mut self) -> &mut [u8; SIZE] {
        &mut self.data
    }

    /// Interpret the storage as a typed reference.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `T` has size <= `SIZE`
    /// - The storage contains valid data for type `T`
    /// - `T` is properly aligned (most DPT types are 1-byte aligned)
    #[inline]
    pub unsafe fn as_typed<T>(&self) -> &T {
        debug_assert!(core::mem::size_of::<T>() <= SIZE);
        unsafe { &*(self.data.as_ptr() as *const T) }
    }

    /// Interpret the storage as a mutable typed reference.
    ///
    /// # Safety
    ///
    /// Same requirements as `as_typed`.
    #[inline]
    pub unsafe fn as_typed_mut<T>(&mut self) -> &mut T {
        debug_assert!(core::mem::size_of::<T>() <= SIZE);
        unsafe { &mut *(self.data.as_mut_ptr() as *mut T) }
    }

    /// Write a typed value into the storage.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `T` has size <= `SIZE`
    /// - `T` is properly aligned
    #[inline]
    pub unsafe fn write_typed<T: AsRef<[u8]>>(&mut self, value: &T) {
        let bytes = value.as_ref();
        debug_assert!(bytes.len() <= SIZE);
        self.data[..bytes.len()].copy_from_slice(bytes);
    }
}

/// Typed wrapper for accessing a communication object with a specific DPT type.
///
/// This struct provides type-safe access to a comm object's value when you know
/// which DPT interpretation is active (e.g., from a selector parameter). The const
/// generic `INDEX` carries the ASAP index for use with stack operations.
///
/// # Usage
///
/// ```rust,ignore
/// // Generated by the EtsComObjects macro when matching on a selector:
/// match params.button_mode.comm_objects(&mut comm_objs) {
///     ButtonModeSelectorObjs::Switch { mut output, status } => {
///         // output is TypedComObj<'_, DPT_Switch, 1>
///         let current = output.get().value();
///         output.set(DPT_Switch::from(!current));
///
///         // Use the index with stack methods
///         stack.update_object(TypedComObj::<_, 1>::index(), output.get()).await;
///     },
///     // ...
/// }
/// ```
pub struct TypedComObj<'a, T: ComObjectValueType, const INDEX: u16> {
    storage: &'a mut [u8],
    status: &'a mut ComObjectStatus,
    _phantom: core::marker::PhantomData<T>,
}

impl<'a, T: ComObjectValueType, const INDEX: u16> TypedComObj<'a, T, INDEX> {
    /// Create a new typed comm object wrapper.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The storage slice has at least `size_of::<T>()` bytes
    /// - The storage contains valid data for type `T`
    #[inline]
    pub unsafe fn new(storage: &'a mut [u8], status: &'a mut ComObjectStatus) -> Self {
        debug_assert!(storage.len() >= core::mem::size_of::<T>());
        Self { storage, status, _phantom: core::marker::PhantomData }
    }

    /// Get a typed reference to the value.
    #[inline]
    pub fn get(&self) -> &T {
        unsafe { &*(self.storage.as_ptr() as *const T) }
    }

    /// Get a mutable typed reference to the value.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *(self.storage.as_mut_ptr() as *mut T) }
    }

    /// Set the value.
    #[inline]
    pub fn set(&mut self, value: T) {
        self.storage[..core::mem::size_of::<T>()].copy_from_slice(value.as_ref());
    }

    /// Get the ASAP index for use with stack methods.
    #[inline]
    pub const fn index() -> u16 {
        INDEX
    }

    /// Get the current status.
    #[inline]
    pub fn status(&self) -> ComObjectStatus {
        *self.status
    }

    /// Set the status.
    #[inline]
    pub fn set_status(&mut self, status: ComObjectStatus) {
        *self.status = status;
    }
}

pub struct ComObjectInfoMut<'a> {
    pub status: &'a mut ComObjectStatus,
    pub value: &'a mut [u8],
}

pub const trait ComObjectIndex: Clone + Sized {
    fn from_index(idx: u16) -> Option<Self>;
    fn index(&self) -> u16;
}

/// Trait for managing communication objects in a KNX application.
pub trait ComObjects {
    type Index: ComObjectIndex;

    fn new() -> Self;
    fn info<'a>(&'a self, idx: u16) -> ComObjectInfo<'a>;
    fn info_mut<'a>(&'a mut self, idx: u16) -> ComObjectInfoMut<'a>;

    #[inline]
    fn status(&self, idx: u16) -> ComObjectStatus {
        let info = self.info(idx);
        *info.status
    }

    #[inline]
    fn set_status(&mut self, idx: u16, status: ComObjectStatus) {
        let info = self.info_mut(idx);
        *info.status = status;
    }

    #[inline]
    fn value(&self, idx: u16) -> &[u8] {
        let info = self.info(idx);
        info.value
    }

    #[inline]
    fn value_mut(&mut self, idx: u16) -> &mut [u8] {
        let info = self.info_mut(idx);
        info.value
    }

    /// Acknowledge that an update has been processed by the application.
    ///
    /// This clears the `Updated` status flag, transitioning the object to `IdleOk`.
    /// Call this after your application has handled a `ComObjectEvent::Updated` event
    /// to indicate that the new value has been processed.
    ///
    /// Only affects objects in `Updated` status; other statuses are left unchanged.
    #[inline]
    fn acknowledge_update(&mut self, idx: u16) {
        if self.status(idx) == ComObjectStatus::Updated {
            self.set_status(idx, ComObjectStatus::IdleOk);
        }
    }

    /// Reset all communication objects to their initial state.
    ///
    /// Clears all values and sets all statuses back to `Uninitialized`.
    /// Called when the application starts running, ensuring read-on-init
    /// correctly re-reads values from the bus after a reload.
    #[inline]
    fn reset(&mut self)
    where
        Self: Sized,
    {
        *self = Self::new();
    }
}

/// Opt-in bus-inbound hook for comm-object containers.
///
/// The application layer calls [`prepare_read`](Self::prepare_read) before
/// serving an incoming `GroupValue_Read` and
/// [`handle_write`](Self::handle_write) after processing an incoming
/// `GroupValue_Write` or `GroupValue_Response`. The vast majority of
/// devices don't need either hook — the ETS-macro-generated containers
/// rely on the empty defaults below.
///
/// Devices that do need the hooks (e.g. BCU1-style shadow objects in
/// the conformance harness) override them on their concrete
/// `ComObjects` type. Any references to other stack state the hook
/// needs (e.g. the CoTab for runtime flag mutation) must be held by the
/// implementing type directly — the trait deliberately has no
/// associated "context" type so that the `ComObjects` trait itself
/// stays minimal.
pub trait ComObjectBusHook {
    /// Called synchronously just before a `GroupValue_Read` response
    /// is serialised. Typical use: populate a synthesised value into
    /// `self` that mirrors some other live state.
    #[inline]
    fn prepare_read(&mut self, _idx: u16) {}

    /// Called synchronously immediately after a bus-originated update
    /// to the object at `idx`. The new value has already been written
    /// into `self` and the status set to `Updated`. Typical use:
    /// propagate the write elsewhere (side-effect another object,
    /// mutate a live CoTab entry, …).
    #[inline]
    fn handle_write(&mut self, _idx: u16) {}
}

/// Trait for device states that provide access to communication objects.
///
/// Mirrors `HasAddressTable` / `HasAssociationTable` — device states that
/// hold comm objects implement this so that layers and augments can access
/// group object values through the state reference.
pub trait HasCommObjects {
    /// The concrete communication objects type.
    type CO: ComObjects;

    /// Get a reference to the communication objects.
    fn comm_objects(&self) -> &RefCell<Self::CO>;
}

/// Per-destination required security policy view.
///
/// Producers in the Application Layer (group sends, future spontaneous
/// P2P writes, broadcasts) consult this trait through the device state to
/// stamp [`RequiredSecurity`] onto outbound messages. The Secure Application
/// Layer reads the stamp at outbox drain and applies the §5.5.3.x decision
/// tree (03/03/07) — encrypt with the appropriate key, or send plaintext.
///
/// All methods default to [`RequiredSecurity::Plain`]. Insecure device
/// states satisfy the trait with an empty `impl` block:
///
/// ```ignore
/// impl HasGoSecurityView for MyInsecureState {}
/// ```
///
/// Secure device states override the methods to consult Security IO state
/// (`PID_GO_SECURITY_FLAGS`, P2P key table, security mode flag) and return
/// the spec-correct level per ASAP / peer IA / destination type. Keeping
/// the default at `Plain` rather than `Unspecified` guarantees that an
/// insecure-stack call site always emits plaintext deterministically;
/// `Unspecified` only carries meaning on secure stacks where it lets the
/// reactive `respond_to` propagation inherit the indication's stamp.
///
/// The trait deliberately exposes no Security IO types so the plain
/// Application Layer compiles without any `HasSecurityState` bound.
///
/// [`RequiredSecurity`]: zweidraehte_proto::messages::knx::RequiredSecurity
pub trait HasGoSecurityView {
    /// Required security for sending from this ASAP (originating GO).
    ///
    /// Per 03/05/01 §6.3.15.3 Table 108: the GO Server uses the GO's
    /// configured `auth`/`conf` bits as `par_auth`/`par_conf` for
    /// `A_GroupValue_Write.req`, `A_GroupValue_Read.req`, and
    /// `A_GroupValue_Read.res`. NOTE 111: the response uses the GO's
    /// own flags, *not* the flags of the initiating request — so callers
    /// pass the *responding* ASAP for read responses.
    fn required_security_for_asap(&self, _asap: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        zweidraehte_proto::messages::knx::RequiredSecurity::Plain
    }

    /// Required security for a P2P-addressed send to `peer_ia`.
    ///
    /// Per 03/03/07 §5.5.3.x: if the peer has an entry in the P2P Key
    /// Table, the spec mandates Auth+Conf (the table holds a single key
    /// without auth/conf granularity). Absent → plaintext.
    fn required_security_for_p2p(&self, _peer_ia: u16) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        zweidraehte_proto::messages::knx::RequiredSecurity::Plain
    }

    /// Required security for a broadcast / system-broadcast send.
    ///
    /// Spontaneous broadcasts that the spec marks as plain (e.g.
    /// `A_NetworkParameter_InfoReport` security reports per 03/05/01
    /// §6.3.11.4) explicitly stamp [`RequiredSecurity::Plain`].
    /// Reactive broadcast responses (e.g. `IndividualAddressResponse`
    /// to a secure `IndividualAddressRead`) propagate the indication's
    /// stamp via `MessageBuilder::respond_to` or by chaining
    /// `.with_required_security(ind.required_security())` when the
    /// destination is broadcast (which precludes `respond_to`).
    ///
    /// [`RequiredSecurity::Plain`]: zweidraehte_proto::messages::knx::RequiredSecurity::Plain
    fn required_security_for_broadcast(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        zweidraehte_proto::messages::knx::RequiredSecurity::Plain
    }

    /// Required security for spontaneous tool-key-encrypted send.
    ///
    /// Tool access uses the configured Tool Key. When security mode is
    /// enabled the spec mandates Auth+Conf for tool-channel traffic; in
    /// factory state the tool key is zero and traffic is plain.
    fn required_security_for_tool_access(&self) -> zweidraehte_proto::messages::knx::RequiredSecurity {
        zweidraehte_proto::messages::knx::RequiredSecurity::Plain
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComObjectEvent {
    /// A communication object was updated remotely by a GroupValueWrite
    Updated,

    /// A communication object was updated locally
    LocallyUpdated,

    /// A remote device requested to read this communication object's value
    Read,

    /// A response to a read request was received
    ReadResponse,
}

/// Events emitted when a program lifecycle state changes.
///
/// These events are published through
/// [`Stack::lifecycle_events()`](crate::Stack::lifecycle_events) whenever a
/// run state machine transitions into or out of the RUNNING state, including
/// transitions caused by load state machine cascades (e.g., ETS programming
/// completing and automatically starting the application).
///
/// Both the Application Program Object and the PEI Program Object have run
/// state machines and emit their own pair of events. User code targeting
/// modern devices should typically only react to the `Application*` variants;
/// the `Pei*` variants are surfaced for completeness so that tools observing
/// the full ETS programming cascade can see both halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleEvent {
    /// The application program transitioned to RUNNING.
    ///
    /// This is the appropriate time to:
    /// - Read ETS parameters and configure application behavior
    /// - Set initial output states
    /// - Send initial group value read requests for status objects
    /// - Start periodic timers
    ApplicationStarted,

    /// The application program transitioned out of RUNNING (to HALTED, READY, or TERMINATED).
    ///
    /// This is the appropriate time to:
    /// - Stop timers and periodic tasks
    /// - Set outputs to a safe state
    /// - Clean up application-level resources
    ApplicationStopped,

    /// The PEI (Physical External Interface) program transitioned to RUNNING.
    ///
    /// PEI is vestigial on modern devices — this event is surfaced for
    /// observability but has no required user-side handling.
    PeiStarted,

    /// The PEI program transitioned out of RUNNING.
    PeiStopped,

    /// The application layer's read-on-init scan has settled — either it
    /// ran to completion (`ReadOnInitState::Done`) or the preconditions
    /// weren't met on this startup and the state machine stayed `Idle`.
    ///
    /// Fires exactly once per AL startup cycle, from
    /// `GroupDataProvider::poll`. The guard flag resets when the app
    /// transitions back out of the running state, so a subsequent
    /// startup re-fires the event.
    ///
    /// Observers:
    /// - The conformance IPC harness uses this to know when it can
    ///   transition from "draining startup ROI frames" to step-driven
    ///   mode. User code rarely needs to care — `ApplicationStarted`
    ///   and comm-object events cover the vast majority of startup
    ///   scenarios.
    ReadOnInitComplete,
}
