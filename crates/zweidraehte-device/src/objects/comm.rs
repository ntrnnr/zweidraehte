use core::cell::RefCell;

use crate::dpt::DatapointType;

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
    /// Context type for hooks. Use `()` if not needed.
    type HookContext: Default;

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

    /// Called before reading an object's value.
    #[inline]
    fn prepare_read(&mut self, _idx: u16, _ctx: &Self::HookContext) {
        // Default: no-op
    }

    /// Called after writing an object's value.
    #[inline]
    fn handle_write(&mut self, _idx: u16, _ctx: &Self::HookContext) {
        // Default: no-op
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

    /// Get a reference to the hook context for communication object hooks.
    fn hook_context(&self) -> &<Self::CO as ComObjects>::HookContext;
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

/// Events emitted when the application lifecycle state changes.
///
/// These events are published through [`Stack::lifecycle_events()`](crate::Stack::lifecycle_events) whenever the
/// run state machine transitions into or out of the RUNNING state, including
/// transitions caused by load state machine cascades (e.g., ETS programming
/// completing and automatically starting the application).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// The application transitioned to RUNNING.
    ///
    /// This is the appropriate time to:
    /// - Read ETS parameters and configure application behavior
    /// - Set initial output states
    /// - Send initial group value read requests for status objects
    /// - Start periodic timers
    ApplicationStarted,

    /// The application transitioned out of RUNNING (to HALTED, READY, or TERMINATED).
    ///
    /// This is the appropriate time to:
    /// - Stop timers and periodic tasks
    /// - Set outputs to a safe state
    /// - Clean up application-level resources
    ApplicationStopped,
}
