//! Standard Interface Object implementations
//!
//! This module provides implementations for the standard KNX interface objects.
//! These can be used directly or as a reference for custom implementations.
//!
//! # Object Types
//!
//! - [`DeviceObject`] - Device Object (Type 0) - Basic device information
//! - [`AddressTableObject`] - Address Table Object (Type 1) - Group address table
//! - [`AssociationTableObject`] - Association Table Object (Type 2) - TSAP/ASAP mapping
//! - [`ApplicationProgramObject`] - Application Program Object (Type 3)
//! - [`RouterObject`] - Router Object (Type 6) - For line/backbone couplers
//!
//! # Table Objects
//!
//! Table objects share a common implementation via [`TableInterfaceObject<T, S>`] where:
//! - `T` is the underlying table type (implementing [`HasLoadStateMachine`])
//! - `S` is a marker type implementing [`TableObjectSpec`] that provides object-specific constants
//!
//! Type aliases are provided for convenience:
//! - [`AddressTableObject<T>`] = `TableInterfaceObject<T, AddressTableSpec>`
//! - [`AssociationTableObject<T>`] = `TableInterfaceObject<T, AssociationTableSpec>`
//! - [`GroupObjectTableObject<T>`] = `TableInterfaceObject<T, GroupObjectTableSpec>`

use core::cell::RefCell;
use core::marker::PhantomData;

use zweidraehte_proto::dpt::PDT_Control;

use crate::StackState;
use crate::device_model::{DeviceModelEvent, DeviceModelNotifier, RunTarget};
use crate::objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadAction, RunEvent};
use zweidraehte_proto::device::DeviceDescriptor;
use zweidraehte_proto::dpt::{
    DeviceControl, InterfaceObjectType, KNXVersion, PDT_Generic02, PDT_Generic04, PDT_Generic05, PDT_Generic06,
    PDT_Generic08, PDT_Generic10, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong, PDT_Version, ProgrammingMode,
    PropertyDataDefinition, RoutingCount,
};

use super::{
    ArrayPropertyWithPrefixRead, ArrayPropertyWithPrefixWrite, InterfaceObject, PropertyAccess, PropertyDescriptor,
    PropertyError, PropertyRead, WriteResponse, interface_object, pid,
};
use zweidraehte_proto::access::AccessPolicy;

// ============================================================================
// Device Object (Object Type 0)
// ============================================================================

/// Device Object - Object Type 0
///
/// The Device Object contains basic device information and is mandatory
/// for all KNX devices. It is always Object Index 0.
///
/// This implementation holds a reference to the stack state for dynamic
/// properties like individual address components.
///
/// # Properties
///
/// | PID | Name | Type | Access |
/// |-----|------|------|--------|
/// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
/// | 11 | Serial Number | PDT_GENERIC_06 | RO | (state-backed)
/// | 12 | Manufacturer ID | PDT_UNSIGNED_INT | RO | (derived from serial number bytes 0-1)
/// | 14 | Device Control | DeviceControl | RW |
/// | 15 | Order Info | PDT_GENERIC_10 | RO |
/// | 25 | Version | PDT_GENERIC_02 | RO |
/// | 51 | Routing Count | RoutingCount | RW |
/// | 54 | Programming Mode | ProgrammingMode | RW |
/// | 56 | Max APDU Length | PDT_UNSIGNED_INT | RO | (state-backed)
/// | 57 | Subnet Address | PDT_UNSIGNED_CHAR | RO |
/// | 58 | Device Address | PDT_UNSIGNED_CHAR | RO |
/// | 78 | Hardware Type | PDT_GENERIC_06 | RW |
/// | 83 | Device Descriptor | PDT_UNSIGNED_INT | RO |
//
// Access levels per Profiles spec Annex A.2.3, covering System B masks
// 07B0h / 17B0h / 57B0h. Where the three masks disagree we take the union
// (most permissive) so the same struct can back any System B device.
//
// Levels name their audience ([`AccessLevel`]) rather than the number
// Annex A prints, because Annex A's tables are in the 4-level notation
// whatever the mask's own model (§A.1.2.1 NOTE 2) and its `3` therefore
// stands for two different audiences. Every `3` here is `Runtime` — the
// level a connection holds before it authorises, so a read or write
// granted at 3 is one granted to everybody, which is what these rows
// mean and what stays true at 16 levels.
//
// Notable choices:
//  - PID 14 PID_DEVICE_CONTROL: RW, written at `Runtime`. Spec lists
//    `3/3` for 07B0h/17B0h and `3/x` (RO) for 57B0h, but ETS writes the
//    verify-mode bit during commissioning even on 57B0h, so the property
//    must stay writable in practice. Note System 7's own device object
//    writes it at `ProductManufacturer`: that is 0705h's Annex A column
//    listing a stricter *number*, not a different reading of this one.
//  - PID 78 PID_HARDWARE_TYPE: RW at `ProductManufacturer` (matches
//    07B0h/17B0h `(3/1)`). 57B0h spec is `(3/3)`, but the stricter
//    level 1 is a safe common denominator since any caller who
//    satisfies 3 satisfies 1.
//  - PID 56 PID_MAX_APDU_LENGTH: see the per-field note for the OPEN
//    policy override.
//  - PID 71 PID_IO_LIST: not declared here; served by the System B
//    container (`SystemBObjects`) because the list spans every object
//    in the container, not just the Device Object.
// Every property must spell out `policy` explicitly — the macro has no
// defaults.
#[interface_object(object_type = InterfaceObjectType::Device)]
pub struct DeviceObject<'a, S: StackState> {
    /// Reference to the stack-state for properties that mirror runtime fields
    /// (programming mode, serial number, address). User-declared — the macro
    /// does not inject fields; closures reach `self.state` via the
    /// `|this| this.state.…` pattern.
    pub state: &'a S,

    #[io(pid = pid::DEVICE_CONTROL, pdt = DeviceControl, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub device_control: DeviceControl,

    #[io(pid = pid::ORDER_INFO, pdt = PDT_Generic10, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer)]
    pub order_info: PDT_Generic10,

    #[io(pid = pid::VERSION, pdt = PDT_Version, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer)]
    pub version: PDT_Version,

    #[io(pid = pid::device::HARDWARE_TYPE, pdt = PDT_Generic06, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = ProductManufacturer)]
    pub hardware_type: PDT_Generic06,

    #[io(pid = pid::device::DEVICE_DESCRIPTOR, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer)]
    pub device_descriptor: PDT_UnsignedInt,

    #[io(pid = pid::device::ROUTING_COUNT, pdt = RoutingCount, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub routing_count: RoutingCount,

    // ----- Virtual properties (unit fields, erased; closures take `&Self`) -----

    // Programming mode is backed by StackState so both the application
    // layer (via property read/write) and the link layer (for discovery
    // responses) see the same value.
    #[io(pid = pid::device::PROGMODE, pdt = ProgrammingMode, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| [if this.state.is_programming_mode() { 0x01u8 } else { 0x00u8 }],
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             // ProgrammingMode is a 1-byte property; reject zero-length writes.
             let &[byte] = data else { return Err(PropertyError::BufferTooSmall); };
             this.state.set_programming_mode(byte != 0);
             Ok(WriteResponse::Echo)
         })]
    progmode: (),

    #[io(pid = pid::SERIAL_NUMBER, pdt = PDT_Generic06, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| *this.state.serial_number())]
    serial_number: (),

    // Manufacturer ID is derived from serial number bytes 0-1.
    #[io(pid = pid::MANUFACTURER_ID, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| { let sn = this.state.serial_number(); [sn[0], sn[1]] })]
    manufacturer_id: (),

    // Max APDU length is read from StackState (may be constrained by link layer).
    //
    // Access policy `3FF/1FF` (OPEN) rather than the default
    // `3FF/0CC`: ETS reads this PID plaintext to negotiate APDU
    // size even after Security Mode is enabled (see Falcon
    // `NegotiateMaxApduLength` → `VerifySecurityMode`). Denying
    // plain reads makes ETS default to 15 bytes which is too small
    // for the subsequent secure sync exchange (23 bytes), aborting
    // commissioning. The property is already `ReadOnly` at the
    // PropertyAccess level, so the `1FF` write bit for unlisted
    // sec-off is not exploitable.
    #[io(pid = pid::device::MAX_APDU_LENGTH, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::OPEN, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| this.state.max_apdu_length().to_be_bytes())]
    max_apdu_length: (),

    // PID_SUBNET_ADDR — AN193 §"Object Type 0" lists `3FF/00C`
    // (`OPEN_OFF_TOOL_ON`): in Security Mode only the Tool may read,
    // since the subnet address ties the device to a specific line.
    // The property is RO at the dispatch layer regardless, so the
    // policy's write bits don't matter; what differs from the
    // workspace default `3FF/0CC` is that role-authenticated clients
    // are denied even read access in Security Mode.
    #[io(pid = pid::device::SUBNET_ADDRESS, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::OPEN_OFF_TOOL_ON, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| {
             let addr = this.state.individual_address();
             [(addr.area() << 4) | addr.line()]
         })]
    subnet_address: (),

    // PID_DEVICE_ADDR — same `3FF/00C` policy as PID_SUBNET_ADDR per
    // AN193; together they form the device's individual address and
    // share the same security profile.
    #[io(pid = pid::device::DEVICE_ADDRESS, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::OPEN_OFF_TOOL_ON, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| [this.state.individual_address().device()])]
    device_address: (),
}

impl<'a, S: StackState> DeviceObject<'a, S> {
    /// Create a fresh device object backed by the given `state`.
    ///
    /// Constructors are hand-written rather than macro-generated: each
    /// interface object has different non-property struct fields, and the
    /// explicit `new()` keeps the API minimal.
    pub fn new(state: &'a S) -> Self {
        Self {
            state,
            device_control: DeviceControl::default(),
            order_info: PDT_Generic10::default(),
            version: PDT_Version::default(),
            hardware_type: PDT_Generic06::default(),
            device_descriptor: PDT_UnsignedInt::default(),
            routing_count: RoutingCount::default(),
        }
    }

    /// Create a device object from a [`DeviceDescriptor`].
    ///
    /// Populates hardware type, mask version, and other static properties
    /// from the descriptor. Serial number, manufacturer ID, and max APDU
    /// length are read dynamically from the `StackState`.
    pub fn from_descriptor(state: &'a S, desc: &DeviceDescriptor) -> Self {
        let mut obj = Self::new(state);
        obj.hardware_type = PDT_Generic06::with_value(desc.hardware_type);
        obj.version = PDT_Version::with_value(KNXVersion::from_triplet(0, 0, 1));
        obj.device_descriptor = PDT_UnsignedInt::with_value(desc.mask_version.as_u16());
        obj
    }
}

// ============================================================================
// Application Program Object (Object Type 3)
// ============================================================================

// ============================================================================
// Application Program Object (with proper state machines)
// ============================================================================

/// Application Program Object - Object Type 3
///
/// This is the proper implementation of the Application Program Object that
/// wraps a [`RunnableApplication<T>`](crate::objects::tables::RunnableApplication)
/// and implements both the Load State Machine and Run State Machine.
///
/// The application object is unique among interface objects because it has
/// two state machines:
/// - **Load State Machine**: Controls loading/unloading of application data
/// - **Run State Machine**: Controls execution state (HALTED, RUNNING, etc.)
///
/// # KNX Properties
///
/// | PID | Name | Type | Access | Description |
/// |-----|------|------|--------|-------------|
/// | 1 | Object Type | PDT_UNSIGNED_INT | RO | Object type identifier (3) |
/// | 5 | Load State Control | PDT_CONTROL | RW | Load state machine |
/// | 6 | Run State Control | PDT_CONTROL | RW | Run state machine |
/// | 13 | Program Version | PDT_GENERIC_05 | RW | Application program version |
/// | 16 | PEI Type | PDT_UNSIGNED_CHAR | RW | Required PEI type for the program |
/// | 28 | Error Code | PDT_UNSIGNED_CHAR | RO | DPT_ErrorClass_System; mirrors LSM Err |
///
/// # Type Parameters
///
/// * `T` - The underlying application table type (must implement both
///   [`HasLoadStateMachine`] and [`HasRunStateMachine`])
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_device::objects::tables::app::Application;
/// use zweidraehte_device::objects::interface::ApplicationProgramObject;
///
/// // Create the underlying application table
/// let app_table = RefCell::new(Application::<()>::new());
///
/// // Create the interface object wrapping it (with allocation address 0x400)
/// let app_obj = ApplicationProgramObject::new(&app_table, 0x400);
/// ```
// Access levels per Profiles spec Annex A.2.6, covering System B masks
// 07B0h / 17B0h / 57B0h. The three masks agree on every property here
// except PID 27 PID_MCB_TABLE and PID 28 PID_ERROR_CODE, where 57B0h
// promotes them from optional to mandatory; we keep them mandatory in
// either case since the underlying state already exists.
//
// Base objects have no explicit access policies in the Profiles spec —
// READ_OPEN_WRITE_TOOL (3FF/0CC) is the implicit default. The RESTRICTED
// policy only applies to the Security IO's LOAD_STATE_CONTROL (§9.1.2.6.4).
//
// Every level Annex A prints as `3` is written here as the `Runtime`
// audience, for the reason given on the Device Object above. System 7's
// twin object restricts the two state controls to `ProductManufacturer`
// — that is 0705h's column, not a re-reading of 07B0h's.
#[interface_object(object_type = InterfaceObjectType::ApplicationProgram)]
pub struct ApplicationProgramObject<'a, T: HasLoadStateMachine + HasRunStateMachine> {
    pub app: &'a RefCell<T>,
    /// Virtual address to assign during RelativeData allocation
    pub alloc_address: u32,
    /// Notifier for DeviceModel events (RSM lifecycle transitions).
    pub notifier: &'a dyn DeviceModelNotifier,

    #[io(pid = pid::PROGRAM_VERSION, pdt = PDT_Generic05, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub program_version: PDT_Generic05,
    // PEI_TYPE on the Application Program Object is the PEI type *required*
    // by the program (distinct from the device-wide PEI_TYPE on the Device
    // Object). Spec Annex A.2.6 lists it as `3/3` (mandatory RW) for all
    // System B masks — ETS writes it during programming.
    #[io(pid = pid::PEI_TYPE, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub pei_type: PDT_UnsignedChar,

    // Load- and Run-state machines are accessed through the application
    // table behind a `RefCell`. Writes intercept LSM/RSM transitions, fan
    // out RunEvents, and echo back the new state byte (`WriteResponse::Data`).
    #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_Control, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| this.app.borrow().read_lsm(),
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let action = this.app.borrow_mut().write_lsm(data, Some(this.alloc_address));
             let run_action = match action {
                 LoadAction::LoadEnd => this.app.borrow_mut().handle_run_event(RunEvent::Loaded),
                 LoadAction::Unload  => this.app.borrow_mut().handle_run_event(RunEvent::Unloaded),
                 _ => None,
             };
             if let Some(action) = run_action {
                 this.notifier.notify(DeviceModelEvent::RunAction(RunTarget::Application, action));
             }
             Ok(WriteResponse::byte(this.app.borrow().read_lsm()[0]))
         })]
    load_state_control: (),

    #[io(pid = pid::RUN_STATE_CONTROL, pdt = PDT_Control, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| this.app.borrow().read_rsm(),
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let run_action = this.app.borrow_mut().write_rsm(data);
             if let Some(action) = run_action {
                 this.notifier.notify(DeviceModelEvent::RunAction(RunTarget::Application, action));
             }
             Ok(WriteResponse::byte(this.app.borrow().read_rsm()[0]))
         })]
    run_state_control: (),

    #[io(pid = pid::TABLE_REFERENCE, pdt = PDT_UnsignedLong, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| this.app.borrow().table_reference().to_be_bytes())]
    table_reference: (),

    // PID_MCB_TABLE — memory-control block (8 bytes, PDT_GENERIC_08).
    // `mcb_bytes()` returns `&[u8]`, so copy into a sized array for the
    // closure's `[u8; 8]` return slot. Trailing bytes are zero-padded.
    //
    // The write level is decorative: `PropertyAccess::ReadOnly` is the
    // first term of `PropertyDescriptor::can_write`, so no write ever
    // reaches the level. It keeps the `Runtime` that Annex A's `3`
    // stands for, rather than the `SystemManufacturer` the other RO
    // properties use, only so the reported descriptor keeps answering
    // the number it answers today.
    #[io(pid = pid::MCB_TABLE, pdt = PDT_Generic08, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| -> [u8; 8] {
             let app = this.app.borrow();
             let src = app.mcb_bytes();
             let mut out = [0u8; 8];
             let n = src.len().min(8);
             out[..n].copy_from_slice(&src[..n]);
             out
         })]
    mcb_table: (),

    // PID_ERROR_CODE — last LSM failure encoded as DPT_ErrorClass_System
    // (20.011). Reads `0` (no fault) whenever the LSM is not in `Err`,
    // see `HasLoadStateMachine::last_error_code`.
    #[io(pid = pid::ERROR_CODE, pdt = PDT_UnsignedChar, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| [this.app.borrow().last_error_code()])]
    error_code: (),
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> ApplicationProgramObject<'a, T> {
    /// Create a new application program object wrapping an existing
    /// application table.
    ///
    /// # Arguments
    /// * `app` - Reference to the application table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation
    /// * `notifier` - Notification sink for DeviceModel lifecycle events
    pub fn new(app: &'a RefCell<T>, alloc_address: u32, notifier: &'a dyn DeviceModelNotifier) -> Self {
        Self {
            app,
            alloc_address,
            program_version: PDT_Generic05::default(),
            pei_type: PDT_UnsignedChar::default(),
            notifier,
        }
    }

    /// Create with specific program version and PEI type.
    pub fn with_info(
        app: &'a RefCell<T>,
        alloc_address: u32,
        program_version: PDT_Generic05,
        pei_type: PDT_UnsignedChar,
        notifier: &'a dyn DeviceModelNotifier,
    ) -> Self {
        Self { app, alloc_address, program_version, pei_type, notifier }
    }

    /// Get the program version.
    pub fn program_version(&self) -> &PDT_Generic05 {
        &self.program_version
    }

    /// Set the program version.
    pub fn set_program_version(&mut self, version: PDT_Generic05) {
        self.program_version = version;
    }

    /// Get the PEI type.
    pub fn pei_type(&self) -> &PDT_UnsignedChar {
        &self.pei_type
    }

    /// Set the PEI type.
    pub fn set_pei_type(&mut self, pei_type: PDT_UnsignedChar) {
        self.pei_type = pei_type;
    }
}

// ============================================================================
// PEI Program Object (Object Type 5) - Interface Program
// ============================================================================

/// PEI (Physical External Interface) Program Object - Object Type 5.
///
/// System B reserves this object for Application Program 2. It remains present in
/// state `Unloaded` for products without AP2; products that use AP2 may give its
/// state transitions real device-side effects. This stack currently implements the
/// no-AP2 form. See [`PeiApplication`](crate::objects::tables::PeiApplication).
///
/// The object exposes the same properties as [`ApplicationProgramObject`] but
/// reports a different object type (0x0005 instead of 0x0004).
///
/// # Properties
///
/// - OBJECT_TYPE (PID 1): Reports InterfaceObjectType::InterfaceProgram (5)
/// - LOAD_STATE_CONTROL (PID 5): Load state machine (no side effects)
/// - RUN_STATE_CONTROL (PID 6): Run state machine (no side effects)
/// - TABLE_REFERENCE (PID 7): Allocated PEI table base address
/// - PROGRAM_VERSION (PID 13): Program version (typically `[0; 5]` on modern devices)
/// - PEI_TYPE (PID 16): PEI type required by the program (typically 0)
// Access levels per Profiles spec Annex A.2.7. The Interface Program
// Object is only listed for masks 07B0h and 17B0h; on 57B0h (System B
// IP) it is absent from the spec entirely. The access levels here
// match those two masks, with Annex A's `3` written as the `Runtime`
// audience for the reason given on the Device Object above.
#[interface_object(object_type = InterfaceObjectType::InterfaceProgram)]
pub struct PeiProgramObject<'a, T: HasLoadStateMachine + HasRunStateMachine> {
    pub pei: &'a RefCell<T>,
    /// Virtual address to assign during RelativeData allocation (typically 0 for PEI)
    pub alloc_address: u32,
    /// Notifier for DeviceModel events. PEI RSM transitions are surfaced as
    /// [`LifecycleEvent::PeiStarted`](crate::lifecycle::LifecycleEvent::PeiStarted) / [`LifecycleEvent::PeiStopped`](crate::lifecycle::LifecycleEvent::PeiStopped)
    /// even though PEI has no required side effects on device operation —
    /// this is purely for observability of the full ETS programming cascade.
    pub notifier: &'a dyn DeviceModelNotifier,

    // Spec Annex A.2.7 lists PROGRAM_VERSION as `3/3` (mandatory RW)
    // for both 07B0h and 17B0h. ETS writes the program version during
    // programming, so the field has to accept writes even though this stack's
    // empty AP2 object has no runtime side effects.
    #[io(pid = pid::PROGRAM_VERSION, pdt = PDT_Generic05, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub program_version: PDT_Generic05,

    // Spec Annex A.2.7 lists PEI_TYPE as `3/(3)` — mandatory, with the
    // write level optional. We follow the Application Program Object
    // and expose it as RW so ETS can stamp the required PEI type.
    #[io(pid = pid::PEI_TYPE, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime)]
    pub pei_type: PDT_UnsignedChar,

    // PID_TABLE_REFERENCE — base address of the PEI table allocation,
    // updated by the LSM during RelativeData allocation and cleared on
    // unload. Spec Annex A.2.7 lists it as `3/x` (mandatory RO).
    #[io(pid = pid::TABLE_REFERENCE, pdt = PDT_UnsignedLong, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = SystemManufacturer,
         read = |this: &Self| this.pei.borrow().table_reference().to_be_bytes())]
    table_reference: (),

    // LSM/RSM use the same cascade-into-run-event pattern as the application
    // program object; differs only in the `RunTarget::Pei` discriminator and
    // a different `RefCell` (`pei` instead of `app`).
    #[io(pid = pid::LOAD_STATE_CONTROL, pdt = PDT_Control, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| this.pei.borrow().read_lsm(),
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let action = this.pei.borrow_mut().write_lsm(data, Some(this.alloc_address));
             let run_action = match action {
                 LoadAction::LoadEnd => this.pei.borrow_mut().handle_run_event(RunEvent::Loaded),
                 LoadAction::Unload  => this.pei.borrow_mut().handle_run_event(RunEvent::Unloaded),
                 _ => None,
             };
             if let Some(action) = run_action {
                 this.notifier.notify(DeviceModelEvent::RunAction(RunTarget::Pei, action));
             }
             Ok(WriteResponse::byte(this.pei.borrow().read_lsm()[0]))
         })]
    load_state_control: (),

    #[io(pid = pid::RUN_STATE_CONTROL, pdt = PDT_Control, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = Runtime, wl = Runtime,
         read = |this: &Self| this.pei.borrow().read_rsm(),
         write = |this: &mut Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             let run_action = this.pei.borrow_mut().write_rsm(data);
             if let Some(action) = run_action {
                 this.notifier.notify(DeviceModelEvent::RunAction(RunTarget::Pei, action));
             }
             Ok(WriteResponse::byte(this.pei.borrow().read_rsm()[0]))
         })]
    run_state_control: (),
}

impl<'a, T: HasLoadStateMachine + HasRunStateMachine> PeiProgramObject<'a, T> {
    /// Create a new PEI program object.
    ///
    /// # Arguments
    /// * `pei` - Reference to the PEI application table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation (typically 0)
    /// * `program_version` - PEI program version (typically [0, 0, 0, 0, 0])
    /// * `notifier` - Notification sink for DeviceModel lifecycle events
    pub fn new(
        pei: &'a RefCell<T>,
        alloc_address: u32,
        program_version: PDT_Generic05,
        notifier: &'a dyn DeviceModelNotifier,
    ) -> Self {
        Self { pei, alloc_address, program_version, pei_type: PDT_UnsignedChar::default(), notifier }
    }

    /// Get the program version.
    pub fn program_version(&self) -> &PDT_Generic05 {
        &self.program_version
    }
}

// // ============================================================================
// // Router Object (Object Type 6) - For line/backbone couplers
// // ============================================================================

// crate::define_interface_object! {
//     /// Router Object - Object Type 6
//     ///
//     /// Contains routing configuration for line/backbone couplers.
//     /// This object is only present in routing devices.
//     ///
//     /// # Properties
//     ///
//     /// | PID | Name | Type | Access |
//     /// |-----|------|------|--------|
//     /// | 1 | Object Type | PDT_UNSIGNED_INT | RO |
//     /// | 51 | Line Status | PDT_GENERIC_01 | RO |
//     /// | 52 | Main LC Config | PDT_GENERIC_01 | RW |
//     /// | 53 | Sub LC Config | PDT_GENERIC_01 | RW |
//     pub struct RouterObject: InterfaceObjectType::Router {
//         pid::router::LINE_STATUS => line_status: PDT_Generic01, ReadOnly;
//         pid::router::MAIN_LCCONFIG => main_lc_config: PDT_Generic01, ReadWrite;
//         pid::router::SUB_LCCONFIG => sub_lc_config: PDT_Generic01, ReadWrite;
//         pid::router::MAIN_LCGRPCONFIG => main_lc_grp_config: PDT_Generic01, ReadWrite;
//         pid::router::SUB_LCGRPCONFIG => sub_lc_grp_config: PDT_Generic01, ReadWrite
//     }
// }

// ============================================================================
// Address Table Object (Object Type 1)
// ============================================================================

// ============================================================================
// Generic Table Interface Object Implementation
// ============================================================================

/// Specification trait for table interface objects.
///
/// This trait provides the constants that differ between table types,
/// allowing a single generic implementation to handle all table objects.
pub trait TableObjectSpec {
    /// The interface object type (e.g., AddressTable, AssociationTable)
    const OBJECT_TYPE: InterfaceObjectType;

    /// Bytes per table entry
    const ENTRY_SIZE: usize;

    /// PDT type ID for the TABLE property
    const TABLE_PDT: u8;

    /// Whether the table data starts with a 2-byte count prefix
    /// (true for most tables, determines offset calculation)
    const HAS_COUNT_PREFIX: bool;
}

/// Generic table interface object implementation.
///
/// This struct provides the `InterfaceObject` implementation for any table type,
/// parameterized by a specification trait that provides the type-specific constants.
///
/// # Type Parameters
///
/// * `T` - The underlying table type (must implement `HasLoadStateMachine`)
/// * `S` - A marker type implementing `TableObjectSpec` for object-specific constants
///
/// # KNX Properties (common to all table objects)
///
/// | PID | Name | Type | Access | Description |
/// |-----|------|------|--------|-------------|
/// | 1 | Object Type | PDT_UNSIGNED_INT | RO | Object type identifier |
/// | 5 | Load State Control | PDT_CONTROL | RW | Load state machine |
/// | 7 | Table Reference | PDT_UNSIGNED_LONG | RO | Base address of allocated table memory |
/// | 23 | Table | varies | RW* | Direct table data access |
/// | 27 | MCB Table | PDT_GENERIC_08 | RO | Memory control block |
/// | 28 | Error Code | PDT_UNSIGNED_CHAR | RO | DPT_ErrorClass_System; mirrors LSM Err |
//
// This object is intentionally **not** rewritten with `#[interface_object]`.
// It has three properties the macro DSL cannot express cleanly:
//  - `pid::TABLE` has a PDT that varies per table type (`S::TABLE_PDT`,
//    a const on the `TableObjectSpec` trait), not a fixed wrapper type.
//  - `max_elements` for `pid::TABLE` is computed at lookup time from the
//    runtime table buffer length divided by `S::ENTRY_SIZE`.
//  - `property_element_count` for `pid::TABLE` branches on whether the
//    table has a count prefix (`S::HAS_COUNT_PREFIX`).
// All remaining table objects in the workspace (Security, Ip, Device, etc.)
// fit the macro DSL — this is the one principled exception.
pub struct TableInterfaceObject<'a, T: HasLoadStateMachine, S: TableObjectSpec> {
    table: &'a RefCell<T>,
    /// Virtual address to assign to this table during RelativeData allocation
    alloc_address: u32,
    _spec: PhantomData<S>,
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> TableInterfaceObject<'a, T, S> {
    /// Create a new table interface object wrapping an existing table.
    ///
    /// # Arguments
    /// * `table` - Reference to the table
    /// * `alloc_address` - Virtual address to assign during RelativeData allocation.
    ///   Per KNX spec, this is set when memory is allocated and cleared on unload.
    pub fn new(table: &'a RefCell<T>, alloc_address: u32) -> Self {
        Self { table, alloc_address, _spec: PhantomData }
    }

    /// Get property descriptors for table objects.
    ///
    /// Access levels per Profiles spec Annex A.2.4 / A.2.5 / A.2.8,
    /// covering System B masks 07B0h / 17B0h / 57B0h.
    ///
    /// These are raw numbers rather than the audiences
    /// ([`AccessLevel`](zweidraehte_proto::access::AccessLevel)) the
    /// macro-declared objects name, and exactly so: this table is built
    /// only by System B, which has one authorisation model, so there is
    /// no profile left to resolve against. System 7 did not reuse it —
    /// `bcus::system_7::objects::System7TableObject` is its own table at
    /// 15/2, and the two differ by more than the audience (System B
    /// hardens `LOAD_STATE_CONTROL` to write level 1 where System 7 uses
    /// 2), which no shared declaration could express.
    ///
    /// Notable choices:
    ///  - PID 5 PID_LOAD_STATE_CONTROL: declared with `wl=1` rather
    ///    than the spec's recommended `wl=3`. For 07B0h/17B0h the
    ///    spec lists `3/(3)` — the parenthesised write level is a
    ///    *recommendation* (Profiles legend Table 3), so a stricter
    ///    `wl=1` is permitted. For 57B0h the spec mandates `3/3`,
    ///    which we are intentionally hardening; the conformance suite
    ///    (test L-2.6 "Test without access rights") relies on this
    ///    stricter level to verify that an unauthorised connection
    ///    cannot drive the load state machine.
    ///  - PID 28 PID_ERROR_CODE: only marked mandatory on 57B0h; we
    ///    expose it everywhere because the underlying `last_error_code`
    ///    state already exists on `HasLoadStateMachine`.
    /// TABLE and TABLE_REFERENCE are writable during loading only; the
    /// LSM enforces that internally.
    fn property_descriptors() -> [PropertyDescriptor; 6] {
        use zweidraehte_proto::access::AccessPolicy;
        [
            PropertyDescriptor::new(
                pid::OBJECT_TYPE,
                PDT_UnsignedInt::ID,
                1,
                PropertyAccess::ReadOnly,
                3,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::LOAD_STATE_CONTROL,
                PDT_Control::ID,
                1,
                PropertyAccess::ReadWrite,
                3,
                1,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::TABLE_REFERENCE,
                PDT_UnsignedLong::ID,
                1,
                PropertyAccess::ReadOnly,
                3,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::TABLE,
                S::TABLE_PDT,
                0,
                PropertyAccess::ReadWrite,
                3,
                3,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ), // max_elements set dynamically
            PropertyDescriptor::new(
                pid::MCB_TABLE,
                PDT_Generic08::ID,
                1,
                PropertyAccess::ReadOnly,
                3,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::ERROR_CODE,
                PDT_UnsignedChar::ID,
                1,
                PropertyAccess::ReadOnly,
                3,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
        ]
    }
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> InterfaceObject for TableInterfaceObject<'a, T, S> {
    fn object_type(&self) -> InterfaceObjectType {
        S::OBJECT_TYPE
    }

    fn property_count(&self) -> u16 {
        6 // Fixed number of properties for all table objects
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        let descriptors = Self::property_descriptors();
        let mut desc = descriptors.get(prop_idx as usize).copied()?;
        // Dynamically set max_elements for TABLE property
        if desc.pid == pid::TABLE {
            desc.max_elements = (self.table.borrow().data_ref().len() / S::ENTRY_SIZE) as u16;
        }
        Some(desc)
    }

    fn property_descriptor_by_id(&self, pid: u16) -> Option<(u16, PropertyDescriptor)> {
        let descriptors = Self::property_descriptors();
        descriptors.iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| {
            let mut desc = *d;
            if desc.pid == super::pid::TABLE {
                desc.max_elements = (self.table.borrow().data_ref().len() / S::ENTRY_SIZE) as u16;
            }
            (i as u16, desc)
        })
    }

    fn read_property(&self, req: super::PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE => {
                let obj_type: u16 = S::OBJECT_TYPE.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::LOAD_STATE_CONTROL => {
                self.table.borrow().read_lsm().read_property(req.start_idx, req.count, buf)
            }
            super::pid::TABLE_REFERENCE => {
                // Base address of the allocated table memory for memory read/write operations
                // Set during RelativeData allocation, cleared on unload
                self.table.borrow().table_reference().to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let table = self.table.borrow();
                if S::HAS_COUNT_PREFIX {
                    table.data_ref().read_array_with_prefix(req.start_idx, req.count, S::ENTRY_SIZE, buf)
                } else {
                    use super::ArrayPropertyRead;
                    table.data_ref().read_array_property(req.start_idx, req.count, S::ENTRY_SIZE, buf)
                }
            }
            super::pid::MCB_TABLE => {
                // Memory Control Block - 8 bytes (PDT_GENERIC_08)
                // The MCB is populated during load (RelativeData segment) and CRC calculated on LoadEnd
                self.table.borrow().mcb_bytes().read_property(req.start_idx, req.count, buf)
            }
            super::pid::ERROR_CODE => {
                // DPT_ErrorClass_System (20.011), 1 byte. Mirrors the LSM
                // Err state via `last_error_code()`; reads `0` whenever the
                // LSM is not in `Err`.
                [self.table.borrow().last_error_code()].read_property(req.start_idx, req.count, buf)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, req: super::PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match req.pid {
            super::pid::OBJECT_TYPE | super::pid::TABLE_REFERENCE | super::pid::MCB_TABLE | super::pid::ERROR_CODE => {
                Err(PropertyError::WriteNotAllowed)
            }
            super::pid::LOAD_STATE_CONTROL => {
                // Write the load event to the state machine, providing the allocation address
                self.table.borrow_mut().write_lsm(req.data, Some(self.alloc_address));
                // Response contains the resulting load state (1 byte), not the echoed data
                Ok(WriteResponse::byte(self.table.borrow().read_lsm()[0]))
            }
            super::pid::TABLE => {
                // Array property - use appropriate trait based on table format
                let mut table = self.table.borrow_mut();
                let _written = if S::HAS_COUNT_PREFIX {
                    table.data_ref_mut().write_array_with_prefix(req.start_idx, req.data, S::ENTRY_SIZE)?
                } else {
                    use super::ArrayPropertyWrite;
                    table.data_ref_mut().write_array_property(req.start_idx, req.data, S::ENTRY_SIZE)?
                };

                // Echo back written data
                Ok(WriteResponse::Echo)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid: u16) -> Result<u16, PropertyError> {
        match pid {
            super::pid::OBJECT_TYPE => Ok(1),
            super::pid::LOAD_STATE_CONTROL => Ok(1),
            super::pid::TABLE_REFERENCE => Ok(1),
            super::pid::TABLE => {
                let table = self.table.borrow();
                if S::HAS_COUNT_PREFIX {
                    Ok(table.data_ref().element_count_from_prefix())
                } else {
                    use super::ArrayPropertyRead;
                    Ok(table.data_ref().element_count(S::ENTRY_SIZE))
                }
            }
            super::pid::MCB_TABLE => Ok(1),
            super::pid::ERROR_CODE => Ok(1),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }
}

// ============================================================================
// Table Object Specifications
// ============================================================================

/// Specification for Address Table Object (Type 1)
pub struct AddressTableSpec;

impl TableObjectSpec for AddressTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::AddressTable;
    const ENTRY_SIZE: usize = 2; // Group Address = 2 bytes
    const TABLE_PDT: u8 = PDT_UnsignedInt::ID; // 2-byte entries
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Association Table Object (Type 2)
pub struct AssociationTableSpec;

impl TableObjectSpec for AssociationTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::AssociationTable;
    const ENTRY_SIZE: usize = 4; // TSAP + ASAP = 4 bytes
    const TABLE_PDT: u8 = PDT_Generic04::ID;
    const HAS_COUNT_PREFIX: bool = true;
}

/// Specification for Group Object Table Object (Type 9)
pub struct GroupObjectTableSpec;

impl TableObjectSpec for GroupObjectTableSpec {
    const OBJECT_TYPE: InterfaceObjectType = InterfaceObjectType::GroupObjectTable;
    const ENTRY_SIZE: usize = 2; // Type + Flags = 2 bytes
    const TABLE_PDT: u8 = PDT_Generic02::ID;
    const HAS_COUNT_PREFIX: bool = true;
}

// ============================================================================
// Type Aliases for Table Interface Objects
// ============================================================================

/// Address Table Object - Object Type 1
///
/// Wraps an existing [`AddressTable`](crate::objects::tables::AddressTable) implementation to provide the
/// Interface Object API. Contains the group address table with entries
/// that can be looked up by TSAP.
pub type AddressTableObject<'a, T> = TableInterfaceObject<'a, T, AddressTableSpec>;

/// Association Table Object - Object Type 2
///
/// Wraps an existing [`AssociationTable`](crate::objects::tables::AssociationTable) implementation. Contains the
/// TSAP/ASAP mapping table for routing group communication.
pub type AssociationTableObject<'a, T> = TableInterfaceObject<'a, T, AssociationTableSpec>;

/// Group Object Table Object - Object Type 9
///
/// Wraps a [`CommunicationObjectTable`](crate::objects::tables::CommunicationObjectTable) implementation. Contains the
/// communication object descriptors (type + flags for each object).
pub type GroupObjectTableObject<'a, T> = TableInterfaceObject<'a, T, GroupObjectTableSpec>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::interface::PropertyReadRequest;
    use crate::objects::interface::PropertyWriteRequest;
    use crate::objects::tables::addr7::AddrTab7;
    use crate::objects::tables::asso6::AssoTab6;
    use crate::objects::tables::co7::CoTab7;
    use crate::objects::tables::{LoadEvent, TableMemory};

    #[test]
    fn test_address_table_object_type() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let obj = AddressTableObject::new(&addr_table, 0x100);

        assert_eq!(obj.object_type(), InterfaceObjectType::AddressTable);

        // Read OBJECT_TYPE property
        let mut buf = [0u8; 4];
        let len =
            obj.read_property(PropertyReadRequest { pid: pid::OBJECT_TYPE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // AddressTable = 1
    }

    #[test]
    fn test_address_table_load_state() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // Should start unloaded
        let mut buf = [0u8; 4];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x00); // Unloaded

        // Start loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::StartLoading.into()],
        })
        .unwrap();

        let len = obj
            .read_property(PropertyReadRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0x02); // Loading
    }

    #[test]
    fn test_address_table_table_property() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());

        // Pre-load some data into the table
        {
            let mut table = addr_table.borrow_mut();
            // Write count = 3, then 3 group addresses
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x03]); // count = 3
            table.data_ref_mut()[2..4].copy_from_slice(&[0x00, 0x01]); // GA 0/0/1
            table.data_ref_mut()[4..6].copy_from_slice(&[0x00, 0x02]); // GA 0/0/2
            table.data_ref_mut()[6..8].copy_from_slice(&[0x00, 0x03]); // GA 0/0/3
        }

        let obj = AddressTableObject::new(&addr_table, 0x100);

        // Read element count (start_idx = 0)
        let mut buf = [0u8; 10];
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x03]); // 3 entries

        // Read first entry (start_idx = 1)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // GA 0/0/1

        // Read all 3 entries
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 3 }, &mut buf).unwrap();
        assert_eq!(len, 6);
        assert_eq!(&buf[0..6], &[0x00, 0x01, 0x00, 0x02, 0x00, 0x03]);
    }

    #[test]
    fn test_address_table_property_descriptors() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let obj = AddressTableObject::new(&addr_table, 0x100);

        assert_eq!(obj.property_count(), 6);

        // Check each property descriptor
        let desc = obj.property_descriptor_by_id(pid::OBJECT_TYPE).unwrap();
        assert_eq!(desc.1.pid, 1);
        assert_eq!(desc.1.access, PropertyAccess::ReadOnly);

        let desc = obj.property_descriptor_by_id(pid::LOAD_STATE_CONTROL).unwrap();
        assert_eq!(desc.1.pid, 5);
        assert_eq!(desc.1.access, PropertyAccess::ReadWrite);

        let desc = obj.property_descriptor_by_id(pid::TABLE).unwrap();
        assert_eq!(desc.1.pid, 23);
        assert_eq!(desc.1.access, PropertyAccess::ReadWrite);
    }

    #[test]
    fn test_association_table_object() {
        let asso_table = RefCell::new(AssoTab6::<40>::new());

        // Pre-load association data
        {
            let mut table = asso_table.borrow_mut();
            // Format: [count:2][tsap1:2][asap1:2][tsap2:2][asap2:2]...
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x02]); // 2 entries
            table.data_ref_mut()[2..6].copy_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TSAP 1 -> ASAP 1
            table.data_ref_mut()[6..10].copy_from_slice(&[0x00, 0x02, 0x00, 0x02]); // TSAP 2 -> ASAP 2
        }

        let obj = AssociationTableObject::new(&asso_table, 0x200);

        assert_eq!(obj.object_type(), InterfaceObjectType::AssociationTable);

        // Read element count
        let mut buf = [0u8; 10];
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (4 bytes: TSAP + ASAP)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_group_object_table_object() {
        let co_table = RefCell::new(CoTab7::<20>::new());

        // Pre-load communication object data
        {
            let mut table = co_table.borrow_mut();
            // Format: [count:2][type1:1][flags1:1][type2:1][flags2:1]...
            table.data_ref_mut()[0..2].copy_from_slice(&[0x00, 0x02]); // 2 entries
            table.data_ref_mut()[2..4].copy_from_slice(&[0x00, 0xDC]); // Type Bit1, flags RTWU
            table.data_ref_mut()[4..6].copy_from_slice(&[0x08, 0x44]); // Type Byte2, flags T
        }

        let obj = GroupObjectTableObject::new(&co_table, 0x300);

        assert_eq!(obj.object_type(), InterfaceObjectType::GroupObjectTable);

        // Read element count
        let mut buf = [0u8; 10];
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]); // 2 entries

        // Read first entry (2 bytes: type + flags)
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0xDC]);

        // Read both entries
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 1, count: 2 }, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0xDC, 0x08, 0x44]);
    }

    #[test]
    fn test_table_object_write_protection() {
        let addr_table = RefCell::new(AddrTab7::<10>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // OBJECT_TYPE should not be writable
        let result =
            obj.write_property(PropertyWriteRequest { pid: pid::OBJECT_TYPE, start_idx: 1, data: &[0x00, 0x00] });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // TABLE_REFERENCE should not be writable
        let result = obj.write_property(PropertyWriteRequest {
            pid: pid::TABLE_REFERENCE,
            start_idx: 1,
            data: &[0x00, 0x00, 0x00, 0x00],
        });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));

        // MCB_TABLE should not be writable
        let result = obj.write_property(PropertyWriteRequest { pid: pid::MCB_TABLE, start_idx: 1, data: &[0x00; 8] });
        assert!(matches!(result, Err(PropertyError::WriteNotAllowed)));
    }

    #[test]
    fn test_table_object_write_data() {
        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x100);

        // Write count and entries via TABLE property
        obj.write_property(PropertyWriteRequest { pid: pid::TABLE, start_idx: 0, data: &[0x00, 0x02] }).unwrap(); // count = 2

        // Verify it was written
        let mut buf = [0u8; 10];
        let len = obj.read_property(PropertyReadRequest { pid: pid::TABLE, start_idx: 0, count: 1 }, &mut buf).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&buf[0..2], &[0x00, 0x02]);
    }

    #[test]
    fn test_table_reference_after_load() {
        use crate::objects::tables::LoadEvent;

        let addr_table = RefCell::new(AddrTab7::<20>::new());
        let mut obj = AddressTableObject::new(&addr_table, 0x1234);

        // TABLE_REFERENCE should be 0 initially (unloaded)
        let mut buf = [0u8; 10];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x00]);

        // Start loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::StartLoading.into()],
        })
        .unwrap();

        // Allocate via RelativeData segment - this sets the TABLE_REFERENCE
        // Format: [event][segment_type][mcb_data...]
        // MCB data: [requested_memory_size:4][mode:1][fill:1][crc:2]
        let alloc_data = [
            LoadEvent::AdditionalLoadControls.into(),
            0x0B, // RelativeData segment
            0x00,
            0x00,
            0x00,
            0x08, // 8 bytes requested
            0x01, // mode = fill enabled
            0xFF, // fill byte
            0x00,
            0x00, // CRC placeholder
        ];
        obj.write_property(PropertyWriteRequest { pid: pid::LOAD_STATE_CONTROL, start_idx: 1, data: &alloc_data })
            .unwrap();

        // Now TABLE_REFERENCE should be set to 0x1234
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Complete loading
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::LoadCompleted.into()],
        })
        .unwrap();

        // TABLE_REFERENCE should still be 0x1234
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x12, 0x34]);

        // Unload - TABLE_REFERENCE should be cleared to 0
        obj.write_property(PropertyWriteRequest {
            pid: pid::LOAD_STATE_CONTROL,
            start_idx: 1,
            data: &[LoadEvent::Unload.into()],
        })
        .unwrap();
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_table_reference_with_preloaded_data() {
        use crate::objects::tables::Table;
        use crate::objects::tables::addr7::AddrTab7Impl;

        // Create a table with pre-loaded data and table_reference
        let preloaded_table: Table<AddrTab7Impl<20>> = Table::with_data(
            &[0x00, 0x01, 0x10, 0x00], // count=1, addr=2/0/0
            0xABCD,
        );
        let addr_table = RefCell::new(preloaded_table);
        let obj = AddressTableObject::new(&addr_table, 0x1234); // alloc_address ignored for preloaded

        // TABLE_REFERENCE should be 0xABCD (from with_data)
        let mut buf = [0u8; 10];
        let len = obj
            .read_property(PropertyReadRequest { pid: pid::TABLE_REFERENCE, start_idx: 1, count: 1 }, &mut buf)
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0xAB, 0xCD]);
    }
}
