//! Interface objects containers for System B devices.
//!
//! This module provides composable interface object containers for System B devices.
//! The containers implement [`PropertyServiceHandler`] to dispatch property reads/writes
//! to the appropriate object.
//!
//! # Composable Design
//!
//! Interface objects are composed using tuples:
//! - `SystemBObjects`: Base 5 objects (Device, ADT, AST, COT, APP) - indices 0-4
//! - `IpObjects`: IP Parameter Object - index 5
//!
//! KNX/IP devices use `(SystemBObjects, IpObjects)`, which automatically handles
//! dispatch via the tuple `PropertyServiceHandler` implementation.
//!
//! # Object Indices
//!
//! Base System B objects (x7B0):
//! - Index 0: Device Object
//! - Index 1: Address Table Object
//! - Index 2: Association Table Object
//! - Index 3: Group Object Table Object
//! - Index 4: Application Program Object
//! - Index 5: PEI Program Object
//!
//! KNX/IP additional objects (57B0):
//! - Index 6: IP Parameter Object

mod dispatch;

use core::cell::RefCell;

use crate::{
    StackState,
    device_model::DeviceModelNotifier,
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceObject, GroupObjectTableObject,
        InterfaceObject, PeiProgramObject, PropertyAccess, PropertyDescriptor, PropertyError, pid,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
};
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Generic05, PDT_UnsignedChar, PDT_UnsignedInt, RoutingCount};

use crate::StackDefinition;
use crate::context::layer::LayerContext;
use crate::objects::interface::HasRoutingCount;
use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasPeiApplication,
};

// ============================================================================
// IO List Constants
// ============================================================================

/// The 6 base interface object types present in every System B device.
///
/// Additional object types (e.g., IPParameter for KNX/IP) are contributed
/// by augments via [`Augment::additional_object_count`].
static BASE_IO_TYPES: [InterfaceObjectType; 6] = [
    InterfaceObjectType::Device,
    InterfaceObjectType::AddressTable,
    InterfaceObjectType::AssociationTable,
    InterfaceObjectType::GroupObjectTable,
    InterfaceObjectType::ApplicationProgram,
    InterfaceObjectType::InterfaceProgram,
];

// ============================================================================
// SystemBObjects - Base 6 Interface Objects
// ============================================================================

/// Interface objects for System B devices.
///
/// Contains the 6 mandatory base interface objects (indices 0-5):
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
/// - PEI Program Object (index 5)
///
/// Augments can extend existing objects with additional properties AND
/// provide entirely new interface objects at indices 6+. For example,
/// `IpExtensionState` provides the IP Parameter Object (Type 11, index 6).
///
/// # Type Parameters
///
/// - `D`:   Stack definition (drives state + augment context typing)
/// - `ADT`: Address table type
/// - `AST`: Association table type
/// - `COT`: Communication object table type
/// - `APP`: Application type (implementing both HasLoadStateMachine and HasRunStateMachine)
/// - `PEI`: PEI application type (implementing both HasLoadStateMachine and HasRunStateMachine)
/// - `Aug`: Borrowed augment registry implementing [`crate::service::Augment<D>`].
///   The container holds `&'a Aug`; the runner owns the chain itself
///   and ticks lifecycles through the owner reference.
pub struct SystemBObjects<'a, D, ADT, AST, COT, APP, PEI, Aug: crate::service::Augment<D> = ()>
where
    D: StackDefinition,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    device: RefCell<DeviceObject<'a, D::State>>,
    address_table: RefCell<AddressTableObject<'a, ADT>>,
    association_table: RefCell<AssociationTableObject<'a, AST>>,
    group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
    application_program: RefCell<ApplicationProgramObject<'a, APP>>,
    pei_program: RefCell<PeiProgramObject<'a, PEI>>,
    augments: &'a Aug,
}

impl<'a, D, ADT, AST, COT, APP, PEI, Aug> SystemBObjects<'a, D, ADT, AST, COT, APP, PEI, Aug>
where
    D: StackDefinition,
    D::State: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
    Aug: crate::service::Augment<D>,
{
    /// Number of base interface objects (Device, ADT, AST, GOT, APP, PEI).
    pub const BASE_OBJECT_COUNT: u16 = 6;

    /// Create a new interface objects container.
    ///
    /// The container borrows the augment registry for the lifetime of
    /// the stack. Augments can intercept property and function-property
    /// requests before they reach the standard object implementations,
    /// and can also provide additional interface objects beyond the
    /// base 6.
    pub fn new(
        state: &'a D::State,
        lctx: &'a LayerContext<D>,
        device: &crate::ets::DeviceDescriptor,
        layout: &super::memory_map::MemoryLayout,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        cot: &'a RefCell<COT>,
        app: &'a RefCell<APP>,
        pei: &'a RefCell<PEI>,
        program_version: [u8; 5],
        pei_program_version: [u8; 5],
        pei_type: u8,
        routing_count: u8,
        augments: &'a Aug,
    ) -> Self {
        let mut device = DeviceObject::from_descriptor(state, device);
        device.routing_count = RoutingCount::from(routing_count);
        Self {
            state,
            lctx,
            device: RefCell::new(device),
            address_table: RefCell::new(AddressTableObject::new(adt, layout.adt_address() as u32)),
            association_table: RefCell::new(AssociationTableObject::new(ast, layout.ast_address() as u32)),
            group_object_table: RefCell::new(GroupObjectTableObject::new(cot, layout.cot_address() as u32)),
            application_program: RefCell::new(ApplicationProgramObject::with_info(
                app,
                layout.app_address() as u32,
                PDT_Generic05::with_value(program_version),
                PDT_UnsignedChar::with_value(pei_type),
                state,
            )),
            pei_program: RefCell::new(PeiProgramObject::new(
                pei,
                0, // PEI has no memory-mapped address
                PDT_Generic05::with_value(pei_program_version),
                state,
            )),
            augments,
        }
    }

    /// Get a reference to the device object.
    pub fn device(&self) -> &RefCell<DeviceObject<'a, D::State>> {
        &self.device
    }

    /// Get a reference to the application program object.
    pub fn application_program(&self) -> &RefCell<ApplicationProgramObject<'a, APP>> {
        &self.application_program
    }

    /// Get the borrowed augment registry.
    pub fn augments(&self) -> &'a Aug {
        self.augments
    }

    /// Total number of interface objects (base + augment-provided).
    fn total_object_count(&self) -> u16 {
        Self::BASE_OBJECT_COUNT + self.augments.additional_object_count()
    }

    /// Total number of IO list entries (base + augment-provided).
    fn io_list_len(&self) -> u16 {
        BASE_IO_TYPES.len() as u16 + self.augments.additional_object_count()
    }

    /// Property descriptor for PID_IO_LIST.
    ///
    /// PID_IO_LIST policy per AN193 §"Object Type 0" — `3FF/0CC`
    /// (READ_OPEN_WRITE_TOOL). The property is read-only at the
    /// dispatch layer regardless of the policy's write bits.
    fn io_list_descriptor(&self) -> PropertyDescriptor {
        use zweidraehte_proto::access::AccessPolicy;
        PropertyDescriptor::array::<PDT_UnsignedInt>(
            pid::IO_LIST,
            self.io_list_len(),
            PropertyAccess::ReadOnly,
            3, // read_level: anyone can read
            0, // write_level: irrelevant (read-only)
            AccessPolicy::READ_OPEN_WRITE_TOOL,
        )
    }

    /// Read PID_IO_LIST as an array property into `buf`.
    ///
    /// Combines the 6 base types with augment-provided types.
    fn read_io_list(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        let total = self.io_list_len() as usize;

        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&(total as u16).to_be_bytes());
            return Ok(2);
        }

        let start = (start_idx - 1) as usize;

        if start >= total {
            return Err(PropertyError::InvalidStartIndex);
        }

        let end = (start + count as usize).min(total);
        let needed = (end - start) * 2;

        if buf.len() < needed {
            return Err(PropertyError::BufferTooSmall);
        }

        // Iterate over base types then augment types.
        let base_len = BASE_IO_TYPES.len();

        for i in start..end {
            let ot = if i < base_len {
                BASE_IO_TYPES[i]
            } else {
                self.augments
                    .additional_object_type_at((i - base_len) as u16)
                    .expect("augment additional_object_count/type_at mismatch")
            };

            let val: u16 = ot.into();
            let offset = (i - start) * 2;
            buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
        }

        Ok(needed)
    }

    /// Get a property descriptor for a base object's property.
    fn get_descriptor(&self, obj_idx: u16, prop_id: u16) -> Option<PropertyDescriptor> {
        // PID_IO_LIST is served by the container, not the DeviceObject.
        if obj_idx == 0 && prop_id == pid::IO_LIST {
            return Some(self.io_list_descriptor());
        }

        match obj_idx {
            0 => self.device.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            1 => self.address_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            2 => self.association_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            3 => self.group_object_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            4 => self.application_program.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            5 => self.pei_program.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            // Augment-provided objects: query augment for the descriptor.
            _ => {
                let obj_type = self.object_type_for(obj_idx)?;
                self.augments.get_property_descriptor(obj_type, prop_id)
            }
        }
    }

    /// Get the number of properties in a base interface object.
    ///
    /// Returns 0 for augment-provided objects (they have no base properties).
    fn base_property_count(&self, object_idx: u16) -> u16 {
        match object_idx {
            0 => self.device.borrow().property_count(),
            1 => self.address_table.borrow().property_count(),
            2 => self.association_table.borrow().property_count(),
            3 => self.group_object_table.borrow().property_count(),
            4 => self.application_program.borrow().property_count(),
            5 => self.pei_program.borrow().property_count(),
            _ => 0,
        }
    }

    /// Resolve the object type for a given index.
    ///
    /// Indices 0-5 are the base System B objects. Indices 6+ are
    /// augment-provided objects.
    fn object_type_for(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match object_idx {
            0 => Some(InterfaceObjectType::Device),
            1 => Some(InterfaceObjectType::AddressTable),
            2 => Some(InterfaceObjectType::AssociationTable),
            3 => Some(InterfaceObjectType::GroupObjectTable),
            4 => Some(InterfaceObjectType::ApplicationProgram),
            5 => Some(InterfaceObjectType::InterfaceProgram),
            _ => self.augments.additional_object_type_at(object_idx - Self::BASE_OBJECT_COUNT),
        }
    }

    /// Whether the given object index is an augment-provided object
    /// (as opposed to one of the 6 base objects).
    fn is_augment_object(&self, object_idx: u16) -> bool {
        object_idx >= Self::BASE_OBJECT_COUNT && object_idx < self.total_object_count()
    }

    /// Whether per-property `AccessPolicy` bitfields apply with their
    /// "Security Mode On" columns rather than the legacy "Security Mode Off"
    /// fallback.
    ///
    /// True only when the device's state actually reports Data Secure as
    /// enabled (Security IO `security_mode_enabled`). The previous version
    /// of this predicate also checked whether any augment contributes an
    /// additional object — that was a structural proxy that misfires the
    /// moment a non-security augment adds objects of its own. Routing
    /// through `state.security_mode_enabled()` directly fixes that and is
    /// semantically what every caller already wanted.
    fn enforce_secure_access_policy(&self) -> bool {
        self.state.security_mode_enabled()
    }

    /// Run the per-property access policy for `(object_idx, pid)` against
    /// the caller's `AccessContext`, calling `policy` to evaluate the
    /// matrix (`can_read_secure`, `can_write_secure`,
    /// `can_function_read_secure`, `can_function_write_secure`).
    ///
    /// Returns `true` if access is allowed (or no descriptor is registered
    /// for the property — unknown properties fall through to the
    /// per-object handlers, which decide whether they exist). Returns
    /// `false` after logging an access-denied event when the policy
    /// rejects the access.
    fn check_access<F>(
        &self,
        object_idx: u16,
        pid: u16,
        ctx: &zweidraehte_proto::access::AccessContext,
        policy: F,
    ) -> bool
    where
        F: FnOnce(&PropertyDescriptor, &zweidraehte_proto::access::AccessContext, bool) -> bool,
    {
        let Some(desc) = self.get_descriptor(object_idx, pid) else {
            return true;
        };

        if policy(&desc, ctx, self.enforce_secure_access_policy()) {
            return true;
        }

        if ctx.source_addr != 0 {
            self.state.log_access_denied(ctx.source_addr);
        }

        false
    }
}

// PropertyServiceHandler and HasDeviceObject impls are in `dispatch.rs`.

/// Type alias for [`SystemBObjects`] that auto-fills the associated type projections.
///
/// This is the TP1 counterpart to [`DefaultKnxIpInterfaceObjects`]. It provides
/// 6 interface objects (no IP Parameter Object).
pub type DefaultSystemBInterfaceObjects<'a, D, A = ()> = SystemBObjects<
    'a,
    D,
    <<D as StackDefinition>::State as HasAddressTable>::ADT,
    <<D as StackDefinition>::State as HasAssociationTable>::AST,
    <<D as StackDefinition>::State as HasCommunicationObjectTable>::COT,
    <<D as StackDefinition>::State as HasApplication>::APP,
    <<D as StackDefinition>::State as HasPeiApplication>::PEI,
    A,
>;

// ============================================================================
// Helper functions
// ============================================================================

/// Create System B interface objects.
///
/// Use this function in your `StackDefinition::create_interface_objects`
/// implementation. Pass `&()` as `augments` if no augmentation is needed
/// (note: the runner's `D::create_augments` already returns the
/// device-wide augment registry, so the `augments` parameter is the
/// `&'a Self::Augments<'a>` argument forwarded into the helper).
///
/// The IO list (PID_IO_LIST) will contain the 6 base System B object
/// types plus any additional objects the augment registry contributes
/// via [`Augment::additional_object_count`](crate::service::Augment::additional_object_count).
pub fn create_system_b_objects<'a, D, Aug>(
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
    layout: &super::memory_map::MemoryLayout,
    augments: &'a Aug,
) -> DefaultSystemBInterfaceObjects<'a, D, Aug>
where
    D: StackDefinition,
    D::State: StackState
        + DeviceModelNotifier
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    <D::State as HasAddressTable>::ADT: HasLoadStateMachine,
    <D::State as HasAssociationTable>::AST: HasLoadStateMachine,
    <D::State as HasCommunicationObjectTable>::COT: HasLoadStateMachine,
    <D::State as HasApplication>::APP: HasLoadStateMachine + HasRunStateMachine,
    <D::State as HasPeiApplication>::PEI: HasLoadStateMachine + HasRunStateMachine,
    Aug: crate::service::Augment<D>,
{
    SystemBObjects::new(
        state,
        lctx,
        D::DEVICE,
        layout,
        state.adt(),
        state.ast(),
        state.cot(),
        state.app(),
        state.pei(),
        D::DEVICE.program_version(),
        D::DEVICE.pei_program_version(),
        D::DEVICE.pei_type,
        state.routing_count(),
        augments,
    )
}

/// Type alias that resolves [`DefaultSystemBInterfaceObjects`] for a
/// [`StackDefinition`]'s `Augments` GAT.
///
/// # Example
///
/// ```rust,ignore
/// type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
/// ```
pub type SystemBInterfaceObjectsFor<'a, D> =
    DefaultSystemBInterfaceObjects<'a, D, <D as StackDefinition>::Augments<'a>>;
