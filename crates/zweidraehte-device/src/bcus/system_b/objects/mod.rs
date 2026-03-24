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

#[cfg(feature = "knxip")]
mod ip;
#[cfg(feature = "knxip")]
pub use ip::*;

use core::cell::RefCell;

use crate::{
    StackState,
    device_model::DeviceModelNotifier,
    dpt::{DeviceControl, InterfaceObjectType, PDT_Generic05, PDT_UnsignedChar, ProgrammingMode, RoutingCount},
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceInfo, DeviceObject,
        FullPropertyReadRequest, FullPropertyWriteRequest, FunctionPropertyRequest, FunctionPropertyResult,
        GroupObjectTableObject, HasDeviceObject, InterfaceObject, InterfaceObjectAugment, PeiProgramObject,
        PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyServiceHandler, WriteResponse, pid,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
};

use crate::StackDefinition;
use crate::objects::interface::HasRoutingCount;
use crate::objects::tables::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasPeiApplication,
};

// ============================================================================
// SystemBObjects - Base 5 Interface Objects
// ============================================================================

/// Base interface objects for System B devices (indices 0-5).
///
/// Contains the 6 mandatory interface objects:
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
/// - PEI Program Object (index 5)
///
/// For KNX/IP devices, compose this with [`IpObjects`] using a tuple:
/// ```rust,ignore
/// type MyObjects<'a, S, ADT, AST, COT, APP, PEI> = (
///     SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>,
///     IpObjects<'a, S>,
/// );
/// ```
///
/// # Type Parameters
///
/// - `S`: Stack state type implementing [`StackState`]
/// - `ADT`: Address table type
/// - `AST`: Association table type
/// - `COT`: Communication object table type
/// - `APP`: Application type (implementing both HasLoadStateMachine and HasRunStateMachine)
/// - `PEI`: PEI application type (implementing both HasLoadStateMachine and HasRunStateMachine)
pub struct SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S> = ()>
where
    S: StackState,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    state: &'a S,
    device: RefCell<DeviceObject<'a, S>>,
    address_table: RefCell<AddressTableObject<'a, ADT>>,
    association_table: RefCell<AssociationTableObject<'a, AST>>,
    group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
    application_program: RefCell<ApplicationProgramObject<'a, APP>>,
    pei_program: RefCell<PeiProgramObject<'a, PEI>>,
    augment: A,
}

impl<'a, S, ADT, AST, COT, APP, PEI> SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>
where
    S: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    /// Create a new interface objects container with no augmentation.
    pub fn new(
        state: &'a S,
        device_info: &DeviceInfo,
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
    ) -> Self {
        Self::with_augment(
            state,
            device_info,
            layout,
            adt,
            ast,
            cot,
            app,
            pei,
            program_version,
            pei_program_version,
            pei_type,
            routing_count,
            (),
        )
    }
}

impl<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S>> SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A>
where
    S: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 6;

    /// Create a new interface objects container with an augment chain.
    ///
    /// The augment can intercept property and function property requests
    /// before they reach the standard object implementations.
    pub fn with_augment(
        state: &'a S,
        device_info: &DeviceInfo,
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
        augment: A,
    ) -> Self {
        let mut device = DeviceObject::with_info(state, device_info);
        device.routing_count = RoutingCount::from(routing_count);
        Self {
            state,
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
            )),
            augment,
        }
    }

    /// Get a reference to the device object.
    pub fn device(&self) -> &RefCell<DeviceObject<'a, S>> {
        &self.device
    }

    /// Get a reference to the application program object.
    pub fn application_program(&self) -> &RefCell<ApplicationProgramObject<'a, APP>> {
        &self.application_program
    }

    /// Get the configured augment chain.
    pub fn augment(&self) -> &A {
        &self.augment
    }

    /// Get a property descriptor for a property.
    fn get_descriptor(&self, obj_idx: u16, prop_id: u8) -> Option<PropertyDescriptor> {
        match obj_idx {
            0 => self.device.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            1 => self.address_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            2 => self.association_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            3 => self.group_object_table.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            4 => self.application_program.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            5 => self.pei_program.borrow().property_descriptor_by_id(prop_id).map(|(_, d)| d),
            _ => None,
        }
    }

    /// Get the number of properties in a base interface object.
    fn base_property_count(&self, object_idx: u16) -> u8 {
        let count = match object_idx {
            0 => self.device.borrow().property_count(),
            1 => self.address_table.borrow().property_count(),
            2 => self.association_table.borrow().property_count(),
            3 => self.group_object_table.borrow().property_count(),
            4 => self.application_program.borrow().property_count(),
            5 => self.pei_program.borrow().property_count(),
            _ => 0,
        };
        count as u8
    }

    /// Resolve the object type for a given index.
    fn object_type_for(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        match object_idx {
            0 => Some(InterfaceObjectType::Device),
            1 => Some(InterfaceObjectType::AddressTable),
            2 => Some(InterfaceObjectType::AssociationTable),
            3 => Some(InterfaceObjectType::GroupObjectTable),
            4 => Some(InterfaceObjectType::ApplicationProgram),
            5 => Some(InterfaceObjectType::InterfaceProgram),
            _ => None,
        }
    }
}

impl<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S>> PropertyServiceHandler
    for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A>
where
    S: StackState + DeviceModelNotifier,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn object_count(&self) -> u16 {
        Self::OBJECT_COUNT
    }

    fn object_type_at(&self, object_idx: u16) -> Option<InterfaceObjectType> {
        self.object_type_for(object_idx)
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        use crate::objects::interface::PropertyLookup;

        let obj_type = self.object_type_for(object_idx);

        if prop_id != 0 {
            // Direct PID lookup: augment first (can intercept/add PIDs),
            // then base.
            if let Some(ot) = obj_type
                && let Some(result) =
                    self.augment.property_description_read(self.state, ot, object_idx, PropertyLookup::ByPid(prop_id))
                {
                    return result;
                }
        }

        let base_result = match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.address_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.association_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.group_object_table.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.application_program.borrow().property_description(object_idx, prop_id, prop_idx),
            5 => self.pei_program.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        };

        if base_result.is_ok() || prop_id != 0 {
            return base_result;
        }

        // Index scan (prop_id == 0): base ran out of properties.
        // Give the augment a chance to append its own, using a 0-based
        // index offset from the base property count.
        if let Some(ot) = obj_type {
            let base_count = self.base_property_count(object_idx);
            let augment_idx = prop_idx.saturating_sub(base_count);
            if let Some(result) =
                self.augment.property_description_read(self.state, ot, object_idx, PropertyLookup::ByIndex(augment_idx))
            {
                // Restore the original prop_idx in the response so it
                // matches the client's request.
                return result.map(|mut resp| {
                    resp.prop_idx = prop_idx;
                    resp
                });
            }
        }

        base_result
    }

    fn property_value_read(&self, req: &FullPropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        // Augment first (can intercept specific PIDs).
        if let Some(obj_type) = self.object_type_for(req.object_idx)
            && let Some(result) = self.augment.property_value_read(self.state, obj_type, req, buf) {
                return result;
            }

        // Check access level
        let desc = self.get_descriptor(req.object_idx, req.pid).ok_or(PropertyError::InvalidPropertyId)?;
        if !desc.can_read(req.ctx) {
            return Err(PropertyError::AccessDenied);
        }

        // Dispatch to the appropriate object
        let prop_req = req.property_request();
        match req.object_idx {
            0 => self.device.borrow().read_property(prop_req, buf),
            1 => self.address_table.borrow().read_property(prop_req, buf),
            2 => self.association_table.borrow().read_property(prop_req, buf),
            3 => self.group_object_table.borrow().read_property(prop_req, buf),
            4 => self.application_program.borrow().read_property(prop_req, buf),
            5 => self.pei_program.borrow().read_property(prop_req, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(&self, req: &FullPropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        // Augment first (can intercept specific PIDs).
        if let Some(obj_type) = self.object_type_for(req.object_idx)
            && let Some(result) = self.augment.property_value_write(self.state, obj_type, req) {
                if result.is_ok() {
                    self.state.mark_dirty();
                }
                return result;
            }

        // Check access level
        let desc = self.get_descriptor(req.object_idx, req.pid).ok_or(PropertyError::InvalidPropertyId)?;
        if !desc.can_write(req.ctx) {
            return Err(PropertyError::AccessDenied);
        }

        // Dispatch to the appropriate object using borrow_mut for interior mutability
        let prop_req = req.property_request();
        let result = match req.object_idx {
            0 => self.device.borrow_mut().write_property(prop_req),
            1 => self.address_table.borrow_mut().write_property(prop_req),
            2 => self.association_table.borrow_mut().write_property(prop_req),
            3 => self.group_object_table.borrow_mut().write_property(prop_req),
            4 => self.application_program.borrow_mut().write_property(prop_req),
            5 => self.pei_program.borrow_mut().write_property(prop_req),
            _ => Err(PropertyError::InvalidObjectIndex),
        };

        // Mark state dirty on successful property writes, but skip volatile
        // properties that don't need persistence (runtime control flags,
        // execution state). These are transient and re-derived on boot.
        if result.is_ok() {
            let volatile = matches!(
                (req.object_idx, req.pid),
                (0, pid::DEVICE_CONTROL)
                    | (0, pid::PROGMODE)
                    | (4, pid::RUN_STATE_CONTROL)
                    | (5, pid::RUN_STATE_CONTROL)
            );
            if !volatile {
                self.state.mark_dirty();
            }
        }

        result
    }

    fn function_property_command(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if let Some(obj_type) = self.object_type_for(req.object_idx)
            && let Some(result) = self.augment.function_property_command(self.state, obj_type, req) {
                return result;
            }
        FunctionPropertyResult::not_supported()
    }

    fn function_property_state_read(&self, req: &FunctionPropertyRequest<'_>) -> FunctionPropertyResult {
        if let Some(obj_type) = self.object_type_for(req.object_idx)
            && let Some(result) = self.augment.function_property_state_read(self.state, obj_type, req) {
                return result;
            }
        FunctionPropertyResult::not_supported()
    }
}

impl<'a, S, ADT, AST, COT, APP, PEI, A: InterfaceObjectAugment<S>> HasDeviceObject
    for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI, A>
where
    S: StackState + DeviceModelNotifier + HasRoutingCount,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn device_control(&self) -> DeviceControl {
        self.device.borrow().device_control
    }

    fn set_device_control(&self, value: DeviceControl) {
        self.device.borrow_mut().device_control = value;
    }

    fn programming_mode(&self) -> ProgrammingMode {
        ProgrammingMode::from(self.state.is_programming_mode())
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.state.set_programming_mode(value.enabled());
    }

    fn routing_count(&self) -> RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.device.borrow_mut().routing_count = value;
        // Sync to state so the network layer (which reads routing count
        // from state via HasRoutingCount) stays in sync with ETS property writes.
        self.state.set_routing_count(value.value());
    }
}

/// Type alias for [`SystemBObjects`] that auto-fills the associated type projections.
///
/// This is the TP1 counterpart to [`DefaultKnxIpInterfaceObjects`]. It provides
/// 6 interface objects (no IP Parameter Object).
pub type DefaultSystemBInterfaceObjects<'a, S, A = ()> = SystemBObjects<
    'a,
    S,
    <S as HasAddressTable>::ADT,
    <S as HasAssociationTable>::AST,
    <S as HasCommunicationObjectTable>::COT,
    <S as HasApplication>::APP,
    <S as HasPeiApplication>::PEI,
    A,
>;

// ============================================================================
// Helper functions
// ============================================================================

/// Create a DeviceInfo struct from a StackDefinition type.
///
/// Note: `max_apdu_length` is not included here because it's read dynamically
/// from `StackState::max_apdu_length()`.
pub fn device_info_from<D: StackDefinition>() -> DeviceInfo {
    DeviceInfo {
        order_info: [0; 10], // Manufacturer-specific, usually left empty
        hardware_type: D::DEVICE.hardware_type,
        version: [0x00, 0x01], // Default version 0.0.1
        device_descriptor: D::DEVICE.mask_version.as_u16(),
    }
}

/// Create a [`DeviceInfo`] from a [`DeviceDescriptor`].
///
/// This is the preferred way to create device info as `DeviceDescriptor` is the
/// single source of truth for device identification.
///
/// # Arguments
///
/// * `desc` - The device descriptor containing hardware and application info
///
/// # Returns
///
/// A `DeviceInfo` struct suitable for the Device Object.
pub fn device_info_from_descriptor(desc: &crate::ets::DeviceDescriptor) -> DeviceInfo {
    DeviceInfo {
        order_info: [0; 10], // Manufacturer-specific, usually left empty
        hardware_type: desc.hardware_type,
        version: [0x00, 0x01], // Default version 0.0.1
        device_descriptor: desc.mask_version.as_u16(),
    }
}

/// Create base System B interface objects (6 objects: indices 0-5).
///
/// Use this function in your `StackDefinition::create_interface_objects`
/// implementation for non-IP System B devices. Pass `()` as the augment
/// if no augmentation is needed, or an [`InterfaceObjectAugment`] to
/// intercept property and function property requests.
pub fn create_system_b_objects<'a, D, S, A>(
    state: &'a S,
    layout: &super::memory_map::MemoryLayout,
    augment: A,
) -> SystemBObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI, A>
where
    D: StackDefinition,
    S: StackState
        + DeviceModelNotifier
        + HasAddressTable
        + HasAssociationTable
        + HasCommunicationObjectTable
        + HasApplication
        + HasPeiApplication
        + HasRoutingCount,
    S::ADT: HasLoadStateMachine,
    S::AST: HasLoadStateMachine,
    S::COT: HasLoadStateMachine,
    S::APP: HasLoadStateMachine + HasRunStateMachine,
    S::PEI: HasLoadStateMachine + HasRunStateMachine,
    A: InterfaceObjectAugment<S>,
{
    let device_info = device_info_from::<D>();
    SystemBObjects::with_augment(
        state,
        &device_info,
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
        augment,
    )
}
