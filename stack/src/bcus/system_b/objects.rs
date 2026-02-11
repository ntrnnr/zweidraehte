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

use core::cell::RefCell;

use crate::{
    IpStackState, StackState,
    dpt::{DeviceControl, PDT_Generic05, PDT_UnsignedChar, ProgrammingMode, RoutingCount},
    objects::interface::{
        AddressTableObject, ApplicationProgramObject, AssociationTableObject, DeviceInfo, DeviceObject,
        GroupObjectTableObject, HasDeviceObject, InterfaceObject, IpParameterObject, PeiProgramObject,
        PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyServiceHandler, WriteResponse,
    },
    objects::tables::{HasLoadStateMachine, HasRunStateMachine},
};

use super::SystemBDevice;
use crate::StackDefinition;
use crate::memory::{
    HasAddressTable, HasApplication, HasAssociationTable, HasCommunicationObjectTable, HasPeiApplication,
    HasRoutingCount,
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
pub struct SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>
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
}

impl<'a, S, ADT, AST, COT, APP, PEI> SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>
where
    S: StackState,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 6;

    /// Create a new interface objects container.
    ///
    /// # Arguments
    ///
    /// - `state`: Reference to the stack state
    /// - `device_info`: Device information for the Device Object
    /// - `layout`: Memory layout defining table allocation addresses
    /// - `adt`: Reference to the address table
    /// - `ast`: Reference to the association table
    /// - `cot`: Reference to the group object table
    /// - `app`: Reference to the application
    /// - `pei`: Reference to the PEI application
    /// - `program_version`: Application program version (5 bytes)
    /// - `pei_program_version`: PEI program version (5 bytes)
    /// - `pei_type`: PEI type (0 = no PEI)
    /// - `routing_count`: Routing count (hop count) for outgoing messages (0-7)
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
            )),
            pei_program: RefCell::new(PeiProgramObject::new(
                pei,
                0, // PEI has no memory-mapped address
                PDT_Generic05::with_value(pei_program_version),
            )),
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
}

impl<'a, S, ADT, AST, COT, APP, PEI> PropertyServiceHandler for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>
where
    S: StackState,
    ADT: HasLoadStateMachine,
    AST: HasLoadStateMachine,
    COT: HasLoadStateMachine,
    APP: HasLoadStateMachine + HasRunStateMachine,
    PEI: HasLoadStateMachine + HasRunStateMachine,
{
    fn object_count(&self) -> u16 {
        Self::OBJECT_COUNT
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        match object_idx {
            0 => self.device.borrow().property_description(object_idx, prop_id, prop_idx),
            1 => self.address_table.borrow().property_description(object_idx, prop_id, prop_idx),
            2 => self.association_table.borrow().property_description(object_idx, prop_id, prop_idx),
            3 => self.group_object_table.borrow().property_description(object_idx, prop_id, prop_idx),
            4 => self.application_program.borrow().property_description(object_idx, prop_id, prop_idx),
            5 => self.pei_program.borrow().property_description(object_idx, prop_id, prop_idx),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        // Check access level
        let desc = self.get_descriptor(object_idx, prop_id).ok_or(PropertyError::InvalidPropertyId)?;
        if !desc.can_read(access_level) {
            return Err(PropertyError::AccessDenied);
        }

        // Dispatch to the appropriate object
        match object_idx {
            0 => self.device.borrow().read_property(prop_id, start_idx, count, buf),
            1 => self.address_table.borrow().read_property(prop_id, start_idx, count, buf),
            2 => self.association_table.borrow().read_property(prop_id, start_idx, count, buf),
            3 => self.group_object_table.borrow().read_property(prop_id, start_idx, count, buf),
            4 => self.application_program.borrow().read_property(prop_id, start_idx, count, buf),
            5 => self.pei_program.borrow().read_property(prop_id, start_idx, count, buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        access_level: u8,
    ) -> Result<WriteResponse, PropertyError> {
        // Check access level
        let desc = self.get_descriptor(object_idx, prop_id).ok_or(PropertyError::InvalidPropertyId)?;
        if !desc.can_write(access_level) {
            return Err(PropertyError::AccessDenied);
        }

        // Dispatch to the appropriate object using borrow_mut for interior mutability
        let result = match object_idx {
            0 => self.device.borrow_mut().write_property(prop_id, start_idx, data),
            1 => self.address_table.borrow_mut().write_property(prop_id, start_idx, data),
            2 => self.association_table.borrow_mut().write_property(prop_id, start_idx, data),
            3 => self.group_object_table.borrow_mut().write_property(prop_id, start_idx, data),
            4 => self.application_program.borrow_mut().write_property(prop_id, start_idx, data),
            5 => self.pei_program.borrow_mut().write_property(prop_id, start_idx, data),
            _ => Err(PropertyError::InvalidObjectIndex),
        };

        // Mark state dirty on any successful property write so that
        // the device state gets persisted before the next restart.
        if result.is_ok() {
            self.state.mark_dirty();
        }

        result
    }
}

impl<'a, S, ADT, AST, COT, APP, PEI> HasDeviceObject for SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>
where
    S: StackState,
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
        self.device.borrow().programming_mode
    }

    fn set_programming_mode(&self, value: ProgrammingMode) {
        self.device.borrow_mut().programming_mode = value;
    }

    fn routing_count(&self) -> RoutingCount {
        self.device.borrow().routing_count
    }

    fn set_routing_count(&self, value: RoutingCount) {
        self.device.borrow_mut().routing_count = value;
    }
}

// ============================================================================
// IpObjects - IP Parameter Object
// ============================================================================

/// IP interface objects for KNX/IP devices (index 6).
///
/// Contains only the IP Parameter Object. Compose with [`SystemBObjects`]
/// using a tuple to create a complete KNX/IP device:
///
/// ```rust,ignore
/// let objects: (SystemBObjects<...>, IpObjects<...>) = (base, ip);
/// // objects.object_count() == 7
/// ```
///
/// The tuple's `PropertyServiceHandler` implementation automatically handles
/// index offsetting - IpObjects receives index 0 for what is logically index 6.
pub struct IpObjects<'a, S: IpStackState> {
    state: &'a S,
    ip_parameter: RefCell<IpParameterObject<'a, S>>,
}

impl<'a, S: IpStackState> IpObjects<'a, S> {
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 1;

    /// Create new IP objects.
    pub fn new(state: &'a S) -> Self {
        Self { state, ip_parameter: RefCell::new(IpParameterObject::with_state(state)) }
    }

    /// Get a reference to the IP Parameter Object.
    pub fn ip_parameter(&self) -> &RefCell<IpParameterObject<'a, S>> {
        &self.ip_parameter
    }
}

impl<'a, S: IpStackState> PropertyServiceHandler for IpObjects<'a, S> {
    fn object_count(&self) -> u16 {
        Self::OBJECT_COUNT
    }

    fn property_description_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        prop_idx: u8,
    ) -> Result<PropertyDescriptionResponse, PropertyError> {
        if object_idx == 0 {
            // Note: We need to report the actual object index (5) in the response,
            // but the tuple impl calls us with 0. The caller handles this.
            self.ip_parameter.borrow().property_description(object_idx, prop_id, prop_idx)
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }

    fn property_value_read(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        count: u16,
        buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        if object_idx == 0 {
            // Check access level
            if let Some((_, desc)) = self.ip_parameter.borrow().property_descriptor_by_id(prop_id) {
                if !desc.can_read(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            } else {
                return Err(PropertyError::InvalidPropertyId);
            }
            self.ip_parameter.borrow().read_property(prop_id, start_idx, count, buf)
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        access_level: u8,
    ) -> Result<WriteResponse, PropertyError> {
        if object_idx == 0 {
            // Check access level
            if let Some((_, desc)) = self.ip_parameter.borrow().property_descriptor_by_id(prop_id) {
                if !desc.can_write(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            } else {
                return Err(PropertyError::InvalidPropertyId);
            }
            let result = self.ip_parameter.borrow_mut().write_property(prop_id, start_idx, data);
            if result.is_ok() {
                self.state.mark_dirty();
            }
            result
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }
}

// ============================================================================
// KNX/IP Interface Objects - Composed Type
// ============================================================================

/// Interface objects for KNX/IP devices (57B0).
///
/// This is a type alias for the tuple `(SystemBObjects, IpObjects)`.
/// The tuple's `PropertyServiceHandler` and `HasDeviceObject` implementations
/// automatically handle dispatch to the appropriate component.
///
/// Contains 7 interface objects:
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
/// - PEI Program Object (index 5)
/// - IP Parameter Object (index 6)
pub type KnxIpInterfaceObjects<'a, S, ADT, AST, COT, APP, PEI> =
    (SystemBObjects<'a, S, ADT, AST, COT, APP, PEI>, IpObjects<'a, S>);

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
        device_descriptor: D::DEVICE.mask_version,
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
        device_descriptor: desc.mask_version,
    }
}

/// Create base System B interface objects (6 objects: indices 0-5).
///
/// Use this function in your `StackDefinition::create_interface_objects` implementation
/// for non-IP System B devices.
///
/// # Type Parameters
///
/// - `D`: Stack definition implementing [`StackDefinition`] + [`SystemBDevice`]
/// - `S`: Unified state type implementing [`StackState`] and the required table traits
pub fn create_system_b_objects<'a, D, S>(
    state: &'a S,
    layout: &super::memory_map::MemoryLayout,
) -> SystemBObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI>
where
    D: StackDefinition + SystemBDevice,
    S: StackState
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
{
    let device_info = device_info_from::<D>();
    SystemBObjects::new(
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
        D::PEI_TYPE,
        state.routing_count(),
    )
}

/// Create KNX/IP interface objects (7 objects: indices 0-6).
///
/// Use this function in your `StackDefinition::create_interface_objects` implementation
/// for KNX/IP System B devices (57B0).
///
/// # Type Parameters
///
/// - `D`: Stack definition implementing [`StackDefinition`] + [`SystemBDevice`]
/// - `S`: Unified state type implementing [`IpStackState`] and the required table traits
pub fn create_knxip_objects<'a, D, S>(
    state: &'a S,
    layout: &super::memory_map::MemoryLayout,
) -> KnxIpInterfaceObjects<'a, S, S::ADT, S::AST, S::COT, S::APP, S::PEI>
where
    D: StackDefinition + SystemBDevice,
    S: IpStackState
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
{
    let base = create_system_b_objects::<D, S>(state, layout);
    let ip = IpObjects::new(state);
    (base, ip)
}
