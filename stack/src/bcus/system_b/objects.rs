//! Interface objects containers for System B devices.
//!
//! This module provides containers that group all interface objects required
//! for System B devices, implementing the [`PropertyServiceHandler`] trait
//! to dispatch property reads/writes to the appropriate object.
//!
//! # Object Indices
//!
//! Base System B objects (x7B0):
//! - Index 0: Device Object
//! - Index 1: Address Table Object
//! - Index 2: Association Table Object
//! - Index 3: Group Object Table Object
//! - Index 4: Application Program Object
//!
//! KNX/IP additional objects (57B0):
//! - Index 5: IP Parameter Object

use core::cell::RefCell;

use crate::{
    IpStackState, StackState,
    dpt::{PDT_Generic05, PDT_UnsignedChar},
    objects::interface::{
        InterfaceObject, PropertyDescriptionResponse, PropertyDescriptor, PropertyError,
        PropertyServiceHandler,
        AddressTableObject, ApplicationProgramObject, AssociationTableObject,
        DeviceInfo, DeviceObject, GroupObjectTableObject, IpParameterObject,
    },
    objects::tables::{LoadableTable, RunnableTable},
};

use super::SystemBDevice;

/// Interface objects container for base System B devices.
///
/// Contains the 5 mandatory interface objects:
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
///
/// The objects are wrapped in `RefCell` to allow interior mutability through
/// the `PropertyServiceHandler` trait which takes `&self` for all methods.
///
/// # Type Parameters
///
/// - `S`: Stack state type implementing [`StackState`]
/// - `ADT`: Address table type
/// - `AST`: Association table type
/// - `COT`: Communication object table type
/// - `APP`: Application type (implementing both LoadableTable and RunnableTable)
pub struct SystemBInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: StackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
{
    device: RefCell<DeviceObject<'a, S>>,
    address_table: RefCell<AddressTableObject<'a, ADT>>,
    association_table: RefCell<AssociationTableObject<'a, AST>>,
    group_object_table: RefCell<GroupObjectTableObject<'a, COT>>,
    application_program: RefCell<ApplicationProgramObject<'a, APP>>,
}

impl<'a, S, ADT, AST, COT, APP> SystemBInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: StackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
{
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 5;

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
    /// - `program_version`: Application program version (5 bytes)
    /// - `pei_type`: PEI type (0 = no PEI)
    pub fn new(
        state: &'a S,
        device_info: &DeviceInfo,
        layout: &super::memory_map::MemoryLayout,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        cot: &'a RefCell<COT>,
        app: &'a RefCell<APP>,
        program_version: [u8; 5],
        pei_type: u8,
    ) -> Self {
        Self {
            device: RefCell::new(DeviceObject::with_info(state, device_info)),
            address_table: RefCell::new(AddressTableObject::new(adt, layout.adt_address() as u32)),
            association_table: RefCell::new(AssociationTableObject::new(ast, layout.ast_address() as u32)),
            group_object_table: RefCell::new(GroupObjectTableObject::new(cot, layout.cot_address() as u32)),
            application_program: RefCell::new(ApplicationProgramObject::with_info(
                app,
                layout.app_address() as u32,
                PDT_Generic05::with_value(program_version),
                PDT_UnsignedChar::with_value(pei_type),
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
            _ => None,
        }
    }
}

impl<'a, S, ADT, AST, COT, APP> PropertyServiceHandler
    for SystemBInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: StackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
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
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }

    fn property_value_write(
        &self,
        object_idx: u16,
        prop_id: u8,
        start_idx: u16,
        data: &[u8],
        response_buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        // Check access level
        let desc = self.get_descriptor(object_idx, prop_id).ok_or(PropertyError::InvalidPropertyId)?;
        if !desc.can_write(access_level) {
            return Err(PropertyError::AccessDenied);
        }

        // Dispatch to the appropriate object using borrow_mut for interior mutability
        match object_idx {
            0 => self.device.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            1 => self.address_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            2 => self.association_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            3 => self.group_object_table.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            4 => self.application_program.borrow_mut().write_property(prop_id, start_idx, data, response_buf),
            _ => Err(PropertyError::InvalidObjectIndex),
        }
    }
}

// ============================================================================
// KNX/IP Interface Objects (adds IP Parameter Object)
// ============================================================================

/// Interface objects container for KNX/IP devices (57B0).
///
/// Extends [`SystemBInterfaceObjects`] with the IP Parameter Object at index 5.
///
/// Contains 6 interface objects:
/// - Device Object (index 0)
/// - Address Table Object (index 1)
/// - Association Table Object (index 2)
/// - Group Object Table Object (index 3)
/// - Application Program Object (index 4)
/// - IP Parameter Object (index 5)
pub struct KnxIpInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: IpStackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
{
    /// Base System B objects (indices 0-4)
    base: SystemBInterfaceObjects<'a, S, ADT, AST, COT, APP>,
    /// IP Parameter Object (index 5)
    ip_parameter: RefCell<IpParameterObject<'a, S>>,
}

impl<'a, S, ADT, AST, COT, APP> KnxIpInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: IpStackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
{
    /// Number of interface objects in this container.
    pub const OBJECT_COUNT: u16 = 6;

    /// Create a new KNX/IP interface objects container.
    pub fn new(
        state: &'a S,
        device_info: &DeviceInfo,
        layout: &super::memory_map::MemoryLayout,
        adt: &'a RefCell<ADT>,
        ast: &'a RefCell<AST>,
        cot: &'a RefCell<COT>,
        app: &'a RefCell<APP>,
        program_version: [u8; 5],
        pei_type: u8,
    ) -> Self {
        Self {
            base: SystemBInterfaceObjects::new(
                state,
                device_info,
                layout,
                adt,
                ast,
                cot,
                app,
                program_version,
                pei_type,
            ),
            ip_parameter: RefCell::new(IpParameterObject::with_state(state)),
        }
    }

    /// Get a reference to the base System B objects.
    pub fn base(&self) -> &SystemBInterfaceObjects<'a, S, ADT, AST, COT, APP> {
        &self.base
    }

    /// Get a reference to the IP Parameter Object.
    pub fn ip_parameter(&self) -> &RefCell<IpParameterObject<'a, S>> {
        &self.ip_parameter
    }
}

impl<'a, S, ADT, AST, COT, APP> PropertyServiceHandler
    for KnxIpInterfaceObjects<'a, S, ADT, AST, COT, APP>
where
    S: IpStackState,
    ADT: LoadableTable,
    AST: LoadableTable,
    COT: LoadableTable,
    APP: LoadableTable + RunnableTable,
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
        if object_idx < 5 {
            self.base.property_description_read(object_idx, prop_id, prop_idx)
        } else if object_idx == 5 {
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
        if object_idx < 5 {
            self.base.property_value_read(object_idx, prop_id, start_idx, count, buf, access_level)
        } else if object_idx == 5 {
            // Check access level for IP parameter object
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
        response_buf: &mut [u8],
        access_level: u8,
    ) -> Result<usize, PropertyError> {
        if object_idx < 5 {
            self.base.property_value_write(object_idx, prop_id, start_idx, data, response_buf, access_level)
        } else if object_idx == 5 {
            // Check access level for IP parameter object
            if let Some((_, desc)) = self.ip_parameter.borrow().property_descriptor_by_id(prop_id) {
                if !desc.can_write(access_level) {
                    return Err(PropertyError::AccessDenied);
                }
            } else {
                return Err(PropertyError::InvalidPropertyId);
            }
            self.ip_parameter.borrow_mut().write_property(prop_id, start_idx, data, response_buf)
        } else {
            Err(PropertyError::InvalidObjectIndex)
        }
    }
}

// ============================================================================
// Helper functions for creating interface objects with SystemBDevice
// ============================================================================

/// Create a DeviceInfo struct from a SystemBDevice type.
pub fn device_info_from<D: SystemBDevice>() -> DeviceInfo {
    DeviceInfo {
        order_info: [0; 10], // Manufacturer-specific, usually left empty
        hardware_type: D::HARDWARE_TYPE,
        version: [0x00, 0x01], // Default version 0.0.1
        max_apdu_length: if D::MASK_VERSION == [0x57, 0xB0] { 254 } else { 14 },
        device_descriptor: u16::from_be_bytes(D::MASK_VERSION),
    }
}
