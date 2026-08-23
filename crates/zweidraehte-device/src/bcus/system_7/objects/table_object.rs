//! Table interface objects for System 7 devices.
//!
//! Same shape as the System B `TableInterfaceObject`, minus `PID_TABLE`:
//! Annex A.2.4/A.2.5 marks the property-based table access optional for
//! the System 7 masks and ETS reaches the table bytes through absolute
//! memory anyway — omitting it also sidesteps the fact that the shared
//! array-property helpers assume the System B tables' 2-octet count
//! prefix, while the compact System 7 tables use a single octet.
//!
//! Access levels per the 0705h column of Annex A.2.4/A.2.5: both reads and
//! writes use controller level 3. The mask's free runtime level remains 15.

use core::cell::RefCell;
use core::marker::PhantomData;

use zweidraehte_proto::access::{AccessLevel, AccessPolicy};
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Generic08, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong,
    PropertyDataDefinition,
};
use zweidraehte_proto::properties::{PropertyAccess, PropertyDescriptor, PropertyDescriptorSpec, PropertyError};

use super::super::SYSTEM7_MAX_ACCESS_LEVELS;
use crate::objects::interface::{
    InterfaceObject, PropertyRead, PropertyReadRequest, PropertyWriteRequest, TableObjectSpec, WriteResponse, pid,
};
use crate::objects::tables::HasLoadStateMachine;

/// Table interface object for System 7 (address / association tables).
///
/// `S` reuses the System B [`TableObjectSpec`] markers for the object
/// type; the entry-size and prefix constants those specs also carry are
/// only meaningful for `PID_TABLE`, which this object does not expose.
pub struct System7TableObject<'a, T: HasLoadStateMachine, S: TableObjectSpec> {
    table: &'a RefCell<T>,
    _spec: PhantomData<S>,
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> System7TableObject<'a, T, S> {
    pub fn new(table: &'a RefCell<T>) -> Self {
        Self { table, _spec: PhantomData }
    }

    /// Resolve the named audiences into the 16-level values MV-0705 puts
    /// on the wire. Keeping the unresolved descriptors here prevents a
    /// literal Annex-A `3` from being confused with unrestricted runtime
    /// access, which is level 15 on System 7.
    fn property_descriptors() -> [PropertyDescriptor; 5] {
        [
            PropertyDescriptorSpec::new(
                pid::OBJECT_TYPE,
                PDT_UnsignedInt::ID,
                1,
                PropertyAccess::ReadOnly,
                AccessLevel::Controller,
                AccessLevel::SystemManufacturer,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptorSpec::new(
                pid::LOAD_STATE_CONTROL,
                PDT_Control::ID,
                1,
                PropertyAccess::ReadWrite,
                AccessLevel::Controller,
                AccessLevel::Controller,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptorSpec::new(
                pid::TABLE_REFERENCE,
                PDT_UnsignedLong::ID,
                1,
                PropertyAccess::ReadWrite,
                AccessLevel::Controller,
                AccessLevel::Controller,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptorSpec::new(
                pid::MCB_TABLE,
                PDT_Generic08::ID,
                1,
                PropertyAccess::ReadOnly,
                AccessLevel::Controller,
                AccessLevel::SystemManufacturer,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptorSpec::new(
                pid::ERROR_CODE,
                PDT_UnsignedChar::ID,
                1,
                PropertyAccess::ReadOnly,
                AccessLevel::Controller,
                AccessLevel::SystemManufacturer,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
        ]
        .map(|descriptor| descriptor.for_levels(SYSTEM7_MAX_ACCESS_LEVELS as u8))
    }
}

impl<'a, T: HasLoadStateMachine, S: TableObjectSpec> InterfaceObject for System7TableObject<'a, T, S> {
    fn object_type(&self) -> InterfaceObjectType {
        S::OBJECT_TYPE
    }

    fn property_count(&self) -> u16 {
        5
    }

    fn property_descriptor_by_index(&self, prop_idx: u16) -> Option<PropertyDescriptor> {
        Self::property_descriptors().get(prop_idx as usize).copied()
    }

    fn property_descriptor_by_id(&self, pid: u16) -> Option<(u16, PropertyDescriptor)> {
        Self::property_descriptors().iter().enumerate().find(|(_, d)| d.pid == pid).map(|(i, d)| (i as u16, *d))
    }

    fn read_property(&self, req: PropertyReadRequest, buf: &mut [u8]) -> Result<usize, PropertyError> {
        match req.pid {
            pid::OBJECT_TYPE => {
                let obj_type: u16 = S::OBJECT_TYPE.into();
                obj_type.to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            pid::LOAD_STATE_CONTROL => self.table.borrow().read_lsm().read_property(req.start_idx, req.count, buf),
            pid::TABLE_REFERENCE => {
                self.table.borrow().table_reference().to_be_bytes().read_property(req.start_idx, req.count, buf)
            }
            pid::MCB_TABLE => self.table.borrow().mcb_bytes().read_property(req.start_idx, req.count, buf),
            pid::ERROR_CODE => [self.table.borrow().last_error_code()].read_property(req.start_idx, req.count, buf),
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn write_property(&mut self, req: PropertyWriteRequest<'_>) -> Result<WriteResponse, PropertyError> {
        match req.pid {
            pid::OBJECT_TYPE | pid::MCB_TABLE | pid::ERROR_CODE => Err(PropertyError::WriteNotAllowed),
            pid::LOAD_STATE_CONTROL => {
                // The absolute-segment records carry their own addresses;
                // no allocation address to hand in.
                self.table.borrow_mut().write_lsm(req.data, None);
                Ok(WriteResponse::byte(self.table.borrow().read_lsm()[0]))
            }
            pid::TABLE_REFERENCE => {
                let bytes: [u8; 4] = req.data.try_into().map_err(|_| PropertyError::InvalidElementCount)?;
                self.table.borrow_mut().set_table_reference(u32::from_be_bytes(bytes));
                Ok(WriteResponse::Echo)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }

    fn property_element_count(&self, pid_: u16) -> Result<u16, PropertyError> {
        match pid_ {
            pid::OBJECT_TYPE | pid::LOAD_STATE_CONTROL | pid::TABLE_REFERENCE | pid::MCB_TABLE | pid::ERROR_CODE => {
                Ok(1)
            }
            _ => Err(PropertyError::InvalidPropertyId),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::interface::AddressTableSpec;
    use crate::objects::tables::addr8::AddrTab8;

    #[test]
    fn mv0705_table_reference_is_writable_at_controller_level() {
        let table = RefCell::new(AddrTab8::<4>::new());
        let mut object = System7TableObject::<_, AddressTableSpec>::new(&table);

        let (_, descriptor) = object.property_descriptor_by_id(pid::TABLE_REFERENCE).expect("property exists");
        assert_eq!(descriptor.access, PropertyAccess::ReadWrite);
        assert_eq!(descriptor.read_level, 3);
        assert_eq!(descriptor.write_level, 3);

        object
            .write_property(PropertyWriteRequest {
                pid: pid::TABLE_REFERENCE,
                start_idx: 1,
                data: &[0x00, 0x00, 0x44, 0x00],
            })
            .expect("four-byte reference is accepted");
        assert_eq!(table.borrow().table_reference(), 0x4400);
    }

    #[test]
    fn mv0705_table_properties_resolve_controller_as_level_three() {
        let table = RefCell::new(AddrTab8::<4>::new());
        let object = System7TableObject::<_, AddressTableSpec>::new(&table);

        for pid in [pid::OBJECT_TYPE, pid::LOAD_STATE_CONTROL, pid::TABLE_REFERENCE, pid::MCB_TABLE, pid::ERROR_CODE] {
            let (_, descriptor) = object.property_descriptor_by_id(pid).expect("property exists");
            assert_eq!(descriptor.read_level, 3, "PID {pid}");
        }
    }
}
