//! Table interface objects for System 7 devices.
//!
//! Same shape as the System B `TableInterfaceObject`, minus `PID_TABLE`:
//! Annex A.2.4/A.2.5 marks the property-based table access optional for
//! the System 7 masks and ETS reaches the table bytes through absolute
//! memory anyway — omitting it also sidesteps the fact that the shared
//! array-property helpers assume the System B tables' 2-octet count
//! prefix, while the compact System 7 tables use a single octet.
//!
//! Access levels per the 0705h column of Annex A.2.4/A.2.5: reads at 15
//! ("everyone" in the 16-level model), the load state machine writable
//! from level 2.

use core::cell::RefCell;
use core::marker::PhantomData;

use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_Control, PDT_Generic08, PDT_UnsignedChar, PDT_UnsignedInt, PDT_UnsignedLong,
    PropertyDataDefinition,
};
use zweidraehte_proto::properties::{PropertyAccess, PropertyDescriptor, PropertyError};

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

    /// Raw numbers rather than audiences, for the same reason as the
    /// System B twin (`objects::interface::TableInterfaceObject`): this
    /// table is built only by System 7, so there is no profile left to
    /// resolve against. The 15s are the 16-level model's "everyone".
    fn property_descriptors() -> [PropertyDescriptor; 5] {
        [
            PropertyDescriptor::new(
                pid::OBJECT_TYPE,
                PDT_UnsignedInt::ID,
                1,
                PropertyAccess::ReadOnly,
                15,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::LOAD_STATE_CONTROL,
                PDT_Control::ID,
                1,
                PropertyAccess::ReadWrite,
                15,
                2,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::TABLE_REFERENCE,
                PDT_UnsignedLong::ID,
                1,
                PropertyAccess::ReadOnly,
                15,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::MCB_TABLE,
                PDT_Generic08::ID,
                1,
                PropertyAccess::ReadOnly,
                15,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
            PropertyDescriptor::new(
                pid::ERROR_CODE,
                PDT_UnsignedChar::ID,
                1,
                PropertyAccess::ReadOnly,
                15,
                0,
                AccessPolicy::READ_OPEN_WRITE_TOOL,
            ),
        ]
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
            pid::OBJECT_TYPE | pid::TABLE_REFERENCE | pid::MCB_TABLE | pid::ERROR_CODE => {
                Err(PropertyError::WriteNotAllowed)
            }
            pid::LOAD_STATE_CONTROL => {
                // The absolute-segment records carry their own addresses;
                // no allocation address to hand in.
                self.table.borrow_mut().write_lsm(req.data, None);
                Ok(WriteResponse::byte(self.table.borrow().read_lsm()[0]))
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
