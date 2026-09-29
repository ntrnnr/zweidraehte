//! The persistent sections of a System B device.
//!
//! These ids and encodings are the on-media format of a System B device's
//! configuration. Changing one is a format change: the layout fingerprint
//! moves with it, and a device that finds a different fingerprint at boot
//! starts factory-fresh (there is no migration). The snapshot test in this
//! module's tests makes such a change visible in review.
//!
//! | Id | Section | Kind | Length |
//! | --- | --- | --- | --- |
//! | 01 | IA, routing count, auth keys | Record | 15 |
//! | 02 | program version, PEI type, PEI program version | Record | 11 |
//! | 03–07 | control of ADT, AST, COT, application, PEI | Record | 14 each |
//! | 08–0B | data of ADT, AST, COT, application parameters | Image | table size |
//! | 20+ | the extension state's sections | | |
//!
//! Applying a section restores state; it does not mark the device dirty.

use core::cell::RefCell;

use const_default::ConstDefault;
use zweidraehte_proto::NUM_AUTH_KEYS;
use zweidraehte_proto::address::IndividualAddress;

use crate::StackDefinition;
use crate::objects::tables::app::ApplicationImpl;
use crate::objects::tables::{CONTROL_RECORD_LEN, Table, TableMemory};
use crate::sections::{
    ExtensionSections, PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image,
    whole_record,
};

use super::SystemBDeviceState;

/// IA (2), routing count (1), auth keys (3 × 4).
pub const SECTION_DEVICE: SectionId = 0x01;
/// Program version (5), PEI type (1), PEI program version (5).
pub const SECTION_VERSIONS: SectionId = 0x02;
/// Control record of the address table.
pub const SECTION_ADT_CONTROL: SectionId = 0x03;
/// Control record of the association table.
pub const SECTION_AST_CONTROL: SectionId = 0x04;
/// Control record of the group object table.
pub const SECTION_COT_CONTROL: SectionId = 0x05;
/// Control record of the application program.
pub const SECTION_APP_CONTROL: SectionId = 0x06;
/// Control record of the PEI program.
pub const SECTION_PEI_CONTROL: SectionId = 0x07;
/// Data of the address table.
pub const SECTION_ADT_DATA: SectionId = 0x08;
/// Data of the association table.
pub const SECTION_AST_DATA: SectionId = 0x09;
/// Data of the group object table.
pub const SECTION_COT_DATA: SectionId = 0x0A;
/// The application parameters.
pub const SECTION_APP_DATA: SectionId = 0x0B;
/// First id of the extension state's sections.
pub const SECTION_EXTENSION_BASE: SectionId = 0x20;

const DEVICE_LEN: usize = 2 + 1 + 4 * NUM_AUTH_KEYS;
const VERSIONS_LEN: usize = 5 + 1 + 5;

/// The factory individual address, 15.15.255.
const FACTORY_IA: IndividualAddress = IndividualAddress::new(15, 15, 255);
/// The factory routing count, as `SystemBDeviceState::new` sets it.
const FACTORY_ROUTING_COUNT: u8 = 6;

/// Read `buf.len()` bytes of a table's control record.
fn read_control<T: TableMemory>(table: &RefCell<Table<T>>, offset: u16, buf: &mut [u8]) {
    read_image(&table.borrow().control_record(), offset, buf);
}

/// Apply a complete control record; a torn one changes nothing.
fn apply_control<T: TableMemory>(table: &RefCell<Table<T>>, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
    let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
    table.borrow_mut().apply_control_record(record).ok_or(SectionError::Malformed)
}

/// Return a table's control fields to "unloaded", keeping its data bytes:
/// an unloaded table's data is never read.
fn reset_control<T: TableMemory>(table: &RefCell<Table<T>>) {
    let unloaded = Table::<T>::new().control_record();
    table.borrow_mut().apply_control_record(&unloaded).expect("a new table's control record is valid");
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionSections,
    const MAX_CONN: usize,
> SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn device_record(&self) -> [u8; DEVICE_LEN] {
        let mut record = [0u8; DEVICE_LEN];
        record[..2].copy_from_slice(self.individual_address.get().as_bytes());
        record[2] = self.routing_count.get();
        for (slot, key) in record[3..].chunks_exact_mut(4).zip(self.auth_keys.borrow().iter()) {
            slot.copy_from_slice(key);
        }
        record
    }

    fn apply_device_record(&self, record: &[u8; DEVICE_LEN]) {
        self.individual_address.set(IndividualAddress::from_bytes(&record[..2]));
        self.routing_count.set(record[2]);
        for (key, slot) in self.auth_keys.borrow_mut().iter_mut().zip(record[3..].chunks_exact(4)) {
            key.copy_from_slice(slot);
        }
    }

    fn versions_record(&self) -> [u8; VERSIONS_LEN] {
        let mut record = [0u8; VERSIONS_LEN];
        record[..5].copy_from_slice(&*self.program_version.borrow());
        record[5] = self.pei_type.get();
        record[6..].copy_from_slice(&*self.pei_program_version.borrow());
        record
    }

    fn apply_versions_record(&self, record: &[u8; VERSIONS_LEN]) {
        self.program_version.borrow_mut().copy_from_slice(&record[..5]);
        self.pei_type.set(record[5]);
        self.pei_program_version.borrow_mut().copy_from_slice(&record[6..]);
    }

    fn app_data_len(&self) -> u16 {
        self.app.borrow().inner().data_image().len() as u16
    }
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionSections,
    const MAX_CONN: usize,
> PersistentSections for SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        let record = |id, len: usize| Section { id, len: len as u16, kind: SectionKind::Record };
        let image = |id, len: usize| Section { id, len: len as u16, kind: SectionKind::Image };

        f(record(SECTION_DEVICE, DEVICE_LEN));
        f(record(SECTION_VERSIONS, VERSIONS_LEN));
        for id in SECTION_ADT_CONTROL..=SECTION_PEI_CONTROL {
            f(record(id, CONTROL_RECORD_LEN));
        }
        f(image(SECTION_ADT_DATA, ADT_SIZE));
        f(image(SECTION_AST_DATA, AST_SIZE));
        f(image(SECTION_COT_DATA, COT_SIZE));
        f(image(SECTION_APP_DATA, usize::from(self.app_data_len())));
        self.extension_state.for_each_section(SECTION_EXTENSION_BASE, f);
    }

    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        match id {
            SECTION_DEVICE => read_image(&self.device_record(), offset, buf),
            SECTION_VERSIONS => read_image(&self.versions_record(), offset, buf),
            SECTION_ADT_CONTROL => read_control(&self.adt, offset, buf),
            SECTION_AST_CONTROL => read_control(&self.ast, offset, buf),
            SECTION_COT_CONTROL => read_control(&self.cot, offset, buf),
            SECTION_APP_CONTROL => read_image(&self.app.borrow().inner().control_record(), offset, buf),
            SECTION_PEI_CONTROL => read_image(&self.pei.borrow().inner().control_record(), offset, buf),
            SECTION_ADT_DATA => read_image(self.adt.borrow().data_image(), offset, buf),
            SECTION_AST_DATA => read_image(self.ast.borrow().data_image(), offset, buf),
            SECTION_COT_DATA => read_image(self.cot.borrow().data_image(), offset, buf),
            SECTION_APP_DATA => read_image(self.app.borrow().inner().data_image(), offset, buf),
            id if id >= SECTION_EXTENSION_BASE => {
                self.extension_state.read_section(id - SECTION_EXTENSION_BASE, offset, buf)
            }
            _ => panic!("SystemBDeviceState has no such section"),
        }
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        match id {
            SECTION_DEVICE => {
                self.apply_device_record(whole_record(offset, bytes)?);
                Ok(())
            }
            SECTION_VERSIONS => {
                self.apply_versions_record(whole_record(offset, bytes)?);
                Ok(())
            }
            SECTION_ADT_CONTROL => apply_control(&self.adt, offset, bytes),
            SECTION_AST_CONTROL => apply_control(&self.ast, offset, bytes),
            SECTION_COT_CONTROL => apply_control(&self.cot, offset, bytes),
            SECTION_APP_CONTROL => {
                let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
                self.app.borrow_mut().inner_mut().apply_control_record(record).ok_or(SectionError::Malformed)
            }
            SECTION_PEI_CONTROL => {
                let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
                self.pei.borrow_mut().inner_mut().apply_control_record(record).ok_or(SectionError::Malformed)
            }
            SECTION_ADT_DATA => apply_image(self.adt.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_AST_DATA => apply_image(self.ast.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_COT_DATA => apply_image(self.cot.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_APP_DATA => apply_image(self.app.borrow_mut().inner_mut().data_image_mut(), offset, bytes),
            id if id >= SECTION_EXTENSION_BASE && id - SECTION_EXTENSION_BASE < ES::SPAN => {
                self.extension_state.apply_section(id - SECTION_EXTENSION_BASE, offset, bytes)
            }
            _ => Err(SectionError::UnknownSection),
        }
    }

    fn reset_section(&self, id: SectionId) {
        match id {
            SECTION_DEVICE => {
                self.individual_address.set(FACTORY_IA);
                self.routing_count.set(FACTORY_ROUTING_COUNT);
                *self.auth_keys.borrow_mut() = [[0xFF; 4]; NUM_AUTH_KEYS];
            }
            // A factory device reports the application it was built with
            // until a download replaces it.
            SECTION_VERSIONS => {
                *self.program_version.borrow_mut() = D::DEVICE.program_version();
                self.pei_type.set(D::DEVICE.pei_type);
                *self.pei_program_version.borrow_mut() = D::DEVICE.pei_program_version();
            }
            SECTION_ADT_CONTROL => reset_control(&self.adt),
            SECTION_AST_CONTROL => reset_control(&self.ast),
            SECTION_COT_CONTROL => reset_control(&self.cot),
            SECTION_APP_CONTROL => {
                let unloaded = Table::<ApplicationImpl<D::P>>::new().control_record();
                self.app.borrow_mut().inner_mut().apply_control_record(&unloaded).expect("valid record");
            }
            SECTION_PEI_CONTROL => {
                let unloaded = Table::<ApplicationImpl<()>>::new().control_record();
                self.pei.borrow_mut().inner_mut().apply_control_record(&unloaded).expect("valid record");
            }
            SECTION_ADT_DATA => self.adt.borrow_mut().data_image_mut().fill(0),
            SECTION_AST_DATA => self.ast.borrow_mut().data_image_mut().fill(0),
            SECTION_COT_DATA => self.cot.borrow_mut().data_image_mut().fill(0),
            SECTION_APP_DATA => *self.app.borrow_mut().params_mut() = D::P::DEFAULT,
            id if id >= SECTION_EXTENSION_BASE => self.extension_state.reset_section(id - SECTION_EXTENSION_BASE),
            _ => {}
        }
    }
}
