//! The persistent sections of a System 7 (mask 0705h) device.
//!
//! These ids and encodings are the on-media format of a System 7 device's
//! configuration; see the System B counterpart for the rules that come with
//! that (fingerprint, no migration, snapshot test).
//!
//! | Id | Section | Kind | Length |
//! | --- | --- | --- | --- |
//! | 01 | routing count, OptionReg, auth keys (15 levels) | Record | 62 |
//! | 02 | program version, PEI type, program-2 version | Record | 11 |
//! | 03–07 | control of ADT, AST, COT, application, application 2 | Record | 14 each |
//! | 08–0B | data of ADT (with the IA), AST, COT, application parameters | Image | table size |
//! | 20+ | the extension state's sections | | |
//!
//! System 7 keeps the individual address inside the address-table image at
//! offset 1–2, as its EEPROM does, so the IA has no section of its own. The
//! 256-byte RAM window is volatile and not persisted.

use core::cell::RefCell;

use const_default::ConstDefault;

use crate::StackDefinition;
use crate::objects::tables::app::ApplicationImpl;
use crate::objects::tables::{AbsoluteAlloc, CONTROL_RECORD_LEN, Table, TableMemory};
use crate::sections::{
    ExtensionSections, PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image,
    whole_record,
};

use super::super::SYSTEM7_NUM_AUTH_KEYS;
use super::System7DeviceState;

/// Routing count (1), OptionReg (1), auth keys (15 × 4).
pub const SECTION_DEVICE: SectionId = 0x01;
/// Program version (5), PEI type (1), program-2 version (5).
pub const SECTION_VERSIONS: SectionId = 0x02;
/// Control record of the address table.
pub const SECTION_ADT_CONTROL: SectionId = 0x03;
/// Control record of the association table.
pub const SECTION_AST_CONTROL: SectionId = 0x04;
/// Control record of the group object table.
pub const SECTION_COT_CONTROL: SectionId = 0x05;
/// Control record of the application program.
pub const SECTION_APP_CONTROL: SectionId = 0x06;
/// Control record of the interface program (application 2).
pub const SECTION_APP2_CONTROL: SectionId = 0x07;
/// Data of the address table, including the individual address.
pub const SECTION_ADT_DATA: SectionId = 0x08;
/// Data of the association table.
pub const SECTION_AST_DATA: SectionId = 0x09;
/// Data of the group object table.
pub const SECTION_COT_DATA: SectionId = 0x0A;
/// The application parameters.
pub const SECTION_APP_DATA: SectionId = 0x0B;
/// First id of the extension state's sections.
pub const SECTION_EXTENSION_BASE: SectionId = 0x20;

const DEVICE_LEN: usize = 1 + 1 + 4 * SYSTEM7_NUM_AUTH_KEYS;
const VERSIONS_LEN: usize = 5 + 1 + 5;

/// The factory routing count and OptionReg, as `System7DeviceState::new`
/// sets them.
const FACTORY_ROUTING_COUNT: u8 = 6;
const FACTORY_OPTION_REG: u8 = 0;

fn read_control<T: TableMemory>(table: &RefCell<Table<T, AbsoluteAlloc>>, offset: u16, buf: &mut [u8]) {
    read_image(&table.borrow().control_record(), offset, buf);
}

fn apply_control<T: TableMemory>(
    table: &RefCell<Table<T, AbsoluteAlloc>>,
    offset: u16,
    bytes: &[u8],
) -> Result<(), SectionError> {
    let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
    table.borrow_mut().apply_control_record(record).ok_or(SectionError::Malformed)
}

/// Return a table's control fields to "unloaded", keeping its data.
fn reset_control<T: TableMemory>(table: &mut Table<T, AbsoluteAlloc>) {
    let unloaded = Table::<T, AbsoluteAlloc>::new().control_record();
    table.apply_control_record(&unloaded).expect("a new table's control record is valid");
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition,
    ES: ExtensionSections,
    const MAX_CONN: usize,
> System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn device_record(&self) -> [u8; DEVICE_LEN] {
        let mut record = [0u8; DEVICE_LEN];
        record[0] = self.routing_count.get();
        record[1] = self.option_reg.get();
        for (slot, key) in record[2..].chunks_exact_mut(4).zip(self.auth_keys.borrow().iter()) {
            slot.copy_from_slice(key);
        }
        record
    }

    fn apply_device_record(&self, record: &[u8; DEVICE_LEN]) {
        self.routing_count.set(record[0]);
        self.option_reg.set(record[1]);
        for (key, slot) in self.auth_keys.borrow_mut().iter_mut().zip(record[2..].chunks_exact(4)) {
            key.copy_from_slice(slot);
        }
    }

    fn versions_record(&self) -> [u8; VERSIONS_LEN] {
        let mut record = [0u8; VERSIONS_LEN];
        record[..5].copy_from_slice(&*self.program_version.borrow());
        record[5] = self.pei_type.get();
        record[6..].copy_from_slice(&*self.program2_version.borrow());
        record
    }

    fn apply_versions_record(&self, record: &[u8; VERSIONS_LEN]) {
        self.program_version.borrow_mut().copy_from_slice(&record[..5]);
        self.pei_type.set(record[5]);
        self.program2_version.borrow_mut().copy_from_slice(&record[6..]);
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
> PersistentSections for System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        let record = |id, len: usize| Section { id, len: len as u16, kind: SectionKind::Record };
        let image = |id, len: usize| Section { id, len: len as u16, kind: SectionKind::Image };

        f(record(SECTION_DEVICE, DEVICE_LEN));
        f(record(SECTION_VERSIONS, VERSIONS_LEN));
        for id in SECTION_ADT_CONTROL..=SECTION_APP2_CONTROL {
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
            SECTION_APP2_CONTROL => read_image(&self.app2.borrow().inner().control_record(), offset, buf),
            SECTION_ADT_DATA => read_image(self.adt.borrow().data_image(), offset, buf),
            SECTION_AST_DATA => read_image(self.ast.borrow().data_image(), offset, buf),
            SECTION_COT_DATA => read_image(self.cot.borrow().data_image(), offset, buf),
            SECTION_APP_DATA => read_image(self.app.borrow().inner().data_image(), offset, buf),
            id if id >= SECTION_EXTENSION_BASE => {
                self.extension_state.read_section(id - SECTION_EXTENSION_BASE, offset, buf)
            }
            _ => panic!("System7DeviceState has no such section"),
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
            SECTION_APP2_CONTROL => {
                let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
                self.app2.borrow_mut().inner_mut().apply_control_record(record).ok_or(SectionError::Malformed)
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

    fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
        // Each range is taken before `f` runs, so no table borrow is held
        // while the store reads the state back.
        let ranges = [
            (SECTION_ADT_DATA, self.adt.borrow_mut().take_dirty()),
            (SECTION_AST_DATA, self.ast.borrow_mut().take_dirty()),
            (SECTION_COT_DATA, self.cot.borrow_mut().take_dirty()),
            (SECTION_APP_DATA, self.app.borrow_mut().inner_mut().take_dirty()),
        ];
        for (id, range) in ranges {
            if let Some((offset, len)) = range {
                f(id, offset, len);
            }
        }
        self.extension_state.take_dirty_images(SECTION_EXTENSION_BASE, f);
    }

    fn reset_section(&self, id: SectionId) {
        match id {
            SECTION_DEVICE => {
                self.routing_count.set(FACTORY_ROUTING_COUNT);
                self.option_reg.set(FACTORY_OPTION_REG);
                *self.auth_keys.borrow_mut() = [[0xFF; 4]; SYSTEM7_NUM_AUTH_KEYS];
            }
            // A factory device reports the application it was built with;
            // the Interface Program has no identity of its own.
            SECTION_VERSIONS => {
                *self.program_version.borrow_mut() = D::DEVICE.program_version();
                self.pei_type.set(D::DEVICE.pei_type);
                *self.program2_version.borrow_mut() = [0; 5];
            }
            SECTION_ADT_CONTROL => reset_control(&mut self.adt.borrow_mut()),
            SECTION_AST_CONTROL => reset_control(&mut self.ast.borrow_mut()),
            SECTION_COT_CONTROL => reset_control(&mut self.cot.borrow_mut()),
            SECTION_APP_CONTROL => reset_control(self.app.borrow_mut().inner_mut()),
            SECTION_APP2_CONTROL => reset_control(self.app2.borrow_mut().inner_mut()),
            // A table whose data is lost is unloaded with it. The address
            // table keeps its IA slot, as `reset_address_table` does: a lost
            // group-address list must not re-address the device.
            SECTION_ADT_DATA => {
                let mut adt = self.adt.borrow_mut();
                let ia = adt.individual_address();
                adt.data_image_mut().fill(0);
                adt.set_individual_address(ia);
                reset_control(&mut adt);
            }
            SECTION_AST_DATA => {
                let mut ast = self.ast.borrow_mut();
                ast.data_image_mut().fill(0);
                reset_control(&mut ast);
            }
            SECTION_COT_DATA => {
                let mut cot = self.cot.borrow_mut();
                cot.data_image_mut().fill(0);
                reset_control(&mut cot);
            }
            SECTION_APP_DATA => {
                let mut app = self.app.borrow_mut();
                *app.params_mut() = D::P::DEFAULT;
                reset_control(app.inner_mut());
            }
            id if id >= SECTION_EXTENSION_BASE => self.extension_state.reset_section(id - SECTION_EXTENSION_BASE),
            _ => {}
        }
    }
}

// The app2 program carries no data, which the section map relies on.
const _: () =
    ::core::assert!(core::mem::size_of::<ApplicationImpl<()>>() <= 1, "application 2 carries no persistent data");
