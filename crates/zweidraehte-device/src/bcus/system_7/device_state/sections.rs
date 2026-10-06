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
//! | 20–7F | the extension state's sections, ids from [`ids`](crate::sections::ids) | | |
//!
//! Ids 03–0B are the family-neutral table sections
//! ([`TableSections`](crate::objects::tables::sections)), with one System 7
//! rule on top: losing the address table's data keeps the IA slot.
//!
//! System 7 keeps the individual address inside the address-table image at
//! offset 1–2, as its EEPROM does, so the IA has no section of its own. The
//! 256-byte RAM window is volatile and not persisted.

use zweidraehte_proto::address::IndividualAddress;

use crate::StackDefinition;
use crate::objects::tables::sections::{ProgramVersions, TableSections};
use crate::objects::tables::{AbsoluteAlloc, AddrTab8Impl, AssoTab8Impl, System7ComObjectTableImpl};
use crate::sections::{
    ConfigRecord, ExtensionSections, PersistentSections, RecordReader, RecordWriter, Section, SectionBytes,
    SectionError, SectionId, SectionKind,
};

pub use crate::objects::tables::sections::{
    SECTION_ADT_CONTROL, SECTION_ADT_DATA, SECTION_APP_CONTROL, SECTION_APP_DATA, SECTION_APP2_CONTROL,
    SECTION_AST_CONTROL, SECTION_AST_DATA, SECTION_COT_CONTROL, SECTION_COT_DATA,
};

use super::super::SYSTEM7_NUM_AUTH_KEYS;
use super::System7DeviceState;

/// Routing count (1), OptionReg (1), auth keys (15 × 4).
pub const SECTION_DEVICE: SectionId = 0x01;
/// Program version (5), PEI type (1), program-2 version (5).
pub const SECTION_VERSIONS: SectionId = 0x02;

const DEVICE_LEN: usize = DeviceRecord::LEN;
const VERSIONS_LEN: usize = ProgramVersions::LEN;

/// The factory individual address, 15.15.255, kept in the address table's
/// IA slot.
pub(super) const FACTORY_INDIVIDUAL_ADDRESS: IndividualAddress = IndividualAddress::new(15, 15, 255);

/// Record 01: the device's routing count, OptionReg and access keys.
#[derive(Clone, Copy)]
pub(super) struct DeviceRecord {
    pub routing_count: u8,
    pub option_reg: u8,
    pub auth_keys: [[u8; 4]; SYSTEM7_NUM_AUTH_KEYS],
}

impl DeviceRecord {
    /// A factory-fresh device: routing count 6, OptionReg 0, and every
    /// authorization key FFFFFFFFh.
    pub(super) const FACTORY: Self =
        Self { routing_count: 6, option_reg: 0, auth_keys: [[0xFF; 4]; SYSTEM7_NUM_AUTH_KEYS] };
}

/// `[routing count][OptionReg][auth key × 4, per level]`.
impl SectionBytes for DeviceRecord {
    const LEN: usize = u8::LEN + u8::LEN + SYSTEM7_NUM_AUTH_KEYS * <[u8; 4]>::LEN;

    fn write(&self, out: &mut [u8]) {
        let mut record = RecordWriter::new(out);
        record.put(&self.routing_count).put(&self.option_reg);
        for key in &self.auth_keys {
            record.put(key);
        }
        record.finish();
    }

    fn read(bytes: &[u8]) -> Option<Self> {
        let mut record = RecordReader::new(bytes);
        let mut device = Self { routing_count: record.take()?, option_reg: record.take()?, ..Self::FACTORY };
        for key in &mut device.auth_keys {
            *key = record.take()?;
        }
        record.finish();
        Some(device)
    }
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
    fn device_record(&self) -> DeviceRecord {
        DeviceRecord {
            routing_count: self.routing_count.get(),
            option_reg: self.option_reg.get(),
            auth_keys: *self.auth_keys.borrow(),
        }
    }

    fn set_device_record(&self, record: DeviceRecord) {
        self.routing_count.set(record.routing_count);
        self.option_reg.set(record.option_reg);
        *self.auth_keys.borrow_mut() = record.auth_keys;
    }

    fn versions(&self) -> ProgramVersions {
        ProgramVersions {
            program: *self.program_version.borrow(),
            pei_type: self.pei_type.get(),
            program2: *self.program2_version.borrow(),
        }
    }

    fn set_versions(&self, versions: ProgramVersions) {
        *self.program_version.borrow_mut() = versions.program;
        self.pei_type.set(versions.pei_type);
        *self.program2_version.borrow_mut() = versions.program2;
    }

    #[allow(clippy::type_complexity)]
    fn tables(
        &self,
    ) -> TableSections<
        '_,
        AddrTab8Impl<ADT_SIZE>,
        AssoTab8Impl<AST_SIZE>,
        System7ComObjectTableImpl<COT_SIZE>,
        D::P,
        AbsoluteAlloc,
    > {
        TableSections { adt: &self.adt, ast: &self.ast, cot: &self.cot, app: &self.app, app2: &self.app2 }
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
        let record = |id, len| Section { id, len, kind: SectionKind::Record };
        let device_len = const { crate::sections::checked_section_len(DEVICE_LEN) };
        let versions_len = const { crate::sections::checked_section_len(VERSIONS_LEN) };

        f(record(SECTION_DEVICE, device_len));
        f(record(SECTION_VERSIONS, versions_len));
        self.tables().for_each_section(f);
        self.extension_state.for_each_section(f);
    }

    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        let tables = self.tables();
        match id {
            SECTION_DEVICE => ConfigRecord::read::<_, DEVICE_LEN>(&self.device_record(), offset, buf),
            SECTION_VERSIONS => ConfigRecord::read::<_, VERSIONS_LEN>(&self.versions(), offset, buf),
            id if tables.contains(id) => tables.read_section(id, offset, buf),
            id if ES::owns(id) => self.extension_state.read_section(id, offset, buf),
            _ => panic!("System7DeviceState has no such section"),
        }
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        let tables = self.tables();
        match id {
            SECTION_DEVICE => {
                self.set_device_record(ConfigRecord::decode::<_, DEVICE_LEN>(offset, bytes)?);
                Ok(())
            }
            SECTION_VERSIONS => {
                self.set_versions(ConfigRecord::decode::<_, VERSIONS_LEN>(offset, bytes)?);
                Ok(())
            }
            id if tables.contains(id) => tables.apply_section(id, offset, bytes),
            id if ES::owns(id) => self.extension_state.apply_section(id, offset, bytes),
            _ => Err(SectionError::UnknownSection),
        }
    }

    fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
        self.tables().take_dirty_images(f);
        self.extension_state.take_dirty_images(f);
    }

    fn image_crc_mismatch(&self, id: SectionId) -> Option<SectionId> {
        if ES::owns(id) {
            return self.extension_state.image_crc_mismatch(id);
        }

        // System 7 loads the COT as part of the application, not through
        // the COT's otherwise unused load control.
        let control_owner = if id == SECTION_COT_DATA { SECTION_APP_DATA } else { id };
        self.tables().image_crc_mismatch(control_owner)
    }

    fn reset_section(&self, id: SectionId) {
        let tables = self.tables();
        match id {
            SECTION_DEVICE => self.set_device_record(DeviceRecord::FACTORY),
            SECTION_VERSIONS => self.set_versions(ProgramVersions::built_in(D::DEVICE)),
            // The address table keeps its IA slot, as `reset_address_table`
            // does: a lost group-address list must not re-address the device.
            SECTION_ADT_DATA => {
                let ia = self.adt.borrow().individual_address();
                tables.reset_section(SECTION_ADT_DATA);
                self.adt.borrow_mut().set_individual_address(ia);
            }
            id if tables.contains(id) => tables.reset_section(id),
            id if ES::owns(id) => self.extension_state.reset_section(id),
            _ => {}
        }
    }
}
