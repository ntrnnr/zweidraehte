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
//! | 20–7F | the extension state's sections, ids from [`ids`](crate::sections::ids) | | |
//!
//! Ids 03–0B are the family-neutral table sections
//! ([`TableSections`](crate::objects::tables::sections)). Applying a section
//! restores state; it does not mark the device dirty.

use zweidraehte_proto::NUM_AUTH_KEYS;
use zweidraehte_proto::address::IndividualAddress;

use crate::StackDefinition;
use crate::objects::tables::sections::{ProgramVersions, TableSections};
use crate::objects::tables::{AddrTab7Impl, AssoTab6Impl, CoTab7Impl, RelativeAlloc};
use crate::sections::{
    ConfigRecord, ExtensionSections, PersistentSections, RecordReader, RecordWriter, Section, SectionBytes,
    SectionError, SectionId, SectionKind,
};

pub use crate::objects::tables::sections::{
    SECTION_ADT_CONTROL, SECTION_ADT_DATA, SECTION_APP_CONTROL, SECTION_APP_DATA, SECTION_APP2_CONTROL,
    SECTION_AST_CONTROL, SECTION_AST_DATA, SECTION_COT_CONTROL, SECTION_COT_DATA,
};

use super::SystemBDeviceState;

/// IA (2), routing count (1), auth keys (3 × 4).
pub const SECTION_DEVICE: SectionId = 0x01;
/// Program version (5), PEI type (1), PEI program version (5).
pub const SECTION_VERSIONS: SectionId = 0x02;

const DEVICE_LEN: usize = DeviceRecord::LEN;
const VERSIONS_LEN: usize = ProgramVersions::LEN;

/// Record 01: the device's address and the access keys.
#[derive(Clone, Copy)]
pub(super) struct DeviceRecord {
    pub individual_address: IndividualAddress,
    pub routing_count: u8,
    pub auth_keys: [[u8; 4]; NUM_AUTH_KEYS],
}

impl DeviceRecord {
    /// A factory-fresh device: IA 15.15.255, routing count 6, and every
    /// authorization key FFFFFFFFh.
    pub(super) const FACTORY: Self = Self {
        individual_address: IndividualAddress::new(15, 15, 255),
        routing_count: 6,
        auth_keys: [[0xFF; 4]; NUM_AUTH_KEYS],
    };
}

/// `[IA × 2][routing count][auth key × 4, per level]`.
impl SectionBytes for DeviceRecord {
    const LEN: usize = IndividualAddress::LEN + u8::LEN + NUM_AUTH_KEYS * <[u8; 4]>::LEN;

    fn write(&self, out: &mut [u8]) {
        let mut record = RecordWriter::new(out);
        record.put(&self.individual_address).put(&self.routing_count);
        for key in &self.auth_keys {
            record.put(key);
        }
        record.finish();
    }

    fn read(bytes: &[u8]) -> Option<Self> {
        let mut record = RecordReader::new(bytes);
        let mut device = Self { individual_address: record.take()?, routing_count: record.take()?, ..Self::FACTORY };
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
> SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES, MAX_CONN>
{
    fn device_record(&self) -> DeviceRecord {
        DeviceRecord {
            individual_address: self.individual_address.get(),
            routing_count: self.routing_count.get(),
            auth_keys: *self.auth_keys.borrow(),
        }
    }

    fn set_device_record(&self, record: DeviceRecord) {
        self.individual_address.set(record.individual_address);
        self.routing_count.set(record.routing_count);
        *self.auth_keys.borrow_mut() = record.auth_keys;
    }

    fn versions(&self) -> ProgramVersions {
        ProgramVersions {
            program: *self.program_version.borrow(),
            pei_type: self.pei_type.get(),
            program2: *self.pei_program_version.borrow(),
        }
    }

    fn set_versions(&self, versions: ProgramVersions) {
        *self.program_version.borrow_mut() = versions.program;
        self.pei_type.set(versions.pei_type);
        *self.pei_program_version.borrow_mut() = versions.program2;
    }

    fn tables(
        &self,
    ) -> TableSections<'_, AddrTab7Impl<ADT_SIZE>, AssoTab6Impl<AST_SIZE>, CoTab7Impl<COT_SIZE>, D::P, RelativeAlloc>
    {
        TableSections { adt: &self.adt, ast: &self.ast, cot: &self.cot, app: &self.app, app2: &self.pei }
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
            _ => panic!("SystemBDeviceState has no such section"),
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

        self.tables().image_crc_mismatch(id)
    }

    fn reset_section(&self, id: SectionId) {
        let tables = self.tables();
        match id {
            SECTION_DEVICE => self.set_device_record(DeviceRecord::FACTORY),
            SECTION_VERSIONS => self.set_versions(ProgramVersions::built_in(D::DEVICE)),
            id if tables.contains(id) => tables.reset_section(id),
            id if ES::owns(id) => self.extension_state.reset_section(id),
            _ => {}
        }
    }
}
