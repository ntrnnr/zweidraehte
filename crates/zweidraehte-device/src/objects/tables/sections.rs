//! The persistent sections the ETS-loaded tables contribute, shared by the
//! BCU families.
//!
//! Every family persists the same five load-controlled objects the same way:
//! the address, association and group object tables and the two application
//! programs, each as a 14-byte control record (ids 03–07), and the data of
//! the three tables and the application parameters as byte images (ids
//! 08–0B). Only the allocation policy differs between families, and it is a
//! type parameter here, so each family still gets its own monomorphized copy.
//! Records 01 and 02 and the extension range stay with the family's device
//! state.
//!
//! Resetting a table's data section also unloads the table, so a store that
//! loses a torn table image never leaves a "Loaded" table over zeroes: the
//! outcome is that of a download interrupted by power loss, which ETS
//! repairs by downloading again.

use core::cell::RefCell;

use const_default::ConstDefault;
use zerocopy::{Immutable, IntoBytes, KnownLayout};
use zweidraehte_proto::device::DeviceDescriptor;

use crate::sections::{
    RecordReader, RecordWriter, Section, SectionBytes, SectionError, SectionId, SectionKind, apply_image, read_image,
    whole_record,
};

use super::app::{Application, ApplicationImpl};
use super::{CONTROL_RECORD_LEN, LoadControlPolicy, Table, TableMemory};

/// Control record of the address table.
pub const SECTION_ADT_CONTROL: SectionId = 0x03;
/// Control record of the association table.
pub const SECTION_AST_CONTROL: SectionId = 0x04;
/// Control record of the group object table.
pub const SECTION_COT_CONTROL: SectionId = 0x05;
/// Control record of the application program.
pub const SECTION_APP_CONTROL: SectionId = 0x06;
/// Control record of application program 2 (System B's PEI program,
/// System 7's interface program).
pub const SECTION_APP2_CONTROL: SectionId = 0x07;
/// Data of the address table.
pub const SECTION_ADT_DATA: SectionId = 0x08;
/// Data of the association table.
pub const SECTION_AST_DATA: SectionId = 0x09;
/// Data of the group object table.
pub const SECTION_COT_DATA: SectionId = 0x0A;
/// The application parameters.
pub const SECTION_APP_DATA: SectionId = 0x0B;

// ============================================================================
// Program versions (record 02 of every family)
// ============================================================================

/// The program identities a device reports: the application's program
/// version, the PEI type it requires and application program 2's version.
///
/// There are two factory values, and the difference is intended:
///
/// - [`built_in`](Self::built_in) is what a device reports before any
///   download: the application it was built with. A new state starts with
///   it, and so does a state whose record was torn, because the device still
///   runs that application.
/// - [`ERASED`](Self::ERASED) is what an erase leaves: a factory reset or a
///   reset of the application program unloads the application, so no program
///   is identified until ETS downloads one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramVersions {
    pub program: [u8; 5],
    pub pei_type: u8,
    pub program2: [u8; 5],
}

impl ProgramVersions {
    /// After an erase: nothing identified.
    pub const ERASED: Self = Self { program: [0; 5], pei_type: 0, program2: [0; 5] };

    /// Before any download: the application the device was built with.
    pub const fn built_in(device: &DeviceDescriptor) -> Self {
        Self { program: device.program_version(), pei_type: device.pei_type, program2: device.pei_program_version() }
    }
}

/// `[program version × 5][PEI type][program 2 version × 5]`.
impl SectionBytes for ProgramVersions {
    const LEN: usize = <[u8; 5]>::LEN + u8::LEN + <[u8; 5]>::LEN;

    fn write(&self, out: &mut [u8]) {
        let mut record = RecordWriter::new(out);
        record.put(&self.program).put(&self.pei_type).put(&self.program2);
        record.finish();
    }

    fn read(bytes: &[u8]) -> Option<Self> {
        let mut record = RecordReader::new(bytes);
        let versions = Self { program: record.take()?, pei_type: record.take()?, program2: record.take()? };
        record.finish();
        Some(versions)
    }
}

// ============================================================================
// Table sections (ids 03–0B)
// ============================================================================

/// Read `buf.len()` bytes of a table's control record.
#[inline]
fn read_control<T: TableMemory, L: LoadControlPolicy>(table: &Table<T, L>, offset: u16, buf: &mut [u8]) {
    read_image(&table.control_record(), offset, buf);
}

/// Apply a complete control record; a torn one changes nothing.
#[inline]
fn apply_control<T: TableMemory, L: LoadControlPolicy>(
    table: &mut Table<T, L>,
    offset: u16,
    bytes: &[u8],
) -> Result<(), SectionError> {
    let record = whole_record::<CONTROL_RECORD_LEN>(offset, bytes)?;
    table.apply_control_record(record).ok_or(SectionError::Malformed)
}

/// The five load-controlled objects of a device state, borrowed to serve
/// section ids 03–0B.
///
/// `A`, `S` and `C` are the address, association and group object table
/// formats, `P` the application parameters and `L` the family's allocation
/// policy.
pub(crate) struct TableSections<'a, A, S, C, P, L>
where
    A: TableMemory,
    S: TableMemory,
    C: TableMemory,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable,
    L: LoadControlPolicy,
{
    pub adt: &'a RefCell<Table<A, L>>,
    pub ast: &'a RefCell<Table<S, L>>,
    pub cot: &'a RefCell<Table<C, L>>,
    pub app: &'a RefCell<Application<P, L>>,
    pub app2: &'a RefCell<Application<(), L>>,
}

impl<A, S, C, P, L> TableSections<'_, A, S, C, P, L>
where
    A: TableMemory,
    S: TableMemory,
    C: TableMemory,
    P: ConstDefault + IntoBytes + KnownLayout + Immutable,
    L: LoadControlPolicy,
{
    /// Whether `id` is one of the table sections.
    #[allow(clippy::manual_range_contains)]
    pub fn contains(&self, id: SectionId) -> bool {
        // Comparisons rather than `RangeInclusive::contains`, which
        // `opt-level = "z"` keeps as an out-of-line call.
        id >= SECTION_ADT_CONTROL && id <= SECTION_APP_DATA
    }

    pub fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        let record = |id| Section { id, len: CONTROL_RECORD_LEN as u16, kind: SectionKind::Record };
        let image = |id, len: usize| Section { id, len: len as u16, kind: SectionKind::Image };

        for id in SECTION_ADT_CONTROL..=SECTION_APP2_CONTROL {
            f(record(id));
        }
        // A data image is the whole table capacity, so its length is a
        // compile-time constant and listing the sections borrows nothing.
        f(image(SECTION_ADT_DATA, A::MAX_SIZE));
        f(image(SECTION_AST_DATA, S::MAX_SIZE));
        f(image(SECTION_COT_DATA, C::MAX_SIZE));
        f(image(SECTION_APP_DATA, ApplicationImpl::<P>::MAX_SIZE));
    }

    pub fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        match id {
            SECTION_ADT_CONTROL => read_control(&self.adt.borrow(), offset, buf),
            SECTION_AST_CONTROL => read_control(&self.ast.borrow(), offset, buf),
            SECTION_COT_CONTROL => read_control(&self.cot.borrow(), offset, buf),
            SECTION_APP_CONTROL => read_control(self.app.borrow().inner(), offset, buf),
            SECTION_APP2_CONTROL => read_control(self.app2.borrow().inner(), offset, buf),
            SECTION_ADT_DATA => read_image(self.adt.borrow().data_image(), offset, buf),
            SECTION_AST_DATA => read_image(self.ast.borrow().data_image(), offset, buf),
            SECTION_COT_DATA => read_image(self.cot.borrow().data_image(), offset, buf),
            SECTION_APP_DATA => read_image(self.app.borrow().inner().data_image(), offset, buf),
            _ => panic!("no such table section"),
        }
    }

    pub fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        match id {
            SECTION_ADT_CONTROL => apply_control(&mut self.adt.borrow_mut(), offset, bytes),
            SECTION_AST_CONTROL => apply_control(&mut self.ast.borrow_mut(), offset, bytes),
            SECTION_COT_CONTROL => apply_control(&mut self.cot.borrow_mut(), offset, bytes),
            SECTION_APP_CONTROL => apply_control(self.app.borrow_mut().inner_mut(), offset, bytes),
            SECTION_APP2_CONTROL => apply_control(self.app2.borrow_mut().inner_mut(), offset, bytes),
            SECTION_ADT_DATA => apply_image(self.adt.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_AST_DATA => apply_image(self.ast.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_COT_DATA => apply_image(self.cot.borrow_mut().data_image_mut(), offset, bytes),
            SECTION_APP_DATA => apply_image(self.app.borrow_mut().inner_mut().data_image_mut(), offset, bytes),
            _ => Err(SectionError::UnknownSection),
        }
    }

    pub fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
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
    }

    pub fn reset_section(&self, id: SectionId) {
        match id {
            // A control record resets to "unloaded" and keeps the data
            // bytes: an unloaded table's data is never read.
            SECTION_ADT_CONTROL => self.adt.borrow_mut().unload_control(),
            SECTION_AST_CONTROL => self.ast.borrow_mut().unload_control(),
            SECTION_COT_CONTROL => self.cot.borrow_mut().unload_control(),
            SECTION_APP_CONTROL => self.app.borrow_mut().inner_mut().unload_control(),
            SECTION_APP2_CONTROL => self.app2.borrow_mut().inner_mut().unload_control(),
            SECTION_ADT_DATA => {
                let mut adt = self.adt.borrow_mut();
                adt.data_image_mut().fill(0);
                adt.unload_control();
            }
            SECTION_AST_DATA => {
                let mut ast = self.ast.borrow_mut();
                ast.data_image_mut().fill(0);
                ast.unload_control();
            }
            SECTION_COT_DATA => {
                let mut cot = self.cot.borrow_mut();
                cot.data_image_mut().fill(0);
                cot.unload_control();
            }
            SECTION_APP_DATA => {
                let mut app = self.app.borrow_mut();
                *app.params_mut() = P::DEFAULT;
                app.inner_mut().unload_control();
            }
            _ => {}
        }
    }
}

// Application program 2 has a control record but no data section: no profile
// this stack implements supplies an AP2 with data.
const _: () =
    ::core::assert!(core::mem::size_of::<ApplicationImpl<()>>() <= 1, "application 2 carries no persistent data");
