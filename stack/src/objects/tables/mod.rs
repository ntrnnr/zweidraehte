use const_default::ConstDefault;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    big_endian::{U16, U32},
};

use crate::{dpt::PDT_Generic08, util::buffer::*, util::crc::crc16_ccitt};

pub trait MemoryBackedTable: ConstDefault + Sized {
    fn max_size() -> usize;
    fn data_ref(&self) -> &[u8];
    fn data_ref_mut(&mut self) -> &mut [u8];
    fn read(&self, offset: usize, data: &mut [u8]);
    fn write(&mut self, offset: usize, data: &[u8]);
}

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadState: u8 {
        Unloaded        , 0x00, "Unloaded";
        Loaded          , 0x01, "Loaded";
        Loading         , 0x02, "Loading";
        Err             , 0x03, "Error";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadEvent: u8 {
        NoOp                    , 0x00, "NoOp";
        StartLoading            , 0x01, "StartLoading";
        LoadCompleted           , 0x02, "LoadCompleted";
        AdditionalLoadControls  , 0x03, "AdditionalLoadControls";
        Unload                  , 0x04, "Unload";
        Err                     , 0x05, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadSegment: u8 {
        AbsoluteData            , 0x00, "AbsoluteData";
        AbsoluteStack           , 0x01, "AbsoluteStack";
        AbsoluteTask            , 0x02, "AbsoluteTask";
        AbsolutePointer         , 0x03, "AbsolutePointer";
        TaskCtrl1               , 0x04, "TaskCtrl1";
        TaskCtrl2               , 0x05, "TaskCtrl2";
        RelativeData            , 0x0b, "RelativeData";
        Err                     , 0x0c, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

// FIXME: this doesn't even need to be a protocol_enum
create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone)]
    enum LoadAction: u8 {
        None                    , 0x00, "None";
        LoadStart               , 0x01, "LoadStart";
        LoadEnd                 , 0x02, "LoadEnd";
        Unload                  , 0x03, "Unload";
        Alloc                   , 0x40, "Alloc";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

#[repr(C)]
#[derive(Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
pub struct McbData {
    pub requested_memory_size: U32,
    pub mode: u8,
    pub fill: u8,
    pub crc: U16,
}

// TODO: Add trait called InterfaceObject?
//       This can contain all the properties for this object
// TODO: Add trait MemoryAccessible which uses pointers of the objects and checks bounds when reading/writing raw?
//       Maybe not necessary as w already have MemoryBackedTable which could do this

#[derive(Debug)]
pub struct Table<T: MemoryBackedTable> {
    // TODO: add alloc() and free() to MemoryBackedTable and use these instead of directly filling them? Would allow for Boxed Tables etc.
    pub(super) table: T,
    pub(super) state: LoadState,
    pub(super) mcb_table: PDT_Generic08,
}

impl<T: MemoryBackedTable> ConstDefault for Table<T> {
    const DEFAULT: Self = Table::new();
}

impl<T: MemoryBackedTable> Table<T> {
    pub const fn new() -> Self {
        Self {
            table: T::DEFAULT,
            state: LoadState::Unloaded,
            mcb_table: PDT_Generic08::with_value([0; 8]),
        }
    }

    pub fn write_lsm(&mut self, mut buf: &[u8]) {
        let mut buf = &mut buf;
        let (mut new_state, action) =
            Self::next_state(buf.take_front(1).unwrap()[0].into(), self.state);

        match action {
            LoadAction::LoadStart => {}
            LoadAction::Alloc => {
                let mut additional_data = &mut buf.take_rest_front();

                match additional_data.take_byte_front().map(LoadSegment::from) {
                    Some(LoadSegment::RelativeData) => {
                        let data = additional_data.take_obj_front::<McbData>().unwrap();

                        let req_mem_sz = data.requested_memory_size.get() as usize;
                        if req_mem_sz <= T::max_size() {
                            // Fill requested?
                            if data.mode & 1 != 0 {
                                self.table.data_ref_mut()[..req_mem_sz].fill(data.fill);
                            }

                            // Store the length in the MCB table
                            // CRC will be calculated later on LoadEnd
                            let stored_mcb =
                                McbData::mut_from_bytes(self.mcb_table.as_mut_bytes()).unwrap();
                            stored_mcb.requested_memory_size = data.requested_memory_size;
                            stored_mcb.mode = 0x00;
                            stored_mcb.fill = 0xFF;
                            stored_mcb.crc.set(0xFFFF);
                        } else {
                            new_state = LoadState::Err;
                        }
                    }
                    _ => new_state = LoadState::Err,
                }
            }
            LoadAction::LoadEnd => {
                let stored_mcb = McbData::mut_from_bytes(self.mcb_table.as_mut_bytes()).unwrap();
                stored_mcb.crc.set(crc16_ccitt(
                    &self.table.data_ref()[0..(stored_mcb.requested_memory_size.get() as usize)],
                ));
            }
            LoadAction::Unload => {
                self.mcb_table.set_value([0; 8]);
                self.table.data_ref_mut().fill(0);
                // TODO: set table ref to 0
            }
            LoadAction::None => {}
            _ => new_state = LoadState::Err,
        }

        self.state = new_state;
    }

    pub fn read_lsm(&self) -> [u8; 1] {
        [self.state.into()]
    }

    fn next_state(event: LoadEvent, cur_state: LoadState) -> (LoadState, LoadAction) {
        match event {
            LoadEvent::NoOp => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Loaded, LoadAction::None),
                LoadState::Loading => (LoadState::Loading, LoadAction::None),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::StartLoading => match cur_state {
                LoadState::Unloaded => (LoadState::Loading, LoadAction::LoadStart),
                LoadState::Loaded => (LoadState::Loading, LoadAction::LoadStart),
                LoadState::Loading => (LoadState::Loading, LoadAction::None),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::LoadCompleted => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Loaded, LoadAction::None),
                LoadState::Loading => (LoadState::Loaded, LoadAction::LoadEnd),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::AdditionalLoadControls => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::None),
                LoadState::Loaded => (LoadState::Err, LoadAction::None),
                LoadState::Loading => (LoadState::Loading, LoadAction::Alloc),
                LoadState::Err => (LoadState::Err, LoadAction::None),
            },
            LoadEvent::Unload => match cur_state {
                LoadState::Unloaded => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Loaded => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Loading => (LoadState::Unloaded, LoadAction::Unload),
                LoadState::Err => (LoadState::Unloaded, LoadAction::Unload),
            },
            _ => panic!("Invalid event for load state machine"),
        }
    }
}

impl<T: MemoryBackedTable> MemoryBackedTable for Table<T> {
    fn data_ref(&self) -> &[u8] {
        self.table.data_ref()
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        self.table.data_ref_mut()
    }

    fn max_size() -> usize {
        T::max_size()
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        self.table.read(offset, data)
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.table.write(offset, data)
    }
}

pub mod addr7;
pub mod app;
pub mod asso6;
pub mod co7;
