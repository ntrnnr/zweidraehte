use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    big_endian::{U16, U32},
};

use crate::{
    address::GroupAddress,
    dpt::PDT_Generic08,
    messages::knx::Priority,
    util::{buffer::*, crc::crc16_ccitt},
};

pub trait TableMemory: ConstDefault + Sized {
    fn max_size() -> usize;
    fn data_ref(&self) -> &[u8];
    fn data_ref_mut(&mut self) -> &mut [u8];
    fn read(&self, offset: usize, data: &mut [u8]);
    fn write(&mut self, offset: usize, data: &[u8]);
}

pub trait LoadableTable: TableMemory {
    fn write_lsm(&mut self, buf: &[u8]);
    fn read_lsm(&self) -> [u8; 1];
    fn is_loaded(&self) -> bool;
}

pub trait AddressTable: LoadableTable {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    fn get_address(&self, tsap: u16) -> Option<GroupAddress>;
    fn get_tsap(&self, address: GroupAddress) -> Option<u16>;
    fn contains(&self, address: GroupAddress) -> bool;
}

pub trait AssociationTable: LoadableTable {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    /// Check if the association table is empty
    fn is_empty(&self) -> bool {
        self.entry_count() == 0
    }

    /// Gets the sending TSAP for a given ASAP
    fn get_sending_tsap(&self, asap: u16) -> Option<u16>;

    fn tsaps_for_asap(&self, asap: u16) -> impl Iterator<Item = u16> + '_;
    fn asaps_for_tsap(&self, tsap: u16) -> impl Iterator<Item = u16> + '_;
}

/// Communication object data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComObjectType {
    Uint1 = 0,
    Uint2 = 1,
    Uint3 = 2,
    Uint4 = 3,
    Uint5 = 4,
    Uint6 = 5,
    Uint7 = 6,
    Byte1 = 7,
    Byte2 = 8,
    Byte3 = 9,
    Byte4 = 10,
    Byte6 = 11,
    Byte8 = 12,
    Byte10 = 13,
    Byte14 = 14,
    // New data types only valid for System B
    Byte5 = 15,
    Byte7 = 16,
    Byte9 = 17,
    Byte11 = 18,
    Byte12 = 19,
    Byte13 = 20,
    Byte15 = 21,
    Byte16 = 22,
    Byte17 = 23,
    Byte18 = 24,
    Byte19 = 25,
    Byte20 = 26,
    Byte21 = 27,
    Byte22 = 28,
    Byte23 = 29,
    Byte24 = 30,
    Byte25 = 31,
    Byte26 = 32,
    Byte27 = 33,
    Byte28 = 34,
    Byte29 = 35,
    Byte30 = 36,
    Byte31 = 37,
    Byte32 = 38,
    Byte33 = 39,
    Byte34 = 40,
    Byte35 = 41,
    Byte36 = 42,
    Byte37 = 43,
    Byte38 = 44,
    Byte39 = 45,
    Byte40 = 46,
    Byte41 = 47,
    Byte42 = 48,
    Byte43 = 49,
    Byte44 = 50,
    Byte45 = 51,
    Byte46 = 52,
    Byte47 = 53,
    Byte48 = 54,
    Byte49 = 55,
    Byte50 = 56,
    Byte51 = 57,
    Byte52 = 58,
    Byte53 = 59,
    Byte54 = 60,
    Byte55 = 61,
    Byte56 = 62,
    Byte57 = 63,
    Byte58 = 64,
    Byte59 = 65,
    Byte60 = 66,
    Byte61 = 67,
    Byte62 = 68,
    Byte63 = 69,
    Byte64 = 70,
    Byte65 = 71,
    Byte66 = 72,
    Byte67 = 73,
    Byte68 = 74,
    Byte69 = 75,
    Byte70 = 76,
    Byte71 = 77,
    Byte72 = 78,
    Byte73 = 79,
    Byte74 = 80,
    Byte75 = 81,
    Byte76 = 82,
    Byte77 = 83,
    Byte78 = 84,
    Byte79 = 85,
    Byte80 = 86,
    Byte81 = 87,
    Byte82 = 88,
    Byte83 = 89,
    Byte84 = 90,
    Byte85 = 91,
    Byte86 = 92,
    Byte87 = 93,
    Byte88 = 94,
    Byte89 = 95,
    Byte90 = 96,
    Byte91 = 97,
    Byte92 = 98,
    Byte93 = 99,
    Byte94 = 100,
    Byte95 = 101,
    Byte96 = 102,
    Byte97 = 103,
    Byte98 = 104,
    Byte99 = 105,
    Byte100 = 106,
    Byte101 = 107,
    Byte102 = 108,
    Byte103 = 109,
    Byte104 = 110,
    Byte105 = 111,
    Byte106 = 112,
    Byte107 = 113,
    Byte108 = 114,
    Byte109 = 115,
    Byte110 = 116,
    Byte111 = 117,
    Byte112 = 118,
    Byte113 = 119,
    Byte114 = 120,
    Byte115 = 121,
    Byte116 = 122,
    Byte117 = 123,
    Byte118 = 124,
    Byte119 = 125,
    Byte120 = 126,
    Byte121 = 127,
    Byte122 = 128,
    Byte123 = 129,
    Byte124 = 130,
    Byte125 = 131,
    Byte126 = 132,
    Byte127 = 133,
    Byte128 = 134,
    Byte129 = 135,
    Byte130 = 136,
    Byte131 = 137,
    Byte132 = 138,
    Byte133 = 139,
    Byte134 = 140,
    Byte135 = 141,
    Byte136 = 142,
    Byte137 = 143,
    Byte138 = 144,
    Byte139 = 145,
    Byte140 = 146,
    Byte141 = 147,
    Byte142 = 148,
    Byte143 = 149,
    Byte144 = 150,
    Byte145 = 151,
    Byte146 = 152,
    Byte147 = 153,
    Byte148 = 154,
    Byte149 = 155,
    Byte150 = 156,
    Byte151 = 157,
    Byte152 = 158,
    Byte153 = 159,
    Byte154 = 160,
    Byte155 = 161,
    Byte156 = 162,
    Byte157 = 163,
    Byte158 = 164,
    Byte159 = 165,
    Byte160 = 166,
    Byte161 = 167,
    Byte162 = 168,
    Byte163 = 169,
    Byte164 = 170,
    Byte165 = 171,
    Byte166 = 172,
    Byte167 = 173,
    Byte168 = 174,
    Byte169 = 175,
    Byte170 = 176,
    Byte171 = 177,
    Byte172 = 178,
    Byte173 = 179,
    Byte174 = 180,
    Byte175 = 181,
    Byte176 = 182,
    Byte177 = 183,
    Byte178 = 184,
    Byte179 = 185,
    Byte180 = 186,
    Byte181 = 187,
    Byte182 = 188,
    Byte183 = 189,
    Byte184 = 190,
    Byte185 = 191,
    Byte186 = 192,
    Byte187 = 193,
    Byte188 = 194,
    Byte189 = 195,
    Byte190 = 196,
    Byte191 = 197,
    Byte192 = 198,
    Byte193 = 199,
    Byte194 = 200,
    Byte195 = 201,
    Byte196 = 202,
    Byte197 = 203,
    Byte198 = 204,
    Byte199 = 205,
    Byte200 = 206,
    Byte201 = 207,
    Byte202 = 208,
    Byte203 = 209,
    Byte204 = 210,
    Byte205 = 211,
    Byte206 = 212,
    Byte207 = 213,
    Byte208 = 214,
    Byte209 = 215,
    Byte210 = 216,
    Byte211 = 217,
    Byte212 = 218,
    Byte213 = 219,
    Byte214 = 220,
    Byte215 = 221,
    Byte216 = 222,
    Byte217 = 223,
    Byte218 = 224,
    Byte219 = 225,
    Byte220 = 226,
    Byte221 = 227,
    Byte222 = 228,
    Byte223 = 229,
    Byte224 = 230,
    Byte225 = 231,
    Byte226 = 232,
    Byte227 = 233,
    Byte228 = 234,
    Byte229 = 235,
    Byte230 = 236,
    Byte231 = 237,
    Byte232 = 238,
    Byte233 = 239,
    Byte234 = 240,
    Byte235 = 241,
    Byte236 = 242,
    Byte237 = 243,
    Byte238 = 244,
    Byte239 = 245,
    Byte240 = 246,
    Byte241 = 247,
    Byte242 = 248,
    Byte243 = 249,
    Byte244 = 250,
    Byte245 = 251,
    Byte246 = 252,
    Byte247 = 253,
    Byte248 = 254,
    Byte252 = 255,
}

impl From<u8> for ComObjectType {
    fn from(value: u8) -> Self {
        // SAFETY: This is safe because the enum is repr(u8) and all values for all variants are defined
        unsafe { core::mem::transmute(value) }
    }
}

impl From<ComObjectType> for u8 {
    fn from(value: ComObjectType) -> Self {
        value as u8
    }
}

impl ComObjectType {
    /// Get the size in bytes for this object type and if it's a compact type
    /// that fits in the 6 APCI bits for the short APCIs
    pub fn size_in_bytes(&self) -> (usize, bool) {
        if *self < Self::Byte15 {
            return (1, *self <= Self::Uint6);
        } else if *self != Self::Byte252 {
            let i: u8 = (*self).into();
            return ((i as usize) - 6, false);
        } else {
            return (252, false);
        }
    }
}

/// A Communication object flags field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ComObjectFlags(u8);

impl ComObjectFlags {
    const UE_FLAG_MASK: u8 = 0b10000000; // Update Enable flag
    const TE_FLAG_MASK: u8 = 0b01000000; // Transmission Enable flag
    const ROI_FLAG_MASK: u8 = 0b00100000; // Read on Init flag
    const WE_FLAG_MASK: u8 = 0b00010000; // Write Enable flag
    const RE_FLAG_MASK: u8 = 0b00001000; // Read Enable flag
    const CE_FLAG_MASK: u8 = 0b00000100; // Communication Enable flag

    const P_SHIFT: u8 = 0;
    const P_LEN: u8 = 2;
    const P_MAX: u8 = (1 << Self::P_LEN) - 1; // Max priority value (3)
    const P_MASK: u8 = (Self::P_MAX as u8) << Self::P_SHIFT;

    /// Common group object configuration: Transmit to bus (T)
    pub const CONFIG_T: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, read from bus (RT)
    pub const CONFIG_RT: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::RE_FLAG_MASK;

    /// Common group object configuration: Receive from bus (WU)
    pub const CONFIG_WU: u8 = Self::CE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, receive, read from bus (RTWU)
    pub const CONFIG_RTWU: u8 =
        Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK | Self::RE_FLAG_MASK;
}

impl Default for ComObjectFlags {
    fn default() -> Self {
        // Default to CONFIG_RTWU - full communication capability
        Self(Self::CONFIG_RTWU | u8::from(Priority::Low))
    }
}

impl ComObjectFlags {
    #[inline]
    pub fn transmission_enable(&self) -> bool {
        self.0 & Self::TE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_on_init(&self) -> bool {
        self.0 & Self::ROI_FLAG_MASK != 0
    }

    #[inline]
    pub fn write_enable(&self) -> bool {
        self.0 & Self::WE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_enable(&self) -> bool {
        self.0 & Self::RE_FLAG_MASK != 0
    }

    #[inline]
    pub fn update_enable(&self) -> bool {
        self.0 & Self::UE_FLAG_MASK != 0
    }

    #[inline]
    pub fn communication_enable(&self) -> bool {
        self.0 & Self::CE_FLAG_MASK != 0
    }

    #[inline]
    pub fn priority(&self) -> Priority {
        let p = (self.0 & Self::P_MASK) >> Self::P_SHIFT;
        Priority::from(p)
    }

    /// Check if flags contain a specific flag pattern
    #[inline]
    pub fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) == flag
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ComObjectTableEntry {
    pub object_type: ComObjectType,
    pub flags: ComObjectFlags,
}

pub trait CommunicationObjectTable: LoadableTable {
    fn max_entries(&self) -> usize;
    fn entry_count(&self) -> u16;

    fn get_object(&self, idx: u16) -> Option<ComObjectTableEntry>;
    fn object_type(&self, idx: u16) -> Option<ComObjectType>;
    fn object_flags(&self, idx: u16) -> Option<ComObjectFlags>;
}

create_protocol_enum!(
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
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
//       Maybe not necessary as w already have TableMemory which could do this

#[derive(Debug, Serialize, Deserialize)]
pub struct Table<T: TableMemory> {
    // TODO: add alloc() and free() to TableMemory and use these instead of directly filling them? Would allow for Boxed Tables etc.
    pub(super) table: T,
    pub(super) state: LoadState,
    pub(super) mcb_table: PDT_Generic08,
}

impl<T: TableMemory> ConstDefault for Table<T> {
    const DEFAULT: Self = Table::new();
}

impl<T: TableMemory> Table<T> {
    pub const fn new() -> Self {
        Self { table: T::DEFAULT, state: LoadState::Unloaded, mcb_table: PDT_Generic08::with_value([0; 8]) }
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

impl<T: TableMemory> LoadableTable for Table<T> {
    fn write_lsm(&mut self, mut buf: &[u8]) {
        let mut buf = &mut buf;
        let (mut new_state, action) = Self::next_state(buf.take_front(1).unwrap()[0].into(), self.state);

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
                            let stored_mcb = McbData::mut_from_bytes(self.mcb_table.as_mut_bytes()).unwrap();
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
                stored_mcb
                    .crc
                    .set(crc16_ccitt(&self.table.data_ref()[0..(stored_mcb.requested_memory_size.get() as usize)]));
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

    fn read_lsm(&self) -> [u8; 1] {
        [self.state.into()]
    }

    fn is_loaded(&self) -> bool {
        self.state == LoadState::Loaded
    }
}

impl<T: TableMemory> TableMemory for Table<T> {
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
