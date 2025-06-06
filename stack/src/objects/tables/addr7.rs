use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::big_endian::U16;

use crate::address::GroupAddress;

use super::{AddressTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, ConstDefault, Serialize, Deserialize)]
pub struct AddrTab7Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<AddrTab7Impl<N>> {
    fn addr(&self, idx: usize) -> GroupAddress {
        // NOTE: idx is 1-indexed and first member is current length!
        GroupAddress::from_bytes(&self.table.data[idx * 2..(idx + 1) * 2])
    }
}

impl<const N: usize> TableMemory for AddrTab7Impl<N> {
    fn max_size() -> usize {
        N
    }

    fn data_ref(&self) -> &[u8] {
        &self.data
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    fn read(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.data[offset..offset + data.len()]);
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.data[offset..offset + data.len()].copy_from_slice(data);
    }
}

impl<const N: usize> AddressTable for Table<AddrTab7Impl<N>> {
    fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    fn get_address(&self, tsap: u16) -> Option<GroupAddress> {
        trace!("Getting address for TSAP {}", tsap);

        if tsap == 0 || tsap > self.entry_count() {
            trace!("TSAP {} is out of bounds (1..{})", tsap, self.entry_count());
            return None;
        }

        Some(self.addr(tsap as usize))
    }

    fn get_tsap(&self, address: GroupAddress) -> Option<u16> {
        let mut low = 1;
        let mut high = self.entry_count();

        while low <= high {
            let idx = (low + high) / 2;
            let addr_tbl = self.addr(idx as usize);

            if address == addr_tbl {
                return Some(idx as u16);
            }

            if address < addr_tbl {
                high = idx - 1;
            } else {
                low = idx + 1;
            }
        }

        None
    }

    fn contains(&self, address: GroupAddress) -> bool {
        self.get_tsap(address) != None
    }
}

// use super::property::{BCU_PropertyContent, BCU_PropertyDesc, EIOObjectType, EIOType, EWriteEnable};

// static ADDR_TAB7_OBJECT: &'static [BCU_PropertyDesc] = &[
//     BCU_PropertyDesc {
//         property_id: 1, //PID_OBJECT_TYPE
//         write_enable: EWriteEnable::propRO,
//         data_type: EIOType::PDT_UNSIGNED_INT,
//         content: BCU_PropertyContent::Ioc_Data(EIOObjectType::IO_ObjectAddresstable as u16),
//     },
//     BCU_PropertyDesc {
//         property_id: 8, //PID_SERVICE_CONTROL
//         write_enable: EWriteEnable::propRW,
//         data_type: EIOType::PDT_UNSIGNED_INT,
//         content: BCU_PropertyContent::Ioc_Ptr_Data(unsafe { EE_VARS.serviceControl.as_slice() }),
//     },
//     BCU_PropertyDesc {
//         property_id: 11, //PID_SERIAL_NUMBER
//         write_enable: EWriteEnable::propRW,
//         data_type: EIOType::PDT_GENERIC_06,
//         content: BCU_PropertyContent::Ioc_Ptr_Func(KNX_GetPtrToSerialNumber),
//     },
//     BCU_PropertyDesc {
//         property_id: 12, //PID_MANUFACTURER_ID
//         write_enable: EWriteEnable::propRW,
//         data_type: EIOType::PDT_UNSIGNED_INT,
//         content: BCU_PropertyContent::Ioc_Ptr_Func(IO_GetManufCodeAddr),
//     },
//     BCU_PropertyDesc {
//         property_id: 14, //PID_DEVICE_CONTROL
//         write_enable: EWriteEnable::propRW,
//         data_type: EIOType::PDT_GENERIC_01,
//         content: BCU_PropertyContent::Ioc_Ptr_Data(unsafe { RAM_VARS.DM0700_deviceControl.as_const_ref() }),
//     },
// ];

pub type AddrTab7<const MAX_ENTRIES: usize> = Table<AddrTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

// enum PropertyContent {
//     Data(u16),
//     Foo(Box<dyn Fn()>),
//     Bar,
// }

// struct PropertyDef {
//     content: PropertyContent,
// }

// #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// struct PropertyDesc {
//     property_id: u8,
//     property_index: u8,
//     data_type: u8, // FIXME: use EIOType, I guess? Uppermost bit set: writable
//     max_nr_of_elements: u16,
//     access: u8,
// }

// enum PropertyAddress {
//     Index(usize),
//     ID(usize),
// }

// trait InterfaceObject<const N: usize> {
//     fn create_interface_object(&self) -> &[PropertyDef; N];

//     // FIXME: add errors
//     fn property_description(&self, address: PropertyAddress) -> PropertyDesc;
//     fn property_read(&self, id: usize, start_idx: usize, num_elems: usize) -> &[u8];
//     fn property_write(&self, id: usize, start_idx: usize, num_elems: usize, data: &[u8]);
// }

// impl<const N: usize> InterfaceObject<3> for Table<AddrTab7Impl<N>> {
//     fn create_interface_object(&self) -> &[PropertyDef; 3] {
//         let foo = Box::new(|| println!("{}", self.addr(0)));

//         &[
//             PropertyDef { content: PropertyContent::Data(1) },
//             PropertyDef { content: PropertyContent::Foo(foo) },
//             PropertyDef { content: PropertyContent::Bar },
//         ]
//     }

//     fn property_description(&self, address: PropertyAddress) -> PropertyDesc {
//         PropertyDesc { ..Default::default() }
//     }

//     fn property_read(&self, id: usize, start_idx: usize, num_elems: usize) -> &[u8] {
//         &[]
//     }

//     fn property_write(&self, id: usize, start_idx: usize, num_elems: usize, data: &[u8]) {
//         &[]
//     }
// }

#[cfg(test)]
mod test {
    use crate::{
        address::GroupAddress as KNXGroupAddress,
        objects::tables::{AddressTable, LoadEvent, LoadState, LoadableTable, TableMemory},
    };

    use super::AddrTab7;

    #[test]
    fn addr7_tab_alloc_load() {
        let mut a = AddrTab7::<10>::new();

        // We should be in an unloaded state
        assert_eq!(a.read_lsm(), [LoadState::Unloaded.into()]);

        // Begin loading
        a.write_lsm(&[LoadEvent::StartLoading.into()]);
        assert_eq!(a.read_lsm(), [LoadState::Loading.into()]);

        // Allocate a table and fill it with 0xFF
        a.write_lsm(&[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0xff, 0x00, 0x00]);
        assert_eq!(a.read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(&a.data_ref()[0..6], &[0xff; 6]);
        assert_eq!(a.mcb_table.as_ref(), &[0x00, 0x00, 0x00, 0x06, 0x00, 0xFF, 0xFF, 0xFF]);

        // Write data into the table
        a.write(0, &[0x00, 0x02]); // current length
        a.write(2, KNXGroupAddress::from_three_level(0, 0, 1).as_bytes()); // Addr 1
        a.write(4, KNXGroupAddress::from_three_level(0, 0, 2).as_bytes()); // Addr 2
        assert_eq!(&a.data_ref()[0..6], &[0x00, 0x02, 0x00, 0x01, 0x00, 0x02]);

        // Issue load complete
        a.write_lsm(&[LoadEvent::LoadCompleted.into()]);
        assert_eq!(a.read_lsm(), [LoadState::Loaded.into()]);
        assert_eq!(a.mcb_table.as_ref(), &[0x00, 0x00, 0x00, 0x06, 0x00, 0xFF, 0x62, 0xCF]);
    }
}
