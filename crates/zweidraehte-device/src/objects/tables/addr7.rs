use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::big_endian::U16;

use zweidraehte_proto::address::GroupAddress;

use super::{AddressTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
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
    const MAX_SIZE: usize = N;
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> AddressTable for Table<AddrTab7Impl<N>> {
    fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    fn entry_count(&self) -> u16 {
        // The count is bus-downloaded data and must not exceed physical capacity.
        U16::from_bytes(self.table.data[0..2].try_into().expect("slice is exactly 2 bytes")).get().min(self.max_entries() as u16)
    }

    fn address(&self, tsap: u16) -> Option<GroupAddress> {
        //trace!("Getting address for TSAP {}", tsap);

        if tsap == 0 || tsap > self.entry_count() {
            trace!("TSAP {} is out of bounds (1..{})", tsap, self.entry_count());
            return None;
        }

        Some(self.addr(tsap as usize))
    }

    fn tsap(&self, address: GroupAddress) -> Option<u16> {
        let mut low = 1;
        let mut high = self.entry_count();

        while low <= high {
            let idx = (low + high) / 2;
            let addr_tbl = self.addr(idx as usize);

            if address == addr_tbl {
                return Some(idx);
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
        self.tsap(address).is_some()
    }
}

pub type AddrTab7<const MAX_ENTRIES: usize> = Table<AddrTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{HasLoadStateMachine, LoadEvent, LoadState, TableMemory};
    use zweidraehte_proto::address::GroupAddress as KNXGroupAddress;

    use super::AddrTab7;

    #[test]
    fn addr7_tab_alloc_load() {
        let mut a = AddrTab7::<10>::new();

        // We should be in an unloaded state
        assert_eq!(a.read_lsm(), [LoadState::Unloaded.into()]);

        // Begin loading
        a.write_lsm(&[LoadEvent::StartLoading.into()], None);
        assert_eq!(a.read_lsm(), [LoadState::Loading.into()]);

        // Allocate a table and fill it with 0xFF
        a.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0xff, 0x00, 0x00],
            None,
        );
        assert_eq!(a.read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(&a.data_ref()[0..6], &[0xff; 6]);
        assert_eq!(a.mcb_table.as_ref(), &[0x00, 0x00, 0x00, 0x06, 0x00, 0xFF, 0xFF, 0xFF]);

        // Write data into the table
        a.write(0, &[0x00, 0x02]); // current length
        a.write(2, KNXGroupAddress::from_three_level(0, 0, 1).as_bytes()); // Addr 1
        a.write(4, KNXGroupAddress::from_three_level(0, 0, 2).as_bytes()); // Addr 2
        assert_eq!(&a.data_ref()[0..6], &[0x00, 0x02, 0x00, 0x01, 0x00, 0x02]);

        // Issue load complete
        a.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(a.read_lsm(), [LoadState::Loaded.into()]);
        assert_eq!(a.mcb_table.as_ref(), &[0x00, 0x00, 0x00, 0x06, 0x00, 0xFF, 0x62, 0xCF]);
    }
}
