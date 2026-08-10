//! Group Address Table — Realisation Type 8 (03/05/01 Resources §4.16.9).
//!
//! The System 7 address table. Fixed at address 4000h in the device's
//! management address space (Resources §4.16.9.2 — the start of the
//! profile's user EEPROM), written by the management client with plain
//! `A_Memory_Write`s after an absolute-segment allocation:
//!
//! ```text
//! offset 0       Length (number of group addresses, NOT bytes)
//! offset 1..3    Individual Address        (TSAP 0)
//! offset 3..5    Group Address nr. 1       (TSAP 1)
//! offset 5..7    Group Address nr. 2       (TSAP 2)
//! ...
//! ```
//!
//! The group addresses are sorted ascending with increasing memory
//! locations, so TSAP lookup by address is a binary search — same
//! search shape as [`AddrTab7`](super::addr7::AddrTab7), which differs
//! in its 2-octet count and the absence of the IA entry.
//!
//! The IA at offset 1–2 is the device's **individual-address storage**:
//! the ETS master data types this table `AddressTable_Bcu1`, and in the
//! BCU lineage the address-table IA field is the one place the device's
//! own address lives. Every download rewrites it with the project's IA,
//! and `NM_IndividualAddress_Write` lands in the same bytes — keeping a
//! second copy elsewhere would let the two diverge in a way real
//! hardware cannot. `System7DeviceState` therefore delegates its
//! individual-address accessors to [`individual_address`] /
//! [`set_individual_address`] on this table.
//!
//! [`individual_address`]: Table::individual_address
//! [`set_individual_address`]: Table::set_individual_address

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use super::{AbsoluteAlloc, AddressTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct AddrTab8Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<AddrTab8Impl<N>, AbsoluteAlloc> {
    fn addr(&self, tsap: usize) -> GroupAddress {
        // TSAP 0 is the Individual Address at offset 1; group address
        // nr. `tsap` starts at offset 1 + 2 * tsap.
        GroupAddress::from_bytes(&self.table.data[1 + tsap * 2..3 + tsap * 2])
    }

    /// The device's individual address, stored at offset 1–2 (TSAP 0).
    ///
    /// The factory-default state seeds these bytes with `FF FF`
    /// (15.15.255, matching erased EEPROM on real silicon) so a
    /// never-addressed device answers on the spec default.
    pub fn individual_address(&self) -> IndividualAddress {
        IndividualAddress::from_bytes(&self.table.data[1..3])
    }

    /// Write the device's individual address into its table slot.
    ///
    /// Shared landing site for `NM_IndividualAddress_Write` (via the
    /// device state) and direct memory writes — downloads overwrite the
    /// same bytes as part of the table blob.
    pub fn set_individual_address(&mut self, address: IndividualAddress) {
        self.table.data[1..3].copy_from_slice(address.as_bytes());
    }
}

impl<const N: usize> TableMemory for AddrTab8Impl<N> {
    const MAX_SIZE: usize = N;
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Unload clears the loadable part — the count and the group
    /// addresses — but spares the Individual Address slot at offsets
    /// 1–2. The IA is a separate resource that merely shares the RT8
    /// memory window (03/05/01 §4.16.9 gives it a dedicated slot ahead
    /// of the group addresses); Unload only declares the *loadable*
    /// data invalid, without mandating erasure (§4.23.2.3.2). ETS's
    /// `ProductProcedure` counts on this: it unloads the table and then
    /// rewrites the blob around the IA bytes, never re-sending them —
    /// wiping the slot would re-address the device to 0.0.0 in the
    /// middle of its own download.
    fn clear_on_unload(&mut self) {
        self.data[0] = 0;
        self.data[3..].fill(0);
    }
}

impl<const N: usize> AddressTable for Table<AddrTab8Impl<N>, AbsoluteAlloc> {
    fn max_entries(&self) -> usize {
        (N - 3) / 2
    }

    fn entry_count(&self) -> u16 {
        // The count is bus-downloaded data and must not exceed physical capacity.
        (self.table.data[0] as u16).min(self.max_entries() as u16)
    }

    fn address(&self, tsap: u16) -> Option<GroupAddress> {
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

pub type AddrTab8<const MAX_ENTRIES: usize> = Table<AddrTab8Impl<{ 3 + MAX_ENTRIES * 2 }>, AbsoluteAlloc>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{AddressTable, HasLoadStateMachine, LoadEvent, LoadState, TableMemory};
    use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

    use super::AddrTab8;

    /// Build a loaded 3-entry table via the System 7 download shape:
    /// absolute-segment allocation at 4000h, then memory writes.
    fn loaded_table() -> AddrTab8<10> {
        let mut a = AddrTab8::<10>::new();

        a.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // AllocAbsDataSeg: [type 00h][start 4000h][length 0017h][access][memtype][memattr][reserved]
        a.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x40, 0x00, 0x00, 0x17, 0xFF, 0x03, 0x80, 0x00],
            None,
        );

        // [len][IA 1.0.1][GA 0/0/1][GA 0/0/2][GA 0/0/4] — sorted ascending.
        a.write(0, &[3]);
        a.write(1, &[0x10, 0x01]);
        a.write(3, GroupAddress::from_three_level(0, 0, 1).as_bytes());
        a.write(5, GroupAddress::from_three_level(0, 0, 2).as_bytes());
        a.write(7, GroupAddress::from_three_level(0, 0, 4).as_bytes());

        a.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(a.read_lsm(), [u8::from(LoadState::Loaded)]);
        assert_eq!(a.table_reference(), 0x4000);
        a
    }

    #[test]
    fn addr8_lookup_by_tsap() {
        let a = loaded_table();
        assert_eq!(a.entry_count(), 3);
        assert_eq!(a.address(1), Some(GroupAddress::from_three_level(0, 0, 1)));
        assert_eq!(a.address(3), Some(GroupAddress::from_three_level(0, 0, 4)));
        // TSAP 0 is the Individual Address, never a group lookup target.
        assert_eq!(a.address(0), None);
        assert_eq!(a.address(4), None);
    }

    #[test]
    fn addr8_tsap_by_address() {
        let a = loaded_table();
        assert_eq!(a.tsap(GroupAddress::from_three_level(0, 0, 1)), Some(1));
        assert_eq!(a.tsap(GroupAddress::from_three_level(0, 0, 2)), Some(2));
        assert_eq!(a.tsap(GroupAddress::from_three_level(0, 0, 4)), Some(3));
        // 0/0/3 falls between two entries — the binary search must miss it.
        assert!(!a.contains(GroupAddress::from_three_level(0, 0, 3)));
    }

    #[test]
    fn addr8_empty_table_matches_nothing() {
        let a = AddrTab8::<10>::new();
        assert_eq!(a.entry_count(), 0);
        assert_eq!(a.address(1), None);
        assert!(!a.contains(GroupAddress::from_three_level(0, 0, 1)));
    }

    /// A corrupt length byte larger than the physical capacity must be
    /// clamped, not walk past the buffer.
    #[test]
    fn addr8_length_byte_is_clamped() {
        let mut a = AddrTab8::<10>::new();
        a.write(0, &[0xFF]);
        assert_eq!(a.entry_count(), 10);
        assert_eq!(a.address(10), Some(GroupAddress::from_bytes(&[0, 0])));
        assert_eq!(a.address(11), None);
    }

    /// Unload clears the loadable part but must spare the IA slot: ETS's
    /// `ProductProcedure` unloads the table first and rewrites the blob
    /// around bytes 1-2, so wiping them would re-address the device to
    /// 0.0.0 mid-download.
    #[test]
    fn addr8_unload_preserves_individual_address() {
        let mut a = loaded_table();
        assert_eq!(a.individual_address(), IndividualAddress::from_bytes(&[0x10, 0x01]));

        a.write_lsm(&[LoadEvent::Unload.into()], None);

        assert_eq!(a.read_lsm(), [u8::from(LoadState::Unloaded)]);
        assert_eq!(a.entry_count(), 0, "count byte cleared");
        assert!(a.data_ref()[3..].iter().all(|&b| b == 0), "group addresses cleared");
        assert_eq!(a.individual_address(), IndividualAddress::from_bytes(&[0x10, 0x01]), "IA slot survives");
    }

    /// The IA slot is one storage shared by the service path and the
    /// download path: whichever wrote last wins, as on real hardware.
    #[test]
    fn addr8_individual_address_slot_is_shared() {
        use zweidraehte_proto::address::IndividualAddress;

        let mut a = loaded_table();
        assert_eq!(a.individual_address(), IndividualAddress::from_bytes(&[0x10, 0x01]));

        a.set_individual_address(IndividualAddress::new(1, 1, 10));
        assert_eq!(&a.data_ref()[1..3], IndividualAddress::new(1, 1, 10).as_bytes());

        // A download rewriting the blob moves the address again.
        a.write(1, &[0x11, 0x05]);
        assert_eq!(a.individual_address(), IndividualAddress::from_bytes(&[0x11, 0x05]));
    }
}
