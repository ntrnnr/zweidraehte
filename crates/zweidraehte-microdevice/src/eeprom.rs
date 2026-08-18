//! In-place table access over the flat EEPROM image.
//!
//! Nothing here owns state: [`Tables`] borrows the EEPROM byte array
//! and walks the address / association / group object tables through
//! the pointer bytes inside it, the way mask firmware walks its
//! EEPROM. Every lookup sees the bytes as they are *now*, so an ETS
//! memory write needs no synchronization step — the next telegram is
//! routed by the new table.
//!
//! All accessors are total: a torn or hostile table (dangling pointer
//! byte, count larger than the image) yields `None` / empty rather
//! than a panic, because ETS legitimately writes tables piecewise and
//! the device keeps running throughout.

use core::marker::PhantomData;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::family::MicroDeviceFamily;

/// One group object table entry, widened to family-independent types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoEntry {
    /// Value location, family-interpreted (BCU2: page-0 RAM address).
    pub data_ptr: u16,
    /// Config octet (`ComObjectFlags` coding: UE/TE/ROI/WE/RE/CE + priority).
    pub config: u8,
    /// Type octet (`ComObjectType` coding).
    pub value_type: u8,
}

/// Borrowing view over the EEPROM image's tables.
pub struct Tables<'a, F: MicroDeviceFamily> {
    eeprom: &'a [u8],
    _family: PhantomData<F>,
}

impl<'a, F: MicroDeviceFamily> Tables<'a, F> {
    pub fn new(eeprom: &'a [u8]) -> Self {
        Self { eeprom, _family: PhantomData }
    }

    fn byte(&self, offset: usize) -> u8 {
        self.eeprom.get(offset).copied().unwrap_or(0)
    }

    // ── Address table ───────────────────────────────────────────────

    pub fn addr_length_byte(&self) -> u8 {
        self.byte(F::ADDR_TABLE_OFFSET)
    }

    pub fn ga_count(&self) -> u8 {
        F::ga_count(self.addr_length_byte())
    }

    /// Group communication is muted while the table holds no group
    /// addresses — the state ETS puts the device in for the duration
    /// of a download by writing the mute length.
    pub fn muted(&self) -> bool {
        self.addr_length_byte() <= F::MUTE_LENGTH
    }

    /// The device's own individual address, stored as the address
    /// table's first entry (TSAP 0).
    pub fn individual_address(&self) -> IndividualAddress {
        let off = F::ADDR_TABLE_OFFSET + 1;
        IndividualAddress([self.byte(off), self.byte(off + 1)])
    }

    /// Group address of TSAP `tsap` (1-based; TSAP 0 is the IA slot).
    pub fn ga_of_tsap(&self, tsap: u8) -> Option<GroupAddress> {
        if tsap == 0 || tsap > self.ga_count() {
            return None;
        }
        let off = F::ADDR_TABLE_OFFSET + 1 + usize::from(tsap) * 2;
        if off + 1 >= self.eeprom.len() {
            return None;
        }
        Some(GroupAddress([self.eeprom[off], self.eeprom[off + 1]]))
    }

    /// TSAP of a destination group address, if the table carries it.
    /// Linear scan: the tables are sorted, but at BCU2 sizes a scan is
    /// smaller than a binary search and never wrong about duplicates.
    pub fn tsap_of(&self, ga: GroupAddress) -> Option<u8> {
        if self.muted() {
            return None;
        }
        (1..=self.ga_count()).find(|&tsap| self.ga_of_tsap(tsap) == Some(ga))
    }

    // ── Association table ───────────────────────────────────────────

    fn assoc_offset(&self) -> usize {
        usize::from(self.byte(F::ASSOC_TAB_PTR_OFFSET))
    }

    pub fn assoc_count(&self) -> u8 {
        self.byte(self.assoc_offset())
    }

    /// Iterate `(tsap, asap)` pairs in table order. Order matters: the
    /// first association of an ASAP is its sending association.
    pub fn associations(&self) -> impl Iterator<Item = (u8, u8)> + '_ {
        let base = self.assoc_offset();
        (0..usize::from(self.assoc_count())).filter_map(move |i| {
            let off = base + 1 + i * 2;
            if off + 1 >= self.eeprom.len() { None } else { Some((self.eeprom[off], self.eeprom[off + 1])) }
        })
    }

    /// The sending association of an ASAP: its first table entry.
    pub fn sending_tsap(&self, asap: u8) -> Option<u8> {
        self.associations().find(|&(_, a)| a == asap).map(|(t, _)| t)
    }

    // ── Group object table ──────────────────────────────────────────

    fn cot_offset(&self) -> usize {
        usize::from(self.byte(F::COMMS_TAB_PTR_OFFSET))
    }

    pub fn co_count(&self) -> u8 {
        self.byte(self.cot_offset())
    }

    /// The RAM-flags pointer from the table header (1 or 2 bytes wide
    /// depending on the family).
    pub fn ram_flags_ptr(&self) -> u16 {
        let base = self.cot_offset() + 1;
        let mut value: u16 = 0;
        for i in 0..(F::COT_HEADER_LEN - 1) {
            value = (value << 8) | u16::from(self.byte(base + i));
        }
        value
    }

    pub fn co_entry(&self, asap: u8) -> Option<CoEntry> {
        if asap >= self.co_count() {
            return None;
        }
        let off = self.cot_offset() + F::COT_HEADER_LEN + usize::from(asap) * F::COT_ENTRY_LEN;
        if off + F::COT_ENTRY_LEN > self.eeprom.len() {
            return None;
        }
        let mut data_ptr: u16 = 0;
        for i in 0..F::COT_CFG_OFFSET {
            data_ptr = (data_ptr << 8) | u16::from(self.eeprom[off + i]);
        }
        Some(CoEntry {
            data_ptr,
            config: self.eeprom[off + F::COT_CFG_OFFSET],
            value_type: self.eeprom[off + F::COT_TYPE_OFFSET],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::family::Bcu2Family;

    /// A hand-laid BCU2 EEPROM: address table at 0116h with two GAs,
    /// association table and group object table behind their pointer
    /// bytes.
    fn image() -> [u8; 0x3E0] {
        let mut e = [0u8; 0x3E0];
        // Pointers: assoc table at 0100h+0x20, CO table at 0100h+0x28.
        e[0x11] = 0x20;
        e[0x12] = 0x28;
        // Address table: length 3 (IA + 2 GAs), IA 1.1.10, GAs 1/0/1 2/0/2.
        e[0x16] = 3;
        e[0x17] = 0x11;
        e[0x18] = 0x0A;
        e[0x19] = 0x08;
        e[0x1A] = 0x01;
        e[0x1B] = 0x10;
        e[0x1C] = 0x02;
        // Association table: 2 entries, both TSAPs to ASAP 0 and 1.
        e[0x20] = 2;
        e[0x21] = 1;
        e[0x22] = 0;
        e[0x23] = 2;
        e[0x24] = 1;
        // Group object table: 2 objects, RAM flags at 00D0h.
        e[0x28] = 2;
        e[0x29] = 0xD0;
        e[0x2A] = 0xC6; // ASAP 0: value at 00C6h
        e[0x2B] = 0x9F;
        e[0x2C] = 0x00;
        e[0x2D] = 0xC7; // ASAP 1: value at 00C7h
        e[0x2E] = 0x4C;
        e[0x2F] = 0x00;
        e
    }

    #[test]
    fn walks_the_tables_in_place() {
        let image = image();
        let t = Tables::<Bcu2Family>::new(&image);
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
        assert_eq!(t.ga_count(), 2);
        assert!(!t.muted());
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(1, 0, 1)), Some(1));
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(2, 0, 2)), Some(2));
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(7, 7, 7)), None);
        assert_eq!(t.sending_tsap(0), Some(1));
        assert_eq!(t.sending_tsap(1), Some(2));
        assert_eq!(t.ram_flags_ptr(), 0x00D0);
        let e = t.co_entry(0).expect("ASAP 0 exists");
        assert_eq!(e.data_ptr, 0x00C6);
        assert_eq!(e.config, 0x9F);
        assert!(t.co_entry(2).is_none());
    }

    #[test]
    fn mute_length_silences_group_lookups() {
        let mut image = image();
        image[0x16] = 1; // RT2 mute: IA slot only
        let t = Tables::<Bcu2Family>::new(&image);
        assert!(t.muted());
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(1, 0, 1)), None);
        // The IA slot is untouched by muting.
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
    }
}
