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

use zweidraehte_proto::{
    address::{GroupAddress, IndividualAddress},
    tables::address::BcuAddressTableView,
    tables::association::BcuAssociationTableView,
    tables::com_object::BcuComObjectTableView,
};

use crate::family::MicroDeviceFamily;
use crate::management::ManagementState;

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
///
/// Carries the management state alongside the image because a family
/// may locate a table through it (System 7 finds the association
/// table via the machine's `table_ref`) rather than through pointer
/// bytes inside the image.
pub struct Tables<'a, F: MicroDeviceFamily> {
    eeprom: &'a [u8],
    mgmt: &'a ManagementState,
    _family: PhantomData<F>,
}

impl<'a, F: MicroDeviceFamily> Tables<'a, F> {
    pub fn new(eeprom: &'a [u8], mgmt: &'a ManagementState) -> Self {
        Self { eeprom, mgmt, _family: PhantomData }
    }

    // ── Address table ───────────────────────────────────────────────

    fn address_table(&self) -> BcuAddressTableView<'_> {
        let data = self.eeprom.get(F::ADDR_TABLE_OFFSET..).unwrap_or_default();
        BcuAddressTableView::new(data)
    }

    pub fn addr_length_byte(&self) -> u8 {
        self.address_table().stored_length().unwrap_or(0)
    }

    pub fn ga_count(&self) -> u8 {
        u8::try_from(self.address_table().group_address_count()).expect("one-octet count bounds the address table")
    }

    /// Whether the table carries the family's explicit mute coding.
    ///
    /// ETS writes length 1 during a download. Length 0 is different: it
    /// requests non-selective group reception and is therefore not reported
    /// as muted.
    pub fn muted(&self) -> bool {
        self.address_table().is_muted()
    }

    /// The device's own individual address, stored as the address
    /// table's first entry (TSAP 0).
    pub fn individual_address(&self) -> IndividualAddress {
        self.address_table().individual_address().unwrap_or_default()
    }

    /// Group address of TSAP `tsap` (1-based; TSAP 0 is the IA slot).
    pub fn ga_of_tsap(&self, tsap: u8) -> Option<GroupAddress> {
        self.address_table().group_address(u16::from(tsap))
    }

    /// TSAP of a destination group address, if the table carries it.
    /// The linear lookup is deliberate on BCU targets: their tables are small,
    /// the loop has a smaller code footprint, and a malformed duplicate still
    /// resolves to the first slot deterministically.
    pub fn tsap_of(&self, ga: GroupAddress) -> Option<u8> {
        if self.muted() {
            return None;
        }
        self.address_table().first_tsap(ga).and_then(|tsap| u8::try_from(tsap).ok())
    }

    // ── Association table ───────────────────────────────────────────

    fn assoc_offset(&self) -> usize {
        F::assoc_table_offset(self.eeprom, self.mgmt)
    }

    fn association_table(&self) -> BcuAssociationTableView<'_> {
        let data = self.eeprom.get(self.assoc_offset()..).unwrap_or_default();
        BcuAssociationTableView::new(data)
    }

    pub fn assoc_count(&self) -> u8 {
        u8::try_from(self.association_table().entry_count()).expect("one-octet count bounds the association table")
    }

    /// Return one association-table row by its zero-based number.
    ///
    /// Group reception walks rows by number rather than buffering matching
    /// ASAPs. That keeps fan-out bounded only by the downloaded table, not by
    /// an unrelated temporary-vector capacity.
    pub(crate) fn association(&self, number: u8) -> Option<(u8, u8)> {
        self.association_table().association(u16::from(number)).map(|association| (association.tsap, association.asap))
    }

    /// Iterate `(tsap, asap)` pairs in table order.
    ///
    /// Receive fan-out uses every matching row. Sending has separate
    /// realization-specific indexed/first-match rules in [`Self::sending_tsap`].
    pub fn associations(&self) -> impl Iterator<Item = (u8, u8)> + '_ {
        self.association_table().associations().map(|association| (association.tsap, association.asap))
    }

    /// The sending association of an ASAP, resolved the family's way.
    ///
    /// RT2 (03/05/01 §4.17.4.3.1) *indexes*: "the Association with
    /// association number equal to the value of the ASAP", and the
    /// slot must name that same ASAP or the transmission request is
    /// confirmed negatively. TSAP FEh is the unused-association
    /// sentinel (§4.17.3.4.1) a dynamic-table-management download
    /// writes into the slot of an object with no group address; it is
    /// no sending association either.
    ///
    /// System 7 *scans*: its compact table is sorted by TSAP, so the
    /// sending association is the first entry naming the ASAP.
    ///
    /// Either way `None` means no association, which the transmit scan
    /// reports as idle-with-error.
    pub fn sending_tsap(&self, asap: u8) -> Option<u8> {
        self.association_table().sending_tsap(asap, F::SENDING_ASSOCIATION)
    }

    // ── Group object table ──────────────────────────────────────────

    fn cot_offset(&self) -> usize {
        F::cot_table_offset(self.eeprom, self.mgmt)
    }

    fn com_object_table(&self) -> BcuComObjectTableView<'_> {
        let data = self.eeprom.get(self.cot_offset()..).unwrap_or_default();
        BcuComObjectTableView::new(data, F::COM_OBJECT_TABLE_FORMAT)
    }

    pub fn co_count(&self) -> u8 {
        u8::try_from(self.com_object_table().entry_count()).expect("one-octet count bounds the group object table")
    }

    /// The RAM-flags pointer from the table header (1 or 2 bytes wide
    /// depending on the family).
    pub fn ram_flags_ptr(&self) -> u16 {
        self.com_object_table().ram_flags_ptr().unwrap_or(0)
    }

    pub fn co_entry(&self, asap: u8) -> Option<CoEntry> {
        self.com_object_table().entry(u16::from(asap)).map(|entry| CoEntry {
            data_ptr: entry.data_ptr,
            config: entry.config,
            value_type: entry.object_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::families::bcu1::Bcu1Family;
    use crate::families::bcu2::Bcu2Family;

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
        let mgmt = ManagementState::new();
        let t = Tables::<Bcu2Family>::new(&image, &mgmt);
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
    fn placeholder_associations_carry_no_sending_tsap() {
        // A dynamic-table-management download writes a TSAP FEh entry
        // into the slot of every unlinked object: relaid table with
        // ASAP 0 linked and ASAP 1 carrying only the placeholder.
        let mut image = image();
        image[0x20] = 2;
        image[0x21] = 1; // slot 0 = (1, 0): ASAP 0 sends through TSAP 1
        image[0x22] = 0;
        image[0x23] = 0xFE; // slot 1 = (FE, 1): ASAP 1 has no group address
        image[0x24] = 1;
        let mgmt = ManagementState::new();
        let t = Tables::<Bcu2Family>::new(&image, &mgmt);
        assert_eq!(t.sending_tsap(0), Some(1));
        assert_eq!(t.sending_tsap(1), None, "the placeholder is not a sending association");
    }

    #[test]
    fn sending_association_is_indexed_not_scanned() {
        // RT2 resolves a transmission request through the slot whose
        // number equals the ASAP; an entry for the right ASAP in the
        // wrong slot is a negative confirmation, not a fallback.
        let mut image = image();
        image[0x20] = 2;
        image[0x21] = 1; // slot 0 = (1, 1): names ASAP 1, not 0
        image[0x22] = 1;
        image[0x23] = 2; // slot 1 = (2, 0): names ASAP 0, not 1
        image[0x24] = 0;
        let mgmt = ManagementState::new();
        let t = Tables::<Bcu2Family>::new(&image, &mgmt);
        assert_eq!(t.sending_tsap(0), None, "slot 0 names another ASAP");
        assert_eq!(t.sending_tsap(1), None, "ASAP 1's entry sits outside its slot");
        assert_eq!(t.sending_tsap(2), None, "beyond the table");
    }

    #[test]
    fn rt1_uses_the_index_without_checking_the_stored_asap() {
        // Resources §4.17.3.3.1 explicitly says RT1 does not check the
        // ASAP in the indexed row; RT2 §4.17.4.3.1 explicitly does.
        let mut image = image();
        image[0x20] = 1;
        image[0x21] = 2;
        image[0x22] = 7;
        let mgmt = ManagementState::new();

        let rt1 = Tables::<Bcu1Family>::new(&image, &mgmt);
        let rt2 = Tables::<Bcu2Family>::new(&image, &mgmt);
        assert_eq!(rt1.sending_tsap(0), Some(2));
        assert_eq!(rt2.sending_tsap(0), None);
    }

    /// A hand-laid System 7 image (window 4000h..4400h): RT8 address
    /// table at offset 0, association table at offset 0x100 (found
    /// through machine 1's `table_ref`), System 7 group object table at
    /// the product address 4200h.
    #[test]
    fn walks_system7_tables_in_place() {
        type S7 = crate::families::system7::System7Family<0x400, 0x4200, 0, 0, 0, 0>;
        let mut e = [0u8; 0x400];
        // ADT: length 3 (IA + 2 GAs), IA 1.1.10 at bytes 1-2.
        e[0] = 3;
        e[1] = 0x11;
        e[2] = 0x0A;
        e[3] = 0x08; // 1/0/1
        e[4] = 0x01;
        e[5] = 0x10; // 2/0/2
        e[6] = 0x02;
        // AST at 0x100: 2 entries.
        e[0x100] = 2;
        e[0x101] = 1;
        e[0x102] = 0;
        e[0x103] = 2;
        e[0x104] = 1;
        // COT at 0x200: 2 objects, RAM flags at 00D0h, 2-byte data
        // pointers.
        e[0x200] = 2;
        e[0x201] = 0x00;
        e[0x202] = 0xD0;
        e[0x203] = 0x00; // ASAP 0: value at 00C6h
        e[0x204] = 0xC6;
        e[0x205] = 0x9F;
        e[0x206] = 0x00;
        e[0x207] = 0x00; // ASAP 1: value at 00C7h
        e[0x208] = 0xC7;
        e[0x209] = 0x4C;
        e[0x20A] = 0x00;

        let mut mgmt = ManagementState::new();
        mgmt.lsm[1].table_ref = 0x4100;
        let t = Tables::<S7>::new(&e, &mgmt);
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
        assert_eq!(t.ga_count(), 2);
        assert!(!t.muted());
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(1, 0, 1)), Some(1));
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(2, 0, 2)), Some(2));
        assert_eq!(t.sending_tsap(0), Some(1));
        assert_eq!(t.sending_tsap(1), Some(2));
        assert_eq!(t.ram_flags_ptr(), 0x00D0);
        let entry = t.co_entry(0).expect("ASAP 0 exists");
        assert_eq!(entry.data_ptr, 0x00C6);
        assert_eq!(entry.config, 0x9F);
        assert!(t.co_entry(2).is_none());

        // Before any allocation the association table does not exist.
        let blank_mgmt = ManagementState::new();
        let t = Tables::<S7>::new(&e, &blank_mgmt);
        assert_eq!(t.assoc_count(), 0);
        assert_eq!(t.sending_tsap(0), None);

        // System 7 resolves the sending association by scan, not by slot:
        // a single entry linking ASAP 3 through TSAP 1 sits in slot 0
        // and still sends (the shape a one-link download writes).
        e[0x100] = 1;
        e[0x101] = 1;
        e[0x102] = 3;
        let t = Tables::<S7>::new(&e, &mgmt);
        assert_eq!(t.sending_tsap(3), Some(1));
        assert_eq!(t.sending_tsap(0), None);
    }

    /// RT8 uses the same length-one mute as RT1/RT2. The IA survives
    /// as the one counted slot.
    #[test]
    fn system7_bcu_table_mute_is_length_one() {
        type S7 = crate::families::system7::System7Family<0x400, 0x4200, 0, 0, 0, 0>;
        let mut e = [0u8; 0x400];
        e[0] = 1;
        e[1] = 0x11;
        e[2] = 0x0A;
        let mgmt = ManagementState::new();
        let t = Tables::<S7>::new(&e, &mgmt);
        assert!(t.muted());
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
    }

    #[test]
    fn mute_length_silences_group_lookups() {
        let mut image = image();
        image[0x16] = 1; // RT2 mute: IA slot only
        let mgmt = ManagementState::new();
        let t = Tables::<Bcu2Family>::new(&image, &mgmt);
        assert!(t.muted());
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(1, 0, 1)), None);
        // The IA slot is untouched by muting.
        assert_eq!(t.individual_address(), IndividualAddress::new(1, 1, 10));
    }

    /// Resources §4.16.3.3.1 reserves RT1/RT2 length zero for
    /// non-selective reception. It contains no TSAP mapping, but it is
    /// not the length-one mute state used during a download.
    #[test]
    fn rt2_zero_length_is_not_the_mute_coding() {
        let mut image = image();
        image[0x16] = 0;
        let mgmt = ManagementState::new();
        let t = Tables::<Bcu2Family>::new(&image, &mgmt);

        assert!(!t.muted());
        assert_eq!(t.ga_count(), 0);
        assert_eq!(t.tsap_of(GroupAddress::from_three_level(1, 0, 1)), None);
    }
}
