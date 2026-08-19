//! Borrowed view over the RT1, RT2, and RT8 group address-table coding.
//!
//! The coding is:
//!
//! ```text
//! [length:1][individual address:2][group address:2 × (length - 1)]
//! ```
//!
//! Resources §4.16.3.3.1 explicitly defines the RT1 length as the number
//! of addresses including the individual address; §4.16.4 makes RT2 use
//! RT1 unchanged. RT8 repeats the layout at fixed address 4000h. The KNX
//! master data selects the same `AddressTable_Bcu1` formatter for masks
//! 0705 and 5705, and an ETS download confirms that four group addresses
//! are written with length `05h`.

use crate::address::{GroupAddress, IndividualAddress};

const HEADER_LEN: usize = 3;
const ENTRY_LEN: usize = 2;

/// Length octet that leaves only the individual-address slot and disables
/// group communication during a download.
pub const BCU_ADDRESS_TABLE_MUTE_LENGTH: u8 = 1;

/// Bounds-checked, ownership-free view of an RT1, RT2, or RT8 address table.
///
/// A downloaded length is untrusted while ETS writes the table piecemeal. The
/// view therefore clamps it to the number of complete entries present in
/// `data`; no accessor can walk beyond the borrowed slice.
#[derive(Debug, Clone, Copy)]
pub struct BcuAddressTableView<'a> {
    data: &'a [u8],
}

impl<'a> BcuAddressTableView<'a> {
    /// Borrow an encoded table.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Return the complete encoded bytes supplied to this view.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Return the leading length octet, or `None` when even the header is
    /// absent.
    pub fn stored_length(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Return the number of group addresses declared by the length octet,
    /// before applying the borrowed slice's physical bound.
    pub fn declared_group_address_count(&self) -> u16 {
        u16::from(self.stored_length().unwrap_or(0).saturating_sub(1))
    }

    /// Return the number of complete group-address entries available through
    /// this view.
    ///
    /// A corrupt or half-written length is clamped to the provided storage.
    pub fn group_address_count(&self) -> u16 {
        let available = self.data.len().saturating_sub(HEADER_LEN) / ENTRY_LEN;
        self.declared_group_address_count().min(available.min(usize::from(u8::MAX)) as u16)
    }

    /// Whether the table's current length disables group communication.
    ///
    /// A missing header is treated as disabled. Length `0` is not disabled:
    /// Resources §4.16.3.3.1 assigns it non-selective receive behavior.
    pub fn is_muted(&self) -> bool {
        self.stored_length().is_none_or(|length| length == BCU_ADDRESS_TABLE_MUTE_LENGTH)
    }

    /// Whether length `0` requests non-selective reception of every group
    /// address.
    ///
    /// This mode does not invent TSAP mappings: [`group_address`](Self::group_address)
    /// and [`tsap`](Self::tsap) still return `None` for an empty table.
    pub fn accepts_all_group_addresses(&self) -> bool {
        self.stored_length() == Some(0)
    }

    /// Return the individual address stored in TSAP slot 0.
    pub fn individual_address(&self) -> Option<IndividualAddress> {
        let bytes: [u8; 2] = self.data.get(1..3)?.try_into().ok()?;
        Some(IndividualAddress(bytes))
    }

    /// Return the group address mapped to a one-based TSAP.
    pub fn group_address(&self, tsap: u16) -> Option<GroupAddress> {
        if tsap == 0 || tsap > self.group_address_count() {
            return None;
        }

        let offset = 1 + usize::from(tsap) * ENTRY_LEN;
        let bytes: [u8; 2] = self.data.get(offset..offset + ENTRY_LEN)?.try_into().ok()?;
        Some(GroupAddress(bytes))
    }

    /// Find the TSAP of a group address using the required ascending order.
    pub fn tsap(&self, address: GroupAddress) -> Option<u16> {
        let mut low = 1;
        let mut high = self.group_address_count();

        while low <= high {
            let tsap = low + (high - low) / 2;
            let candidate = self.group_address(tsap)?;

            match address.cmp(&candidate) {
                core::cmp::Ordering::Equal => return Some(tsap),
                core::cmp::Ordering::Less => high = tsap - 1,
                core::cmp::Ordering::Greater => low = tsap + 1,
            }
        }

        None
    }

    /// Find the first TSAP carrying a group address.
    ///
    /// This linear form is useful on the smallest BCU targets, where code
    /// size matters more than the asymptotic improvement of [`tsap`](Self::tsap).
    /// It also gives deterministic first-entry behavior if a malformed table
    /// contains duplicates.
    pub fn first_tsap(&self, address: GroupAddress) -> Option<u16> {
        (1..=self.group_address_count()).find(|&tsap| self.group_address(tsap) == Some(address))
    }

    /// Whether the table contains a group address.
    pub fn contains(&self, address: GroupAddress) -> bool {
        self.tsap(address).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IA: IndividualAddress = IndividualAddress::new(1, 1, 10);
    const GA1: GroupAddress = GroupAddress::from_three_level(1, 0, 1);
    const GA2: GroupAddress = GroupAddress::from_three_level(2, 0, 2);

    #[test]
    fn length_includes_the_individual_address() {
        let data = [3, 0x11, 0x0A, 0x08, 0x01, 0x10, 0x02];
        let table = BcuAddressTableView::new(&data);

        assert_eq!(table.stored_length(), Some(3));
        assert_eq!(table.group_address_count(), 2);
        assert_eq!(table.individual_address(), Some(IA));
        assert_eq!(table.group_address(1), Some(GA1));
        assert_eq!(table.group_address(2), Some(GA2));
        assert_eq!(table.tsap(GA2), Some(2));
    }

    /// Captures the RT8-compatible length from an ETS image for mask 0705:
    /// length 5 is the IA slot plus four group addresses, not five GAs.
    #[test]
    fn mask_0705_uses_the_rt8_length_coding() {
        let data = [5, 0x11, 0x0A, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04];
        let table = BcuAddressTableView::new(&data);

        assert_eq!(table.group_address_count(), 4);
        assert_eq!(table.group_address(4), Some(GroupAddress::from_three_level(0, 0, 4)));
        assert_eq!(table.group_address(5), None);
    }

    #[test]
    fn linear_lookup_returns_the_first_duplicate() {
        let data = [4, 0x11, 0x0A, 0x08, 0x01, 0x08, 0x01, 0x10, 0x02];
        let table = BcuAddressTableView::new(&data);

        assert_eq!(table.first_tsap(GA1), Some(1));
    }

    #[test]
    fn zero_and_one_keep_their_distinct_receive_semantics() {
        let open = BcuAddressTableView::new(&[0, 0x11, 0x0A]);
        let muted = BcuAddressTableView::new(&[1, 0x11, 0x0A]);

        assert!(open.accepts_all_group_addresses());
        assert!(!open.is_muted());
        assert!(!muted.accepts_all_group_addresses());
        assert!(muted.is_muted());
    }

    #[test]
    fn downloaded_length_is_clamped_to_complete_entries() {
        let data = [u8::MAX, 0x11, 0x0A, 0x08, 0x01, 0x10];
        let table = BcuAddressTableView::new(&data);

        assert_eq!(table.declared_group_address_count(), 254);
        assert_eq!(table.group_address_count(), 1);
        assert_eq!(table.group_address(1), Some(GA1));
        assert_eq!(table.group_address(2), None);
    }

    #[test]
    fn truncated_header_is_safe() {
        let table = BcuAddressTableView::new(&[3, 0x11]);

        assert_eq!(table.individual_address(), None);
        assert_eq!(table.group_address_count(), 0);
        assert_eq!(table.group_address(1), None);
    }
}
