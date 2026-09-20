//! Borrowed views over the compact BCU group-object-table codings.
//!
//! RT1 and RT2 use:
//!
//! ```text
//! [count:1][RAM-flags pointer:1][(data pointer:1, config:1, type:1) × count]
//! ```
//!
//! Resources §4.18.3 and §4.18.4 define those two realizations. Their
//! layouts are identical; only the config octet's bit 7 differs: RT1 fixes
//! it at one, while RT2 interprets it as UpdateEnable.
//!
//! System 7 mask 0705 has no group-object-table realization assigned in
//! Profiles §4.6.1; its own mask document leaves the realization unknown.
//! ETS nevertheless writes a related wide-pointer format through its
//! `GroupObjectTable_M112` formatter:
//!
//! ```text
//! [count:1][RAM-flags pointer:2 BE][(data pointer:2 BE, config:1, type:1) × count]
//! ```
//!
//! [`BcuComObjectTableFormat`] keeps that profile-specific format separate
//! instead of giving it a realization number the specification does not.

use core::marker::PhantomData;

const RT1_FIXED_CONFIG_BIT: u8 = 0x80;
const LEGACY_SEGMENT_SELECTOR: u8 = 0x20;

/// Group Object Table Realisation Type 1 (System 1 / BCU1).
#[derive(Debug, Clone, Copy)]
pub struct Rt1;

/// Group Object Table Realisation Type 2 (System 2 / BCU2).
#[derive(Debug, Clone, Copy)]
pub struct Rt2;

/// System 7's `GroupObjectTable_M112` wide-pointer format.
#[derive(Debug, Clone, Copy)]
pub struct System7;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Rt1 {}
    impl Sealed for super::Rt2 {}
    impl Sealed for super::System7 {}
}

/// Compile-time compact group-object-table coding used by one BCU family.
///
/// Sealed to the supported layouts. A view carries only the borrowed bytes;
/// its marker type specializes pointer widths and config-bit handling.
pub trait BcuComObjectTableFormat: private::Sealed + core::fmt::Debug + Copy {
    /// Width of both pointer fields in this format.
    const POINTER_LEN: usize;
    /// Bits which must be set when writing a config octet.
    const FIXED_CONFIG_BITS: u8;

    /// Count octet plus the RAM-flags pointer.
    const HEADER_LEN: usize = 1 + Self::POINTER_LEN;

    /// Data pointer plus config and type octets.
    const ENTRY_LEN: usize = Self::POINTER_LEN + 2;

    /// Apply the realization-specific invariant before storing a config
    /// octet. Reading deliberately preserves the raw byte.
    fn encode_config(config: u8) -> u8 {
        config | Self::FIXED_CONFIG_BITS
    }

    /// Resolve a descriptor's value pointer according to this format.
    ///
    /// RT1 and RT2 carry only the low address octet; config bit 5 selects
    /// segment `0000h` or `0100h`. System 7 already stores a complete 16-bit
    /// pointer and has no specified segment-selector bit.
    fn value_address(data_pointer: u16, config: u8) -> u16 {
        if Self::POINTER_LEN == 1 && config & LEGACY_SEGMENT_SELECTOR != 0 {
            data_pointer | 0x0100
        } else {
            data_pointer
        }
    }

    /// Decode either pointer field; incomplete storage has no pointer.
    fn read_pointer(bytes: &[u8]) -> Option<u16> {
        if Self::POINTER_LEN == 1 {
            bytes.first().copied().map(u16::from)
        } else {
            Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
        }
    }
}

impl BcuComObjectTableFormat for Rt1 {
    const POINTER_LEN: usize = 1;
    const FIXED_CONFIG_BITS: u8 = RT1_FIXED_CONFIG_BIT;
}

impl BcuComObjectTableFormat for Rt2 {
    const POINTER_LEN: usize = 1;
    const FIXED_CONFIG_BITS: u8 = 0;
}

impl BcuComObjectTableFormat for System7 {
    const POINTER_LEN: usize = 2;
    const FIXED_CONFIG_BITS: u8 = 0;
}

/// One compact group-object-table row, with narrow pointers widened to
/// family-independent values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcuComObjectTableEntry {
    /// Stored value pointer before realization-specific address resolution.
    pub data_ptr: u16,
    /// Raw config and priority octet.
    pub config: u8,
    /// Raw, zero-based communication-object type coding.
    pub object_type: u8,
}

/// Bounds-checked, ownership-free view of a compact group object table.
///
/// A downloaded count is untrusted while ETS writes the table piecemeal. The
/// view therefore clamps it to the number of complete rows present in `data`;
/// no accessor can walk beyond the borrowed slice.
///
/// A mutable view retains its format when borrowed for reading; RT1's fixed
/// config bit cannot silently acquire RT2's UpdateEnable semantics.
///
/// ```compile_fail,E0308
/// use zweidraehte_proto::tables::com_object::{BcuComObjectTableView, BcuComObjectTableViewMut, Rt1, Rt2};
/// let mut eeprom = [0; 8];
/// let table = BcuComObjectTableViewMut::<Rt1>::new(&mut eeprom);
/// let read_only: BcuComObjectTableView<'_, Rt2> = table.as_view(); // different format type
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BcuComObjectTableView<'a, F: BcuComObjectTableFormat> {
    data: &'a [u8],
    _format: PhantomData<F>,
}

impl<'a, F: BcuComObjectTableFormat> BcuComObjectTableView<'a, F> {
    /// Borrow an encoded table in the selected realization or profile format.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, _format: PhantomData }
    }

    /// Return the complete encoded bytes supplied to this view.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Return the leading count octet, or `None` when it is absent.
    pub fn stored_count(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Return the row count declared by the count octet, before applying the
    /// borrowed slice's physical bound.
    pub fn declared_entry_count(&self) -> u16 {
        u16::from(self.stored_count().unwrap_or(0))
    }

    /// Return the number of complete rows available through this view.
    pub fn entry_count(&self) -> u16 {
        let available = self.data.len().saturating_sub(F::HEADER_LEN) / F::ENTRY_LEN;
        self.declared_entry_count().min(available.min(usize::from(u8::MAX)) as u16)
    }

    /// Decode the RAM-flags pointer from the complete header.
    pub fn ram_flags_ptr(&self) -> Option<u16> {
        F::read_pointer(self.data.get(1..F::HEADER_LEN)?)
    }

    /// Return a row by its zero-based ASAP.
    pub fn entry(&self, asap: u16) -> Option<BcuComObjectTableEntry> {
        let offset = self.entry_offset(asap)?;
        let pointer_len = F::POINTER_LEN;
        let data_ptr = F::read_pointer(self.data.get(offset..offset + pointer_len)?)?;

        Some(BcuComObjectTableEntry {
            data_ptr,
            config: *self.data.get(offset + pointer_len)?,
            object_type: *self.data.get(offset + pointer_len + 1)?,
        })
    }

    /// Return the config octet's offset from the start of the encoded table.
    ///
    /// This lets a live-storage owner route the mutation through its own
    /// write path while the table codec remains responsible for the layout.
    pub fn config_offset(&self, asap: u16) -> Option<usize> {
        self.entry_offset(asap)?.checked_add(F::POINTER_LEN)
    }

    fn entry_offset(&self, asap: u16) -> Option<usize> {
        if asap >= self.entry_count() {
            return None;
        }
        Some(F::HEADER_LEN + usize::from(asap) * F::ENTRY_LEN)
    }
}

/// Mutable counterpart to [`BcuComObjectTableView`].
///
/// Mutations preserve both pointer fields and refuse rows beyond either the
/// stored count or the borrowed slice.
#[derive(Debug)]
pub struct BcuComObjectTableViewMut<'a, F: BcuComObjectTableFormat> {
    data: &'a mut [u8],
    _format: PhantomData<F>,
}

impl<'a, F: BcuComObjectTableFormat> BcuComObjectTableViewMut<'a, F> {
    /// Mutably borrow an encoded table in the selected format.
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, _format: PhantomData }
    }

    /// Borrow the same bytes as a read-only view.
    pub fn as_view(&self) -> BcuComObjectTableView<'_, F> {
        BcuComObjectTableView::new(self.data)
    }

    /// Replace one row's config octet, enforcing RT1's fixed bit 7.
    pub fn set_config(&mut self, asap: u16, config: u8) -> bool {
        let Some(offset) = self.as_view().config_offset(asap) else {
            return false;
        };
        self.data[offset] = F::encode_config(config);
        true
    }

    /// Replace one row's config and type octets, preserving its data pointer.
    pub fn set_config_and_type(&mut self, asap: u16, config: u8, object_type: u8) -> bool {
        let Some(config_offset) = self.as_view().config_offset(asap) else {
            return false;
        };
        self.data[config_offset] = F::encode_config(config);
        self.data[config_offset + 1] = object_type;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rt1_and_rt2_decode_one_octet_pointers() {
        fn check<F: BcuComObjectTableFormat>() {
            let data = [2, 0xD0, 0xC6, 0x9F, 0, 0xC7, 0x4C, 3];
            let table = BcuComObjectTableView::<F>::new(&data);
            assert_eq!(table.stored_count(), Some(2));
            assert_eq!(table.entry_count(), 2);
            assert_eq!(table.ram_flags_ptr(), Some(0x00D0));
            assert_eq!(table.entry(1), Some(BcuComObjectTableEntry { data_ptr: 0x00C7, config: 0x4C, object_type: 3 }));
            assert_eq!(table.entry(2), None);
        }
        check::<Rt1>();
        check::<Rt2>();
    }

    #[test]
    fn legacy_bit_5_selects_the_value_segment() {
        fn check<F: BcuComObjectTableFormat>() {
            assert_eq!(F::value_address(0x00C6, 0xDF), 0x00C6);
            assert_eq!(F::value_address(0x00C6, 0xFF), 0x01C6);
        }
        check::<Rt1>();
        check::<Rt2>();

        assert_eq!(System7::value_address(0x42C6, 0xFF), 0x42C6);
    }

    #[test]
    fn system7_decodes_big_endian_wide_pointers() {
        let data = [1, 0x12, 0x34, 0xAB, 0xCD, 0x47, 3];
        let table = BcuComObjectTableView::<System7>::new(&data);

        assert_eq!(table.ram_flags_ptr(), Some(0x1234));
        assert_eq!(table.entry(0), Some(BcuComObjectTableEntry { data_ptr: 0xABCD, config: 0x47, object_type: 3 }));
    }

    #[test]
    fn downloaded_count_is_clamped_to_complete_rows() {
        let table = BcuComObjectTableView::<Rt2>::new(&[u8::MAX, 0xD0, 0xC6, 0x9F, 0, 0xC7]);

        assert_eq!(table.declared_entry_count(), u16::from(u8::MAX));
        assert_eq!(table.entry_count(), 1);
        assert_eq!(table.entry(0).map(|entry| entry.data_ptr), Some(0xC6));
        assert_eq!(table.entry(1), None);
    }

    #[test]
    fn truncated_headers_are_safe() {
        let rt2 = BcuComObjectTableView::<Rt2>::new(&[1]);
        let system7 = BcuComObjectTableView::<System7>::new(&[1, 0x12]);

        assert_eq!(rt2.ram_flags_ptr(), None);
        assert_eq!(rt2.entry_count(), 0);
        assert_eq!(system7.ram_flags_ptr(), None);
        assert_eq!(system7.entry_count(), 0);
    }

    #[test]
    fn mutation_preserves_pointers_and_applies_rt1_bit_7() {
        let mut rt1 = [1, 0xD0, 0xC6, 0x00, 0x03];
        let mut table = BcuComObjectTableViewMut::<Rt1>::new(&mut rt1);
        assert!(table.set_config_and_type(0, 0x43, 0));
        assert_eq!(rt1, [1, 0xD0, 0xC6, 0xC3, 0]);

        let mut rt2 = [1, 0xD0, 0xC6, 0x80, 0x03];
        let mut table = BcuComObjectTableViewMut::<Rt2>::new(&mut rt2);
        assert!(table.set_config(0, 0x43));
        assert_eq!(rt2, [1, 0xD0, 0xC6, 0x43, 0x03]);
    }
}
