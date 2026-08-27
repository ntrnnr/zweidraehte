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

const RT1_FIXED_CONFIG_BIT: u8 = 0x80;
const LEGACY_SEGMENT_SELECTOR: u8 = 0x20;

/// Compact group-object-table coding used by one BCU family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcuComObjectTableFormat {
    /// Group Object Table Realisation Type 1 (System 1 / BCU1).
    Rt1,
    /// Group Object Table Realisation Type 2 (System 2 / BCU2).
    Rt2,
    /// System 7's `GroupObjectTable_M112` wide-pointer format.
    System7,
}

impl BcuComObjectTableFormat {
    /// Width of both pointer fields in this format.
    pub const fn pointer_len(self) -> usize {
        match self {
            Self::Rt1 | Self::Rt2 => 1,
            Self::System7 => 2,
        }
    }

    /// Count octet plus the RAM-flags pointer.
    pub const fn header_len(self) -> usize {
        1 + self.pointer_len()
    }

    /// Data pointer plus config and type octets.
    pub const fn entry_len(self) -> usize {
        self.pointer_len() + 2
    }

    /// Apply the realization-specific invariant before storing a config
    /// octet. Reading deliberately preserves the raw byte.
    pub const fn encode_config(self, config: u8) -> u8 {
        match self {
            Self::Rt1 => config | RT1_FIXED_CONFIG_BIT,
            Self::Rt2 | Self::System7 => config,
        }
    }

    /// Resolve a descriptor's value pointer according to this format.
    ///
    /// RT1 and RT2 carry only the low address octet; config bit 5 selects
    /// segment `0000h` or `0100h`. System 7 already stores a complete 16-bit
    /// pointer and has no specified segment-selector bit.
    pub const fn value_address(self, data_pointer: u16, config: u8) -> u16 {
        match self {
            Self::Rt1 | Self::Rt2 if config & LEGACY_SEGMENT_SELECTOR != 0 => data_pointer | 0x0100,
            Self::Rt1 | Self::Rt2 | Self::System7 => data_pointer,
        }
    }
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
#[derive(Debug, Clone, Copy)]
pub struct BcuComObjectTableView<'a> {
    data: &'a [u8],
    format: BcuComObjectTableFormat,
}

impl<'a> BcuComObjectTableView<'a> {
    /// Borrow an encoded table in the selected realization or profile format.
    pub const fn new(data: &'a [u8], format: BcuComObjectTableFormat) -> Self {
        Self { data, format }
    }

    /// Return the complete encoded bytes supplied to this view.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Return the selected coding.
    pub const fn format(&self) -> BcuComObjectTableFormat {
        self.format
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
        let available = self.data.len().saturating_sub(self.format.header_len()) / self.format.entry_len();
        self.declared_entry_count().min(available.min(usize::from(u8::MAX)) as u16)
    }

    /// Decode the RAM-flags pointer from the complete header.
    pub fn ram_flags_ptr(&self) -> Option<u16> {
        let pointer = self.data.get(1..self.format.header_len())?;
        match self.format {
            BcuComObjectTableFormat::Rt1 | BcuComObjectTableFormat::Rt2 => pointer.first().copied().map(u16::from),
            BcuComObjectTableFormat::System7 => {
                let bytes: [u8; 2] = pointer.try_into().ok()?;
                Some(u16::from_be_bytes(bytes))
            }
        }
    }

    /// Return a row by its zero-based ASAP.
    pub fn entry(&self, asap: u16) -> Option<BcuComObjectTableEntry> {
        let offset = self.entry_offset(asap)?;
        let pointer_len = self.format.pointer_len();
        let data_ptr = match self.format {
            BcuComObjectTableFormat::Rt1 | BcuComObjectTableFormat::Rt2 => u16::from(*self.data.get(offset)?),
            BcuComObjectTableFormat::System7 => {
                let bytes: [u8; 2] = self.data.get(offset..offset + pointer_len)?.try_into().ok()?;
                u16::from_be_bytes(bytes)
            }
        };

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
        self.entry_offset(asap)?.checked_add(self.format.pointer_len())
    }

    fn entry_offset(&self, asap: u16) -> Option<usize> {
        if asap >= self.entry_count() {
            return None;
        }
        Some(self.format.header_len() + usize::from(asap) * self.format.entry_len())
    }
}

/// Mutable counterpart to [`BcuComObjectTableView`].
///
/// Mutations preserve both pointer fields and refuse rows beyond either the
/// stored count or the borrowed slice.
#[derive(Debug)]
pub struct BcuComObjectTableViewMut<'a> {
    data: &'a mut [u8],
    format: BcuComObjectTableFormat,
}

impl<'a> BcuComObjectTableViewMut<'a> {
    /// Mutably borrow an encoded table in the selected format.
    pub fn new(data: &'a mut [u8], format: BcuComObjectTableFormat) -> Self {
        Self { data, format }
    }

    /// Borrow the same bytes as a read-only view.
    pub fn as_view(&self) -> BcuComObjectTableView<'_> {
        BcuComObjectTableView::new(self.data, self.format)
    }

    /// Replace one row's config octet, enforcing RT1's fixed bit 7.
    pub fn set_config(&mut self, asap: u16, config: u8) -> bool {
        let Some(offset) = self.as_view().config_offset(asap) else {
            return false;
        };
        self.data[offset] = self.format.encode_config(config);
        true
    }

    /// Replace one row's config and type octets, preserving its data pointer.
    pub fn set_config_and_type(&mut self, asap: u16, config: u8, object_type: u8) -> bool {
        let Some(config_offset) = self.as_view().config_offset(asap) else {
            return false;
        };
        self.data[config_offset] = self.format.encode_config(config);
        self.data[config_offset + 1] = object_type;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rt1_and_rt2_decode_one_octet_pointers() {
        let data = [2, 0xD0, 0xC6, 0x9F, 0, 0xC7, 0x4C, 3];

        for format in [BcuComObjectTableFormat::Rt1, BcuComObjectTableFormat::Rt2] {
            let table = BcuComObjectTableView::new(&data, format);
            assert_eq!(table.stored_count(), Some(2));
            assert_eq!(table.entry_count(), 2);
            assert_eq!(table.ram_flags_ptr(), Some(0x00D0));
            assert_eq!(table.entry(1), Some(BcuComObjectTableEntry { data_ptr: 0x00C7, config: 0x4C, object_type: 3 }));
            assert_eq!(table.entry(2), None);
        }
    }

    #[test]
    fn legacy_bit_5_selects_the_value_segment() {
        for format in [BcuComObjectTableFormat::Rt1, BcuComObjectTableFormat::Rt2] {
            assert_eq!(format.value_address(0x00C6, 0xDF), 0x00C6);
            assert_eq!(format.value_address(0x00C6, 0xFF), 0x01C6);
        }

        assert_eq!(BcuComObjectTableFormat::System7.value_address(0x42C6, 0xFF), 0x42C6);
    }

    #[test]
    fn system7_decodes_big_endian_wide_pointers() {
        let data = [1, 0x12, 0x34, 0xAB, 0xCD, 0x47, 3];
        let table = BcuComObjectTableView::new(&data, BcuComObjectTableFormat::System7);

        assert_eq!(table.ram_flags_ptr(), Some(0x1234));
        assert_eq!(table.entry(0), Some(BcuComObjectTableEntry { data_ptr: 0xABCD, config: 0x47, object_type: 3 }));
    }

    #[test]
    fn downloaded_count_is_clamped_to_complete_rows() {
        let table = BcuComObjectTableView::new(&[u8::MAX, 0xD0, 0xC6, 0x9F, 0, 0xC7], BcuComObjectTableFormat::Rt2);

        assert_eq!(table.declared_entry_count(), u16::from(u8::MAX));
        assert_eq!(table.entry_count(), 1);
        assert_eq!(table.entry(0).map(|entry| entry.data_ptr), Some(0xC6));
        assert_eq!(table.entry(1), None);
    }

    #[test]
    fn truncated_headers_are_safe() {
        let rt2 = BcuComObjectTableView::new(&[1], BcuComObjectTableFormat::Rt2);
        let system7 = BcuComObjectTableView::new(&[1, 0x12], BcuComObjectTableFormat::System7);

        assert_eq!(rt2.ram_flags_ptr(), None);
        assert_eq!(rt2.entry_count(), 0);
        assert_eq!(system7.ram_flags_ptr(), None);
        assert_eq!(system7.entry_count(), 0);
    }

    #[test]
    fn mutation_preserves_pointers_and_applies_rt1_bit_7() {
        let mut rt1 = [1, 0xD0, 0xC6, 0x00, 0x03];
        let mut table = BcuComObjectTableViewMut::new(&mut rt1, BcuComObjectTableFormat::Rt1);
        assert!(table.set_config_and_type(0, 0x43, 0));
        assert_eq!(rt1, [1, 0xD0, 0xC6, 0xC3, 0]);

        let mut rt2 = [1, 0xD0, 0xC6, 0x80, 0x03];
        let mut table = BcuComObjectTableViewMut::new(&mut rt2, BcuComObjectTableFormat::Rt2);
        assert!(table.set_config(0, 0x43));
        assert_eq!(rt2, [1, 0xD0, 0xC6, 0x43, 0x03]);
    }
}
