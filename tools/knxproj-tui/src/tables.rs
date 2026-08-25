//! The memory tab's view over the download engine's table codings.
//!
//! The three management tables are displayed *in place*, inside the
//! segments a product's defaults occupy (BCU1, BCU2, System 7) or as
//! synthetic segments (System B). Byte layouts and count semantics
//! come from `zweidraehte_client::download`'s
//! [`TableCoding`] declarations — the same code the download compiler
//! writes real devices with — so the viewer cannot drift from the
//! wire formats. This module picks the per-mask formats, describes
//! their layout for annotations, and does the in-place work of
//! splicing the configured entries over a segment's default bytes.

use zweidraehte_client::download::{
    Addr1, Addr2, Addr7, Addr8, Asso1, Asso2, Asso6, Co7, Cot1, Cot2, System7AssociationTableCoding,
    System7ComObjectTableCoding, TableCoding,
};
use zweidraehte_client::{ComObjectFlags, ComObjectType, GroupAddress, IndividualAddress};

/// Which family's table wire formats a product uses. Fixed per mask
/// family, so the product's own `MaskVersion` decides — no master
/// data needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFormats {
    /// System 1 / BCU1 (masks 0010h–0013h and the PL110 siblings
    /// 1012h/1013h): RT1 tables — RT2's layouts with the group object
    /// table's config bit 7 fixed at 1.
    Bcu1,
    /// System 2 / BCU2 (masks 0020h, 0021h, 0025h): RT2 tables.
    Bcu2,
    /// System 7 (07x1..07x5 masks): compact one-octet linking tables
    /// and the profile-specific group object table.
    System7,
    /// System B (x7B0 masks) — also the fallback for families whose
    /// tables we cannot display natively (couplers).
    SystemB,
}

/// One table's layout facts, lifted from a [`TableCoding`] impl: what
/// an annotator or in-place patcher needs to find count, header and
/// entries.
pub struct TableShape {
    pub count_len: usize,
    /// Named fixed-header fields between count and entries, in wire
    /// order. These octets are the device's (IA, RAM-flags pointer),
    /// never the configuration's.
    pub header_fields: &'static [(&'static str, usize)],
    pub header_len: usize,
    pub entry_len: usize,
}

impl TableShape {
    fn of<C: TableCoding>() -> Self {
        Self {
            count_len: C::COUNT.len(),
            header_fields: C::HEADER_FIELDS,
            header_len: C::HEADER_LEN,
            entry_len: C::ENTRY_LEN,
        }
    }

    /// Offset of the first entry, relative to the table start.
    pub fn entries_base(&self) -> usize {
        self.count_len + self.header_len
    }
}

impl TableFormats {
    pub fn for_mask(mask_version: &str) -> Self {
        match mask_version {
            "MV-0010" | "MV-0011" | "MV-0012" | "MV-0013" | "MV-1012" | "MV-1013" => Self::Bcu1,
            "MV-0020" | "MV-0021" | "MV-0025" => Self::Bcu2,
            // System 7 masks are 07xxh with the System B TP1 mask
            // 07B0h carved out (its RF/IP siblings 27B0h/57B0h do not
            // start with 07 in the first place).
            mv if mv.starts_with("MV-07") && !mv.ends_with("B0") => Self::System7,
            _ => Self::SystemB,
        }
    }

    pub fn adt_shape(self) -> TableShape {
        match self {
            Self::Bcu1 => TableShape::of::<Addr1>(),
            Self::Bcu2 => TableShape::of::<Addr2>(),
            Self::System7 => TableShape::of::<Addr8>(),
            Self::SystemB => TableShape::of::<Addr7>(),
        }
    }

    /// `small_entries` selects the System B small association format
    /// (one-octet identifiers behind a two-octet count); the one-octet
    /// families ignore it.
    pub fn ast_shape(self, small_entries: bool) -> TableShape {
        match self {
            Self::Bcu1 => TableShape::of::<Asso1>(),
            Self::Bcu2 => TableShape::of::<Asso2>(),
            Self::System7 => TableShape::of::<System7AssociationTableCoding>(),
            Self::SystemB if small_entries => {
                // `AssociationTable_SystemBSmall` has no download
                // coding yet — describe its shape literally.
                TableShape { count_len: 2, header_fields: &[], header_len: 0, entry_len: 2 }
            }
            Self::SystemB => TableShape::of::<Asso6>(),
        }
    }

    pub fn cot_shape(self) -> TableShape {
        match self {
            Self::Bcu1 => TableShape::of::<Cot1>(),
            Self::Bcu2 => TableShape::of::<Cot2>(),
            Self::System7 => TableShape::of::<System7ComObjectTableCoding>(),
            Self::SystemB => TableShape::of::<Co7>(),
        }
    }

    /// First ASAP the family's group object table can express: RT7
    /// numbers objects from 1 (its table cannot hold ASAP 0), the
    /// absolute-table families from 0.
    pub fn cot_first_asap(self) -> u16 {
        match self {
            Self::SystemB => 1,
            Self::Bcu1 | Self::Bcu2 | Self::System7 => 0,
        }
    }

    /// The configured group address table, assembled by the family's
    /// coding — count semantics included (BCU2's length octet counts
    /// the IA slot). `None` when the coding refuses: more addresses
    /// than the count field carries. Input must be sorted ascending.
    pub fn adt_blob(self, group_addresses: &[u16]) -> Option<Vec<u8>> {
        let gas: Vec<GroupAddress> = group_addresses.iter().map(|&raw| GroupAddress(raw.to_be_bytes())).collect();
        // The IA header octets are never spliced into a display —
        // they stay the device's — so a placeholder does.
        let ia = IndividualAddress::new(0, 0, 0);
        match self {
            Self::Bcu1 => Addr1 { individual_address: ia }.blob(&gas).ok(),
            Self::Bcu2 => Addr2 { individual_address: ia }.blob(&gas).ok(),
            Self::System7 => Addr8 { individual_address: ia }.blob(&gas).ok(),
            Self::SystemB => Addr7.blob(&gas).ok(),
        }
    }

    /// The configured association table as `(tsap, asap)` pairs.
    /// `None` when an identifier does not fit the family's octet
    /// width, or for the small System B format (synthesized, never
    /// spliced).
    pub fn ast_blob(self, entries: &[(u16, u16)], small_entries: bool) -> Option<Vec<u8>> {
        match self {
            Self::Bcu1 | Self::Bcu2 | Self::System7 => {
                let narrowed: Option<Vec<(u8, u8)>> = entries
                    .iter()
                    .map(|&(tsap, asap)| Some((u8::try_from(tsap).ok()?, u8::try_from(asap).ok()?)))
                    .collect();
                match self {
                    Self::Bcu1 => Asso1.blob(&narrowed?).ok(),
                    Self::Bcu2 => Asso2.blob(&narrowed?).ok(),
                    Self::System7 => System7AssociationTableCoding.blob(&narrowed?).ok(),
                    Self::SystemB => unreachable!("handled by the outer match"),
                }
            }
            Self::SystemB if small_entries => None,
            Self::SystemB => Asso6.blob(entries).ok(),
        }
    }
}

/// Splice a coding-assembled blob over a segment's default bytes at
/// `base`: the count field and the entries are the installation's,
/// the header octets between them (IA, RAM-flags pointer) keep their
/// default values — the same split an ETS download honours via the
/// segment `Mask`. `max_entries` clamps the entry region to the
/// table's declared capacity so an oversized configuration cannot
/// bleed past it (e.g. into the MCB checksum octet trailing BCU2
/// tables); segment bounds clamp the rest.
pub fn splice_count_and_entries(
    data: &mut [u8],
    base: usize,
    shape: &TableShape,
    blob: &[u8],
    max_entries: Option<u16>,
) {
    copy_clamped(data, base, &blob[..shape.count_len.min(blob.len())]);

    let entries_base = shape.entries_base();
    let Some(mut entries) = blob.get(entries_base..) else { return };
    if let Some(max) = max_entries {
        entries = &entries[..entries.len().min(max as usize * shape.entry_len)];
    }
    copy_clamped(data, base + entries_base, entries);
}

fn copy_clamped(data: &mut [u8], at: usize, src: &[u8]) {
    let Some(room) = data.len().checked_sub(at) else { return };
    let len = src.len().min(room);
    data[at..at + len].copy_from_slice(&src[..len]);
}

/// Overlay the effective per-object `(number, flags, type)` octets
/// onto a group object table living in a real segment's default
/// bytes, preserving the vendor's count and firmware pointers — the
/// exact operation an ETS download performs on these families. Rows
/// the vendor table cannot hold are skipped (overlaid one by one so a
/// stray number does not abort the rest). No-op for System B, whose
/// table never lives inside a product segment.
pub fn overlay_cot(format: TableFormats, data: &mut [u8], base: usize, rows: &[(u16, u8, u8)]) {
    let Some(table) = data.get_mut(base..) else { return };
    if format == TableFormats::SystemB {
        return;
    }

    // The typed overlay first resets the complete declared roster and then
    // applies the effective rows, so it must see the batch as one operation.
    // Calling it once per row would make every later row deactivate the rows
    // already displayed. The memory pane only has the effective roster; use
    // it for both inputs and discard out-of-range rows as this best-effort
    // view historically did.
    let count = table.first().copied().unwrap_or(0) as u16;
    let rows: Vec<_> = rows
        .iter()
        .filter(|(number, _, _)| *number < count)
        .map(|&(number, flags, object_type)| {
            (number, ComObjectFlags::from_byte(flags), ComObjectType::from(object_type))
        })
        .collect();
    let _ = match format {
        TableFormats::Bcu1 => Cot1::overlay(table, &rows, &rows),
        TableFormats::Bcu2 => Cot2::overlay(table, &rows, &rows),
        TableFormats::System7 => System7ComObjectTableCoding::overlay(table, &rows, &rows),
        TableFormats::SystemB => unreachable!("handled above"),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_selects_the_family() {
        assert_eq!(TableFormats::for_mask("MV-0021"), TableFormats::Bcu2);
        assert_eq!(TableFormats::for_mask("MV-0705"), TableFormats::System7);
        assert_eq!(TableFormats::for_mask("MV-07B0"), TableFormats::SystemB);
        assert_eq!(TableFormats::for_mask("MV-57B0"), TableFormats::SystemB);
        assert_eq!(TableFormats::for_mask("MV-0012"), TableFormats::Bcu1);
        assert_eq!(TableFormats::for_mask("MV-1012"), TableFormats::Bcu1);
    }

    /// The scenario the L&J MV-0021 product exposed: its `AS-0116`
    /// factory image is `57 | 00 00 | 40 00 40 01 …` (length 86+1, IA
    /// placeholder, default links to 8/0/n). Assigning 0/0/1 and
    /// 0/0/2 must rewrite the length and the first two entries, leave
    /// the IA octets alone, and leave the remaining factory entries
    /// (masked out by the new length) in place.
    #[test]
    fn splice_replaces_count_and_entries_but_not_the_ia() {
        let format = TableFormats::Bcu2;
        let mut segment = vec![0x57, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x40, 0x02];

        let blob = format.adt_blob(&[0x0001, 0x0002]).expect("two addresses fit");
        splice_count_and_entries(&mut segment, 0, &format.adt_shape(), &blob, Some(86));

        assert_eq!(segment, [0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x40, 0x02]);
    }

    #[test]
    fn splice_clamps_to_capacity_and_segment_end() {
        let format = TableFormats::Bcu2;
        let shape = format.adt_shape();

        // Capacity 1: the second address must not reach the segment
        // (here it would land on the trailing checksum octet).
        let mut segment = vec![0xFF; 6];
        let blob = format.adt_blob(&[0x0001, 0x0002]).expect("fits");
        splice_count_and_entries(&mut segment, 0, &shape, &blob, Some(1));
        assert_eq!(segment, [0x03, 0xFF, 0xFF, 0x00, 0x01, 0xFF]);

        // A segment shorter than the blob truncates instead of
        // panicking.
        let mut short = vec![0xFF; 4];
        splice_count_and_entries(&mut short, 0, &shape, &blob, None);
        assert_eq!(short, [0x03, 0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn bcu1_cot_overlay_forces_config_bit_7() {
        // Same vendor table as below, but through the RT1 coding the
        // overlaid config octet gains the fixed bit 7 (03/05/01
        // §4.18.3) even though the flags byte does not carry it.
        let mut segment = vec![0x02, 0xCE, 0xC6, 0x00, 0x00, 0xC7, 0x00, 0x00];
        overlay_cot(TableFormats::Bcu1, &mut segment, 0, &[(1, 0x47, 0x00)]);
        assert_eq!(segment, [0x02, 0xCE, 0xC6, 0x80, 0x00, 0xC7, 0xC7, 0x00]);
    }

    #[test]
    fn cot_overlay_skips_rows_the_vendor_table_lacks() {
        // BCU2 vendor table: 2 rows, RAM-flags ptr CEh, pointers C6/C7.
        let mut segment = vec![0x02, 0xCE, 0xC6, 0x00, 0x00, 0xC7, 0x00, 0x00];
        overlay_cot(TableFormats::Bcu2, &mut segment, 0, &[(1, 0x47, 0x00), (5, 0xFF, 0xFF)]);
        assert_eq!(segment, [0x02, 0xCE, 0xC6, 0x00, 0x00, 0xC7, 0x47, 0x00]);
    }
}
