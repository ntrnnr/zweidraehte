//! Table wire codings: one declarative description per realization
//! type, one assembly routine for all of them.
//!
//! Every KNX table blob a download writes has the same skeleton — a
//! count field, an optional fixed header, an entry list — and formats
//! differ only in the count's width, what the header holds, how an
//! entry is laid down, and who owns the entry order. [`TableCoding`]
//! captures exactly those four degrees of freedom, so adding a mask
//! family's table format is a short impl next to its format doc, not
//! another hand-rolled builder function.
//!
//! This is the write side of the split whose read side lives in the
//! device crate: each `TableMemory` impl there parses what one
//! `TableCoding` impl here emits, and both document the same layout.
//! The formats:
//!
//! | | BCU2 (RT2) | System 7 | System B |
//! |---|---|---|---|
//! | address table | `[len:1][IA:2][GA:2×(len-1)]` ([`Addr2`]) | same coding ([`Addr8`]) | `[count:2BE][GA:2×n]` ([`Addr7`]) |
//! | association table | `[count:1][(tsap:1,asap:1)×n]` ([`Asso2`]) | same bytes, compact first-match order ([`System7AssociationTableCoding`]) | `[count:2BE][(tsap:2BE,asap:2BE)×n]` ([`Asso6`]) |
//! | group object table | `[count:1][ram-ptr:1][(ptr:1,cfg:1,type:1)×n]` ([`Cot2`]) | `[count:1][ram-ptr:2][(ptr:2,cfg:1,type:1)×n]` ([`System7ComObjectTableCoding`]) | `[count:2BE][(flags:1,type:1)×n]` ([`Co7`]) |
//!
//! BCU2 and System 7 store the device's own individual address inside
//! the address table; System B does not. The two families' address
//! tables use the same byte coding, including a length that counts the IA
//! slot. See [`Addr1`] for the specification and ETS evidence.
//!
//! BCU1 (RT1) shares the RT2 column outright for the address and
//! association tables (the [`Addr1`] and [`Asso1`] names; 03/05/01
//! §4.16.3, §4.17.3); its group object table is [`Cot1`], the RT2
//! layout with the config octet's bit 7 fixed at 1 instead of
//! carrying UpdateEnable (03/05/01 §4.18.3).
//!
//! The framework covers count-prefixed entry-list tables only. A
//! format that is not one — the line couplers' filter table is a flat
//! group-address bitmap — gets its own builder when its family
//! arrives.

use std::borrow::Cow;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::tables::com_object::{BcuComObjectTableFormat, BcuComObjectTableViewMut};

use crate::error::{Error, Result};

// ============================================================================
// The coding contract
// ============================================================================

/// Width of a table's leading count field. Also the capacity limit:
/// what cannot be counted cannot be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountWidth {
    U8,
    U16,
}

impl CountWidth {
    /// The largest count this field can carry.
    pub fn max(self) -> usize {
        match self {
            Self::U8 => u8::MAX as usize,
            Self::U16 => u16::MAX as usize,
        }
    }

    /// Octets the field occupies.
    pub fn len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
        }
    }

    /// Decode a count from the start of a complete table blob.
    pub fn read(self, data: &[u8]) -> Option<usize> {
        match self {
            Self::U8 => data.first().copied().map(usize::from),
            Self::U16 => {
                data.get(..2).and_then(|bytes| <[u8; 2]>::try_from(bytes).ok()).map(u16::from_be_bytes).map(usize::from)
            }
        }
    }

    /// Serialize the count (big-endian for the two-octet form). The
    /// caller has range-checked `count` against [`max`](Self::max).
    fn write(self, count: usize, out: &mut Vec<u8>) {
        match self {
            Self::U8 => out.push(count as u8),
            Self::U16 => out.extend_from_slice(&(count as u16).to_be_bytes()),
        }
    }
}

/// One realization type's table coding.
///
/// An impl declares the format; the provided [`blob`](Self::blob) owns
/// the assembly, in wire order: count, header, entries. The hooks
/// exist for the ways real formats deviate from the plain skeleton —
/// each documents which format needs it.
pub trait TableCoding {
    /// The typed entry this table stores.
    type Entry: Clone;

    /// Octets per entry — preallocation only, never addressing.
    const ENTRY_LEN: usize;

    /// Octets of fixed header between count and entries —
    /// preallocation only.
    const HEADER_LEN: usize = 0;

    /// The named fields making up that header, `(label, octets)` in
    /// wire order, summing to [`HEADER_LEN`](Self::HEADER_LEN). For
    /// viewers that annotate a table in place — the download path
    /// never reads it.
    const HEADER_FIELDS: &'static [(&'static str, usize)] = &[];

    /// Width of the leading count field, which also caps the table.
    const COUNT: CountWidth;

    /// The error for a table that exceeds what [`COUNT`](Self::COUNT)
    /// can express. Per-format, so the message can name the table and
    /// its limit while staying a `&'static str` like every other
    /// `Error::DownloadConfig`.
    const OVERFLOW_MSG: &'static str;

    /// The value of the count field. Defaults to the entry count;
    /// this is a hook because BCU address tables count their IA slot
    /// too.
    fn count(&self, entries: &[Self::Entry]) -> usize {
        entries.len()
    }

    /// Fixed bytes between count and entries — the BCU address table's
    /// individual-address slot, System 7's RAM-flags pointer. Default: none.
    fn write_header(&self, _out: &mut Vec<u8>) {}

    /// Put the entries in wire order.
    ///
    /// The default keeps them as given, which is what the group object
    /// tables need: they are positionally indexed (the row index *is*
    /// the ASAP), so reordering would corrupt them. Association tables
    /// override with sort + dedup — their order is a pure wire
    /// requirement with no upstream meaning. Address tables override
    /// with a debug assertion instead of sorting, because their order
    /// is load-bearing *upstream*: association TSAPs are indices into
    /// the sorted address list, so the compile step must have sorted
    /// it before it could build the associations at all.
    fn normalize(entries: &[Self::Entry]) -> Cow<'_, [Self::Entry]> {
        Cow::Borrowed(entries)
    }

    /// Lay down one entry. An associated function, not a method:
    /// entry coding is format-determined, never instance-dependent.
    fn write_entry(entry: &Self::Entry, out: &mut Vec<u8>);

    /// Assemble the blob: normalize, then count, header, entries.
    ///
    /// The overflow check tests the count *as written* — computed
    /// after normalization (dedup may shrink it) and through the
    /// [`count`](Self::count) hook (BCU address tables count one more
    /// than the entries). Checking `entries.len()` instead would let a
    /// maximal table pass and then truncate its count octet to zero.
    fn blob(&self, entries: &[Self::Entry]) -> Result<Vec<u8>> {
        let entries = Self::normalize(entries);

        let count = self.count(&entries);
        if count > Self::COUNT.max() {
            return Err(Error::DownloadConfig(Self::OVERFLOW_MSG));
        }

        let mut out = Vec::with_capacity(Self::COUNT.len() + Self::HEADER_LEN + Self::ENTRY_LEN * entries.len());
        Self::COUNT.write(count, &mut out);
        self.write_header(&mut out);
        for entry in entries.iter() {
            Self::write_entry(entry, &mut out);
        }

        Ok(out)
    }
}

/// The shared normalize of the address tables: assert, don't sort.
/// See [`TableCoding::normalize`] for why the caller owns this order.
fn expect_sorted(group_addresses: &[GroupAddress]) -> Cow<'_, [GroupAddress]> {
    debug_assert!(
        group_addresses.windows(2).all(|w| w[0] < w[1]),
        "input must be sorted and deduplicated — association TSAPs index this order"
    );
    Cow::Borrowed(group_addresses)
}

// ============================================================================
// RT1 and its byte-identical realizations
// ============================================================================

/// The RT1 group address table coding (Resources §4.16.3).
///
/// ```text
/// [length:1][individual_address:2][group_address:2 × (length - 1)]
/// ```
///
/// Section 4.16.3.3.1 explicitly says the length counts the IA. RT2 uses
/// RT1 unchanged. RT8 repeats this byte layout at fixed address 4000h;
/// the KNX master data selects the same `AddressTable_Bcu1` formatter for
/// masks 0705 and 5705, and an observed 0705 ETS image with four GAs carries
/// length `05h`.
pub struct Addr1 {
    /// The device's own address, stored in TSAP slot 0 — the one place
    /// a BCU-family device keeps it.
    pub individual_address: IndividualAddress,
}

impl TableCoding for Addr1 {
    type Entry = GroupAddress;
    const ENTRY_LEN: usize = 2;
    const HEADER_LEN: usize = 2;
    const HEADER_FIELDS: &'static [(&'static str, usize)] = &[("individual address", 2)];
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "the BCU address table length octet holds at most 254 group addresses";

    fn count(&self, entries: &[GroupAddress]) -> usize {
        entries.len() + 1
    }

    fn write_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.individual_address.as_bytes());
    }

    fn normalize(entries: &[GroupAddress]) -> Cow<'_, [GroupAddress]> {
        expect_sorted(entries)
    }

    fn write_entry(ga: &GroupAddress, out: &mut Vec<u8>) {
        out.extend_from_slice(ga.as_bytes());
    }
}

// ============================================================================
// System 7 codings
// ============================================================================

/// RT8 uses the RT1 byte coding at fixed address 4000h.
pub type Addr8 = Addr1;

/// The RT8 association table (Resources §4.17.6):
///
/// ```text
/// [count:1][(tsap:1, asap:1) × count]
/// ```
///
/// TSAP is the 1-based index into the group address table (TSAP 0 is
/// the device's own IA), ASAP the group object number. The format's
/// one-octet fields cap both at 255. Section 4.17.6 specifies no
/// ordering or sending-association rule, so this coding preserves the
/// caller's row order.
pub struct Asso8;

impl TableCoding for Asso8 {
    type Entry = (u8, u8);
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "RT8 association table holds at most 255 associations";

    fn write_entry(&(tsap, asap): &(u8, u8), out: &mut Vec<u8>) {
        out.push(tsap);
        out.push(asap);
    }
}

/// The compact System 7 association-table coding used by mask 0705.
///
/// ETS names the formatter `AssociationTable_M112`; Profiles §4.5.2
/// does not assign 0705 to RT8 even though its rows have RT8's byte
/// shape. Unlike the indexed RT1/RT2 tables, only actual links are
/// stored, sorted by `(TSAP, ASAP)` and deduplicated. The device finds
/// a sending association by the first matching ASAP.
pub struct System7AssociationTableCoding;

impl TableCoding for System7AssociationTableCoding {
    type Entry = (u8, u8);
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "the System 7 association table holds at most 255 associations";

    fn normalize(entries: &[(u8, u8)]) -> Cow<'_, [(u8, u8)]> {
        let mut sorted = entries.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        Cow::Owned(sorted)
    }

    fn write_entry(&(tsap, asap): &(u8, u8), out: &mut Vec<u8>) {
        out.push(tsap);
        out.push(asap);
    }
}

/// One row of the System 7 group object table.
///
/// `config` is the flags octet and `object_type` the 0-based type
/// coding — raw octets, because a product database supplies them
/// verbatim. `data_ptr` points the real silicon's firmware at the
/// object value in RAM; devices built on our stack ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComObjectEntry {
    pub data_ptr: u16,
    pub config: u8,
    pub object_type: u8,
}

/// Patch installation-owned fields in a compact BCU group object table while
/// preserving its product-defined pointers.
fn overlay_bcu_com_object_table(
    defaults: &mut [u8],
    objects: &[(u16, ComObjectFlags, ComObjectType)],
    format: BcuComObjectTableFormat,
) -> Result<()> {
    if defaults.len() < format.header_len() {
        return Err(Error::ProductData(
            "the product's group object table data is shorter than its own header".to_string(),
        ));
    }

    let mut table = BcuComObjectTableViewMut::new(defaults, format);
    let count = table.as_view().declared_entry_count();
    for (number, flags, object_type) in objects {
        if *number >= count {
            return Err(Error::ProductData(format!(
                "object {number} lies outside the product's default group object table ({count} rows)"
            )));
        }
        if !table.set_config_and_type(*number, flags.to_byte(), (*object_type).into()) {
            return Err(Error::ProductData(format!(
                "the product's group object table data is truncated before object {number}"
            )));
        }
    }
    Ok(())
}

/// The System 7 group object table, pinned by an ETS download trace and
/// its `GroupObjectTable_M112` formatter (see the device crate's
/// `co_system7` module):
///
/// ```text
/// [count:1][ram_flags_ptr:2 BE][(data_ptr:2 BE, config:1, type:1) × count]
/// ```
///
/// `entries[n]` is the row for ASAP `n` — System 7 products number
/// group objects from 0, and the table covers `0..count` gaplessly,
/// so unused numbers get zeroed rows. Positionally indexed, hence no
/// normalization.
pub struct System7ComObjectTableCoding {
    pub ram_flags_ptr: u16,
}

impl System7ComObjectTableCoding {
    /// Overlay per-object `config`/`type` octets onto a
    /// product-supplied default table.
    ///
    /// A vendor product ships its System 7 table as segment data whose
    /// count, `ram_flags_ptr` and per-row `data_ptr`s point into the
    /// real firmware's RAM layout — values nothing but the product
    /// database knows, so the table cannot be synthesized the way our
    /// own devices' can. What *is* the installation's to decide are
    /// each object's config flags and value type, and those two
    /// octets are what this touches — a Falcon download trace
    /// (2026-08-13, `$4400`) shows ETS writing per-row config *and*
    /// type (`43 00`, `DB 03`, …) over the preserved pointers, the
    /// type in the standard coding (`00h` = 1 bit). Rows for objects
    /// not in `objects` keep their product defaults.
    pub fn overlay(defaults: &mut [u8], objects: &[(u16, ComObjectFlags, ComObjectType)]) -> Result<()> {
        overlay_bcu_com_object_table(defaults, objects, BcuComObjectTableFormat::System7)
    }
}

impl TableCoding for System7ComObjectTableCoding {
    type Entry = ComObjectEntry;
    const ENTRY_LEN: usize = 4;
    const HEADER_LEN: usize = 2;
    const HEADER_FIELDS: &'static [(&'static str, usize)] = &[("RAM-flags pointer", 2)];
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "the System 7 group object table holds at most 255 objects";

    fn write_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ram_flags_ptr.to_be_bytes());
    }

    fn write_entry(entry: &ComObjectEntry, out: &mut Vec<u8>) {
        out.extend_from_slice(&entry.data_ptr.to_be_bytes());
        out.push(entry.config);
        out.push(entry.object_type);
    }
}

// ============================================================================
// BCU2 (System 2, RT2) codings
// ============================================================================

/// RT2 uses the RT1 byte coding unchanged.
pub type Addr2 = Addr1;

/// The BCU2 association table (Realisation Type 2, 03/05/01 §4.17.4):
/// RT2's byte coding is RT8's — one-octet count, (tsap:1, asap:1)
/// entries — but its build rules make row order load-bearing. Callers
/// must put ASAP `n`'s sending association in row `n`.
pub struct Asso2;

impl TableCoding for Asso2 {
    type Entry = (u8, u8);
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "RT2 association table holds at most 255 associations";

    fn write_entry(&(tsap, asap): &(u8, u8), out: &mut Vec<u8>) {
        out.push(tsap);
        out.push(asap);
    }
}

/// One row of the BCU2 group object table — [`ComObjectEntry`] with
/// the pointer narrowed to the one octet the HC05's address space
/// affords (the value lives in page-0 RAM or the $100-based EEPROM
/// segment, selected by the config octet's SegmentSelector bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComObjectEntry2 {
    pub data_ptr: u8,
    pub config: u8,
    pub object_type: u8,
}

/// The BCU2 group object table (03/05/01 §4.18.4):
///
/// ```text
/// [count:1][ram_flags_ptr:1][(data_ptr:1, config:1, type:1) × count]
/// ```
///
/// The System 7 table's shape with every pointer one octet instead of
/// two. Positionally indexed from ASAP 0, hence no normalization.
/// One RT2 coding difference worth knowing when reading `config`
/// back: bit 7 is UpdateEnable, where RT1 fixes it at 1.
pub struct Cot2 {
    pub ram_flags_ptr: u8,
}

impl Cot2 {
    /// Overlay per-object `config`/`type` octets onto a
    /// product-supplied default table — same contract as
    /// [`System7ComObjectTableCoding::overlay`]: the count, RAM-flags pointer and per-row
    /// data pointers are the firmware's and survive untouched; only
    /// the two installation-owned octets per row change.
    pub fn overlay(defaults: &mut [u8], objects: &[(u16, ComObjectFlags, ComObjectType)]) -> Result<()> {
        overlay_bcu_com_object_table(defaults, objects, BcuComObjectTableFormat::Rt2)
    }
}

impl TableCoding for Cot2 {
    type Entry = ComObjectEntry2;
    const ENTRY_LEN: usize = 3;
    const HEADER_LEN: usize = 1;
    const HEADER_FIELDS: &'static [(&'static str, usize)] = &[("RAM-flags pointer", 1)];
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "the BCU2 group object table holds at most 255 objects";

    fn write_header(&self, out: &mut Vec<u8>) {
        out.push(self.ram_flags_ptr);
    }

    fn write_entry(entry: &ComObjectEntry2, out: &mut Vec<u8>) {
        out.push(entry.data_ptr);
        out.push(entry.config);
        out.push(entry.object_type);
    }
}

// ============================================================================
// BCU1 (System 1, RT1) codings
// ============================================================================

/// The BCU1 association table (Realisation Type 1, 03/05/01 §4.17.3):
/// the same one-octet-identifier coding RT2 and RT8 use. As with RT2,
/// callers must arrange the indexed sending-association rows before
/// encoding.
pub struct Asso1;

impl TableCoding for Asso1 {
    type Entry = (u8, u8);
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "RT1 association table holds at most 255 associations";

    fn write_entry(&(tsap, asap): &(u8, u8), out: &mut Vec<u8>) {
        out.push(tsap);
        out.push(asap);
    }
}

/// The BCU1 group object table (Realisation Type 1, 03/05/01
/// §4.18.3): [`Cot2`]'s layout with one semantic delta — the config
/// octet's bit 7 is a fixed 1, where RT2 reads it as UpdateEnable.
/// Assembly and overlay both force the bit, so a configuration
/// expressed in Table-87 flags cannot clear what the device expects
/// set.
pub struct Cot1 {
    pub ram_flags_ptr: u8,
}

impl Cot1 {
    /// Overlay per-object `config`/`type` octets onto a
    /// product-supplied default table — [`Cot2::overlay`]'s contract,
    /// with the config octet's bit 7 forced to 1 on the way in.
    pub fn overlay(defaults: &mut [u8], objects: &[(u16, ComObjectFlags, ComObjectType)]) -> Result<()> {
        overlay_bcu_com_object_table(defaults, objects, BcuComObjectTableFormat::Rt1)
    }
}

impl TableCoding for Cot1 {
    type Entry = ComObjectEntry2;
    const ENTRY_LEN: usize = 3;
    const HEADER_LEN: usize = 1;
    const HEADER_FIELDS: &'static [(&'static str, usize)] = &[("RAM-flags pointer", 1)];
    const COUNT: CountWidth = CountWidth::U8;
    const OVERFLOW_MSG: &'static str = "the BCU1 group object table holds at most 255 objects";

    fn write_header(&self, out: &mut Vec<u8>) {
        out.push(self.ram_flags_ptr);
    }

    fn write_entry(entry: &ComObjectEntry2, out: &mut Vec<u8>) {
        out.push(entry.data_ptr);
        out.push(BcuComObjectTableFormat::Rt1.encode_config(entry.config));
        out.push(entry.object_type);
    }
}

// ============================================================================
// System B codings
// ============================================================================

/// The System B group address table (Realisation Type 7):
///
/// ```text
/// [count:2BE][group_address:2 × count]
/// ```
///
/// Unlike RT8 there is no individual-address slot — a System B device
/// keeps its own address elsewhere — and the count is two octets, so
/// the table is not capped at 255 entries.
pub struct Addr7;

impl TableCoding for Addr7 {
    type Entry = GroupAddress;
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U16;
    const OVERFLOW_MSG: &'static str = "address table exceeds the 16-bit entry count";

    fn normalize(entries: &[GroupAddress]) -> Cow<'_, [GroupAddress]> {
        expect_sorted(entries)
    }

    fn write_entry(ga: &GroupAddress, out: &mut Vec<u8>) {
        out.extend_from_slice(ga.as_bytes());
    }
}

/// The System B association table (`AssociationTable_SystemBBig`):
///
/// ```text
/// [count:2BE][(tsap:2BE, asap:2BE) × count]
/// ```
///
/// Both identifiers are 16-bit here, so neither the address table nor
/// the group object table is limited to 255 entries the way RT8 is.
pub struct Asso6;

impl TableCoding for Asso6 {
    type Entry = (u16, u16);
    const ENTRY_LEN: usize = 4;
    const COUNT: CountWidth = CountWidth::U16;
    const OVERFLOW_MSG: &'static str = "association table exceeds the 16-bit entry count";

    fn normalize(entries: &[(u16, u16)]) -> Cow<'_, [(u16, u16)]> {
        let mut sorted = entries.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        Cow::Owned(sorted)
    }

    fn write_entry(&(tsap, asap): &(u16, u16), out: &mut Vec<u8>) {
        out.extend_from_slice(&tsap.to_be_bytes());
        out.extend_from_slice(&asap.to_be_bytes());
    }
}

/// The System B group object table (Realisation Type 7):
///
/// ```text
/// [count:2BE][(flags:1, type:1) × count]
/// ```
///
/// Each entry is the big-endian 16-bit Group Object Descriptor of
/// Table 87 — the proto types carry it typed, and the octet packing
/// happens here. Entries are 1-based (ASAP 1 is the first), which is
/// why `entries[0]` describes object 1 — the opposite of the System 7
/// table, where ASAPs start at 0. Positionally indexed, hence no
/// normalization.
pub struct Co7;

impl TableCoding for Co7 {
    type Entry = (ComObjectFlags, ComObjectType);
    const ENTRY_LEN: usize = 2;
    const COUNT: CountWidth = CountWidth::U16;
    const OVERFLOW_MSG: &'static str = "group object table exceeds the 16-bit entry count";

    fn write_entry(&(flags, object_type): &(ComObjectFlags, ComObjectType), out: &mut Vec<u8>) {
        out.push(flags.to_byte());
        out.push(object_type.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ga(main: u8, middle: u8, sub: u8) -> GroupAddress {
        GroupAddress::from_three_level(main, middle, sub)
    }

    #[test]
    fn addr8_blob_matches_device_layout() {
        // Mirrors the device crate's addr8 loaded_table fixture:
        // length 4, IA 1.0.1, GAs 0/0/1 0/0/2 0/0/4.
        let blob = Addr8 { individual_address: IndividualAddress::new(1, 0, 1) }
            .blob(&[ga(0, 0, 1), ga(0, 0, 2), ga(0, 0, 4)])
            .expect("3 entries fit");
        assert_eq!(blob, [4, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04]);
    }

    #[test]
    fn asso8_blob_preserves_unspecified_row_order() {
        let blob = Asso8.blob(&[(2, 5), (1, 3), (2, 4), (1, 3)]).expect("fits");
        assert_eq!(blob, [4, 2, 5, 1, 3, 2, 4, 1, 3]);
    }

    #[test]
    fn system7_association_blob_sorts_and_dedups() {
        let blob = System7AssociationTableCoding.blob(&[(2, 5), (1, 3), (2, 4), (1, 3)]).expect("fits");
        assert_eq!(blob, [3, 1, 3, 2, 4, 2, 5]);
    }

    #[test]
    fn cot_blob_matches_the_ets_trace() {
        // The exact bytes ETS wrote for the six-object light switch
        // (same fixture the device crate parses in co_system7.rs).
        let entries = [
            ComObjectEntry { data_ptr: 0, config: 0x00, object_type: 0x00 }, // ASAP 0 unused
            ComObjectEntry { data_ptr: 0, config: 0x47, object_type: 0x00 },
            ComObjectEntry { data_ptr: 0, config: 0xD7, object_type: 0x00 },
            ComObjectEntry { data_ptr: 0, config: 0x47, object_type: 0x03 },
            ComObjectEntry { data_ptr: 0, config: 0x43, object_type: 0x00 },
            ComObjectEntry { data_ptr: 0, config: 0xD3, object_type: 0x00 },
            ComObjectEntry { data_ptr: 0, config: 0x00, object_type: 0x00 }, // ASAP 6 unused
        ];
        let blob = System7ComObjectTableCoding { ram_flags_ptr: 0 }.blob(&entries).expect("fits");
        assert_eq!(blob, [
            0x07, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x47, 0x00, //
            0x00, 0x00, 0xD7, 0x00, //
            0x00, 0x00, 0x47, 0x03, //
            0x00, 0x00, 0x43, 0x00, //
            0x00, 0x00, 0xD3, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
        ]);
    }

    #[test]
    fn addr1_addr2_and_addr8_share_the_length_coding() {
        // The realization-facing names share the byte codec, while their
        // locations and load procedures remain profile decisions.
        let blob = Addr2 { individual_address: IndividualAddress::new(1, 0, 1) }
            .blob(&[ga(0, 0, 1), ga(0, 0, 2), ga(0, 0, 4)])
            .expect("3 entries fit");
        assert_eq!(blob, [4, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04]);
    }

    #[test]
    fn cot2_blob_and_overlay_use_one_octet_pointers() {
        let entries = [ComObjectEntry2 { data_ptr: 0xC6, config: 0x47, object_type: 0x00 }, ComObjectEntry2 {
            data_ptr: 0xC7,
            config: 0xD7,
            object_type: 0x03,
        }];
        let blob = Cot2 { ram_flags_ptr: 0xCE }.blob(&entries).expect("fits");
        assert_eq!(blob, [0x02, 0xCE, 0xC6, 0x47, 0x00, 0xC7, 0xD7, 0x03]);

        // Overlay patches config/type in place, preserving the
        // firmware's RAM-flags and data pointers.
        let mut defaults = blob.clone();
        Cot2::overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
            .expect("row 1 exists");
        assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0x47, 0x00, 0xC7, 0x43, 0x00]);

        // A row beyond the product's RT2 table is refused.
        assert!(Cot2::overlay(&mut defaults, &[(2, ComObjectFlags::from_byte(0), ComObjectType::Uint1)]).is_err());
    }

    #[test]
    fn compact_cot_overlay_rejects_a_physically_truncated_row() {
        // Count declares two System 7 rows, but only row 0 is physically
        // present. The declared range and the storage bound remain distinct.
        let mut defaults = [2, 0, 0, 0, 0, 0x47, 0];
        let error = System7ComObjectTableCoding::overlay(&mut defaults, &[(
            1,
            ComObjectFlags::from_byte(0x43),
            ComObjectType::Uint1,
        )])
        .expect_err("row 1 is truncated");

        assert!(error.to_string().contains("truncated before object 1"));
    }

    #[test]
    fn cot1_forces_config_bit_7() {
        // Same fixture as the Cot2 test, but the RT1 coding must set
        // bit 7 of every config octet regardless of what the flags
        // carry (03/05/01 §4.18.3 fixes it at 1).
        let entries = [ComObjectEntry2 { data_ptr: 0xC6, config: 0x47, object_type: 0x00 }, ComObjectEntry2 {
            data_ptr: 0xC7,
            config: 0xD7,
            object_type: 0x03,
        }];
        let blob = Cot1 { ram_flags_ptr: 0xCE }.blob(&entries).expect("fits");
        assert_eq!(blob, [0x02, 0xCE, 0xC6, 0xC7, 0x00, 0xC7, 0xD7, 0x03]);

        let mut defaults = blob.clone();
        Cot1::overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
            .expect("row 1 exists");
        assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0xC7, 0x00, 0xC7, 0xC3, 0x00]);
    }

    #[test]
    fn system_b_blobs_use_two_octet_counts() {
        // RT7 address table: no IA slot, 16-bit count.
        let adt = Addr7.blob(&[ga(0, 0, 1), ga(0, 0, 2)]).expect("fits");
        assert_eq!(adt, [0x00, 0x02, 0x00, 0x01, 0x00, 0x02]);

        // SystemBBig associations: 16-bit TSAP and ASAP.
        let ast = Asso6.blob(&[(2, 5), (1, 3)]).expect("fits");
        assert_eq!(ast, [0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x05]);

        // RT7 group objects: flags octet then type octet, 1-based.
        let cot = Co7
            .blob(&[
                (ComObjectFlags::from_byte(0x47), ComObjectType::Uint1),
                (ComObjectFlags::from_byte(0xD7), ComObjectType::Uint4),
            ])
            .expect("fits");
        assert_eq!(cot, [0x00, 0x02, 0x47, 0x00, 0xD7, 0x03]);
    }

    #[test]
    fn overflow_is_checked_on_the_written_count() {
        // 256 distinct associations overflow the one-octet count...
        let too_many: Vec<(u8, u8)> = (0..=255u8).map(|n| (n, n)).collect();
        assert!(System7AssociationTableCoding.blob(&too_many).is_err());

        // ...but duplicates that dedup away below the cap do not: the
        // check tests the count as written, not the input length.
        let mut with_duplicates = too_many.clone();
        with_duplicates.truncate(255);
        with_duplicates.push((0, 0));
        assert_eq!(with_duplicates.len(), 256);
        let blob = System7AssociationTableCoding.blob(&with_duplicates).expect("255 after dedup fits");
        assert_eq!(blob[0], 255);
    }
}
