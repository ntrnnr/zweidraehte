//! A resolved table codec returns bytes, owned bits and the encoded row count.
//! The image pipeline neither selects mask functions nor interprets wire headers.

mod address;
mod association;
mod objects;

pub(crate) use address::AddressTable;
pub(crate) use association::AssociationTable;
pub(crate) use objects::ObjectTable;
#[cfg(test)]
pub(crate) use objects::{NativeObjectFormat, NativeObjectTable};

use super::CompiledTableKind;
use crate::commissioning::catalog::profile::ResourceFlavour;
use crate::commissioning::error::{CompileError, OverflowedTable};
use crate::configuration::MaterializedDevice;
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::com_object::ComObjectFlags;

pub(super) struct TableInput<'a> {
    pub product: &'a ProductData,
    pub device: &'a MaterializedDevice,
    pub groups: Vec<GroupAddress>,
    pub load_parameters: bool,
}

impl<'a> TableInput<'a> {
    pub fn new(product: &'a ProductData, device: &'a MaterializedDevice) -> Self {
        let mut groups: Vec<_> = device.object_memberships().iter().map(|link| link.group_address).collect();
        groups.sort_unstable();
        groups.dedup();
        Self { product, device, groups, load_parameters: true }
    }

    /// Active objects as their table rows encode them.
    ///
    /// An active object's communication-enable bit is cleared while no group
    /// address is linked to it. Measured on System B (LightSwitch2
    /// 0301: `0x47` to `0x43`), BCU2 (M-00EE_A-4301: `0x37` to `0x33`, one row
    /// per unlinked object at every link count) and BCU1 (M-0048_A-105A:
    /// `0xC7` to `0xC3`). The configured flag is kept for linked objects.
    pub fn linked_objects(&self) -> Vec<ComObjectDef> {
        let linked: std::collections::BTreeSet<u16> =
            self.device.object_memberships().iter().map(|link| link.com_object).collect();
        self.device
            .com_objects()
            .iter()
            .map(|object| {
                let mut object = object.clone();
                if !linked.contains(&object.number) {
                    object.flags = ComObjectFlags::from_byte(object.flags.to_byte() & !ComObjectFlags::CE_FLAG_MASK);
                }
                object
            })
            .collect()
    }

    pub fn active_numbers(&self) -> Vec<u16> {
        self.device.com_objects().iter().map(|object| object.number).collect()
    }

    pub fn associations(&self) -> Result<Vec<(u16, u16)>, CompileError> {
        self.device
            .object_memberships()
            .iter()
            .map(|link| {
                let index =
                    self.groups.binary_search(&link.group_address).expect("links supplied the sorted addresses");
                Ok((
                    u16::try_from(index + 1).map_err(|_| {
                        CompileError::table_overflow(
                            OverflowedTable::Association,
                            "association table exceeds its declared table capacity",
                        )
                    })?,
                    link.com_object,
                ))
            })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct EncodedTable {
    pub data: Vec<u8>,
    pub mask: Vec<u8>,
    /// Logical entries after normalization; excludes a legacy individual address.
    pub entries: usize,
}

pub(super) struct TableSeed {
    pub data: Vec<u8>,
    /// Current ownership, retained by property-table overlays which update
    /// flags without replacing parameter-authored descriptor bytes.
    pub mask: Vec<u8>,
    pub first_byte_owned: bool,
}

impl EncodedTable {
    fn owned(data: Vec<u8>, entries: usize) -> Self {
        Self { mask: vec![u8::MAX; data.len()], data, entries }
    }
}

/// Closed, statically dispatched formats selected from exact resource declarations.
pub(super) enum TableCodec {
    Addresses(AddressTable),
    Associations(AssociationTable),
    Objects(ObjectTable),
}

impl TableCodec {
    pub fn new(kind: CompiledTableKind, flavour: ResourceFlavour) -> Result<Self, CompileError> {
        Ok(match kind {
            CompiledTableKind::GroupAddress => Self::Addresses(AddressTable::from_flavour(flavour)?),
            CompiledTableKind::Association => Self::Associations(AssociationTable::from_flavour(flavour)?),
            CompiledTableKind::GroupObject => Self::Objects(ObjectTable::from_flavour(flavour)?),
        })
    }

    /// Fixed header storage a legacy object formatter must be able to read.
    /// Other table kinds and descriptor arrays do not use this seed contract.
    pub(super) fn legacy_object_header_len(flavour: ResourceFlavour) -> Option<u32> {
        match ObjectTable::from_flavour(flavour).ok()? {
            ObjectTable::Native(codec) => Some(codec.header_len() as u32),
            _ => None,
        }
    }

    /// Bytes the product reserves for `max_entries` rows, if the format has rows.
    pub fn capacity(&self, max_entries: u32) -> Result<Option<u64>, CompileError> {
        Ok(match self {
            Self::Addresses(codec) => Some(codec.capacity(max_entries)),
            Self::Associations(codec) => Some(codec.capacity(max_entries)?),
            Self::Objects(_) => None,
        })
    }

    /// The `(offset, length)` of a legacy individual address inside the
    /// table, which address assignment rather than the table owns.
    pub fn individual_address_slot(&self) -> Option<(u32, u32)> {
        match self {
            Self::Addresses(AddressTable::WithIndividualAddress) => Some((1, 2)),
            _ => None,
        }
    }

    pub fn encode(
        &self,
        input: &TableInput<'_>,
        seed: impl FnOnce() -> Result<TableSeed, CompileError>,
    ) -> Result<EncodedTable, CompileError> {
        match self {
            Self::Addresses(codec) => codec.encode(input.device.individual_address(), &input.groups),
            // Indexed formats reserve one slot per roster object; the roster
            // contains the active objects (see `ObjectTable`).
            Self::Associations(codec) => codec.encode(&input.associations()?, &input.active_numbers()),
            // TODO: confirm the unlinked-object rule for System 300 before
            // changing the configured bit in its DPT rows.
            Self::Objects(codec @ ObjectTable::DptProperties) => {
                let mut encoded = codec.encode(input.product, input.device.com_objects(), seed)?;
                if input.load_parameters {
                    // Native LoadApplicationProgram includes parameter loading.
                    // Fill only wholly unowned bytes; partially owned parameter
                    // bytes retain their existing value and mask.
                    for (data, mask) in encoded.data.iter_mut().zip(&mut encoded.mask) {
                        if *mask == 0 {
                            *data = 0;
                            *mask = u8::MAX;
                        }
                    }
                }
                Ok(encoded)
            }
            Self::Objects(codec) => codec.encode(input.product, &input.linked_objects(), seed),
        }
    }
}

fn unsupported(table: &str, flavour: ResourceFlavour) -> CompileError {
    CompileError::unsupported(format!(
        "{table} table cannot use resource flavour {flavour:?}",
        flavour = flavour.to_string()
    ))
}

/// Encodes a table's entry count. `overflowed` identifies the table for a
/// count that its header cannot hold; `None` marks a count that cannot
/// exceed the header by construction.
fn count_prefix(
    count: usize,
    wide: bool,
    table: &'static str,
    overflowed: Option<OverflowedTable>,
) -> Result<Vec<u8>, CompileError> {
    let overflow = || {
        let message = format!("{table} exceeds its declared table capacity");
        match overflowed {
            Some(overflowed) => CompileError::table_overflow(overflowed, message),
            None => CompileError::invalid(message),
        }
    };
    if wide {
        let count = u16::try_from(count).map_err(|_| overflow())?;
        Ok(count.to_be_bytes().to_vec())
    } else {
        let count = u8::try_from(count).map_err(|_| overflow())?;
        Ok(vec![count])
    }
}

#[cfg(test)]
mod tests;
