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
use crate::commissioning::error::CompileError;
use crate::configuration::LoweredDeviceConfiguration;
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::com_object::ComObjectFlags;

pub(super) struct TableInput<'a> {
    pub product: &'a ProductData,
    pub configuration: &'a LoweredDeviceConfiguration,
    pub groups: Vec<GroupAddress>,
}

impl<'a> TableInput<'a> {
    pub fn new(product: &'a ProductData, configuration: &'a LoweredDeviceConfiguration) -> Self {
        let mut groups: Vec<_> = configuration.links.iter().map(|link| link.group_address).collect();
        groups.sort_unstable();
        groups.dedup();
        Self { product, configuration, groups }
    }

    /// Active objects as their table rows encode them.
    ///
    /// ETS clears an active object's communication-enable bit while no group
    /// address is linked to it. Measured with Hawk on System B (LightSwitch2
    /// 0301: `0x47` to `0x43`), BCU2 (M-00EE_A-4301: `0x37` to `0x33`, one row
    /// per unlinked object at every link count) and BCU1 (M-0048_A-105A:
    /// `0xC7` to `0xC3`). The configured flag is kept for linked objects.
    pub fn linked_objects(&self) -> Vec<ComObjectDef> {
        let linked: std::collections::BTreeSet<u16> =
            self.configuration.links.iter().map(|link| u16::from(link.com_object)).collect();
        self.configuration
            .com_objects
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
        self.configuration.com_objects.iter().map(|object| object.number).collect()
    }

    pub fn associations(&self) -> Result<Vec<(u16, u16)>, CompileError> {
        self.configuration
            .links
            .iter()
            .map(|link| {
                let index =
                    self.groups.binary_search(&link.group_address).expect("links supplied the sorted addresses");
                Ok((
                    u16::try_from(index + 1)
                        .map_err(|_| CompileError::invalid("association table exceeds its declared table capacity"))?,
                    u16::from(link.com_object),
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

    /// Bytes the product reserves for `max_entries` rows, if the format has rows.
    pub fn capacity(&self, max_entries: u16) -> Result<Option<usize>, CompileError> {
        Ok(match self {
            Self::Addresses(codec) => Some(codec.capacity(max_entries)),
            Self::Associations(codec) => Some(codec.capacity(max_entries)?),
            Self::Objects(_) => None,
        })
    }

    pub fn encode(
        &self,
        input: &TableInput<'_>,
        seed: impl FnOnce() -> Result<Vec<u8>, CompileError>,
    ) -> Result<EncodedTable, CompileError> {
        match self {
            Self::Addresses(codec) => codec.encode(input.configuration.individual_address, &input.groups),
            // Indexed formats reserve one slot per roster object; the roster
            // contains the active objects (see `ObjectTable`).
            Self::Associations(codec) => codec.encode(&input.associations()?, &input.active_numbers()),
            // TODO: confirm the unlinked-object rule for System 300 before
            // changing the configured bit in its DPT rows.
            Self::Objects(codec @ ObjectTable::DptProperties) => {
                codec.encode(input.product, &input.configuration.com_objects, seed)
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

fn count_prefix(count: usize, wide: bool, table: &'static str) -> Result<Vec<u8>, CompileError> {
    let overflow = || CompileError::invalid(format!("{table} exceeds its declared table capacity"));
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
