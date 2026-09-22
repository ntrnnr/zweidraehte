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
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_proto::address::GroupAddress;

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

    pub fn encode(
        &self,
        input: &TableInput<'_>,
        seed: impl FnOnce() -> Result<Vec<u8>, CompileError>,
    ) -> Result<EncodedTable, CompileError> {
        match self {
            Self::Addresses(codec) => codec.encode(input.configuration.individual_address, &input.groups),
            Self::Associations(codec) => codec.encode(&input.associations()?, input.product.com_object_numbers()),
            Self::Objects(codec) => codec.encode(input.product, &input.configuration.com_objects, seed),
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
