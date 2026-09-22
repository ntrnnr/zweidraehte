use super::{CompileError, EncodedTable, ResourceFlavour, count_prefix, unsupported};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

#[derive(Debug, Clone, Copy)]
pub(crate) enum AddressTable {
    WithIndividualAddress,
    GroupsOnly,
}

impl AddressTable {
    pub(crate) fn from_flavour(flavour: ResourceFlavour) -> Result<Self, CompileError> {
        match flavour {
            ResourceFlavour::AddressTableBcu1 | ResourceFlavour::AddressTableBcu1Pl => Ok(Self::WithIndividualAddress),
            ResourceFlavour::AddressTableSystemB => Ok(Self::GroupsOnly),
            _ => Err(unsupported("address", flavour)),
        }
    }

    pub(crate) fn encode(
        &self,
        individual: IndividualAddress,
        groups: &[GroupAddress],
    ) -> Result<EncodedTable, CompileError> {
        debug_assert!(groups.windows(2).all(|pair| pair[0] < pair[1]));
        let mut data = match self {
            Self::WithIndividualAddress => {
                let mut data = count_prefix(groups.len() + 1, false, "BCU address table")?;
                data.extend_from_slice(individual.as_bytes());
                data
            }
            Self::GroupsOnly => count_prefix(groups.len(), true, "address table")?,
        };
        for group in groups {
            data.extend_from_slice(group.as_bytes());
        }
        // MaxEntries counts group addresses; the legacy IA is not a group.
        Ok(EncodedTable::owned(data, groups.len()))
    }
}
