use super::{CompileError, EncodedTable, ResourceFlavour, count_prefix, unsupported};
use crate::commissioning::error::OverflowedTable;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

#[derive(Debug, Clone, Copy)]
pub(crate) enum AddressTable {
    WithIndividualAddress,
    PowerLineWithIndividualAddress,
    GroupsOnly,
}

impl AddressTable {
    pub(crate) fn from_flavour(flavour: ResourceFlavour) -> Result<Self, CompileError> {
        match flavour {
            ResourceFlavour::AddressTableBcu1 => Ok(Self::WithIndividualAddress),
            ResourceFlavour::AddressTableBcu1Pl => Ok(Self::PowerLineWithIndividualAddress),
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
            Self::WithIndividualAddress | Self::PowerLineWithIndividualAddress => {
                let mut data =
                    count_prefix(groups.len() + 1, false, "BCU address table", Some(OverflowedTable::GroupAddress))?;
                data.extend_from_slice(individual.as_bytes());
                data
            }
            Self::GroupsOnly => count_prefix(groups.len(), true, "address table", Some(OverflowedTable::GroupAddress))?,
        };
        for group in groups {
            let mut address = [group.as_bytes()[0], group.as_bytes()[1]];
            if matches!(self, Self::PowerLineWithIndividualAddress) {
                // PL110 stores the group/individual discriminator in bit 15
                // of each table entry; the first IA slot remains unowned.
                // A group address already using bit 15 would alias another
                // entry and shift every later association index.
                if address[0] & 0x80 != 0 {
                    return Err(CompileError::invalid(format!(
                        "PL110 address table cannot encode group address {group}: bit 15 is the group discriminator"
                    )));
                }
                address[0] |= 0x80;
            }
            data.extend_from_slice(&address);
        }
        let mut encoded = EncodedTable::owned(data, groups.len());
        if matches!(self, Self::WithIndividualAddress | Self::PowerLineWithIndividualAddress) {
            // Address assignment programs the individual-address slot;
            // application downloads leave its ownership unchanged.
            encoded.mask[1..3].fill(0);
        }
        // MaxEntries counts group addresses; the legacy IA is not a group.
        Ok(encoded)
    }

    /// Bytes reserved for `max_entries` group addresses.
    pub(crate) fn capacity(&self, max_entries: u32) -> u64 {
        let header = match self {
            Self::WithIndividualAddress | Self::PowerLineWithIndividualAddress => 3,
            Self::GroupsOnly => 2,
        };
        header + 2 * u64::from(max_entries)
    }
}
