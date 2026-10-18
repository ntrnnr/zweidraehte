use super::{CompileError, EncodedTable, ResourceFlavour, unsupported};
use crate::commissioning::error::OverflowedTable;
use std::collections::BTreeSet;
use zweidraehte_proto::tables::association::{
    Association, AssociationTableError, AssociationTableFormat, Bcu, SystemBBig, SystemBSmall, UNUSED_SENDING_TSAP,
};

#[derive(Debug, Clone, Copy)]
pub(crate) enum AssociationTable {
    Indexed,
    Sorted,
    SystemBSmall,
    SystemBBig,
}

impl AssociationTable {
    pub(crate) fn from_flavour(flavour: ResourceFlavour) -> Result<Self, CompileError> {
        Ok(match flavour {
            ResourceFlavour::AssociationTableBcu1 | ResourceFlavour::AssociationTableBcu2 => Self::Indexed,
            ResourceFlavour::AssociationTableM112 => Self::Sorted,
            ResourceFlavour::AssociationTableSystemBSmall => Self::SystemBSmall,
            ResourceFlavour::AssociationTableSystemBBig => Self::SystemBBig,
            ResourceFlavour::AssociationTableSystemB => {
                return Err(CompileError::missing_evidence(
                    "System B association-table entry size is unresolved; supply the target's two- or four-byte row capability",
                ));
            }
            _ => return Err(unsupported("association", flavour)),
        })
    }

    pub(crate) fn encode(&self, associations: &[(u16, u16)], roster: &[u16]) -> Result<EncodedTable, CompileError> {
        let mut rows: Vec<_> = associations.iter().map(|&(tsap, asap)| Association { tsap, asap }).collect();
        match self {
            Self::Indexed => rows = indexed_association_rows(associations, roster)?,
            Self::Sorted => {
                rows.sort_unstable();
                rows.dedup();
            }
            Self::SystemBSmall | Self::SystemBBig => {
                // RT6 transmits through the first matching ASAP.
                let mut seen = std::collections::BTreeSet::new();
                rows.retain(|row| seen.insert(*row));
            }
        }
        // Product data chooses the target at runtime; each shared codec is
        // still specialized for one format, just as it is in device firmware.
        match self {
            Self::Indexed | Self::Sorted => encode_rows::<Bcu>(&rows),
            Self::SystemBSmall => encode_rows::<SystemBSmall>(&rows),
            Self::SystemBBig => encode_rows::<SystemBBig>(&rows),
        }
    }
}

impl AssociationTable {
    /// Bytes reserved for `max_entries` rows.
    pub(crate) fn capacity(&self, max_entries: u32) -> Result<u64, CompileError> {
        let rows = u64::from(max_entries);
        // Reserved storage can exceed the count the selected wire format
        // can transmit. Check that count when encoding actual rows, not
        // when releasing unused product-owned capacity.
        let (header, entry) = match self {
            Self::Indexed | Self::Sorted => (Bcu::HEADER_LEN, Bcu::ENTRY_LEN),
            Self::SystemBSmall => (SystemBSmall::HEADER_LEN, SystemBSmall::ENTRY_LEN),
            Self::SystemBBig => (SystemBBig::HEADER_LEN, SystemBBig::ENTRY_LEN),
        };
        Ok(header as u64 + rows * entry as u64)
    }
}

fn encode_rows<F: AssociationTableFormat>(rows: &[Association]) -> Result<EncodedTable, CompileError> {
    // Too many rows overflow the table. An identifier wider than the
    // format's field, such as a wide object roster in a one-octet format,
    // is a product and format mismatch instead; a short buffer is a defect.
    let error = |error: AssociationTableError| match error {
        AssociationTableError::CountOverflow => {
            CompileError::table_overflow(OverflowedTable::Association, error.to_string())
        }
        AssociationTableError::IdentifierOverflow | AssociationTableError::BufferTooShort => {
            CompileError::invalid(error.to_string())
        }
    };
    let length = F::encoded_len(rows.len()).map_err(error)?;
    let mut bytes = vec![0; length];
    F::encode(rows, &mut bytes).map_err(error)?;
    Ok(EncodedTable::owned(bytes, rows.len()))
}

fn indexed_association_rows(associations: &[(u16, u16)], roster: &[u16]) -> Result<Vec<Association>, CompileError> {
    let capacity_error = || CompileError::invalid("association table exceeds its declared table capacity");
    let slot_count = roster
        .iter()
        .chain(associations.iter().map(|(_, asap)| asap))
        .max()
        .map_or(0, |maximum| usize::from(*maximum) + 1);
    if slot_count > usize::from(u8::MAX) {
        return Err(capacity_error());
    }
    // The first link occupies the object's indexed slot; 0xfe represents an
    // unused slot on the wire. Extra links follow in ascending object order,
    // while preserving each object's authored group-link order.
    let unused = u16::from(UNUSED_SENDING_TSAP);
    let mut rows: Vec<_> = (0..slot_count).map(|asap| Association { tsap: unused, asap: asap as u16 }).collect();
    let mut extras = Vec::new();
    for &(tsap, asap) in associations {
        // Group indices from 0xfe up collide with the unused-slot marker:
        // the configuration has more group addresses than the format holds.
        if tsap >= unused {
            return Err(CompileError::table_overflow(
                OverflowedTable::Association,
                "association table exceeds its declared table capacity",
            ));
        }
        let slot = &mut rows[usize::from(asap)];
        if slot.tsap == unused {
            slot.tsap = tsap;
        } else {
            extras.push(Association { tsap, asap });
        }
    }
    // A stable grouping matches the native compiler without changing which
    // link sends, sorting TSAPs within an object, or removing duplicate links.
    extras.sort_by_key(|row| row.asap);
    // An unused sending slot can hold a receiving association for a group
    // that has no sender. Groups with a primary sending association stay in
    // the tail: moving them would change the indexed sending relationship.
    // Fill holes in ascending slot order, keeping the eligible row order.
    let sending: BTreeSet<_> = rows.iter().filter(|row| row.tsap != unused).map(|row| row.tsap).collect();
    for slot in &mut rows {
        if slot.tsap != unused {
            continue;
        }
        let Some(index) = extras.iter().position(|row| !sending.contains(&row.tsap)) else {
            break;
        };
        *slot = extras.remove(index);
    }
    rows.extend(extras);
    Ok(rows)
}
