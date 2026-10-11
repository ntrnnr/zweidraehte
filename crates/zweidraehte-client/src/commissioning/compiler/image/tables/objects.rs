use super::{CompileError, EncodedTable, ResourceFlavour, TableSeed, count_prefix, unsupported};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};
use zweidraehte_ets_files::runtime::ProductDptReferences;
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::tables::com_object::{BcuComObjectTableFormat, BcuComObjectTableViewMut, Rt1, Rt2, System7};

/// Host-side selection from product data. Embedded views use the marker types
/// directly; this enum never enters their table access path.
#[derive(Debug, Clone, Copy)]
pub(crate) enum NativeObjectFormat {
    Rt1,
    Rt2,
    System7,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ObjectTable {
    Native(NativeObjectTable),
    Descriptors,
    DptProperties,
}

impl ObjectTable {
    pub(crate) fn from_flavour(flavour: ResourceFlavour) -> Result<Self, CompileError> {
        use NativeObjectFormat as Format;
        Ok(match flavour {
            ResourceFlavour::GroupObjectTableBcu10
            | ResourceFlavour::GroupObjectTableBcu11
            | ResourceFlavour::GroupObjectTableBcu1Pl => Self::Native(NativeObjectTable::new(Format::Rt1)),
            ResourceFlavour::GroupObjectTableBcu2 => Self::Native(NativeObjectTable::new(Format::Rt2)),
            ResourceFlavour::GroupObjectTableM112 => Self::Native(NativeObjectTable::new(Format::System7)),
            ResourceFlavour::GroupObjectTableSystemB => Self::Descriptors,
            ResourceFlavour::GroupObjectTableSystem300 => Self::DptProperties,
            _ => return Err(unsupported("group object", flavour)),
        })
    }

    pub(crate) fn first_object_number(&self) -> u16 {
        match self {
            Self::Descriptors => 1,
            Self::Native(_) | Self::DptProperties => 0,
        }
    }

    pub(super) fn encode(
        &self,
        product: &ProductData,
        effective: &[ComObjectDef],
        seed: impl FnOnce() -> Result<TableSeed, CompileError>,
    ) -> Result<EncodedTable, CompileError> {
        match self {
            Self::Native(codec) => {
                let seed = seed()?;
                let mut data = seed.data;
                if !seed.first_byte_owned {
                    // An owned firmware count keeps its declared roster. With
                    // an unowned count, publish the effective roster ending at
                    // its highest active object.
                    let count = effective
                        .iter()
                        .map(|object| object.number)
                        .max()
                        .map_or(Some(0), |number| number.checked_add(1))
                        .and_then(|count| u8::try_from(count).ok())
                        .ok_or_else(|| CompileError::invalid("group object table exceeds its one-byte count"))?;
                    let header = data.first_mut().ok_or_else(|| {
                        CompileError::invalid("the product's group object table is shorter than its header")
                    })?;
                    *header = count;
                }
                let effective: Vec<_> = effective.iter().map(|o| (o.number, o.flags, o.object_type)).collect();
                let mut mask = codec.overlay(&mut data, &effective)?;
                data.truncate(mask.len());
                let entries = usize::from(data[0]); // overlay validated the count and all rows
                // Formatting preserves firmware pointers and reserved bits,
                // but the transfer owns the header and each formatted row in
                // full. Declared rows beyond the effective roster stay unowned.
                let (header, row) = match codec.format {
                    NativeObjectFormat::Rt1 => (Rt1::HEADER_LEN, Rt1::ENTRY_LEN),
                    NativeObjectFormat::Rt2 => (Rt2::HEADER_LEN, Rt2::ENTRY_LEN),
                    NativeObjectFormat::System7 => (System7::HEADER_LEN, System7::ENTRY_LEN),
                };
                let roster = effective.iter().map(|(number, ..)| usize::from(*number) + 1).max().unwrap_or(0);
                mask[..header + roster * row].fill(u8::MAX);
                Ok(EncodedTable { data, mask, entries })
            }
            Self::Descriptors => {
                let data = encode_descriptors(effective)?;
                let entries = (data.len() - 2) / 2;
                Ok(EncodedTable::owned(data, entries))
            }
            Self::DptProperties => {
                // TODO: confirm whether System 300's roster ends at the
                // highest active object before dropping its declared roster.
                let data = encode_dpt_objects(product.com_object_numbers(), effective)?;
                let entries = data.len() / 6;
                Ok(EncodedTable::owned(data, entries))
            }
        }
    }
}

/// The protocol view owns pointer geometry; this policy owns configurable bits.
///
/// The roster contains the device's active object instances by number,
/// with every gap inside that range
/// as a blank inactive entry, ending at the highest active object. Declared
/// but inactive product objects therefore format exactly like gaps, and rows
/// after the highest active object stay as the product seeded them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NativeObjectTable {
    format: NativeObjectFormat,
    inactive_mask: u8,
    type_mask: u8,
}

impl NativeObjectTable {
    pub(crate) fn new(format: NativeObjectFormat) -> Self {
        let (inactive_mask, type_mask) = match format {
            NativeObjectFormat::System7 => (ComObjectFlags::CE_FLAG_MASK, 0x3F),
            NativeObjectFormat::Rt1 | NativeObjectFormat::Rt2 => (!(ComObjectFlags::ROI_FLAG_MASK | 0x03), u8::MAX),
        };
        Self { format, inactive_mask, type_mask }
    }

    pub(crate) fn overlay(
        &self,
        defaults: &mut [u8],
        effective: &[(u16, ComObjectFlags, ComObjectType)],
    ) -> Result<Vec<u8>, CompileError> {
        match self.format {
            NativeObjectFormat::Rt1 => self.overlay_as::<Rt1>(defaults, effective),
            NativeObjectFormat::Rt2 => self.overlay_as::<Rt2>(defaults, effective),
            NativeObjectFormat::System7 => self.overlay_as::<System7>(defaults, effective),
        }
    }

    fn overlay_as<F: BcuComObjectTableFormat>(
        &self,
        defaults: &mut [u8],
        effective: &[(u16, ComObjectFlags, ComObjectType)],
    ) -> Result<Vec<u8>, CompileError> {
        if defaults.len() < F::HEADER_LEN {
            return Err(CompileError::invalid("the product's group object table is shorter than its header"));
        }
        let mut table = BcuComObjectTableViewMut::<F>::new(defaults);
        let count = table.as_view().declared_entry_count();
        let physical = table.as_view().entry_count();
        if physical < count {
            return Err(CompileError::invalid(format!(
                "the product's group object table is truncated before object {physical}"
            )));
        }
        for (number, ..) in effective {
            if *number >= count {
                return Err(CompileError::invalid(format!(
                    "object {number} lies outside the product's default group object table ({count} rows)"
                )));
            }
        }
        let effective: BTreeMap<_, _> =
            effective.iter().map(|(number, flags, kind)| (*number, (*flags, *kind))).collect();
        let reset_count = effective.keys().next_back().map_or(0, |number| number + 1);
        let mut ownership = vec![0; F::HEADER_LEN + usize::from(count) * F::ENTRY_LEN];

        for number in 0..count {
            let active = effective.get(&number);
            let (flags, mask) = if let Some((flags, _)) = active {
                (flags.to_byte(), !ComObjectFlags::ROI_FLAG_MASK)
            } else if number < reset_count {
                // Blank entries inside the roster. System 7 clears only CE;
                // RT1/RT2 keep the firmware bit 7 and priority bits.
                (0, self.inactive_mask)
            } else {
                // The active roster ends here; preserve the product seed.
                continue;
            };
            let existing = table.as_view().entry(number).expect("the physical table is complete");
            let offset = table.as_view().config_offset(number).expect("the row is in the physical table");
            let config = (existing.config & !mask) | (flags & mask);
            ownership[offset] = mask;
            let written = if let Some((_, kind)) = active {
                let type_mask = self.type_mask;
                ownership[offset + 1] = type_mask;
                table.set_config_and_type(
                    number,
                    config,
                    (existing.object_type & !type_mask) | (u8::from(*kind) & type_mask),
                )
            } else {
                table.set_config(number, config)
            };
            debug_assert!(written, "the physical table is complete");
        }
        Ok(ownership)
    }
}

/// Rows run to the highest active object.
fn encode_descriptors(effective_objects: &[ComObjectDef]) -> Result<Vec<u8>, CompileError> {
    let maximum = effective_objects.iter().map(|object| object.number).max();
    if effective_objects.iter().any(|object| object.number == 0) {
        return Err(CompileError::invalid("group object number 0 lies below the table's first ASAP 1"));
    }
    let mut bytes = count_prefix(usize::from(maximum.unwrap_or(0)), true, "group object table")?;
    // RT7 starts at ASAP 1. Unused rows keep disabled UINT1 defaults;
    // encode directly into the final table instead of staging tuples.
    for _ in 0..maximum.unwrap_or(0) {
        bytes.extend_from_slice(&[0, ComObjectType::Uint1.into()]);
    }
    for object in effective_objects {
        let offset = 2 * usize::from(object.number);
        bytes[offset..offset + 2].copy_from_slice(&[object.flags.to_byte(), object.object_type.into()]);
    }
    Ok(bytes)
}

/// Resources 03/05/01 §4.18.5, Realisation Type 6: each property element
/// holds a 16-bit configuration field followed by the main and subtype DPT.
fn encode_dpt_objects(
    declared_numbers: &[u16],
    effective_objects: &[ComObjectDef],
) -> core::result::Result<Vec<u8>, CompileError> {
    let Some(maximum) =
        declared_numbers.iter().copied().chain(effective_objects.iter().map(|object| object.number)).max()
    else {
        return Ok(Vec::new());
    };

    let mut rows = vec![[0u8; 6]; usize::from(maximum) + 1];
    for object in effective_objects {
        let row = rows.get_mut(usize::from(object.number)).ok_or(CompileError::invalid(format!(
            "effective communication object {0} is absent from the product roster",
            object.number
        )))?;
        let raw_dpt = object.datapoint_type.as_deref().ok_or(CompileError::invalid(format!(
            "System 300 communication object {0} has no datapoint type",
            object.number
        )))?;
        let dpt = ProductDptReferences::parse(raw_dpt).ok_or_else(|| {
            CompileError::invalid(format!(
                "System 300 communication object {object} has invalid datapoint type {value:?}",
                object = object.number,
                value = raw_dpt.to_owned()
            ))
        })?;
        let dpt = dpt.preferred();

        // The low octet uses the same flag coding as the standardized
        // communication-object configuration byte. Bit 5 is left exactly as
        // selected by the product because RT6 defines it as a memory-segment
        // selector rather than RT7's read-on-init flag.
        row[1] = object.flags.to_byte();
        row[2..4].copy_from_slice(&dpt.main.to_be_bytes());
        row[4..6].copy_from_slice(&dpt.subtype.unwrap_or(0).to_be_bytes());
    }

    Ok(rows.into_iter().flatten().collect())
}
