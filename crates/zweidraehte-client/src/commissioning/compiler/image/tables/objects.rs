use super::{CompileError, EncodedTable, ResourceFlavour, TableSeed, count_prefix, unsupported};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::tables::com_object::{BcuComObjectTableFormat, BcuComObjectTableViewMut, Rt1, Rt2, System7};

/// Host-side selection from product data. Embedded views use the marker types
/// directly; this enum never enters their table access path.
#[derive(Debug, Clone, Copy)]
pub(crate) enum NativeObjectFormat {
    Bcu10,
    Bcu11,
    Bcu1Pl,
    Bcu2,
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
            ResourceFlavour::GroupObjectTableBcu10 => Self::Native(NativeObjectTable::new(Format::Bcu10)),
            ResourceFlavour::GroupObjectTableBcu11 => Self::Native(NativeObjectTable::new(Format::Bcu11)),
            ResourceFlavour::GroupObjectTableBcu1Pl => Self::Native(NativeObjectTable::new(Format::Bcu1Pl)),
            ResourceFlavour::GroupObjectTableBcu2 => Self::Native(NativeObjectTable::new(Format::Bcu2)),
            ResourceFlavour::GroupObjectTableM112 => Self::Native(NativeObjectTable::new(Format::System7)),
            ResourceFlavour::GroupObjectTableSystemB => Self::Descriptors,
            ResourceFlavour::GroupObjectTableSystem300 => Self::DptProperties,
            _ => return Err(unsupported("group object", flavour)),
        })
    }

    pub(crate) fn first_object_number(&self) -> u16 {
        match self {
            Self::Descriptors | Self::DptProperties => 1,
            Self::Native(_) => 0,
        }
    }

    pub(super) fn encode(
        &self,
        _product: &ProductData,
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
                    NativeObjectFormat::System7 => (System7::HEADER_LEN, System7::ENTRY_LEN),
                    _ => (Rt1::HEADER_LEN, Rt1::ENTRY_LEN),
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
            Self::DptProperties => encode_dpt_objects(effective, seed()?),
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
    config_mask: u8,
    fixed_config_bits: u8,
    inactive_mask: u8,
    inactive_flags: u8,
}

impl NativeObjectTable {
    pub(super) fn header_len(&self) -> usize {
        match self.format {
            NativeObjectFormat::System7 => System7::HEADER_LEN,
            NativeObjectFormat::Bcu10 | NativeObjectFormat::Bcu11 => Rt1::HEADER_LEN,
            NativeObjectFormat::Bcu1Pl | NativeObjectFormat::Bcu2 => Rt2::HEADER_LEN,
        }
    }

    pub(crate) fn new(format: NativeObjectFormat) -> Self {
        // Flavours share pointer geometry but have distinct flag invariants.
        // BCU1 1.0 fixes update/transmit on; 1.1 fixes only update. PL110
        // preserves firmware update/segment bits. Narrow inactive rows use
        // the native blank object's low priority rather than the seed priority.
        let segment = ComObjectFlags::ROI_FLAG_MASK;
        let (config_mask, fixed_config_bits, inactive_mask, inactive_flags) = match format {
            NativeObjectFormat::Bcu10 => (!segment, 0xc0, !segment, 3),
            NativeObjectFormat::Bcu11 => (!segment, 0x80, !segment, 3),
            NativeObjectFormat::Bcu1Pl => (!(segment | 0x80), 0, !(segment | 0x80), 3),
            NativeObjectFormat::Bcu2 => (!segment, 0, !segment, 3),
            NativeObjectFormat::System7 => (!segment, 0, ComObjectFlags::CE_FLAG_MASK, 0),
        };
        Self { format, config_mask, fixed_config_bits, inactive_mask, inactive_flags }
    }

    pub(crate) fn overlay(
        &self,
        defaults: &mut [u8],
        effective: &[(u16, ComObjectFlags, ComObjectType)],
    ) -> Result<Vec<u8>, CompileError> {
        match self.format {
            NativeObjectFormat::Bcu10 | NativeObjectFormat::Bcu11 => self.overlay_as::<Rt1>(defaults, effective),
            // PL110 shares narrow pointer geometry but does not force RT1's
            // update bit; its native policy above preserves the authored bit.
            NativeObjectFormat::Bcu1Pl | NativeObjectFormat::Bcu2 => self.overlay_as::<Rt2>(defaults, effective),
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
        let effective: BTreeMap<_, _> =
            effective.iter().map(|(number, flags, kind)| (*number, (*flags, *kind))).collect();
        let reset_count = effective.keys().next_back().map_or(0, |number| number + 1);

        // The reference keeps an owned count that disagrees with the roster
        // (it only logs the difference) and still formats a row for every
        // effective object. Products whose table segment carries no data
        // therefore download a zero count followed by formatted rows. The
        // protocol view bounds rows by the count octet, so rows past a
        // smaller count are formatted through a scratch count, and the owned
        // count is restored afterwards.
        let stored = defaults[0];
        let count = u16::from(stored);
        let rows = count.max(reset_count);
        defaults[0] =
            u8::try_from(rows).map_err(|_| CompileError::invalid("group object table exceeds its one-byte count"))?;
        let mut table = BcuComObjectTableViewMut::<F>::new(defaults);
        let physical = table.as_view().entry_count();
        if physical < rows {
            return Err(CompileError::invalid(format!(
                "the product's group object table is truncated before object {physical}"
            )));
        }
        let mut ownership = vec![0; F::HEADER_LEN + usize::from(rows) * F::ENTRY_LEN];

        for number in 0..rows {
            let active = effective.get(&number);
            let (flags, mask) = if let Some((flags, _)) = active {
                (flags.to_byte(), self.config_mask)
            } else if number < reset_count {
                // System 7 clears only CE. Narrow formats use blank-object
                // traffic flags and priority while retaining their firmware bits.
                (self.inactive_flags, self.inactive_mask)
            } else {
                // The active roster ends here; preserve the product seed.
                continue;
            };
            let existing = table.as_view().entry(number).expect("the physical table is complete");
            let offset = table.as_view().config_offset(number).expect("the row is in the physical table");
            let config = (existing.config & !mask) | (flags & mask) | self.fixed_config_bits;
            ownership[offset] = mask;
            let written = if let Some((_, kind)) = active {
                // The top two type bits belong to firmware in every compact
                // flavour, including both narrow BCU table layouts.
                let type_mask = 0x3f;
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

        defaults[0] = stored;
        Ok(ownership)
    }
}

/// Rows run to the highest active object.
fn encode_descriptors(effective_objects: &[ComObjectDef]) -> Result<Vec<u8>, CompileError> {
    let maximum = effective_objects.iter().map(|object| object.number).max();
    let mut bytes = count_prefix(usize::from(maximum.unwrap_or(0)), true, "group object table")?;
    // RT7 starts at ASAP 1. Unused rows keep disabled UINT1 defaults;
    // encode directly into the final table instead of staging tuples.
    for _ in 0..maximum.unwrap_or(0) {
        bytes.extend_from_slice(&[0, ComObjectType::Uint1.into()]);
    }
    // The descriptor roster starts at one. A product may still expose object
    // zero (and associate it); the reference formatter omits its descriptor
    // rather than letting it overwrite the count or rejecting the product.
    for object in effective_objects.iter().filter(|object| object.number != 0) {
        let offset = 2 * usize::from(object.number);
        bytes[offset..offset + 2].copy_from_slice(&[object.flags.to_byte(), object.object_type.into()]);
    }
    Ok(bytes)
}

/// System 300 formats flags over the parameter image; DPT bytes belong to
/// that image even when the configured object's DPT disagrees or is absent.
fn encode_dpt_objects(effective_objects: &[ComObjectDef], seed: TableSeed) -> Result<EncodedTable, CompileError> {
    if seed.data.len() != seed.mask.len() {
        return Err(CompileError::invalid("the group object table seed has inconsistent ownership"));
    }
    let entries = effective_objects.iter().map(|object| usize::from(object.number)).max().unwrap_or(0);
    let length = entries * 6;
    let mut data = seed.data;
    let mut mask = seed.mask;
    // Emit only the active prefix. The image merger keeps any longer seed
    // tail untouched, while missing prefix bytes remain zero and unowned.
    data.resize(length, 0);
    mask.resize(length, 0);
    for row in 0..entries {
        data[row * 6 + 1] = 3;
        mask[row * 6 + 1] = u8::MAX;
    }
    for object in effective_objects.iter().filter(|object| object.number != 0) {
        data[(usize::from(object.number) - 1) * 6 + 1] = object.flags.to_byte() & !0x20;
    }
    // The codec dispatcher applies parameter-loading zero-fill separately;
    // group-only formatting retains the untouched descriptor ownership.
    Ok(EncodedTable { data, mask, entries })
}
