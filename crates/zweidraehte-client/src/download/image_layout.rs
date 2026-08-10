//! Per-management-model image layout definitions.
//!
//! The compile pipeline in [`super::project`] is generic; what varies
//! between management models is declared here, one [`ImageLayout`]
//! per model. This is deliberately the residue the master data
//! *cannot* express — table byte formats and numbering conventions —
//! kept as small definition tables next to each other, the same move
//! [`super::table_coding`] makes one level down. Everything the
//! master data *does* express (which machines exist, how they are
//! driven, at which objects) comes from
//! [`LsmModel`](super::mask::LsmModel) instead and must not be
//! duplicated here.
//!
//! Adding a management model (BCU2 is the realistic next one) means
//! adding its table codings in `table_coding.rs`, one `ImageLayout`
//! const here, and nothing in the pipeline.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};

use super::table_coding::{Addr7, Addr8, Asso6, Asso8, Co7, ComObjectEntry, CotM112, TableCoding};
use crate::error::{Error, Result};

/// Where a model's generated content lands in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Content goes to fixed addresses, into the segments the product
    /// names (BIM M112: the product fixes every address).
    AbsoluteSegments,
    /// Content is keyed by interface object; the device allocates the
    /// addresses during load (System B).
    RelativeObjects,
}

/// How one management model turns compiled content into image bytes.
///
/// The three builders are named free functions (a `const` table
/// cannot hold closures), each a thin adapter onto the
/// [`TableCoding`](super::table_coding::TableCoding) of the model's
/// realization types.
pub(crate) struct ImageLayout {
    /// The master data's `ManagementModel` spelling this layout serves.
    pub management_model: &'static str,
    pub placement: Placement,
    /// First ASAP the model's group object table can express —
    /// M112 numbers objects from 0, RT7 from 1 (its table cannot hold
    /// ASAP 0).
    pub first_asap: u16,
    /// The group address table. The individual address is passed to
    /// every layout; only RT8 stores it (in TSAP slot 0).
    pub address_table: fn(IndividualAddress, &[GroupAddress]) -> Result<Vec<u8>>,
    /// The association table, from `(tsap, asap)` pairs.
    pub association_table: fn(&[(u16, u16)]) -> Result<Vec<u8>>,
    /// The group object table, from gapless descriptor rows where
    /// row `i` is ASAP `first_asap + i`.
    pub group_object_table: fn(&[(ComObjectFlags, ComObjectType)]) -> Result<Vec<u8>>,
}

impl ImageLayout {
    /// The layout for a mask's declared management model, or `None`
    /// for models whose downloads are not implemented (BCU1, plain
    /// couplers, …).
    pub fn for_management_model(model: &str) -> Option<&'static ImageLayout> {
        LAYOUTS.iter().find(|layout| layout.management_model == model)
    }
}

pub(crate) const LAYOUTS: [ImageLayout; 2] = [BIM_M112, SYSTEM_B];

// ============================================================================
// BIM M112 (System 7)
// ============================================================================

const BIM_M112: ImageLayout = ImageLayout {
    management_model: "BimM112",
    placement: Placement::AbsoluteSegments,
    first_asap: 0,
    address_table: m112_address_table,
    association_table: m112_association_table,
    group_object_table: m112_group_object_table,
};

/// RT8: the device's own address rides in the table, ahead of the
/// group addresses.
fn m112_address_table(ia: IndividualAddress, group_addresses: &[GroupAddress]) -> Result<Vec<u8>> {
    Addr8 { individual_address: ia }.blob(group_addresses)
}

/// RT8 associations are one octet per identifier. The narrowing is a
/// checked assertion, not a live branch: the address table's 255-GA
/// cap fails compilation before a TSAP could exceed a `u8`, and ASAPs
/// arrive as `u8` in the project already.
fn m112_association_table(associations: &[(u16, u16)]) -> Result<Vec<u8>> {
    let narrow =
        |v: u16| u8::try_from(v).map_err(|_| Error::DownloadConfig("an RT8 association identifier exceeds one octet"));
    let narrowed: Vec<(u8, u8)> =
        associations.iter().map(|&(tsap, asap)| Ok((narrow(tsap)?, narrow(asap)?))).collect::<Result<_>>()?;
    Asso8.blob(&narrowed)
}

/// The BIM M112 group object table. A product with no group objects
/// contributes **no** blob — an empty return keeps the COT segment
/// out of the image entirely, where `CotM112.blob(&[])` would write a
/// three-octet placeholder table.
fn m112_group_object_table(rows: &[(ComObjectFlags, ComObjectType)]) -> Result<Vec<u8>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<ComObjectEntry> = rows
        .iter()
        .map(|&(flags, object_type)| ComObjectEntry {
            data_ptr: 0,
            config: flags.to_byte(),
            object_type: object_type.into(),
        })
        .collect();
    CotM112 { ram_flags_ptr: 0 }.blob(&entries)
}

// ============================================================================
// System B
// ============================================================================

const SYSTEM_B: ImageLayout = ImageLayout {
    management_model: "SystemB",
    placement: Placement::RelativeObjects,
    first_asap: 1,
    address_table: system_b_address_table,
    association_table: system_b_association_table,
    group_object_table: system_b_group_object_table,
};

/// RT7 keeps the device's address elsewhere; the table is group
/// addresses only.
fn system_b_address_table(_ia: IndividualAddress, group_addresses: &[GroupAddress]) -> Result<Vec<u8>> {
    Addr7.blob(group_addresses)
}

fn system_b_association_table(associations: &[(u16, u16)]) -> Result<Vec<u8>> {
    Asso6.blob(associations)
}

/// RT7 descriptors are the rows as-is; an empty product yields the
/// two-octet zero-count table (the object still loads, holding
/// nothing).
fn system_b_group_object_table(rows: &[(ComObjectFlags, ComObjectType)]) -> Result<Vec<u8>> {
    Co7.blob(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_resolve_by_management_model() {
        assert_eq!(ImageLayout::for_management_model("BimM112").map(|l| l.first_asap), Some(0));
        assert_eq!(ImageLayout::for_management_model("SystemB").map(|l| l.first_asap), Some(1));
        assert!(ImageLayout::for_management_model("Bcu1").is_none(), "BCU1 downloads are not implemented");
        assert!(ImageLayout::for_management_model("").is_none());
    }

    #[test]
    fn empty_group_object_rows_differ_per_model_on_purpose() {
        // M112: no objects -> no blob, so the COT segment stays out of
        // the absolute image. RT7: no objects -> a zero-count table,
        // because the group object table machine still loads.
        assert_eq!(m112_group_object_table(&[]).expect("builds"), Vec::<u8>::new());
        assert_eq!(system_b_group_object_table(&[]).expect("builds"), vec![0x00, 0x00]);
    }
}
