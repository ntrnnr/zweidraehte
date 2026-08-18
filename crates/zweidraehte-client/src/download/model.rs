//! Per-management-model download definitions.
//!
//! The compile pipeline in [`super::project`] is generic; what varies
//! between management models is declared here, one [`DownloadModel`]
//! row per BCU kind. Each row is deliberately the residue the master
//! data *cannot* express — table byte formats, numbering conventions,
//! the load-control path policy, whether the family speaks
//! `A_Authorize` — kept as small definition tables next to each
//! other, the same move [`super::table_coding`] makes one level down.
//! Everything the master data *does* express (which machines exist,
//! how they are driven, at which objects) comes from
//! [`LsmModel`](super::mask::LsmModel) instead and must not be
//! duplicated here.
//!
//! Adding a management model means adding its table codings in
//! `table_coding.rs`, one `DownloadModel` row here, and nothing in
//! the pipeline.

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};

use super::interpreter::LoadControlPath;
use super::mask::{LsmRealization, MaskData};
use super::table_coding::{
    Addr1, Addr2, Addr7, Addr8, Asso6, Asso8, Co7, ComObjectEntry, ComObjectEntry2, Cot1, Cot2, CotM112, TableCoding,
};
use crate::error::{Error, Result};

/// How one management model is programmed: everything about a BCU
/// kind that neither the master data nor the product file expresses.
///
/// The image half lives in the embedded [`ImageLayout`]; the rest is
/// download behavior. One row per BCU kind — System 7 and System B
/// today's working paths, BCU1 and BCU2 the legacy families, couplers
/// a future row.
pub struct DownloadModel {
    /// The master data's `ManagementModel` spelling this row serves.
    pub management_model: &'static str,
    /// Table byte formats and placement — the image half.
    pub(crate) layout: ImageLayout,
    /// The load-control path policy. Mostly derived from the mask's
    /// own LSM resource declarations ([`declared_path`]), but a row
    /// may overrule them where real silicon does (BIM M112) or where
    /// there is nothing to declare (BCU1).
    pub load_control: fn(&MaskData<'_>) -> Result<LoadControlPath>,
    /// Whether the `Connect` step issues `A_Authorize`. BCU1 has no
    /// access levels — the service itself is a BCU2 addition — so
    /// sending it there is undefined; every other family gates
    /// configuration writes behind the granted level.
    pub authorize_on_connect: bool,
    /// Whether the management surface has interface objects and
    /// properties at all. False only for BCU1, whose management is
    /// entirely memory-mapped — a property read there is not a
    /// fallback-worthy attempt but a service the device does not
    /// speak. Callers use this to skip the `PID_MAX_APDULENGTH`
    /// negotiation (and similar property probes) outright.
    pub has_properties: bool,
    /// The APDU capacity to assume when `PID_MAX_APDULENGTH` cannot be
    /// read. 15 — the TP1 standard frame, 12-byte memory chunks — is
    /// the 03/05/01 §4.3.7.2.1 fallback for every family; BCU1 devices
    /// have no properties at all, so for them it is not a fallback but
    /// the answer.
    pub default_max_apdu: u16,
}

impl DownloadModel {
    /// The model for a mask's declared management model, or `None` for
    /// models whose downloads are not implemented (plain couplers, …).
    pub fn for_management_model(model: &str) -> Option<&'static DownloadModel> {
        MODELS.iter().find(|m| m.management_model == model)
    }
}

/// The management-model spelling whose [`ImageLayout`] a product of
/// the given mask family lays its tables out in.
///
/// Needed for downward-compatible downloads (a BCU1 program carried
/// by a BCU2): the *procedure* follows the device's mask, but the
/// tables stay in the program's own realization — a BCU1 application
/// reads its group object table RT1-style (config bit 7 fixed)
/// whatever silicon executes it.
pub(crate) fn family_management_model(family: zweidraehte_proto::device::MaskFamily) -> &'static str {
    use zweidraehte_proto::device::MaskFamily;
    match family {
        MaskFamily::Bcu1 => "Bcu1",
        MaskFamily::Bcu2 => "Bcu2",
        MaskFamily::System7 => "BimM112",
        MaskFamily::SystemB => "SystemB",
        // No layout rows exist for the coupler families; callers fall
        // back to the device mask's own layout.
        MaskFamily::Bim => "Bim",
        MaskFamily::BimM => "BimM",
    }
}

const MODELS: [DownloadModel; 4] = [
    DownloadModel {
        management_model: "Bcu1",
        layout: BCU1_LAYOUT,
        // Mask 001xh has no load state machines at all — the whole
        // download is a direct memory-write sequence.
        load_control: direct_path,
        authorize_on_connect: false,
        has_properties: false,
        default_max_apdu: 15,
    },
    DownloadModel {
        management_model: "Bcu2",
        layout: BCU2_LAYOUT,
        // Property-mapped machines 1–3 (addr/assoc/app), declared in
        // the mask's resources.
        load_control: declared_path,
        authorize_on_connect: true,
        has_properties: true,
        default_max_apdu: 15,
    },
    DownloadModel {
        management_model: "BimM112",
        layout: BIM_M112_LAYOUT,
        load_control: forced_property_path,
        authorize_on_connect: true,
        has_properties: true,
        default_max_apdu: 15,
    },
    DownloadModel {
        management_model: "SystemB",
        layout: SYSTEM_B_LAYOUT,
        load_control: declared_path,
        authorize_on_connect: true,
        has_properties: true,
        default_max_apdu: 15,
    },
];

// ============================================================================
// Load-control path policies
// ============================================================================

/// BCU1: no machines, no records, no polling — the procedure is plain
/// memory writes.
fn direct_path(_mask: &MaskData<'_>) -> Result<LoadControlPath> {
    Ok(LoadControlPath::Direct)
}

/// BIM M112: always the property path, regardless of what the
/// resources declare. The master data still describes the legacy
/// memory-mapped window at 0104h for these masks, but that is not
/// what ETS does — a Falcon trace of a real MDT 0705 device (ETS.log,
/// 2026-08-13) unloads through PropertyValue_Write on interface
/// objects 1..4, PID_LOAD_STATE_CONTROL, and the device never reacted
/// to spec-shaped window writes at all. 03/05/02 §3.31.2 marks the
/// memory procedure "shall not be used for further developments", the
/// certification templates only ever exercise the property
/// realization, and the machine index *is* the object index — so the
/// property path is what real System 7 silicon actually speaks.
fn forced_property_path(_mask: &MaskData<'_>) -> Result<LoadControlPath> {
    Ok(LoadControlPath::Property)
}

/// The path the mask's own LSM resource declarations describe —
/// per-mask data, not family lore (MV-2705 is BimM112-managed yet
/// property-driven, which is why the BimM112 row overrules rather
/// than trusts this).
fn declared_path(mask: &MaskData<'_>) -> Result<LoadControlPath> {
    let model = mask.lsm_model();
    match model.realization() {
        Some(LsmRealization::Property) => Ok(LoadControlPath::Property),
        Some(LsmRealization::Memory) => {
            let resources = mask.memory_resources().ok_or(Error::DownloadConfig(
                "this mask drives its machines through memory but does not locate all of \
                 ProgrammingMode / load control / load status / address table there",
            ))?;
            Ok(LoadControlPath::Memory(resources))
        }
        None if model.is_empty() => Err(Error::DownloadConfig(
            "this mask declares no load state machines, but its management model expects them",
        )),
        None => Err(Error::DownloadConfig(
            "this mask mixes memory-mapped and property-driven machines; no published mask does",
        )),
    }
}

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
    /// Overlay per-object octets onto a *product-supplied* group
    /// object table (the segment's default data), for models whose
    /// table carries firmware pointers only the product database
    /// knows — synthesizing would zero them. `None` for models whose
    /// tables are fully synthesizable.
    pub overlay_group_object_table: Option<fn(&mut [u8], &[super::product::ComObjectDef]) -> Result<()>>,
}

// ============================================================================
// BCU1 (System 1)
// ============================================================================

const BCU1_LAYOUT: ImageLayout = ImageLayout {
    placement: Placement::AbsoluteSegments,
    first_asap: 0,
    address_table: bcu1_address_table,
    association_table: narrow_association_table,
    group_object_table: bcu1_group_object_table,
    overlay_group_object_table: Some(bcu1_overlay_group_object_table),
};

/// RT1: RT2's coding (the [`Addr1`] alias) — device address in the
/// table, length octet counting its slot.
fn bcu1_address_table(ia: IndividualAddress, group_addresses: &[GroupAddress]) -> Result<Vec<u8>> {
    Addr1 { individual_address: ia }.blob(group_addresses)
}

/// Overlay flags/type onto the vendor-supplied table; [`Cot1`]
/// forces config bit 7 on the way in.
fn bcu1_overlay_group_object_table(defaults: &mut [u8], objects: &[super::product::ComObjectDef]) -> Result<()> {
    let rows: Vec<(u16, ComObjectFlags, ComObjectType)> =
        objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect();
    Cot1::overlay(defaults, &rows)
}

/// The BCU1 group object table — BCU2's, through the bit-7-forcing
/// RT1 coding. As on the other absolute families, no objects means no
/// blob.
fn bcu1_group_object_table(rows: &[(ComObjectFlags, ComObjectType)]) -> Result<Vec<u8>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<ComObjectEntry2> = rows
        .iter()
        .map(|&(flags, object_type)| ComObjectEntry2 {
            data_ptr: 0,
            config: flags.to_byte(),
            object_type: object_type.into(),
        })
        .collect();
    Cot1 { ram_flags_ptr: 0 }.blob(&entries)
}

// ============================================================================
// BCU2 (System 2)
// ============================================================================

const BCU2_LAYOUT: ImageLayout = ImageLayout {
    placement: Placement::AbsoluteSegments,
    first_asap: 0,
    address_table: bcu2_address_table,
    // RT2 associations are RT8's coding (one octet per identifier).
    association_table: narrow_association_table,
    group_object_table: bcu2_group_object_table,
    overlay_group_object_table: Some(bcu2_overlay_group_object_table),
};

/// RT2: the device's own address rides in the table, and the length
/// octet counts its slot too.
fn bcu2_address_table(ia: IndividualAddress, group_addresses: &[GroupAddress]) -> Result<Vec<u8>> {
    Addr2 { individual_address: ia }.blob(group_addresses)
}

/// Overlay flags/type onto the vendor-supplied table, preserving its
/// one-octet firmware pointers (see [`Cot2::overlay`]).
fn bcu2_overlay_group_object_table(defaults: &mut [u8], objects: &[super::product::ComObjectDef]) -> Result<()> {
    let rows: Vec<(u16, ComObjectFlags, ComObjectType)> =
        objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect();
    Cot2::overlay(defaults, &rows)
}

/// The BCU2 group object table. Like M112, a product with no group
/// objects contributes no blob rather than a header-only table.
fn bcu2_group_object_table(rows: &[(ComObjectFlags, ComObjectType)]) -> Result<Vec<u8>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<ComObjectEntry2> = rows
        .iter()
        .map(|&(flags, object_type)| ComObjectEntry2 {
            data_ptr: 0,
            config: flags.to_byte(),
            object_type: object_type.into(),
        })
        .collect();
    Cot2 { ram_flags_ptr: 0 }.blob(&entries)
}

// ============================================================================
// BIM M112 (System 7)
// ============================================================================

const BIM_M112_LAYOUT: ImageLayout = ImageLayout {
    placement: Placement::AbsoluteSegments,
    first_asap: 0,
    address_table: m112_address_table,
    association_table: narrow_association_table,
    group_object_table: m112_group_object_table,
    overlay_group_object_table: Some(m112_overlay_group_object_table),
};

/// RT8: the device's own address rides in the table, ahead of the
/// group addresses.
fn m112_address_table(ia: IndividualAddress, group_addresses: &[GroupAddress]) -> Result<Vec<u8>> {
    Addr8 { individual_address: ia }.blob(group_addresses)
}

/// RT2 and RT8 associations are one octet per identifier. The
/// narrowing is a checked assertion, not a live branch: both address
/// tables' one-octet caps fail compilation before a TSAP could exceed
/// a `u8`, and ASAPs arrive as `u8` in the project already.
fn narrow_association_table(associations: &[(u16, u16)]) -> Result<Vec<u8>> {
    let narrow =
        |v: u16| u8::try_from(v).map_err(|_| Error::DownloadConfig("an association identifier exceeds one octet"));
    let narrowed: Vec<(u8, u8)> =
        associations.iter().map(|&(tsap, asap)| Ok((narrow(tsap)?, narrow(asap)?))).collect::<Result<_>>()?;
    Asso8.blob(&narrowed)
}

/// Overlay flags/type onto a vendor-supplied M112 table (see
/// [`CotM112::overlay`] for why replacing it wholesale corrupts real
/// silicon).
fn m112_overlay_group_object_table(defaults: &mut [u8], objects: &[super::product::ComObjectDef]) -> Result<()> {
    let rows: Vec<(u16, ComObjectFlags, ComObjectType)> =
        objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect();
    CotM112::overlay(defaults, &rows)
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

const SYSTEM_B_LAYOUT: ImageLayout = ImageLayout {
    placement: Placement::RelativeObjects,
    first_asap: 1,
    address_table: system_b_address_table,
    association_table: system_b_association_table,
    group_object_table: system_b_group_object_table,
    // RT7 descriptors are flags + type only; nothing product-secret to
    // preserve, so a default-data table would be a plain synthesis
    // target anyway.
    overlay_group_object_table: None,
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
    fn models_resolve_by_management_model() {
        assert_eq!(DownloadModel::for_management_model("Bcu1").map(|m| m.layout.first_asap), Some(0));
        assert_eq!(DownloadModel::for_management_model("Bcu2").map(|m| m.layout.first_asap), Some(0));
        assert_eq!(DownloadModel::for_management_model("BimM112").map(|m| m.layout.first_asap), Some(0));
        assert_eq!(DownloadModel::for_management_model("SystemB").map(|m| m.layout.first_asap), Some(1));
        assert!(DownloadModel::for_management_model("").is_none());
    }

    #[test]
    fn only_bcu1_skips_authorization() {
        for model in &MODELS {
            assert_eq!(model.authorize_on_connect, model.management_model != "Bcu1", "{}", model.management_model);
        }
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
