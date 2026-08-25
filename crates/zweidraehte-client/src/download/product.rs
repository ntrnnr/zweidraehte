//! The product layer: what a `.knxprod` / MTXML application program
//! says about one product.
//!
//! Sits between the mask ([`super::mask`], per mask version) and the
//! project ([`super::project`], per installation). It carries what
//! only the manufacturer knows: where the loadable segments live, what
//! the load procedure looks like, which group objects exist, and where
//! parameters are stored.
//!
//! Extracted from the schema types the knxprod parser already
//! produces, rather than through `DeviceInfo` — that type answers
//! "describe this program to a human" and deliberately leaves out the
//! segment bytes, the `AddressTable`/`AssociationTable` elements and
//! the System 7 load controls a download needs.
//!
//! [`ProductData`] is a plain owned struct, so a test (or a caller
//! with a device that has no product file) can construct one by hand.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use zweidraehte_knxprod::runtime::KnxprodArchive;
use zweidraehte_knxprod::runtime::parser::parse_application_program;
use zweidraehte_knxprod::schema::{ApplicationProgram, Knx, LoadControl, LoadProcedure};
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::device::MaskVersion;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::knx::Priority;

use crate::error::{Error, Result};

/// One loadable memory segment of a product.
///
/// System 7 products place segments at absolute addresses; System B
/// declares sizes and lets the device allocate, so `address` is `None`
/// there until the device reports one back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment's MTXML id, e.g. `M-00FA_A-0306-02-0000_AS-4000`.
    /// Load-control records reference segments by this id.
    pub id: String,
    /// Absolute address (System 7), or `None` for relative segments.
    pub address: Option<u16>,
    /// Allocated size in bytes.
    pub size: u32,
    /// `"EEPROM"`, `"RAM"`, or absent.
    pub memory_type: Option<String>,
    /// Load state machine index, for relative (System B) segments.
    pub load_state_machine: Option<u8>,
    /// The segment's default contents, decoded from the MTXML's
    /// base64. This is what ETS seeds the download image with before
    /// applying project data.
    pub data: Vec<u8>,
    /// Which bytes of `data` belong to the product image. A zero byte leaves
    /// a hole for device state or project data; a non-zero byte seeds the
    /// corresponding data byte. MTXML without a mask owns all supplied data.
    pub mask: Option<Vec<u8>>,
}

/// One group object the product defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComObjectDef {
    /// Object number — the ASAP the association table references.
    pub number: u16,
    /// Value field type, resolved from MTXML's `ObjectSize` spelling
    /// at extraction time so an unknown size fails there rather than
    /// silently becoming `Uint1` in a table.
    pub object_type: ComObjectType,
    /// The configuration flags, in the group object table's coding.
    pub flags: ComObjectFlags,
}

/// Where one parameter lives in device memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterLocation {
    pub id: String,
    /// Segment id the offset is relative to.
    pub code_segment: String,
    pub offset: u32,
    /// Bit position within the byte at `offset`, counted from the MSB —
    /// the convention ETS uses when packing sub-byte parameters.
    pub bit_offset: u8,
    /// Storage width in bits, from the parameter's type or its DPT float
    /// encoding. 0 means the type declares no usable width (or there is no
    /// `ParameterTypes` section); patching then falls back to a whole-byte
    /// copy sized by the value.
    pub size_bits: u16,
    /// ETS writes this parameter on every download even when its value
    /// equals the product default; a diff-based project must include it.
    pub legacy_patch_always: bool,
    /// Whether the declared base value initializes this location before
    /// active references and project edits are applied. Ordinary parameters
    /// always do; a union contributes only its `DefaultUnionParameter`.
    pub seeds_default: bool,
}

/// Interface-object identity used by a property-backed parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropertyObject {
    Index(u8),
    Type { object_type: InterfaceObjectType, occurrence: u16 },
}

/// Where one parameter contributes bits to an interface-object property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyParameterLocation {
    pub id: String,
    pub object: PropertyObject,
    pub property_id: u16,
    pub offset: u32,
    pub bit_offset: u8,
    pub size_bits: u16,
    pub legacy_patch_always: bool,
}

/// How a product's load procedures compose with the mask.
///
/// From MTXML's `ApplicationProgram/@LoadProcedureStyle`; decides
/// whether the product supplies a whole procedure or fragments the
/// mask template merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadProcedureStyle {
    /// System 7: the product carries one complete procedure that
    /// replaces the mask's Load template.
    Product,
    /// System B: the product carries `MergeId`-tagged fragments the
    /// mask template splices in.
    Merged,
    /// A BCU-era `DefaultProcedure`, or anything else — carried
    /// verbatim, executed as fragments.
    #[default]
    Other,
}

impl LoadProcedureStyle {
    fn from_mtxml(s: &str) -> Self {
        match s {
            "ProductProcedure" => Self::Product,
            "MergedProcedure" => Self::Merged,
            _ => Self::Other,
        }
    }
}

/// Everything the product file says that a download needs.
#[derive(Debug, Clone, Default)]
pub struct ProductData {
    /// Application program id, e.g. `M-00FA_A-0306-02-0000`.
    pub id: String,
    /// The mask this product runs on, from `@MaskVersion` (`MV-0705`).
    pub mask_version: Option<MaskVersion>,
    /// Whether the product supplies a whole procedure (System 7) or
    /// fragments the mask template merges (System B).
    pub load_procedure_style: LoadProcedureStyle,
    /// The application identity task-segment records announce, from
    /// the program element's own attributes (the load-procedure XML
    /// does not repeat them).
    pub task_identity: super::ir::TaskIdentity,
    /// Whether the application declares KNX Data Secure capability.
    ///
    /// The project separately decides whether to enable that capability for
    /// a device instance. Keeping the two values separate prevents a capable
    /// product from silently turning a plain installation into a secure one.
    pub supports_data_secure: bool,
    /// Product-declared Security IO capacities. The compile step checks the
    /// project configuration against these before emitting table writes.
    pub max_security_individual_address_entries: Option<u16>,
    pub max_security_group_key_table_entries: Option<u16>,
    pub max_security_p2p_key_table_entries: Option<u16>,
    pub segments: Vec<Segment>,
    /// The product's load procedures: one complete `ProductProcedure`
    /// for System 7, or `MergeId`-tagged fragments for System B.
    pub load_procedures: Vec<LoadProcedure>,
    /// Complete product-declared communication-object definitions.
    pub com_objects: Vec<ComObjectDef>,
    /// Visible, configuration-resolved communication objects. `None` means
    /// the unconfigured product definitions above are effective.
    ///
    /// Keeping both is necessary for BCU-era tables: inactive objects still
    /// occupy descriptor and association slots, while System B writes zeroed
    /// descriptors for them.
    pub configured_com_objects: Option<Vec<ComObjectDef>>,
    /// Every object number the program declares, visible or not.
    /// [`configured_com_objects`](Self::configured_com_objects) carries the
    /// effective visible subset, but the BCU-era group object table keeps a
    /// row per declared object regardless —
    /// dynamic table management sizes its association slots off this
    /// roster (ETS emits TSAP FEh placeholders for objects the
    /// configuration hides: BCU1.log writes three slots with one
    /// object visible).
    pub com_object_numbers: Vec<u16>,
    pub parameters: Vec<ParameterLocation>,
    /// Parameters written through `LdCtrlWriteProp` rather than into a
    /// memory segment. Their values form a property-local data block.
    pub property_parameters: Vec<PropertyParameterLocation>,
    /// Segment id holding the group address table, if the product
    /// says (`Static/AddressTable/@CodeSegment`).
    pub address_table_segment: Option<String>,
    /// Offset of the table inside its segment
    /// (`Static/AddressTable/@Offset`). Zero on the families with
    /// dedicated table segments (System 7, BCU2); non-zero on BCU1,
    /// whose tables live inside the one EEPROM segment (the MDT
    /// MV-0012 reference points all three tables into it).
    pub address_table_offset: u32,
    pub address_table_max_entries: Option<u16>,
    pub association_table_segment: Option<String>,
    pub association_table_offset: u32,
    pub association_table_max_entries: Option<u16>,
    /// Segment id holding the group object table.
    pub com_object_table_segment: Option<String>,
    pub com_object_table_offset: u32,
    /// The program's fixups (BCU-era native code): mask-ROM routine
    /// addresses to patch into the code segments, resolved against
    /// the mask the download is compiled for.
    pub fixups: Vec<FixupDef>,
    /// Whether ETS lays the tables out dynamically for this program
    /// (`@DynamicTableManagement`, true on converted pre-ETS4 BCU-era
    /// programs). ETS's CommunicationTableFormatter then packs the
    /// association table immediately after the actual-size address
    /// table, repoints AssocTabPtr, and pads the association table
    /// with a TSAP FEh placeholder per unlinked group object — instead
    /// of honoring the vendor's static table offsets (bench traces
    /// BCU1.log and BCU2_partial.log at the repo root).
    pub dynamic_table_management: bool,
}

/// One fixup, extraction-side: which routine, which segment, where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixupDef {
    /// The `_ME-…` id suffix naming the routine
    /// (`Fixup/@FunctionRef` minus its product-mask prefix).
    pub function: String,
    /// The code segment the offsets index into.
    pub code_segment: String,
    pub offsets: Vec<u32>,
}

impl ProductData {
    /// Communication objects active in the selected product configuration.
    pub(crate) fn effective_com_objects(&self) -> &[ComObjectDef] {
        self.configured_com_objects.as_deref().unwrap_or(&self.com_objects)
    }

    /// Read a loose MTXML application program file.
    pub fn from_mtxml_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let xml = std::fs::read_to_string(path)?;
        Self::from_mtxml_str(&xml)
    }

    /// Read a loose MTXML application program from a string.
    pub fn from_mtxml_str(xml: &str) -> Result<Self> {
        let knx = parse_application_program(xml).map_err(|e| Error::ProductData(e.to_string()))?;
        Self::from_knx(&knx)
    }

    /// Take the sole application program out of a parsed document.
    pub fn from_knx(knx: &Knx) -> Result<Self> {
        let programs = &knx.manufacturer_data.manufacturer.application_programs.programs;
        match programs.as_slice() {
            [program] => Self::from_program(program),
            [] => Err(Error::ProductData("the document defines no application program".to_string())),
            _ => Err(Error::ProductData(format!(
                "the document defines {} application programs; name the one you want",
                programs.len()
            ))),
        }
    }

    /// Read one application program out of a `.knxprod` archive by id.
    pub fn from_knxprod(archive: &KnxprodArchive, program_id: &str) -> Result<Self> {
        let knx = archive
            .parse_application_program(program_id)
            .ok_or_else(|| Error::ProductData(format!("no application program {program_id} in the archive")))?
            .map_err(|e| Error::ProductData(e.to_string()))?;
        Self::from_knx(&knx)
    }

    /// Extract from an already-parsed application program.
    pub fn from_program(program: &ApplicationProgram) -> Result<Self> {
        let (segments, address_table_segment, association_table_segment, com_object_table_segment) =
            extract_segments(program);

        let com_objects = extract_com_objects(program)?;
        let mut com_object_numbers: Vec<u16> = com_objects.iter().map(|o| o.number).collect();
        com_object_numbers.sort_unstable();
        com_object_numbers.dedup();
        let (parameters, property_parameters) = extract_parameters(program)?;

        Ok(Self {
            id: program.id.clone(),
            mask_version: parse_mask_version(&program.mask_version),
            load_procedure_style: LoadProcedureStyle::from_mtxml(&program.load_procedure_style),
            task_identity: extract_task_identity(program),
            supports_data_secure: program.is_secure_enabled.unwrap_or(false),
            max_security_individual_address_entries: program.max_security_individual_address_entries,
            max_security_group_key_table_entries: program.max_security_group_key_table_entries,
            max_security_p2p_key_table_entries: program.max_security_p2p_key_table_entries,
            segments,
            load_procedures: program
                .static_section
                .load_procedures
                .as_ref()
                .map(|lp| lp.procedures.clone())
                .unwrap_or_default(),
            com_objects,
            configured_com_objects: None,
            com_object_numbers,
            parameters,
            property_parameters,
            address_table_segment,
            address_table_offset: program.static_section.address_table.as_ref().and_then(|t| t.offset).unwrap_or(0),
            address_table_max_entries: program.static_section.address_table.as_ref().map(|t| t.max_entries),
            association_table_segment,
            association_table_offset: program
                .static_section
                .association_table
                .as_ref()
                .and_then(|t| t.offset)
                .unwrap_or(0),
            association_table_max_entries: program.static_section.association_table.as_ref().map(|t| t.max_entries),
            com_object_table_segment,
            com_object_table_offset: program
                .static_section
                .com_object_table
                .as_ref()
                .and_then(|t| t.offset)
                .unwrap_or(0),
            fixups: extract_fixups(program),
            dynamic_table_management: program.dynamic_table_management,
        })
    }

    /// A segment by id.
    pub fn segment(&self, id: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.id == id)
    }

    /// The product's single `ProductProcedure` (System 7): the
    /// complete load procedure, needing no mask template.
    pub fn product_procedure(&self) -> Option<&[LoadControl]> {
        match self.load_procedures.as_slice() {
            [only] if only.merge_id.is_none() => Some(&only.controls),
            _ => None,
        }
    }

    /// The product's fragment for one `LdCtrlMerge` splice point
    /// (System B).
    pub fn merge_fragment(&self, merge_id: u8) -> Option<&[LoadControl]> {
        self.load_procedures.iter().find(|p| p.merge_id == Some(merge_id)).map(|p| p.controls.as_slice())
    }
}

// ============================================================================
// Extraction
// ============================================================================

/// The application identity ETS stamps into task-segment records:
/// `[manufacturer:2][application number:2][version:1]`, manufacturer
/// from the program id's `M-XXXX` prefix, the rest from the program's
/// own attributes. A malformed id yields manufacturer 0 — the task
/// record is informational to the devices we drive, and failing the
/// whole product extraction over it would be out of proportion.
fn extract_task_identity(program: &ApplicationProgram) -> super::ir::TaskIdentity {
    let manufacturer = program
        .id
        .strip_prefix("M-")
        .and_then(|rest| rest.get(..4))
        .and_then(|hex| u16::from_str_radix(hex, 16).ok())
        .unwrap_or(0);
    let [mfr_hi, mfr_lo] = manufacturer.to_be_bytes();
    let [app_hi, app_lo] = program.application_number.to_be_bytes();
    super::ir::TaskIdentity {
        application_id: [mfr_hi, mfr_lo, app_hi, app_lo, program.application_version],
        pei_type: program.pei_type,
    }
}

/// `MV-0705` → `MaskVersion::System7Tp1`.
fn parse_mask_version(raw: &str) -> Option<MaskVersion> {
    let hex = raw.strip_prefix("MV-")?;
    // Some ids carry a suffix after the mask itself (MV-0300-0100...).
    let hex = hex.split('-').next()?;
    u16::from_str_radix(hex, 16).ok().map(MaskVersion::from)
}

/// The program's fixups, with each `FunctionRef` reduced to its
/// `_ME-…` suffix — the routine's identity across masks (the prefix
/// is the product's mask, and resolution happens against the mask the
/// download compiles for). A reference without the `_ME-` marker is
/// kept whole; the resolution will fail loudly on it.
fn extract_fixups(program: &ApplicationProgram) -> Vec<FixupDef> {
    program
        .static_section
        .fixup_list
        .iter()
        .flat_map(|list| &list.fixups)
        .map(|fixup| FixupDef {
            function: fixup
                .function_ref
                .rsplit_once("_ME-")
                .map(|(_, suffix)| suffix.to_string())
                .unwrap_or_else(|| fixup.function_ref.clone()),
            code_segment: fixup.code_segment.clone(),
            offsets: fixup.offsets.clone(),
        })
        .collect()
}

/// Segments plus the ids the table elements point at.
fn extract_segments(program: &ApplicationProgram) -> (Vec<Segment>, Option<String>, Option<String>, Option<String>) {
    let mut segments = Vec::new();

    if let Some(code) = &program.static_section.code {
        for abs in &code.absolute_segments {
            segments.push(Segment {
                id: abs.id.clone(),
                address: u16::try_from(abs.address).ok(),
                size: abs.size,
                memory_type: abs.memory_type.clone(),
                load_state_machine: None,
                data: decode_base64(abs.data.as_deref()),
                mask: abs.mask.as_deref().map(|mask| decode_base64(Some(mask))),
            });
        }

        for rel in &code.relative_segments {
            segments.push(Segment {
                id: rel.id.clone(),
                address: None,
                size: rel.size,
                memory_type: None,
                load_state_machine: Some(rel.load_state_machine),
                data: decode_base64(rel.data.as_deref()),
                mask: rel.mask.as_deref().map(|mask| decode_base64(Some(mask))),
            });
        }
    }

    let adt = program.static_section.address_table.as_ref().and_then(|t| t.code_segment.clone());
    let ast = program.static_section.association_table.as_ref().and_then(|t| t.code_segment.clone());
    let cot = program.static_section.com_object_table.as_ref().and_then(|t| t.code_segment.clone());

    (segments, adt, ast, cot)
}

/// Malformed base64 yields an empty default rather than an error: a
/// segment with unreadable defaults is still a segment, and the
/// download writes project data over it anyway.
fn decode_base64(data: Option<&str>) -> Vec<u8> {
    data.and_then(|d| BASE64.decode(d.trim()).ok()).unwrap_or_default()
}

fn extract_com_objects(program: &ApplicationProgram) -> Result<Vec<ComObjectDef>> {
    let Some(table) = &program.static_section.com_object_table else {
        return Ok(Vec::new());
    };

    table
        .objects
        .iter()
        .map(|obj| {
            let object_type = ComObjectType::from_ets_size_string(&obj.object_size).ok_or_else(|| {
                Error::ProductData(format!("object {} has an unrecognized size {:?}", obj.number, obj.object_size))
            })?;
            Ok(ComObjectDef { number: obj.number, object_type, flags: pack_flags(obj) })
        })
        .collect()
}

/// Pack MTXML's per-flag `Enabled`/`Disabled` attributes and priority
/// into the group object table's `ComObjectFlags` octet (Table 87).
///
/// Uses the proto flag masks and `Priority`, so the bit positions have
/// one definition rather than a copy here.
fn pack_flags(obj: &zweidraehte_knxprod::schema::ComObject) -> ComObjectFlags {
    use zweidraehte_knxprod::schema::{ComObjectPriority, EnableFlag};
    let on = |f: &EnableFlag| matches!(f, EnableFlag::Enabled);

    let mut byte = 0u8;
    for (enabled, mask) in [
        (on(&obj.update_flag), ComObjectFlags::UE_FLAG_MASK),
        (on(&obj.transmit_flag), ComObjectFlags::TE_FLAG_MASK),
        (on(&obj.read_on_init_flag), ComObjectFlags::ROI_FLAG_MASK),
        (on(&obj.write_flag), ComObjectFlags::WE_FLAG_MASK),
        (on(&obj.read_flag), ComObjectFlags::RE_FLAG_MASK),
        (on(&obj.communication_flag), ComObjectFlags::CE_FLAG_MASK),
    ] {
        if enabled {
            byte |= mask;
        }
    }

    // Priority occupies bits 1:0; ETS's default (and an absent
    // attribute) is Low. "Alert" is the wire's Alarm priority.
    let priority = match obj.priority.unwrap_or(ComObjectPriority::Low) {
        ComObjectPriority::Low => Priority::Low,
        ComObjectPriority::High => Priority::High,
        ComObjectPriority::Alert => Priority::Alarm,
    };
    byte |= u8::from(priority);

    ComObjectFlags::from_byte(byte)
}

fn extract_parameters(
    program: &ApplicationProgram,
) -> Result<(Vec<ParameterLocation>, Vec<PropertyParameterLocation>)> {
    use zweidraehte_knxprod::schema::{ParameterItem, PropertyLocation};

    let Some(parameters) = &program.static_section.parameters else {
        return Ok((Vec::new(), Vec::new()));
    };

    // Width lookup through the parameter-type table. A product without
    // one (our own generated test fixtures) degrades every width to 0,
    // which keeps the whole-byte patching path.
    let types = program.static_section.parameter_types.as_ref().map(|pt| pt.types.as_slice()).unwrap_or_default();
    let size_of =
        |type_id: &str| -> u16 { types.iter().find(|t| t.id == type_id).map_or(0, |t| t.type_def.size_bits()) };

    let mut locations = Vec::new();
    let mut property_locations = Vec::new();

    let property_object = |location: &PropertyLocation| -> Result<PropertyObject> {
        match (location.object_index, location.object_type) {
            (Some(index), None) => Ok(PropertyObject::Index(index)),
            (None, Some(object_type)) => Ok(PropertyObject::Type {
                object_type: InterfaceObjectType::from(object_type),
                occurrence: location.occurrence.unwrap_or(0),
            }),
            (None, None) => {
                Err(Error::ProductData("a property parameter declares neither ObjectIndex nor ObjectType".to_string()))
            }
            (Some(_), Some(_)) => {
                Err(Error::ProductData("a property parameter declares both ObjectIndex and ObjectType".to_string()))
            }
        }
    };
    for item in &parameters.items {
        match item {
            // Only stored parameters have a location; the memoryless
            // ones exist purely to drive the ETS UI.
            ParameterItem::Parameter(p) => {
                if let Some(m) = &p.memory {
                    locations.push(ParameterLocation {
                        id: p.id.clone(),
                        code_segment: m.code_segment.clone(),
                        offset: m.offset,
                        bit_offset: m.bit_offset,
                        size_bits: size_of(&p.parameter_type),
                        legacy_patch_always: p.legacy_patch_always,
                        seeds_default: true,
                    });
                }
                if let Some(property) = &p.property {
                    property_locations.push(PropertyParameterLocation {
                        id: p.id.clone(),
                        object: property_object(property)?,
                        property_id: property.property_id,
                        offset: property.offset,
                        bit_offset: property.bit_offset,
                        size_bits: size_of(&p.parameter_type),
                        legacy_patch_always: p.legacy_patch_always,
                    });
                }
            }
            // A union's members each carry a byte+bit offset relative
            // to the union's own location; normalize the bit sum so a
            // location's bit offset always stays inside its byte.
            ParameterItem::Union(u) => {
                for sub in &u.parameters {
                    if let Some(memory) = &u.memory {
                        let total_bits = u32::from(memory.bit_offset) + u32::from(sub.bit_offset);
                        locations.push(ParameterLocation {
                            id: sub.id.clone(),
                            code_segment: memory.code_segment.clone(),
                            offset: memory.offset + u32::from(sub.offset) + total_bits / 8,
                            bit_offset: (total_bits % 8) as u8,
                            size_bits: size_of(&sub.parameter_type),
                            legacy_patch_always: false,
                            seeds_default: sub.default_union_parameter == Some(true),
                        });
                    }
                    if let Some(property) = &u.property {
                        let total_bits = u32::from(property.bit_offset) + u32::from(sub.bit_offset);
                        property_locations.push(PropertyParameterLocation {
                            id: sub.id.clone(),
                            object: property_object(property)?,
                            property_id: property.property_id,
                            offset: property.offset + u32::from(sub.offset) + total_bits / 8,
                            bit_offset: (total_bits % 8) as u8,
                            size_bits: size_of(&sub.parameter_type),
                            legacy_patch_always: false,
                        });
                    }
                }
            }
        }
    }
    Ok((locations, property_locations))
}

// A `.knxprod` supplying both layers is read through the two
// constructors that already exist — `MaskDb::from_knxprod` for the
// bundled master data, `ProductData::from_knxprod` for the program —
// so there is deliberately no combined helper returning a tuple.

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A System 7 product in the shape our own generator emits: four
    /// absolute segments, a `ProductProcedure`, table elements naming
    /// their segments.
    pub(crate) const SYSTEM7_MTXML: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0306-02-0000" ApplicationNumber="774" ApplicationVersion="2" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="S7 Light Switch" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4000" Address="16384" Size="17" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4100" Address="16640" Size="15" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4200" Address="16896" Size="31" MemoryType="EEPROM" />
          <AbsoluteSegment Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>
        </Code>
        <Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
        </Parameters>
        <ComObjectTable CodeSegment="M-00FA_A-0306-02-0000_AS-4200" Offset="0">
          <ComObject Id="M-00FA_A-0306-02-0000_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Enabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0306-02-0000_AS-4000" Offset="0" MaxEntries="7" />
        <AssociationTable CodeSegment="M-00FA_A-0306-02-0000_AS-4100" Offset="0" MaxEntries="7" />
        <LoadProcedures>
          <LoadProcedure>
            <LdCtrlConnect />
            <LdCtrlCompareProp ObjIdx="0" PropId="78" InlineData="00FA0000000A0000" />
            <LdCtrlUnload LsmIdx="1" />
            <LdCtrlLoad LsmIdx="1" />
            <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="17" Access="255" MemType="3" SegFlags="128" />
            <LdCtrlLoadCompleted LsmIdx="1" />
            <LdCtrlRestart />
            <LdCtrlDisconnect />
          </LoadProcedure>
        </LoadProcedures>
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    /// A BCU1 product in the vendor shape (the MDT MV-0012 reference):
    /// one 256-byte EEPROM segment covering the whole ETS-visible
    /// window at 0100h, all three tables pointing *into* it at
    /// offsets, `DefaultProcedure` (the mask template is the whole
    /// procedure). The segment's default data is the 00..FF ramp so
    /// splice tests can see what survived.
    pub(crate) const BCU1_MTXML: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-0310-01-0000" ApplicationNumber="784" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="BCU1 Switch" LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code>
          <AbsoluteSegment Id="M-00FA_A-0310-01-0000_AS-0100" Address="256" Size="256" MemoryType="EEPROM"><Data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==</Data></AbsoluteSegment>
        </Code>
        <Parameters>
          <Parameter Id="M-00FA_A-0310-01-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0310-01-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="200" BitOffset="0" />
          </Parameter>
        </Parameters>
        <ComObjectTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="80">
          <ComObject Id="M-00FA_A-0310-01-0000_O-0" Name="Switch" Text="Switch" Number="0" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
          <ComObject Id="M-00FA_A-0310-01-0000_O-1" Name="Status" Text="Status" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Disabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <AddressTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="22" MaxEntries="5" />
        <AssociationTable CodeSegment="M-00FA_A-0310-01-0000_AS-0100" Offset="60" MaxEntries="5" />
        <FixupList>
          <Fixup FunctionRef="MV-0012_ME-U.5FGetTMx" CodeSegment="M-00FA_A-0310-01-0000_AS-0100">
            <Offset>239</Offset>
          </Fixup>
        </FixupList>
        <LoadProcedures />
      </Static>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn product() -> ProductData {
        ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("the fixture parses")
    }

    #[test]
    fn extracts_bcu1_table_offsets() {
        let p = ProductData::from_mtxml_str(BCU1_MTXML).expect("the BCU1 fixture parses");
        assert_eq!(p.mask_version, Some(MaskVersion::Bcu1Tp1));
        assert_eq!(p.load_procedure_style, LoadProcedureStyle::Other);
        assert_eq!(p.address_table_offset, 22);
        assert_eq!(p.association_table_offset, 60);
        assert_eq!(p.com_object_table_offset, 80);
        // All three point into the one EEPROM segment.
        let segment = p.address_table_segment.as_deref().expect("ADT segment named");
        assert_eq!(p.association_table_segment.as_deref(), Some(segment));
        assert_eq!(p.com_object_table_segment.as_deref(), Some(segment));

        // The fixup, reduced to its cross-mask routine identity.
        assert_eq!(p.fixups, vec![FixupDef {
            function: "U.5FGetTMx".to_string(),
            code_segment: segment.to_string(),
            offsets: vec![239],
        }]);
    }

    #[test]
    fn extracts_dynamic_table_management() {
        assert!(!ProductData::from_mtxml_str(BCU1_MTXML).expect("the BCU1 fixture parses").dynamic_table_management);

        let converted = BCU1_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
        let p = ProductData::from_mtxml_str(&converted).expect("the converted fixture parses");
        assert!(p.dynamic_table_management);
    }

    #[test]
    fn extracts_identity_and_style() {
        let p = product();
        assert_eq!(p.id, "M-00FA_A-0306-02-0000");
        assert_eq!(p.mask_version, Some(MaskVersion::System7Tp1));
        assert_eq!(p.load_procedure_style, LoadProcedureStyle::Product);
    }

    #[test]
    fn extracts_data_secure_capacities() {
        let xml = SYSTEM7_MTXML.replace(
            "Linkable=\"false\"",
            "Linkable=\"false\" IsSecureEnabled=\"true\" \
             MaxSecurityIndividualAddressEntries=\"190\" \
             MaxSecurityGroupKeyTableEntries=\"64\" \
             MaxSecurityP2PKeyTableEntries=\"0\"",
        );
        let p = ProductData::from_mtxml_str(&xml).expect("secure attributes parse");
        assert!(p.supports_data_secure);
        assert_eq!(p.max_security_individual_address_entries, Some(190));
        assert_eq!(p.max_security_group_key_table_entries, Some(64));
        assert_eq!(p.max_security_p2p_key_table_entries, Some(0));
    }

    #[test]
    fn extracts_absolute_segments_with_decoded_defaults() {
        let p = product();
        assert_eq!(p.segments.len(), 4);

        let adt = p.segment("M-00FA_A-0306-02-0000_AS-4000").expect("ADT segment");
        assert_eq!(adt.address, Some(0x4000));
        assert_eq!(adt.size, 17);
        assert_eq!(adt.memory_type.as_deref(), Some("EEPROM"));
        assert!(adt.data.is_empty(), "no <Data> means no defaults");

        // The parameter segment's base64 defaults decode to bytes —
        // this is what the download image gets seeded with.
        let params = p.segment("M-00FA_A-0306-02-0000_AS-4300").expect("param segment");
        assert_eq!(params.data, [1, 2, 3, 4]);
    }

    #[test]
    fn extracts_table_segment_bindings() {
        let p = product();
        assert_eq!(p.address_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4000"));
        assert_eq!(p.address_table_max_entries, Some(7));
        assert_eq!(p.association_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4100"));
        assert_eq!(p.com_object_table_segment.as_deref(), Some("M-00FA_A-0306-02-0000_AS-4200"));
    }

    #[test]
    fn extracts_the_product_procedure() {
        let p = product();
        let procedure = p.product_procedure().expect("System 7 carries one unmerged procedure");
        assert_eq!(procedure.len(), 8);
        assert!(matches!(procedure[0], LoadControl::LdCtrlConnect(_)));
        // The identity guard survives with its inline serial.
        match &procedure[1] {
            LoadControl::LdCtrlCompareProp(c) => {
                assert_eq!(c.obj_idx, Some(0));
                assert_eq!(c.prop_id, 78);
                assert_eq!(c.inline_data.as_deref(), Some("00FA0000000A0000"));
            }
            other => panic!("expected CompareProp, got {other:?}"),
        }
        assert!(p.merge_fragment(1).is_none(), "a ProductProcedure has no merge points");
    }

    #[test]
    fn packs_com_object_type_and_flags_into_the_device_coding() {
        let p = product();
        let obj = &p.com_objects[0];
        assert_eq!(obj.number, 1);
        assert_eq!(obj.object_type, ComObjectType::Uint1, "1 Bit");
        // Write + Communication + Update enabled, Read/Transmit/ROI
        // off, priority Low — 0b1001_0100 | 0b11.
        assert_eq!(obj.flags.to_byte(), 0b1001_0100 | 0b11);
    }

    #[test]
    fn an_unrecognized_object_size_is_rejected() {
        // A product whose ComObject declares a size string outside the
        // ETS coding fails to extract, rather than silently becoming
        // Uint1.
        let xml = SYSTEM7_MTXML.replace(r#"ObjectSize="1 Bit""#, r#"ObjectSize="3 Widgets""#);
        assert!(matches!(ProductData::from_mtxml_str(&xml), Err(crate::error::Error::ProductData(_))));
    }

    #[test]
    fn honors_com_object_priority() {
        // The fixture's object omits Priority (defaults Low = 3); an
        // Alert priority must reach the descriptor as the wire's Alarm
        // (2), not stay Low.
        let xml =
            SYSTEM7_MTXML.replace(r#"ObjectSize="1 Bit" ReadFlag"#, r#"ObjectSize="1 Bit" Priority="Alert" ReadFlag"#);
        let p = ProductData::from_mtxml_str(&xml).expect("parses");
        assert_eq!(p.com_objects[0].flags.priority(), Priority::Alarm);
    }

    #[test]
    fn extracts_parameter_locations() {
        let p = product();
        assert_eq!(p.parameters.len(), 1);
        let param = &p.parameters[0];
        assert_eq!(param.code_segment, "M-00FA_A-0306-02-0000_AS-4300");
        assert_eq!(param.offset, 2);
        assert_eq!(param.bit_offset, 0);
        // The fixture declares no ParameterTypes section, so the width
        // is unknown and patching falls back to whole-byte copies.
        assert_eq!(param.size_bits, 0);
        assert!(!param.legacy_patch_always);
    }

    #[test]
    fn extracts_property_parameter_locations() {
        let xml = SYSTEM7_MTXML.replace(
            r#"<Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />"#,
            r#"<Property ObjectIndex="0" PropertyId="86" Offset="0" BitOffset="0" />"#,
        );
        let product = ProductData::from_mtxml_str(&xml).expect("property parameter product parses");

        assert!(product.parameters.is_empty());
        assert_eq!(product.property_parameters.len(), 1);
        let parameter = &product.property_parameters[0];
        assert_eq!(parameter.object, PropertyObject::Index(0));
        assert_eq!(parameter.property_id, 86);
    }

    /// The fixture's `<Parameters>` block swapped for one with a type
    /// table, a `LegacyPatchAlways` parameter, and a union — the
    /// shapes a vendor program (the MDT Push Button Lite) uses.
    fn vendor_shaped_product() -> ProductData {
        let old = r#"<Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
        </Parameters>"#;
        let new = r#"<ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-2" Name="E4"><TypeRestriction Base="Value" SizeInBit="4"><Enumeration Text="Off" Value="0" Id="M-00FA_A-0306-02-0000_PT-2_EN-0" /></TypeRestriction></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-0306-02-0000_P-1" Name="Mode" ParameterType="M-00FA_A-0306-02-0000_PT-1" Text="Mode" Value="0" LegacyPatchAlways="true">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" />
          </Parameter>
          <Union SizeInBit="16">
            <Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="4" />
            <Parameter Id="M-00FA_A-0306-02-0000_P-2" Name="UnionA" ParameterType="M-00FA_A-0306-02-0000_PT-2" Text="A" Value="0" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
            <Parameter Id="M-00FA_A-0306-02-0000_P-3" Name="UnionB" ParameterType="M-00FA_A-0306-02-0000_PT-2" Text="B" Value="0" Offset="1" BitOffset="6" />
          </Union>
        </Parameters>"#;
        let xml = SYSTEM7_MTXML.replace(old, new);
        assert_ne!(xml, SYSTEM7_MTXML, "the Parameters block must have matched");
        ProductData::from_mtxml_str(&xml).expect("the vendor-shaped fixture parses")
    }

    #[test]
    fn resolves_type_widths_and_legacy_patch_always() {
        let p = vendor_shaped_product();
        let mode = p.parameters.iter().find(|l| l.id.ends_with("_P-1")).expect("P-1");
        assert_eq!(mode.size_bits, 8);
        assert!(mode.legacy_patch_always, "the attribute must survive extraction");
    }

    #[test]
    fn extracts_union_members_with_normalized_offsets() {
        let p = vendor_shaped_product();

        // Union base: offset 0, bit 4. Member A adds nothing on top:
        // it stays in byte 0 at bit 4.
        let a = p.parameters.iter().find(|l| l.id.ends_with("_P-2")).expect("P-2");
        assert_eq!((a.offset, a.bit_offset, a.size_bits), (0, 4, 4));
        assert!(a.seeds_default);

        // Member B adds byte 1 and bit 6: 4 + 6 = 10 bits carries one
        // byte, so it lands in byte 2 at bit 2.
        let b = p.parameters.iter().find(|l| l.id.ends_with("_P-3")).expect("P-3");
        assert_eq!((b.offset, b.bit_offset, b.size_bits), (2, 2, 4));
        assert!(!b.seeds_default);
    }

    #[test]
    fn mask_version_parses_from_the_mtxml_spelling() {
        assert_eq!(parse_mask_version("MV-0705"), Some(MaskVersion::System7Tp1));
        assert_eq!(parse_mask_version("MV-07B0"), Some(MaskVersion::SystemBTp1));
        // Masks with a variant suffix keep the mask itself.
        assert_eq!(parse_mask_version("MV-0300-01000000000000000000"), Some(MaskVersion::from(0x0300)));
        assert_eq!(parse_mask_version("nonsense"), None);
    }
}
