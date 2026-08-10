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
    pub bit_offset: u8,
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
    pub segments: Vec<Segment>,
    /// The product's load procedures: one complete `ProductProcedure`
    /// for System 7, or `MergeId`-tagged fragments for System B.
    pub load_procedures: Vec<LoadProcedure>,
    pub com_objects: Vec<ComObjectDef>,
    pub parameters: Vec<ParameterLocation>,
    /// Segment id holding the group address table, if the product
    /// says (`Static/AddressTable/@CodeSegment`).
    pub address_table_segment: Option<String>,
    pub address_table_max_entries: Option<u16>,
    pub association_table_segment: Option<String>,
    pub association_table_max_entries: Option<u16>,
    /// Segment id holding the group object table.
    pub com_object_table_segment: Option<String>,
}

impl ProductData {
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

        Ok(Self {
            id: program.id.clone(),
            mask_version: parse_mask_version(&program.mask_version),
            load_procedure_style: LoadProcedureStyle::from_mtxml(&program.load_procedure_style),
            segments,
            load_procedures: program
                .static_section
                .load_procedures
                .as_ref()
                .map(|lp| lp.procedures.clone())
                .unwrap_or_default(),
            com_objects: extract_com_objects(program)?,
            parameters: extract_parameters(program),
            address_table_segment,
            address_table_max_entries: program.static_section.address_table.as_ref().map(|t| t.max_entries),
            association_table_segment,
            association_table_max_entries: program.static_section.association_table.as_ref().map(|t| t.max_entries),
            com_object_table_segment,
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

/// `MV-0705` → `MaskVersion::System7Tp1`.
fn parse_mask_version(raw: &str) -> Option<MaskVersion> {
    let hex = raw.strip_prefix("MV-")?;
    // Some ids carry a suffix after the mask itself (MV-0300-0100...).
    let hex = hex.split('-').next()?;
    u16::from_str_radix(hex, 16).ok().map(MaskVersion::from)
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

fn extract_parameters(program: &ApplicationProgram) -> Vec<ParameterLocation> {
    use zweidraehte_knxprod::schema::ParameterItem;

    let Some(parameters) = &program.static_section.parameters else {
        return Vec::new();
    };

    parameters
        .items
        .iter()
        .filter_map(|item| match item {
            // Only stored parameters have a location; the memoryless
            // ones exist purely to drive the ETS UI.
            ParameterItem::Parameter(p) => p.memory.as_ref().map(|m| ParameterLocation {
                id: p.id.clone(),
                code_segment: m.code_segment.clone(),
                offset: m.offset,
                bit_offset: m.bit_offset,
            }),
            ParameterItem::Union(_) => None,
        })
        .collect()
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

    fn product() -> ProductData {
        ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("the fixture parses")
    }

    #[test]
    fn extracts_identity_and_style() {
        let p = product();
        assert_eq!(p.id, "M-00FA_A-0306-02-0000");
        assert_eq!(p.mask_version, Some(MaskVersion::System7Tp1));
        assert_eq!(p.load_procedure_style, LoadProcedureStyle::Product);
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
