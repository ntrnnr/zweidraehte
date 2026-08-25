//! Static section types: Code, segments, Extension, BaggageDef, Messages.

use serde::{Deserialize, Serialize};

use super::com_objects::{ComObjectRefs, ComObjectTable};
use super::load_procedures::LoadProcedures;
use super::param_refs::ParameterRefs;
use super::parameters::{ParameterTypes, Parameters};

// ============================================================================
// Static Section
// ============================================================================

/// The Static section containing Code, Parameters, ComObjects, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticSection {
    #[serde(rename = "Code", skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    #[serde(rename = "ParameterTypes", alias = "PTS", skip_serializing_if = "Option::is_none")]
    pub parameter_types: Option<ParameterTypes>,
    #[serde(rename = "Parameters", alias = "PS", skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Parameters>,
    #[serde(rename = "ParameterRefs", alias = "PRS", skip_serializing_if = "Option::is_none")]
    pub parameter_refs: Option<ParameterRefs>,
    #[serde(rename = "ComObjectTable", alias = "COT", skip_serializing_if = "Option::is_none")]
    pub com_object_table: Option<ComObjectTable>,
    #[serde(rename = "ComObjectRefs", alias = "CORS", skip_serializing_if = "Option::is_none")]
    pub com_object_refs: Option<ComObjectRefs>,
    #[serde(rename = "AddressTable", alias = "ADRT", skip_serializing_if = "Option::is_none")]
    pub address_table: Option<AddressTable>,
    #[serde(rename = "AssociationTable", alias = "ASSOT", skip_serializing_if = "Option::is_none")]
    pub association_table: Option<AssociationTable>,
    #[serde(rename = "FixupList", alias = "FL", skip_serializing_if = "Option::is_none")]
    pub fixup_list: Option<FixupList>,
    #[serde(rename = "LoadProcedures", skip_serializing_if = "Option::is_none")]
    pub load_procedures: Option<LoadProcedures>,
    #[serde(rename = "Extension", skip_serializing_if = "Option::is_none")]
    pub extension: Option<Extension>,
    #[serde(rename = "Messages", skip_serializing_if = "Option::is_none")]
    pub messages: Option<Messages>,
    #[serde(rename = "BusInterfaces", skip_serializing_if = "Option::is_none")]
    pub bus_interfaces: Option<BusInterfaces>,
    #[serde(rename = "Options", alias = "Opt", skip_serializing_if = "Option::is_none")]
    pub options: Option<Options>,
}

/// The program's fixups: places in the code segments where the tool
/// patches in the address of a mask-ROM routine (the BCU-era
/// application code calls the BCU's operating system, and each mask
/// puts those entry points elsewhere — the master data's
/// `MaskEntries`). ETS applies them on every download; getting this
/// wrong ships code that calls the *product* mask's addresses on
/// whatever device carries it, which crashes a downward-compatible
/// host (a real BCU2 wedged until its programming button over
/// exactly this).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FixupList {
    #[serde(rename = "Fixup", alias = "F", default)]
    pub fixups: Vec<Fixup>,
}

/// One fixup: a mask-ROM routine reference and the offsets inside a
/// code segment where its (16-bit, big-endian) address lands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fixup {
    /// The mask entry, e.g. `MV-0012_ME-U.5Fdeb30` — the part after
    /// `_ME-` names the routine, the mask prefix is the *product's*
    /// mask (resolution happens against the device's).
    #[serde(rename = "@FunctionRef")]
    pub function_ref: String,
    #[serde(rename = "@CodeSegment")]
    pub code_segment: String,
    #[serde(rename = "Offset", alias = "Off", default)]
    pub offsets: Vec<u32>,
}

/// Extension element - contains baggages and other optional extension data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Extension {
    #[serde(rename = "Baggage", default, skip_serializing_if = "Vec::is_empty")]
    pub baggages: Vec<BaggageRef>,
}

/// Reference to a baggage item (image, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaggageRef {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
}

// ============================================================================
// Baggage Definition Types (for generation)
// ============================================================================

/// Definition of a baggage file for generation.
///
/// Baggages are resource files (typically images) that are:
/// 1. Listed in the ApplicationProgram's Extension/Baggage refs
/// 2. Indexed in a separate Baggages.xml manifest
/// 3. Stored in a Baggages/ subdirectory
/// 4. Included in signed .knxprod packages
///
/// # Example
///
/// ```rust,ignore
/// use zweidraehte_knxprod::{BaggageDef, BaggageContent};
///
/// const BAGGAGES: &[BaggageDef] = &[
///     BaggageDef {
///         name: "light.png",
///         target_path: "",
///         content: BaggageContent::Embedded(include_bytes!("icons/light.png")),
///     },
/// ];
/// ```
#[derive(Debug, Clone)]
pub struct BaggageDef<'a> {
    /// Filename (e.g., "licht.png")
    pub name: &'a str,
    /// Optional subdirectory within Baggages/ (usually empty string)
    pub target_path: &'a str,
    /// File contents - either embedded or loaded at generation time
    pub content: BaggageContent<'a>,
}

/// Content source for a baggage file.
#[derive(Debug, Clone)]
pub enum BaggageContent<'a> {
    /// Embed file bytes at compile time using `include_bytes!`
    Embedded(&'a [u8]),
    /// Load from a file path at generation time
    External(&'a str),
}

impl<'a> BaggageDef<'a> {
    /// Create a new baggage definition with embedded content.
    pub const fn embedded(name: &'a str, content: &'a [u8]) -> Self {
        Self { name, target_path: "", content: BaggageContent::Embedded(content) }
    }

    /// Create a new baggage definition with external file path.
    pub const fn external(name: &'a str, path: &'a str) -> Self {
        Self { name, target_path: "", content: BaggageContent::External(path) }
    }

    /// Create a new baggage definition with a target subdirectory.
    pub const fn with_target_path(mut self, target_path: &'a str) -> Self {
        self.target_path = target_path;
        self
    }
}

// ============================================================================
// Messages
// ============================================================================

/// Container for messages used in error handling, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Messages {
    #[serde(rename = "Message", default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<Message>,
}

/// A message displayed to the user (e.g., for error conditions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Text")]
    pub text: String,
}

// ============================================================================
// Bus Interfaces
// ============================================================================

/// Container for bus interface definitions.
///
/// ETS uses `BusInterfaces` to identify tunneling channels, USB
/// connections, and routing endpoints exposed by an IP Interface or
/// similar device. Each [`BusInterface`] maps to an additional
/// individual address slot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BusInterfaces {
    #[serde(rename = "BusInterface", default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<BusInterface>,
}

/// Access type for a bus interface (XSD `AccessType` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BusAccessType {
    Tunneling,
    USB,
    Routing,
}

/// A single bus interface entry.
///
/// Declares one tunneling/USB/routing channel that ETS can assign an
/// additional individual address to. The `address_index` corresponds
/// to the slot index in the device's additional IA table (PID 53).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusInterface {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@AddressIndex")]
    pub address_index: u8,
    #[serde(rename = "@AccessType")]
    pub access_type: BusAccessType,
    #[serde(rename = "@Text", skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

// ============================================================================
// Code Segments
// ============================================================================

/// Code section containing memory segments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Code {
    #[serde(rename = "AbsoluteSegment", alias = "AS", default, skip_serializing_if = "Vec::is_empty")]
    pub absolute_segments: Vec<AbsoluteSegment>,
    #[serde(rename = "RelativeSegment", default, skip_serializing_if = "Vec::is_empty")]
    pub relative_segments: Vec<RelativeSegment>,
}

/// Absolute memory segment (System 7)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsoluteSegment {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Address")]
    pub address: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@MemoryType", skip_serializing_if = "Option::is_none")]
    pub memory_type: Option<String>,

    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "Mask", skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
}

/// Relative memory segment (System B)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelativeSegment {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@LoadStateMachine")]
    pub load_state_machine: u8,
    #[serde(rename = "@Offset")]
    pub offset: u32,

    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(rename = "Mask", skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
}

// ============================================================================
// Address and Association Tables
// ============================================================================

/// Address table configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTable {
    #[serde(rename = "@CodeSegment", skip_serializing_if = "Option::is_none")]
    pub code_segment: Option<String>,
    #[serde(rename = "@Offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(rename = "@MaxEntries")]
    pub max_entries: u16,
}

/// Association table configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationTable {
    #[serde(rename = "@CodeSegment", skip_serializing_if = "Option::is_none")]
    pub code_segment: Option<String>,
    #[serde(rename = "@Offset", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(rename = "@MaxEntries")]
    pub max_entries: u16,
}

/// Options element with device comparison/reconstruction flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Options {
    /// Whether the application program is comparable (for device comparison).
    #[serde(rename = "@Comparable", skip_serializing_if = "Option::is_none")]
    pub comparable: Option<bool>,
    /// Whether the application program is reconstructable (for device reconstruction).
    #[serde(rename = "@Reconstructable", skip_serializing_if = "Option::is_none")]
    pub reconstructable: Option<bool>,
}
