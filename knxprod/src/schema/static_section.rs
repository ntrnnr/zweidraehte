//! Static section types: Code, segments, Extension, BaggageDef, Messages.

use serde::{Deserialize, Serialize};

use super::com_objects::{ComObjectRefs, ComObjectTable};
use super::load_procedures::LoadProcedures;
use super::param_refs::ParameterRefs;
use super::parameters::{Parameters, ParameterTypes};

// ============================================================================
// Static Section
// ============================================================================

/// The Static section containing Code, Parameters, ComObjects, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticSection {
    #[serde(rename = "Code", skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    #[serde(rename = "ParameterTypes", skip_serializing_if = "Option::is_none")]
    pub parameter_types: Option<ParameterTypes>,
    #[serde(rename = "Parameters", skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Parameters>,
    #[serde(rename = "ParameterRefs", skip_serializing_if = "Option::is_none")]
    pub parameter_refs: Option<ParameterRefs>,
    #[serde(rename = "ComObjectTable", skip_serializing_if = "Option::is_none")]
    pub com_object_table: Option<ComObjectTable>,
    #[serde(rename = "ComObjectRefs", skip_serializing_if = "Option::is_none")]
    pub com_object_refs: Option<ComObjectRefs>,
    #[serde(rename = "AddressTable", skip_serializing_if = "Option::is_none")]
    pub address_table: Option<AddressTable>,
    #[serde(rename = "AssociationTable", skip_serializing_if = "Option::is_none")]
    pub association_table: Option<AssociationTable>,
    #[serde(rename = "LoadProcedures", skip_serializing_if = "Option::is_none")]
    pub load_procedures: Option<LoadProcedures>,
    #[serde(rename = "Extension", skip_serializing_if = "Option::is_none")]
    pub extension: Option<Extension>,
    #[serde(rename = "Messages", skip_serializing_if = "Option::is_none")]
    pub messages: Option<Messages>,
    #[serde(rename = "Options", skip_serializing_if = "Option::is_none")]
    pub options: Option<Options>,
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
/// use knxprod::{BaggageDef, BaggageContent};
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
        Self {
            name,
            target_path: "",
            content: BaggageContent::Embedded(content),
        }
    }

    /// Create a new baggage definition with external file path.
    pub const fn external(name: &'a str, path: &'a str) -> Self {
        Self {
            name,
            target_path: "",
            content: BaggageContent::External(path),
        }
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
// Code Segments
// ============================================================================

/// Code section containing memory segments
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Code {
    #[serde(rename = "AbsoluteSegment", default, skip_serializing_if = "Vec::is_empty")]
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
