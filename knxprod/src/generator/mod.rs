//! MTXML Generator - Builds ApplicationProgram XML from device definitions.
//!
//! This module is organized into submodules:
//! - [`mtxml`] - Main MtxmlGenerator for ApplicationProgram XML
//! - [`hardware`] - HardwareGenerator for Hardware XML
//! - [`catalog`] - CatalogGenerator for Catalog XML
//! - [`baggage`] - BaggageGenerator for Baggages XML
//! - [`builder`] - KnxprodBuilder for unified generation workflow
//! - [`traversal`] - Page layout traversal utilities (picture/text collection)

pub mod baggage;
mod builder;
mod catalog;
mod hardware;
mod helpers;
mod mtxml;
mod traversal;

use std::collections::HashMap;

use crate::definition::module::ModuleCollection;
use crate::definition::page_layout::PageStructure;
use crate::schema::{BaggageDef, MaskFamily};

use zweidraehte::ets::{
    DeviceDescriptor, EtsCommObjectDef, EtsCommObjectRefDef, EtsParamDefExt, EtsTranslation, EtsUnionFieldInfo,
};

// Re-export public types
pub use baggage::BaggageGenerator;
pub use builder::{BuilderError, KnxprodBuilder, KnxprodOutput};
pub use catalog::CatalogGenerator;
pub use hardware::HardwareGenerator;
pub use mtxml::MtxmlGenerator;

// ============================================================================
// Shared Types
// ============================================================================

/// Tracks active conditions when generating nested XML structures.
/// This allows us to avoid redundant choose/when nesting when an object's
/// selector_param matches an already-active condition.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveConditions {
    /// Active conditions as (selector_param_name, values) pairs.
    /// When processing items inside a `when` block, this tracks which selector
    /// is active and what values are being tested.
    conditions: Vec<(String, Vec<i64>)>,
}

impl ActiveConditions {
    /// Create an empty set of active conditions.
    pub fn new() -> Self {
        Self { conditions: Vec::new() }
    }

    /// Add a condition to the active set.
    pub fn with_condition(&self, selector: &str, values: Vec<i64>) -> Self {
        let mut new = self.clone();
        new.conditions.push((selector.to_string(), values));
        new
    }

    /// Check if the given selector matches any active condition.
    /// Returns Some(values) if the selector matches an active condition.
    pub fn get_active_values(&self, selector: &str) -> Option<&Vec<i64>> {
        self.conditions.iter().find(|(sel, _)| sel == selector).map(|(_, vals)| vals)
    }
}

/// Maps parameter names to ParameterRef IDs.
pub(crate) struct ParamRefMap {
    /// Ref map: param name -> ref_id
    pub primary: HashMap<String, String>,
    /// Text-based ref map: (param_name, text_override) -> ref_id
    /// For union variant params that have different text overrides in different contexts
    pub by_text: HashMap<(String, Option<String>), String>,
    /// Total number of ParameterRefs generated. ComObjectRef _R-N suffixes
    /// must start after this to avoid collisions with ParameterRef suffixes.
    pub total_ref_count: u32,
}

impl ParamRefMap {
    /// Get the ref ID for a param.
    pub fn get(&self, param_name: &str) -> Option<&String> {
        self.primary.get(param_name)
    }

    /// Get the ref ID for a param with a specific text override.
    /// Used for union variant params that have context-specific text.
    pub fn get_by_text(&self, param_name: &str, text: Option<&str>) -> Option<&String> {
        let key = (param_name.to_string(), text.map(|s| s.to_string()));
        self.by_text.get(&key)
    }
}

/// Memory segment definition for System 7 devices.
#[derive(Debug, Clone)]
pub struct System7Segment {
    /// Segment name suffix (e.g., "4000" for address table)
    pub name: &'static str,
    /// Memory address
    pub address: u32,
    /// Segment size in bytes
    pub size: u32,
    /// Memory type ("EEPROM" or "RAM", None for default)
    pub memory_type: Option<&'static str>,
    /// Data bytes (base64 encoded). If None, segment is uninitialized (RAM).
    pub data: Option<&'static [u8]>,
    /// Mask bytes (base64 encoded). If None, no mask.
    pub mask: Option<&'static [u8]>,
}

/// System 7 memory layout configuration.
#[derive(Debug, Clone)]
pub struct System7MemoryLayout {
    /// Memory segments for the Code section
    pub segments: Vec<System7Segment>,
    /// Address table segment name (reference to segment in segments)
    pub address_table_segment: &'static str,
    /// Association table segment name
    pub association_table_segment: &'static str,
    /// Address table offset within segment
    pub address_table_offset: u32,
    /// Association table offset within segment
    pub association_table_offset: u32,
    /// Address table max entries
    pub address_table_max_entries: u16,
    /// Association table max entries
    pub association_table_max_entries: u16,
}

/// Configuration for generating MTXML files (ApplicationProgram, Hardware, Catalog).
pub struct ApplicationProgramConfig<'a> {
    /// Human-readable application name
    pub name: &'a str,
    /// Device descriptor with mask version, manufacturer ID, etc.
    pub device: &'a DeviceDescriptor,
    /// Extended parameter definitions with enum variants
    pub params: &'a [EtsParamDefExt],
    /// Virtual parameter definitions that exist only in ETS (not stored in device memory).
    /// These are useful for things like device name, channel names, or other text parameters
    /// that are displayed in ETS but don't consume device memory.
    ///
    /// Virtual params appear first in the parameter list, followed by regular params.
    pub virtual_params: Option<&'a [EtsParamDefExt]>,
    /// Default parameter values as raw bytes
    pub param_defaults: &'a [u8],
    /// Communication object definitions
    pub comm_objects: &'a [EtsCommObjectDef],
    /// Communication object reference definitions (for multi-ref objects)
    pub comm_object_refs: &'a [EtsCommObjectRefDef],
    /// Union fields from derive macro (optional)
    pub union_fields: Option<&'a [EtsUnionFieldInfo]>,
    /// Channel name for the UI grouping
    pub channel_name: &'a str,
    /// Base address for absolute segments (System 7 only, deprecated - use system7_layout)
    /// For System 7, this is the memory address where parameters start
    pub absolute_segment_address: Option<u32>,
    /// System 7 memory layout configuration (if None, uses simple single-segment layout)
    pub system7_layout: Option<System7MemoryLayout>,
    /// Application hash/suffix for the ApplicationProgram ID (4 hex chars).
    /// If None, defaults to "0000". Example: "E59D" for MDT devices.
    pub application_hash: Option<&'a str>,

    // ========================================================================
    // ApplicationProgram optional version attributes
    // ========================================================================
    /// Non-registration relevant data version (optional).
    /// Used for version management in ETS.
    pub non_reg_relevant_data_version: Option<u32>,
    /// Previous versions this program replaces (space-separated list).
    /// Example: "18 19" means this version replaces versions 18 and 19.
    pub replaces_versions: Option<&'a str>,
    /// Hash of the application data (base64 encoded).
    /// Used by ETS for integrity checking.
    pub application_data_hash: Option<&'a str>,

    // ========================================================================
    // Hardware/Catalog fields (for Hardware.mtxml and Catalog.mtxml generation)
    // ========================================================================
    /// Device serial number (6 bytes, unique per device).
    /// First 2 bytes should match manufacturer_id.
    pub serial_number: [u8; 6],
    /// Hardware version number (displayed in ETS)
    pub hardware_version: u8,
    /// Hardware name (displayed in ETS hardware list)
    pub hardware_name: &'a str,
    /// Product display text (shown in ETS catalog)
    pub product_name: &'a str,
    /// Product order number (for ordering/identification)
    pub order_number: &'a str,
    /// Whether the device is rail-mounted (DIN rail)
    pub is_rail_mounted: bool,
    /// Catalog section name (category in ETS catalog)
    pub catalog_section: &'a str,
    /// Optional page layout definition. If provided, the Dynamic section will be
    /// generated according to this layout. If None, auto-generation is used.
    pub page_layout: Option<PageStructure>,
    /// Optional module collection. If provided, ModuleDefs and Module instances
    /// will be generated in the output XML.
    pub modules: Option<ModuleCollection>,
    /// Optional baggage definitions. If provided, these files (images, etc.) will be:
    /// - Referenced in the Extension section of ApplicationProgram
    /// - Listed in a generated Baggages.xml manifest
    /// - Included in the signed .knxprod package
    pub baggages: Option<&'a [BaggageDef<'a>]>,
    /// Optional translations for non-default languages.
    /// Translations are generated into a `<Languages>` section at the Manufacturer level
    /// in the ApplicationProgram MTXML file. Use the `ets_translations!` macro to define translations.
    pub translations: Option<&'a [EtsTranslation]>,
}

impl<'a> ApplicationProgramConfig<'a> {
    /// Get the mask family for this configuration
    pub fn mask_family(&self) -> MaskFamily {
        MaskFamily::from_mask_version(self.device.mask_version.as_u16())
    }

    /// Get the number of virtual params at the device level.
    pub fn virtual_params_count(&self) -> usize {
        self.virtual_params.map_or(0, |vp| vp.len())
    }

    /// Iterate over all device-level params (virtual params first, then regular params).
    /// This matches the XML generation order.
    pub fn all_params(&self) -> impl Iterator<Item = &EtsParamDefExt> {
        let virtual_params = self.virtual_params.unwrap_or(&[]);
        virtual_params.iter().chain(self.params.iter())
    }

    /// Find a device-level parameter by name (searches virtual params first, then regular).
    /// Returns the 1-based parameter number.
    pub fn find_param_num_by_name(&self, name: &str) -> Option<u32> {
        let virtual_params = self.virtual_params.unwrap_or(&[]);

        // First search virtual params (index 0 -> param_num 1)
        if let Some(idx) = virtual_params.iter().position(|p| p.base.name == name) {
            return Some((idx + 1) as u32);
        }

        // Then search regular params (offset by virtual_params.len())
        if let Some(idx) = self.params.iter().position(|p| p.base.name == name) {
            return Some((virtual_params.len() + idx + 1) as u32);
        }

        None
    }
}

/// Errors that can occur during MTXML generation.
#[derive(Debug)]
pub enum GeneratorError {
    /// Error during XML serialization
    Serialization(String),
    /// Missing reference error - a RefId was used but no matching definition exists
    MissingReference {
        /// Type of reference (ParameterRef, ComObjectRef, ParameterType, etc.)
        ref_type: String,
        /// The RefId that was used but not found
        ref_id: String,
        /// Where the reference was used (e.g., "Dynamic/Choose" or "ParameterRefRef")
        context: String,
    },
    /// Unknown translation target - a translation references a non-existent param, object, or enum variant
    UnknownTranslation {
        /// The language this translation is for
        language: String,
        /// The reference path that couldn't be resolved (e.g., "IconSelection::Nightasdasdads")
        ref_path: String,
        /// What kind of translation this was (enum, param, obj)
        kind: String,
    },
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            GeneratorError::MissingReference { ref_type, ref_id, context } => {
                write!(f, "Missing {ref_type} reference: '{ref_id}' referenced in {context}")
            }
            GeneratorError::UnknownTranslation { language, ref_path, kind } => {
                write!(f, "Unknown {kind} in translation for {language}: '{ref_path}' does not exist")
            }
        }
    }
}

impl std::error::Error for GeneratorError {}

/// Strip bytes belonging to `no_memory` (virtual) parameters from the raw defaults.
///
/// Virtual parameters exist in the Rust struct for metadata purposes but should not
/// occupy device memory. This function creates a new byte vector with the `no_memory`
/// fields' bytes removed.
pub(crate) fn strip_no_memory_bytes(raw_defaults: &[u8], params: &[EtsParamDefExt]) -> Vec<u8> {
    // Collect ranges of bytes to exclude (offset, size_bytes) for no_memory params
    let mut exclude_ranges: Vec<(usize, usize)> = params
        .iter()
        .filter(|p| p.base.no_memory)
        .map(|p| {
            let offset = p.base.offset as usize;
            let size_bytes = (p.base.size_bits as usize).div_ceil(8);
            (offset, size_bytes)
        })
        .collect();

    // If no no_memory params, return as-is
    if exclude_ranges.is_empty() {
        return raw_defaults.to_vec();
    }

    // Sort by offset and merge overlapping ranges
    exclude_ranges.sort_by_key(|(offset, _)| *offset);

    // Build output by copying non-excluded ranges
    let mut result = Vec::with_capacity(raw_defaults.len());
    let mut current_pos = 0;

    for (exclude_start, exclude_size) in &exclude_ranges {
        // Copy bytes before this exclusion
        if current_pos < *exclude_start {
            result.extend_from_slice(&raw_defaults[current_pos..*exclude_start]);
        }
        // Skip past the excluded bytes
        current_pos = (*exclude_start + *exclude_size).max(current_pos);
    }

    // Copy any remaining bytes after the last exclusion
    if current_pos < raw_defaults.len() {
        result.extend_from_slice(&raw_defaults[current_pos..]);
    }

    result
}

/// Get the medium type string from a mask version.
pub(crate) fn medium_type_from_mask(mask_version: u16) -> &'static str {
    // High nibble of high byte determines medium type
    match (mask_version >> 12) & 0xF {
        0 => "MT-0", // TP1 (Twisted Pair)
        1 => "MT-1", // PL110
        2 => "MT-2", // RF
        5 => "MT-5", // KNXnet/IP
        _ => "MT-0", // Default to TP1
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_family_detection() {
        assert_eq!(MaskFamily::from_mask_version(0x0701), MaskFamily::System7); // 0701 is System7
        assert_eq!(MaskFamily::from_mask_version(0x07B0), MaskFamily::SystemB);
        assert_eq!(MaskFamily::from_mask_version(0x57B0), MaskFamily::SystemB); // 57B0 maps to SystemB
        assert_eq!(MaskFamily::from_mask_version(0x0912), MaskFamily::Bim); // 0912 is Bim
    }

    #[test]
    fn test_medium_type() {
        assert_eq!(medium_type_from_mask(0x07B0), "MT-0"); // TP1
        assert_eq!(medium_type_from_mask(0x57B0), "MT-5"); // KNXnet/IP
        assert_eq!(medium_type_from_mask(0x27B0), "MT-2"); // RF
    }
}
