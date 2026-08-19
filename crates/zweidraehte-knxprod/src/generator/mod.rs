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
mod project;
mod traversal;

// The packaging half — signing, ZIP archives, `.knxproj` topology —
// needs the crypto/HTTP/ZIP stack, so it is gated here, once per
// module, rather than on the individual items. Everything above builds
// with quick-xml alone.
#[cfg(feature = "packaging")]
mod packaging;
#[cfg(feature = "packaging")]
mod project_gen;

use std::collections::BTreeMap;

use crate::definition::module::ModuleCollection;
use crate::definition::page_layout::PageStructure;
use crate::schema::{BaggageDef, BusAccessType, MaskFamily};

use zweidraehte_device::ets::{
    DeviceDescriptor, EtsCommObjectDef, EtsCommObjectRefDef, EtsParamDefExt, EtsTranslation, EtsUnionFieldInfo,
};

// Re-export public types
pub use baggage::BaggageGenerator;
pub use builder::{AppProgramRef, BuilderError, HardwareRef, KnxprodBuilder, KnxprodOutput};
pub use catalog::CatalogGenerator;
pub use hardware::HardwareGenerator;
pub use mtxml::MtxmlGenerator;
pub use project::DeviceInstanceDef;

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
    pub primary: BTreeMap<String, String>,
    /// Text-based ref map: (param_name, text_override) -> ref_id
    /// For union variant params that have different text overrides in different contexts
    pub by_text: BTreeMap<(String, Option<String>), String>,
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
    /// Device serial number for load procedure verification.
    ///
    /// Used in the `LdCtrlCompareProp` load control to verify the device
    /// identity before programming. This is the hardware serial number
    /// that ETS checks against `PID_SERIAL_NUMBER`.
    pub serial_number: [u8; 6],
}

/// BCU2 (mask 0020h family) memory layout: the RT2 table page and the
/// parameter block, each its own absolute EEPROM segment.
///
/// The table segment's `Data` is the device's baked boot image — that
/// is load-bearing, not decoration: the download engine synthesizes
/// group object tables with zeroed RAM pointers and only preserves
/// real ones through `Cot2::overlay`, which runs when the product
/// ships the table bytes as segment data. The parameter segment's
/// data is the generator's `param_defaults` blob, so parameters sit
/// at offset 0 of their segment and the `<Memory>` references need no
/// base-offset arithmetic.
#[derive(Debug, Clone)]
pub struct Bcu2MemoryLayout {
    /// Address of the table segment — 0100h on every BCU2.
    pub tables_address: u32,
    /// The baked table page (`Bcu2DeviceDefinition::build_eeprom()` up
    /// to the parameter block).
    pub tables_data: &'static [u8],
    /// Table offsets within the table segment, from the definition's
    /// `addr_table_offset()` / `assoc_table_offset()` / `cot_offset()`.
    pub addr_table_offset: u32,
    pub assoc_table_offset: u32,
    pub cot_offset: u32,
    /// Address of the parameter segment (its size and data come from
    /// `param_defaults`).
    pub params_address: u32,
}

// ============================================================================
// Public Definition Types
// ============================================================================

/// Everything needed to generate one ApplicationProgram XML file.
///
/// Contains only application-program-level concerns: parameters,
/// communication objects, page layout, modules, and memory layout.
/// Hardware/product/catalog properties are defined separately via
/// [`ProductDef`], [`HardwareDef`], and [`CatalogSectionDef`].
pub struct ApplicationProgramDef<'a> {
    /// Human-readable application name (becomes `ApplicationProgram/@Name`).
    pub name: &'a str,
    /// Device descriptor with mask version, manufacturer ID, application ID/version, etc.
    pub device: &'a DeviceDescriptor,
    /// Extended parameter definitions with enum variants.
    pub params: &'a [EtsParamDefExt],
    /// Virtual parameter definitions (ETS-only, not stored in device memory).
    pub virtual_params: Option<&'a [EtsParamDefExt]>,
    /// Default parameter values as raw bytes.
    pub param_defaults: &'a [u8],
    /// Communication object definitions.
    pub comm_objects: &'a [EtsCommObjectDef],
    /// Communication object reference definitions (for multi-ref objects).
    pub comm_object_refs: &'a [EtsCommObjectRefDef],
    /// Union fields from derive macro.
    pub union_fields: Option<&'a [EtsUnionFieldInfo]>,
    /// Channel name for the UI grouping.
    pub channel_name: &'a str,
    /// Base address for absolute segments (System 7 only, deprecated — use `system7_layout`).
    pub absolute_segment_address: Option<u32>,
    /// System 7 memory layout configuration.
    pub system7_layout: Option<System7MemoryLayout>,
    /// BCU2 memory layout configuration.
    pub bcu2_layout: Option<Bcu2MemoryLayout>,
    /// Application hash/suffix for the ApplicationProgram ID (4 hex chars).
    /// If None, defaults to "0000".
    pub application_hash: Option<&'a str>,
    /// Non-registration relevant data version.
    pub non_reg_relevant_data_version: Option<u32>,
    /// Previous versions this program replaces (space-separated list).
    pub replaces_versions: Option<&'a str>,
    /// Hash of the application data (base64 encoded).
    pub application_data_hash: Option<&'a str>,
    /// Page layout definition for the Dynamic section.
    pub page_layout: Option<PageStructure>,
    /// Module collection for ModuleDefs/Module instances.
    pub modules: Option<ModuleCollection>,
    /// Baggage definitions (icons, etc.).
    pub baggages: Option<&'a [BaggageDef<'a>]>,
    /// Translations for non-default languages.
    pub translations: Option<&'a [EtsTranslation]>,
    /// Bus interface definitions for IP Interface devices.
    ///
    /// Each entry declares one tunneling/USB/routing channel that ETS can
    /// assign an additional individual address to. Typically 4 entries for
    /// an IP Interface with 4 tunneling channels.
    pub bus_interfaces: Option<&'a [BusInterfaceDef]>,
    /// Number of additional individual addresses the device supports (for tunneling channels).
    /// Corresponds to `ApplicationProgram/@AdditionalAddressesCount`.
    pub additional_addresses_count: Option<u32>,
    /// IP configuration mode. Typically `"Tool"` for tool-configured devices.
    /// Corresponds to `ApplicationProgram/@IPConfig`.
    pub ip_config: Option<&'a str>,
    /// Marks the device as KNX Data Secure-capable. Emits
    /// `ApplicationProgram/@IsSecureEnabled`. ETS only offers secure
    /// configuration options when this is `Some(true)`.
    pub is_secure_enabled: Option<bool>,
    /// KNX IP Secure user-password table capacity. Emits
    /// `ApplicationProgram/@MaxUserEntries`, which is how ETS learns how
    /// many `PID_PASSWORD_HASHES` entries the device can hold.
    ///
    /// **Required on any IP Secure device.** ETS builds its IP security
    /// config from this attribute alone — it never reads the capacity from
    /// the device — and treats an absent attribute as `0`, failing the
    /// download with "too many assigned users" before any bus traffic.
    /// 03/08/09 §2.5.2 requires at least one entry (User ID 1, the
    /// management user ETS itself authenticates as), so set this to at
    /// least `1` and never above the firmware's `MAX_PW`.
    pub max_user_entries: Option<u16>,
    /// KNX IP Secure tunnelling-user table capacity (`PID_TUNNELLING_USERS`).
    /// Emits `ApplicationProgram/@MaxTunnelingUserEntries`. Leave `None`
    /// (default 0) on devices that do no secure tunnelling; must not exceed
    /// the firmware's `MAX_TU`.
    pub max_tunneling_user_entries: Option<u16>,
    /// Secure Individual Address Table (SIAT) capacity — one entry per
    /// configured P2P peer. Emits
    /// `ApplicationProgram/@MaxSecurityIndividualAddressEntries`. Must
    /// not exceed the firmware's actual SIAT size.
    pub max_security_individual_address_entries: Option<u16>,
    /// Group key table capacity — one entry per group address the
    /// device may subscribe to. Emits
    /// `ApplicationProgram/@MaxSecurityGroupKeyTableEntries`. Must not
    /// exceed the firmware's actual group-key table size (typically
    /// matches the address table size).
    pub max_security_group_key_table_entries: Option<u16>,
    /// Peer-to-peer key table capacity. Emits
    /// `ApplicationProgram/@MaxSecurityP2PKeyTableEntries`. Leave as
    /// `None` (default 0) on devices that do not support P2P traffic.
    pub max_security_p2p_key_table_entries: Option<u16>,
}

/// Definition of a single bus interface channel.
///
/// Used in [`ApplicationProgramDef::bus_interfaces`] to declare
/// tunneling, USB, or routing channels for ETS.
#[derive(Debug, Clone)]
pub struct BusInterfaceDef {
    /// Slot index in the device's additional IA table (PID 53).
    /// Typically 1-based (1, 2, 3, ...).
    pub address_index: u8,
    /// Access type for this channel.
    pub access_type: BusAccessType,
    /// Human-readable label shown in ETS (e.g., "Tunneling Channel 1").
    pub text: Option<&'static str>,
}

/// A product variant within a hardware definition.
///
/// Multiple products can exist per hardware — for example, "55" and "63"
/// frame variants of the same push button that differ only in order number
/// and product text.
pub struct ProductDef<'a> {
    /// Product display text (shown in ETS catalog).
    pub name: &'a str,
    /// Product order number (for ordering/identification).
    pub order_number: &'a str,
    /// Whether the device is rail-mounted (DIN rail).
    pub is_rail_mounted: bool,
    /// Optional additional description text.
    pub visible_description: Option<&'a str>,
}

/// A hardware definition linking products to application programs.
///
/// In the XML, a `<Hardware>` element contains `<Products>` and
/// `<Hardware2Programs>`. Multiple products can share the same hardware,
/// and multiple `<Hardware2Program>` entries can link to different
/// application programs.
pub struct HardwareDef<'a> {
    /// Device serial number (6 bytes, first 2 should match manufacturer_id).
    pub serial_number: [u8; 6],
    /// Hardware version number (displayed in ETS).
    pub hardware_version: u8,
    /// Hardware name (displayed in ETS hardware list).
    pub name: &'a str,
    /// Bus current consumption in mA (optional).
    pub bus_current: Option<u16>,
    /// Whether this hardware is an IP-enabled device.
    /// Corresponds to `Hardware/@IsIPEnabled`.
    pub is_ip_enabled: Option<bool>,
    /// Whether this KNX-RF device acts as a retransmitter (repeater).
    /// Corresponds to `Hardware/@IsRFRetransmitter`. Leave `None` for
    /// non-RF hardware; ETS treats an absent attribute as `false`.
    pub is_rf_retransmitter: Option<bool>,
    /// KNX-RF receive capability class. Corresponds to
    /// `Hardware/@RFRxCapabilities`. Only meaningful for RF hardware.
    pub rf_rx_capabilities: Option<RfRxCapabilities>,
    /// KNX-RF transmit capability class. Corresponds to
    /// `Hardware/@RFTxCapabilities`. Only meaningful for RF hardware.
    pub rf_tx_capabilities: Option<RfTxCapabilities>,
    /// Products in this hardware definition.
    pub products: Vec<ProductDef<'a>>,
    /// Application programs linked to this hardware.
    /// Each entry creates a `<Hardware2Program>` element.
    pub application_programs: Vec<AppProgramRef>,
}

/// KNX-RF receive capability class (`Hardware/@RFRxCapabilities`).
///
/// Mirrors the `RFRxCapabilities_t` enumeration in the KNX project
/// schema. The value is registration-relevant — it feeds the hardware
/// hash — so it must serialize to the exact spec string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfRxCapabilities {
    /// Standard receive timing.
    Ready,
    /// Fast receive timing.
    ReadyFast,
    /// Slow receive timing.
    Slow,
}

impl RfRxCapabilities {
    /// The exact schema string emitted into `@RFRxCapabilities`.
    pub fn as_str(self) -> &'static str {
        match self {
            RfRxCapabilities::Ready => "Ready",
            RfRxCapabilities::ReadyFast => "ReadyFast",
            RfRxCapabilities::Slow => "Slow",
        }
    }
}

/// KNX-RF transmit capability class (`Hardware/@RFTxCapabilities`).
///
/// Mirrors the `RFTxCapabilities_t` enumeration in the KNX project
/// schema. Registration-relevant, same as [`RfRxCapabilities`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfTxCapabilities {
    /// Standard transmit timing.
    Ready,
    /// Fast transmit timing.
    ReadyFast,
    /// Both fast and slow transmit timing.
    ReadyFastSlow,
}

impl RfTxCapabilities {
    /// The exact schema string emitted into `@RFTxCapabilities`.
    pub fn as_str(self) -> &'static str {
        match self {
            RfTxCapabilities::Ready => "Ready",
            RfTxCapabilities::ReadyFast => "ReadyFast",
            RfTxCapabilities::ReadyFastSlow => "ReadyFastSlow",
        }
    }
}

/// A catalog entry linking a product to a hardware-to-program mapping.
///
/// Each entry becomes a `<CatalogItem>` in the output XML. It references
/// a specific product (by order number within a hardware) and a specific
/// application program (via the Hardware2Program linkage).
pub struct CatalogEntryDef<'a> {
    /// Display name in ETS catalog.
    pub name: &'a str,
    /// Which hardware this entry refers to.
    pub hardware: HardwareRef,
    /// Which product within that hardware (by order number).
    pub product_order_number: &'a str,
    /// Which application program (determines the Hardware2Program link).
    pub application_program: AppProgramRef,
}

/// A section (category) in the ETS catalog, containing entries and/or
/// nested subsections.
pub struct CatalogSectionDef<'a> {
    /// Section name (displayed in ETS).
    pub name: &'a str,
    /// Catalog entries in this section.
    pub entries: Vec<CatalogEntryDef<'a>>,
    /// Nested sub-sections.
    pub subsections: Vec<CatalogSectionDef<'a>>,
}

/// Convenience struct for the common single-device case.
///
/// Captures all the hardware/product/catalog data while referencing an
/// [`ApplicationProgramDef`] for the program-specific data. Internally,
/// `KnxprodBuilder::single_device` expands this into one hardware with
/// one product, one Hardware2Program, one catalog section, and one
/// catalog item.
pub struct SingleDeviceDef<'a> {
    /// The application program definition.
    pub app: &'a ApplicationProgramDef<'a>,
    /// Device serial number (6 bytes).
    pub serial_number: [u8; 6],
    /// Hardware version number.
    pub hardware_version: u8,
    /// Hardware name.
    pub hardware_name: &'a str,
    /// Product display text.
    pub product_name: &'a str,
    /// Product order number.
    pub order_number: &'a str,
    /// Whether the device is rail-mounted.
    pub is_rail_mounted: bool,
    /// Catalog section name.
    pub catalog_section: &'a str,
    /// Whether this hardware is an IP-enabled device.
    /// Corresponds to `Hardware/@IsIPEnabled`.
    pub is_ip_enabled: Option<bool>,
    /// Whether this hardware is a KNX-RF retransmitter.
    /// Corresponds to `Hardware/@IsRFRetransmitter`.
    pub is_rf_retransmitter: Option<bool>,
    /// KNX-RF receive capabilities (`Hardware/@RFRxCapabilities`).
    pub rf_rx_capabilities: Option<RfRxCapabilities>,
    /// KNX-RF transmit capabilities (`Hardware/@RFTxCapabilities`).
    pub rf_tx_capabilities: Option<RfTxCapabilities>,
}

/// Internal configuration passed to the MTXML generator.
///
/// This type is an implementation detail — external code should use
/// [`ApplicationProgramDef`] + [`SingleDeviceDef`] or the multi-device
/// builder API instead. The builder constructs this internally as an
/// adapter for `MtxmlGenerator`.
pub(crate) struct ApplicationProgramConfig<'a> {
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
    /// BCU2 memory layout configuration.
    pub bcu2_layout: Option<Bcu2MemoryLayout>,
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
    /// Bus interface definitions for IP Interface devices.
    pub bus_interfaces: Option<&'a [BusInterfaceDef]>,
    pub additional_addresses_count: Option<u32>,
    pub ip_config: Option<&'a str>,
    pub is_secure_enabled: Option<bool>,
    pub max_user_entries: Option<u16>,
    pub max_tunneling_user_entries: Option<u16>,
    pub max_security_individual_address_entries: Option<u16>,
    pub max_security_group_key_table_entries: Option<u16>,
    pub max_security_p2p_key_table_entries: Option<u16>,
}

impl<'a> ApplicationProgramConfig<'a> {
    /// Get the mask family for this configuration.
    pub fn mask_family(&self) -> MaskFamily {
        MaskFamily::from_mask_version(self.device.mask_version.as_u16())
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
    /// The ApplicationPrograms list is empty; at least one program is required
    EmptyApplicationPrograms,
    /// A parameter size_bits value is outside the range [1, 63]
    InvalidParameterSize {
        /// The out-of-range value
        size_bits: u16,
    },
    /// A parameter extends past the end of the code segment holding it
    ParameterOutOfSegment {
        /// Name of the offending parameter
        param_name: &'static str,
        /// Byte offset the parameter starts at
        offset: usize,
        /// First byte past the parameter
        end: usize,
        /// Declared size of the segment
        segment_size: usize,
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
            GeneratorError::EmptyApplicationPrograms => {
                write!(f, "ApplicationPrograms list is empty; at least one program is required")
            }
            GeneratorError::InvalidParameterSize { size_bits } => {
                write!(f, "Parameter size_bits {size_bits} is out of range [1, 63]")
            }
            GeneratorError::ParameterOutOfSegment { param_name, offset, end, segment_size } => {
                write!(
                    f,
                    "Parameter '{param_name}' occupies bytes {offset}..{end} but its code segment is only \
                     {segment_size} bytes: either the segment is declared too small or the parameter struct \
                     has outgrown it (consider `#[ets(no_memory)]` for parameters the device does not need)"
                )
            }
        }
    }
}

impl std::error::Error for GeneratorError {}

// There is deliberately no `strip_no_memory_bytes` here.
//
// An earlier version removed each tool-only parameter's bytes from the defaults
// blob, for a design where such parameters still occupied the params struct.
// That design was rejected — the struct is the download image, so a parameter
// ETS is never told the offset of must not sit in it at all — and
// `#[ets(no_memory)]` now drops the field before the struct is emitted. Nothing
// is left to strip, and stripping would be actively wrong: tool-only parameters
// carry offset 0, so it would have removed the first bytes of real parameters.

/// Check that every stored parameter fits inside the code segment it is placed in.
///
/// Without this the generator will happily emit offsets past the end of the
/// declared segment — which is what the MDT replication did, running to offset
/// 546 in a segment declared as 498 bytes, producing XML ETS is likely to
/// reject. Failing here points at the parameter instead.
///
/// Only `config.params` is checked, which is exactly the set that carries
/// absolute offsets into this segment. Union *variant* parameters live in
/// `config.union_fields` with offsets relative to the union's data area, and
/// module parameters live in `config.modules` behind a `BaseOffset`; neither is
/// addressed in this space. Union *selector* parameters are in `config.params`
/// with a true struct offset and are checked like any other.
pub(crate) fn validate_param_offsets(config: &ApplicationProgramConfig) -> Result<(), GeneratorError> {
    // System 7 devices declare their segments explicitly; everything else sizes
    // the segment from the defaults blob, which is the struct itself.
    let segment_size = match config.system7_layout {
        Some(ref layout) => layout
            .segments
            .iter()
            .find(|segment| segment.memory_type == Some("EEPROM"))
            .map(|segment| segment.size as usize)
            .unwrap_or(config.param_defaults.len()),
        None => config.param_defaults.len(),
    };

    for param_ext in config.params {
        let param = &param_ext.base;
        if param.no_memory {
            continue;
        }

        let end = param.offset as usize + (param.size_bits as usize).div_ceil(8);
        if end > segment_size {
            return Err(GeneratorError::ParameterOutOfSegment {
                param_name: param.name,
                offset: param.offset as usize,
                end,
                segment_size,
            });
        }
    }

    Ok(())
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
