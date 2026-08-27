//! KNX Master Data Parser
//!
//! Parses the knx_master.xml file to extract mask version definitions,
//! resource locations, and table configurations. This information is
//! essential for properly generating memory layouts and table structures
//! based on the device's mask version.
//!
//! # Overview
//!
//! Different KNX mask versions (e.g., MV-0705 for System 7.5, MV-07B0 for System B)
//! define different memory addressing schemes:
//!
//! - **StandardMemory**: Fixed absolute addresses (older BCU systems)
//! - **SystemProperty**: Properties of interface objects
//! - **RelativeMemory**: Dynamic allocation via load state machines (System B)
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_ets_files::MasterData;
//! use zweidraehte_ets_files::schema::master_data::ResourceName;
//!
//! let master = MasterData::from_file("knx_master.xml")?;
//! let mv = master.get_mask_version("MV-07B0")?;
//!
//! // Get address table location for this mask version
//! if let Some(resource) = mv.get_resource(ResourceName::GroupAddressTable) {
//!     match &resource.location {
//!         AddressSpaceLocation::RelativeMemory { interface_object_ref, property_id, .. } => {
//!             // System B: table is loaded dynamically
//!         }
//!         AddressSpaceLocation::StandardMemory { start_address } => {
//!             // System 7.x: table is at fixed address
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use crate::schema::LoadControl;

#[derive(Debug, thiserror::Error)]
pub enum MasterDataError {
    #[error("cannot read ETS master data from {path}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse ETS master data")]
    Xml(#[source] quick_xml::DeError),
}

/// Root element of the KNX XML file (wraps MasterData).
#[derive(Debug, Clone, Deserialize)]
pub struct KnxRoot {
    #[serde(rename = "MasterData")]
    pub master_data: MasterDataElement,
}

/// MasterData element containing mask versions.
#[derive(Debug, Clone, Deserialize)]
pub struct MasterDataElement {
    /// Stable document ID in current schemas. Project-11 master data predates
    /// the attribute, so an empty value represents its absence there.
    #[serde(rename = "@Id", default)]
    pub id: String,

    #[serde(rename = "@Version")]
    pub version: String,

    #[serde(rename = "MaskVersions")]
    pub mask_versions: Option<MaskVersions>,

    #[serde(rename = "PropertyDataTypes", default)]
    pub property_data_types: Option<PropertyDataTypes>,
}

/// Convenience wrapper for working with KNX master data.
pub struct MasterData {
    root: KnxRoot,
}

impl FromStr for MasterData {
    type Err = MasterDataError;

    fn from_str(xml: &str) -> Result<Self, Self::Err> {
        let root: KnxRoot = quick_xml::de::from_str(xml).map_err(MasterDataError::Xml)?;
        Ok(Self { root })
    }
}

impl MasterData {
    /// Parse master data from an XML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, MasterDataError> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|source| MasterDataError::Io { path: path.to_owned(), source })?;
        content.parse()
    }

    /// Get the raw mask versions container.
    pub fn mask_versions(&self) -> Option<&MaskVersions> {
        self.root.master_data.mask_versions.as_ref()
    }

    /// Get a mask version by its ID (e.g., "MV-07B0").
    pub fn get_mask_version(&self, id: &str) -> Option<&MaskVersion> {
        self.mask_versions().and_then(|mv| mv.versions.iter().find(|v| v.id == id))
    }

    /// Get a mask version by its numeric version code (e.g., 1968 for MV-07B0).
    pub fn get_mask_version_by_code(&self, code: u16) -> Option<&MaskVersion> {
        self.mask_versions().and_then(|mv| mv.versions.iter().find(|v| v.mask_version_code == code))
    }

    /// Get total number of mask versions.
    pub fn mask_version_count(&self) -> usize {
        self.mask_versions().map(|mv| mv.versions.len()).unwrap_or(0)
    }

    /// Fixed wire width of a property data type declared by master data.
    /// Variable-length PDTs intentionally return `None`.
    pub fn property_data_type_size(&self, name: &str) -> Option<u32> {
        self.root
            .master_data
            .property_data_types
            .as_ref()?
            .types
            .iter()
            .find(|data_type| data_type.name == name)
            .and_then(|data_type| data_type.size)
    }
}

/// Property data type catalogue bundled with `knx_master.xml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PropertyDataTypes {
    #[serde(rename = "PropertyDataType", default)]
    pub types: Vec<PropertyDataType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PropertyDataType {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Size", default)]
    pub size: Option<u32>,
}

/// Container for mask version definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct MaskVersions {
    #[serde(rename = "MaskVersion", default)]
    pub versions: Vec<MaskVersion>,
}

/// A KNX mask version definition.
///
/// Each mask version defines the capabilities and memory layout of a
/// particular device family.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MaskVersion {
    /// Mask version ID (e.g., "MV-07B0")
    #[serde(rename = "@Id")]
    pub id: String,

    /// Numeric mask version code (e.g., 1968 = 0x07B0)
    #[serde(rename = "@MaskVersion")]
    pub mask_version_code: u16,

    /// Human-readable name (e.g., "System B")
    #[serde(rename = "@Name")]
    pub name: String,

    /// Management model identifier (e.g., "SystemB", "BimM112")
    #[serde(rename = "@ManagementModel")]
    pub management_model: String,

    /// Medium type reference ID
    #[serde(rename = "@MediumTypeRefId", default)]
    pub medium_type_ref_id: Option<String>,

    /// Hawk configuration data containing features and resources
    /// (Some mask versions may have multiple HawkConfigurationData elements)
    #[serde(rename = "HawkConfigurationData", default)]
    pub hawk_configs: Vec<HawkConfigurationData>,

    /// The older masks whose application programs this mask runs
    /// (MV-0020 lists MV-0010/0011/0012: a BCU2 executes BCU1
    /// programs in its compat mode). ETS accepts a product for any
    /// mask listed here and then programs the device per *its own*
    /// mask — see `VerifyCompatibleMaskVersionTask` ("Match
    /// compatible") in a Hawk log.
    #[serde(rename = "DownwardCompatibleMasks", default)]
    downward_compatible_masks: Option<DownwardCompatibleMasks>,

    /// The mask's OS entry points — the routine addresses a program's
    /// `FixupList` patches into its code segments. Per mask: the same
    /// routine lives at 0D6Ch on MV-0012 and 5063h on MV-0020, which
    /// is the whole reason fixups exist.
    #[serde(rename = "MaskEntries", default)]
    mask_entries: Option<MaskEntries>,
}

/// Container for the mask's OS entry points.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MaskEntries {
    #[serde(rename = "MaskEntry", default)]
    pub entries: Vec<MaskEntry>,
}

/// One `<MaskEntry Id="MV-0012_ME-U.5Fdeb30" Name="U_deb30"
/// Address="3183" />`.
#[derive(Debug, Clone, Deserialize)]
pub struct MaskEntry {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Address")]
    pub address: u32,
}

/// Container for the downward-compatible mask references.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DownwardCompatibleMasks {
    #[serde(rename = "DownwardCompatibleMask", default)]
    pub masks: Vec<DownwardCompatibleMask>,
}

/// One `<DownwardCompatibleMask RefId="MV-0012" />` reference.
#[derive(Debug, Clone, Deserialize)]
pub struct DownwardCompatibleMask {
    #[serde(rename = "@RefId")]
    pub ref_id: String,
}

impl MaskVersion {
    /// The mask codes this mask is downward compatible with — whose
    /// application programs it runs (empty for most masks).
    ///
    /// The ref ids are `MV-xxxx` with the code in hex; a ref this
    /// cannot be read out of is skipped rather than failing the whole
    /// mask.
    pub fn downward_compatible_masks(&self) -> impl Iterator<Item = u16> + '_ {
        self.downward_compatible_masks
            .iter()
            .flat_map(|dcm| &dcm.masks)
            .filter_map(|mask| mask.ref_id.strip_prefix("MV-"))
            .filter_map(|hex| u16::from_str_radix(hex, 16).ok())
    }

    /// Whether a program written for mask `code` runs on this mask —
    /// the identical mask, or one this mask lists as downward
    /// compatible.
    pub fn is_downward_compatible_with(&self, code: u16) -> bool {
        self.mask_version_code == code || self.downward_compatible_masks().any(|mask| mask == code)
    }

    /// The address of a mask OS entry point, looked up by the
    /// `_ME-…` id suffix a program's `Fixup/@FunctionRef` carries.
    ///
    /// Matched by suffix, never by the full id: the reference embeds
    /// the *product's* mask (`MV-0012_ME-U.5Fdeb30`) while every
    /// mask's own entry carries its own prefix — and the point of the
    /// lookup is resolving a BCU1 program's routine names against the
    /// BCU2 that actually executes them.
    pub fn mask_entry_address(&self, me_suffix: &str) -> Option<u32> {
        self.mask_entries
            .iter()
            .flat_map(|me| &me.entries)
            .find(|entry| entry.id.rsplit_once("_ME-").map(|(_, suffix)| suffix) == Some(me_suffix))
            .map(|entry| entry.address)
    }

    /// Check if this is a System B mask version.
    pub fn is_system_b(&self) -> bool {
        self.management_model == "SystemB"
    }

    /// Check whether this mask uses the System 7 management model.
    pub fn is_system7(&self) -> bool {
        self.management_model == "BimM112"
    }

    /// Get the first HawkConfigurationData element (most mask versions only have one).
    pub fn hawk_config(&self) -> Option<&HawkConfigurationData> {
        self.hawk_configs.first()
    }

    /// Get a feature value by name.
    pub fn get_feature(&self, name: &str) -> Option<&str> {
        self.hawk_config().and_then(|hc| {
            hc.features
                .as_ref()
                .and_then(|f| f.features.iter().find(|feat| feat.name == name))
                .map(|f| f.value.as_str())
        })
    }

    /// Get the first application object index for this mask version.
    pub fn first_app_object_idx(&self) -> u8 {
        self.get_feature("FirstAppObjectIdx").and_then(|v| v.parse().ok()).unwrap_or(5)
    }

    /// Get a resource definition by name.
    pub fn get_resource(&self, name: ResourceName) -> Option<&Resource> {
        self.hawk_config()
            .and_then(|hc| hc.resources.as_ref().and_then(|r| r.resources.iter().find(|res| res.name == name.as_str())))
    }

    /// Get the address table resource definition.
    pub fn address_table(&self) -> Option<&Resource> {
        self.get_resource(ResourceName::GroupAddressTable)
    }

    /// Get the association table resource definition.
    pub fn association_table(&self) -> Option<&Resource> {
        self.get_resource(ResourceName::GroupAssociationTable)
    }

    /// Get the group object table resource definition.
    pub fn group_object_table(&self) -> Option<&Resource> {
        self.get_resource(ResourceName::GroupObjectTable)
    }

    /// All programming procedures of this mask (empty slice when the
    /// master data carries none).
    pub fn procedures(&self) -> &[Procedure] {
        self.hawk_config().and_then(|hc| hc.procedures.as_ref()).map(|p| p.procedures.as_slice()).unwrap_or_default()
    }

    /// PDT name for an indexed interface-object property.
    pub fn indexed_property_data_type(&self, object_index: u8, property_id: u16) -> Option<&str> {
        self.hawk_config()?
            .interface_objects
            .as_ref()?
            .objects
            .iter()
            .find(|object| object.index == Some(object_index))?
            .properties
            .iter()
            .find(|property| property.property_id == property_id)
            .map(|property| property.property_data_type.as_str())
    }

    /// PDT name for an extended object-type-addressed property.
    pub fn typed_property_data_type(&self, object_type: u16, property_id: u16) -> Option<&str> {
        self.hawk_config()?
            .interface_objects
            .as_ref()?
            .objects
            .iter()
            .find(|object| object.object_type == Some(object_type))?
            .properties
            .iter()
            .find(|property| property.property_id == property_id)
            .map(|property| property.property_data_type.as_str())
    }

    /// Find a procedure by type (`"Load"` / `"Unload"`) and subtype
    /// (`"all"`, `"grp"`, …), preferring one a remote client may run.
    pub fn find_procedure(&self, procedure_type: &str, sub_type: &str) -> Option<&Procedure> {
        let matches =
            |p: &&Procedure| p.procedure_type == procedure_type && p.procedure_sub_type.as_deref() == Some(sub_type);
        // Should a mask ever list the same procedure twice with
        // different Access scopes, prefer the remote-capable one —
        // we are always the bus-side client.
        self.procedures()
            .iter()
            .find(|p| matches(p) && p.allows_remote())
            .or_else(|| self.procedures().iter().find(matches))
    }

    /// Build a lookup table of all resources by name.
    /// Resources of the **first** `HawkConfigurationData` block only
    /// (see [`hawk_config`](Self::hawk_config)): a mask may carry
    /// several blocks (MV-07B0 has two, differing in `Access` scope),
    /// and the first is the complete remote-access one — the later
    /// blocks are subsets. Widening this to merge all blocks would
    /// have to decide collision semantics first.
    pub fn resource_map(&self) -> HashMap<&str, &Resource> {
        let mut map = HashMap::new();
        if let Some(hc) = self.hawk_config()
            && let Some(resources) = &hc.resources
        {
            for res in &resources.resources {
                map.insert(res.name.as_str(), res);
            }
        }
        map
    }
}

/// Well-known resource names in KNX master data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceName {
    /// Group address table (ADT)
    GroupAddressTable,
    /// Group association table (AST)
    GroupAssociationTable,
    /// Group object table (COT)
    GroupObjectTable,
    /// Address table load control
    GroupAddressTableLoadControl,
    /// Association table load control
    GroupAssociationTableLoadControl,
    /// Application program load control. The published master data
    /// spells the prefix `Application`, not `ApplicationProgram`.
    ApplicationLoadControl,
    /// PEI program load control
    PeiprogLoadControl,
}

impl ResourceName {
    /// Get the string name as used in the XML.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceName::GroupAddressTable => "GroupAddressTable",
            ResourceName::GroupAssociationTable => "GroupAssociationTable",
            ResourceName::GroupObjectTable => "GroupObjectTable",
            ResourceName::GroupAddressTableLoadControl => "GroupAddressTableLoadControl",
            ResourceName::GroupAssociationTableLoadControl => "GroupAssociationTableLoadControl",
            ResourceName::ApplicationLoadControl => "ApplicationLoadControl",
            ResourceName::PeiprogLoadControl => "PeiprogLoadControl",
        }
    }
}

/// Hawk configuration data for a mask version.
///
/// Note: We only deserialize this, not serialize. Serialization derives are kept for
/// consistency but some fields are skipped during serialization.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HawkConfigurationData {
    #[serde(rename = "Features", default)]
    pub features: Option<Features>,

    #[serde(rename = "Resources", default)]
    pub resources: Option<Resources>,

    /// The per-mask programming procedure templates (`LdCtrl*`
    /// instruction streams). System B masks carry complete generic
    /// Load procedures (with `LdCtrlMerge` splice points for the
    /// product's MTXML fragments); System 7 masks carry
    /// only `Unload all` — their Load procedures are entirely
    /// product-specific.
    #[serde(rename = "Procedures", default)]
    pub procedures: Option<Procedures>,

    #[serde(rename = "InterfaceObjects", default)]
    pub interface_objects: Option<InterfaceObjects>,

    // Present but not needed by the current runtime model.
    #[serde(rename = "MemorySegments", default)]
    _memory_segments: IgnoredElement,
}

/// Interface-object property metadata for one mask. This is what gives a
/// load procedure's raw `InlineData` its actual per-element wire width.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InterfaceObjects {
    #[serde(rename = "InterfaceObject", default)]
    pub objects: Vec<InterfaceObject>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceObject {
    #[serde(rename = "@Index", default)]
    pub index: Option<u8>,
    #[serde(rename = "@ObjectType", default)]
    pub object_type: Option<u16>,
    #[serde(rename = "Property", default)]
    pub properties: Vec<InterfaceObjectProperty>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceObjectProperty {
    #[serde(rename = "@PropertyID")]
    pub property_id: u16,
    #[serde(rename = "@PropertyDataType")]
    pub property_data_type: String,
}

/// Container for the programming procedures of a mask version.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Procedures {
    #[serde(rename = "Procedure", default)]
    pub procedures: Vec<Procedure>,
}

/// One programming procedure: a typed stream of `LdCtrl*`
/// instructions, reusing the MTXML [`LoadControl`] vocabulary from
/// [`crate::schema`] (master data uses the same element language
/// plus the tool-side-only superset).
#[derive(Debug, Clone, Deserialize)]
pub struct Procedure {
    /// `"Load"` or `"Unload"`.
    #[serde(rename = "@ProcedureType")]
    pub procedure_type: String,

    /// What the procedure covers: `"all"`, `"grp"` (group addresses +
    /// associations), `"par"` (parameters), `"par,grp"`, `"cfg"`, or
    /// `"ap1"` (application 1 only).
    #[serde(rename = "@ProcedureSubType", default)]
    pub procedure_sub_type: Option<String>,

    /// Where the procedure may run from (e.g. `"remote local1
    /// local2"`); `remote` is the bus-client path.
    #[serde(rename = "@Access", default)]
    pub access: Option<String>,

    #[serde(rename = "$value", default)]
    pub controls: Vec<LoadControl>,
}

impl Procedure {
    pub fn is_load(&self) -> bool {
        self.procedure_type == "Load"
    }

    pub fn is_unload(&self) -> bool {
        self.procedure_type == "Unload"
    }

    /// Whether a remote management client (our case: the bus-side
    /// tool) may run this procedure. Procedures without an `Access`
    /// attribute carry no restriction.
    pub fn allows_remote(&self) -> bool {
        self.access.as_deref().is_none_or(|a| a.split_whitespace().any(|part| part == "remote"))
    }
}

/// A placeholder struct for XML elements we want to ignore during parsing.
#[derive(Debug, Clone, Default)]
struct IgnoredElement;

impl<'de> serde::Deserialize<'de> for IgnoredElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Consume and ignore the value
        let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(IgnoredElement)
    }
}

/// Container for feature definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct Features {
    #[serde(rename = "Feature", default)]
    pub features: Vec<Feature>,
}

/// A feature definition.
#[derive(Debug, Clone, Deserialize)]
pub struct Feature {
    #[serde(rename = "@Name")]
    pub name: String,

    #[serde(rename = "@Value")]
    pub value: String,
}

/// Container for resource definitions.
#[derive(Debug, Clone, Deserialize)]
pub struct Resources {
    #[serde(rename = "Resource", default)]
    pub resources: Vec<Resource>,
}

/// A resource definition specifying how to access a particular memory region.
#[derive(Debug, Clone, Deserialize)]
pub struct Resource {
    /// Resource name (e.g., "GroupAddressTable")
    #[serde(rename = "@Name")]
    pub name: String,

    /// Access modes (e.g., "remote local2")
    #[serde(rename = "@Access")]
    pub access: Option<String>,

    /// Location specification
    #[serde(rename = "Location")]
    pub location: Option<Location>,

    /// Resource type specification
    #[serde(rename = "ResourceType")]
    pub resource_type: Option<ResourceType>,

    /// Access rights
    #[serde(rename = "AccessRights")]
    pub access_rights: Option<AccessRights>,
}

impl Resource {
    /// Check if this resource uses relative memory (System B style).
    pub fn is_relative_memory(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "RelativeMemory").unwrap_or(false)
    }

    /// Check if this resource uses standard memory (fixed address).
    pub fn is_standard_memory(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "StandardMemory").unwrap_or(false)
    }

    /// Check if this resource is a system property.
    pub fn is_system_property(&self) -> bool {
        self.location.as_ref().map(|l| l.address_space == "SystemProperty").unwrap_or(false)
    }

    /// Get the interface object reference if applicable.
    pub fn interface_object_ref(&self) -> Option<u8> {
        self.location.as_ref().and_then(|l| l.interface_object_ref)
    }

    /// Get the property ID if applicable.
    pub fn property_id(&self) -> Option<u8> {
        self.location.as_ref().and_then(|l| l.property_id)
    }

    /// Get the start address if applicable.
    pub fn start_address(&self) -> Option<u32> {
        self.location.as_ref().and_then(|l| l.start_address)
    }

    /// Get the location's address space type.
    pub fn address_space(&self) -> Option<&str> {
        self.location.as_ref().map(|l| l.address_space.as_str())
    }
}

/// Location specification for a resource.
///
/// The meaning of fields depends on the `address_space` type:
/// - StandardMemory: Uses `start_address` as absolute memory address
/// - SystemProperty: Uses `interface_object_ref` + `property_id`
/// - RelativeMemory: Uses `interface_object_ref` + `property_id` for allocation info
/// - Pointer: Uses `ptr_resource` to reference another resource
/// - Constant: Uses `start_address` as constant value
/// - ADC: Uses `start_address` for ADC channel
/// - None: No physical location
#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    /// Address space type
    #[serde(rename = "@AddressSpace")]
    pub address_space: String,

    /// Start address (for StandardMemory, Constant, ADC)
    #[serde(rename = "@StartAddress")]
    pub start_address: Option<u32>,

    /// Interface object reference (for SystemProperty, RelativeMemory)
    #[serde(rename = "@InterfaceObjectRef")]
    pub interface_object_ref: Option<u8>,

    /// Property ID (for SystemProperty, RelativeMemory)
    #[serde(rename = "@PropertyID")]
    pub property_id: Option<u8>,

    /// Pointer resource name (for Pointer address space)
    #[serde(rename = "@PtrResource")]
    pub ptr_resource: Option<String>,
}

impl Location {
    /// Parse into a structured address space location enum.
    pub fn to_address_space(&self) -> AddressSpaceLocation {
        match self.address_space.as_str() {
            "StandardMemory" => AddressSpaceLocation::StandardMemory { start_address: self.start_address.unwrap_or(0) },
            "SystemProperty" => AddressSpaceLocation::SystemProperty {
                interface_object_ref: self.interface_object_ref.unwrap_or(0),
                property_id: self.property_id.unwrap_or(0),
                start_address: self.start_address.unwrap_or(0),
            },
            "RelativeMemory" => AddressSpaceLocation::RelativeMemory {
                interface_object_ref: self.interface_object_ref.unwrap_or(0),
                property_id: self.property_id.unwrap_or(0),
                start_address: self.start_address.unwrap_or(0),
            },
            "Constant" => AddressSpaceLocation::Constant { value: self.start_address.unwrap_or(0) },
            "Pointer" => AddressSpaceLocation::Pointer { ptr_resource: self.ptr_resource.clone().unwrap_or_default() },
            "ADC" => AddressSpaceLocation::Adc { channel: self.start_address.unwrap_or(0) },
            "None" | "" => AddressSpaceLocation::None,
            _ => AddressSpaceLocation::Unknown { address_space: self.address_space.clone() },
        }
    }
}

/// Structured address space location for easier pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSpaceLocation {
    /// Fixed absolute address in device memory.
    StandardMemory { start_address: u32 },

    /// System property on an interface object.
    SystemProperty { interface_object_ref: u8, property_id: u8, start_address: u32 },

    /// Relative memory allocated via load state machine.
    RelativeMemory { interface_object_ref: u8, property_id: u8, start_address: u32 },

    /// Constant value (not a memory location).
    Constant { value: u32 },

    /// Indirect via pointer resource.
    Pointer { ptr_resource: String },

    /// ADC channel.
    Adc { channel: u32 },

    /// No physical location.
    None,

    /// Unknown address space type.
    Unknown { address_space: String },
}

/// Resource type specification.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceType {
    /// Length in bytes
    #[serde(rename = "@Length")]
    pub length: u32,

    /// Semantic flavour (e.g., "AddressTable_SystemB")
    #[serde(rename = "@Flavour")]
    pub flavour: Option<String>,
}

/// Access rights for a resource.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessRights {
    #[serde(rename = "@Read")]
    pub read: String,

    #[serde(rename = "@Write")]
    pub write: String,
}

/// Table flavours that indicate the semantic type of a table resource.
///
/// These flavours determine the binary format of KNX tables (count field size,
/// entry size, and entry structure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFlavour {
    /// BCU1-style address table (1-byte count + 2-byte entries)
    AddressTableBcu1,
    /// System B address table (2-byte count + 2-byte entries)
    AddressTableSystemB,

    /// BCU1-style association table (1-byte count + 2-byte entries: u8 TSAP + u8 ASAP)
    AssociationTableBcu1,
    /// BCU2-style association table
    AssociationTableBcu2,
    /// System 7 association table
    AssociationTableSystem7,
    /// System B association table (2-byte count + 4-byte entries: u16 TSAP + u16 ASAP)
    AssociationTableSystemB,
    /// System B small association table (2-byte count + 2-byte entries: u8 TSAP + u8 ASAP)
    AssociationTableSystemBSmall,
    /// System B big association table (2-byte count + 4-byte entries: u16 TSAP + u16 ASAP)
    AssociationTableSystemBBig,

    /// BCU 1.0 group object table (RT1: narrow pointers)
    GroupObjectTableBcu10,
    /// BCU 1.1 group object table (RT1: narrow pointers)
    GroupObjectTableBcu11,
    /// Power-line BCU1 group object table (RT1: narrow pointers)
    GroupObjectTableBcu1Pl,
    /// BCU2 group object table (RT2: narrow pointers)
    GroupObjectTableBcu2,
    /// M112/System 7 group object table (wide pointers)
    GroupObjectTableM112,
    /// System 300 property-based group object table
    GroupObjectTableSystem300,
    /// System B group object table (flags and type rows)
    GroupObjectTableSystemB,
    /// Unknown flavour
    Unknown,
}

impl TableFlavour {
    /// Parse from flavour string.
    pub fn parse_flavour(s: &str) -> Self {
        match s {
            "AddressTable_Bcu1" => TableFlavour::AddressTableBcu1,
            "AddressTable_SystemB" => TableFlavour::AddressTableSystemB,
            "AssociationTable_Bcu1" => TableFlavour::AssociationTableBcu1,
            "AssociationTable_Bcu2" => TableFlavour::AssociationTableBcu2,
            "AssociationTable_M112" => TableFlavour::AssociationTableSystem7,
            "AssociationTable_SystemB" => TableFlavour::AssociationTableSystemB,
            "AssociationTable_SystemBSmall" => TableFlavour::AssociationTableSystemBSmall,
            "AssociationTable_SystemBBig" => TableFlavour::AssociationTableSystemBBig,
            "GroupObjectTable_Bcu10" => TableFlavour::GroupObjectTableBcu10,
            "GroupObjectTable_Bcu11" => TableFlavour::GroupObjectTableBcu11,
            "GroupObjectTable_Bcu1PL" => TableFlavour::GroupObjectTableBcu1Pl,
            "GroupObjectTable_Bcu2" => TableFlavour::GroupObjectTableBcu2,
            "GroupObjectTable_M112" => TableFlavour::GroupObjectTableM112,
            "GroupObjectTable_System300" => TableFlavour::GroupObjectTableSystem300,
            "GroupObjectTable_SystemB" => TableFlavour::GroupObjectTableSystemB,
            _ => TableFlavour::Unknown,
        }
    }

    /// Get the count field size in bytes.
    pub fn count_size(&self) -> usize {
        match self {
            // BCU1/BCU2/System 7 use a 1-byte count
            TableFlavour::AddressTableBcu1
            | TableFlavour::AssociationTableBcu1
            | TableFlavour::AssociationTableBcu2
            | TableFlavour::AssociationTableSystem7
            | TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2
            | TableFlavour::GroupObjectTableM112 => 1,
            // System B uses 2-byte count
            _ => 2,
        }
    }

    /// Get the complete table header size in bytes.
    ///
    /// Most tables contain only their count field. Compact group-object
    /// tables also store the RAM-flags pointer before the first row.
    pub fn header_size(&self) -> usize {
        match self {
            TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2 => 2,
            TableFlavour::GroupObjectTableM112 => 3,
            _ => self.count_size(),
        }
    }

    /// Get the entry size in bytes.
    pub fn entry_size(&self) -> usize {
        match self {
            // Address tables are always 2 bytes per entry (group address)
            TableFlavour::AddressTableBcu1 | TableFlavour::AddressTableSystemB => 2,

            // BCU1/BCU2/System 7 use 2-byte entries (u8 TSAP + u8 ASAP)
            TableFlavour::AssociationTableBcu1
            | TableFlavour::AssociationTableBcu2
            | TableFlavour::AssociationTableSystem7 => 2,

            // SystemBSmall uses 2-byte entries (u8 TSAP + u8 ASAP)
            TableFlavour::AssociationTableSystemBSmall => 2,

            // SystemB and SystemBBig use 4-byte entries (u16 TSAP + u16 ASAP)
            TableFlavour::AssociationTableSystemB | TableFlavour::AssociationTableSystemBBig => 4,

            // RT1/RT2 rows: narrow data pointer + config + type
            TableFlavour::GroupObjectTableBcu10
            | TableFlavour::GroupObjectTableBcu11
            | TableFlavour::GroupObjectTableBcu1Pl
            | TableFlavour::GroupObjectTableBcu2 => 3,

            // M112 rows: wide data pointer + config + type
            TableFlavour::GroupObjectTableM112 => 4,

            // Property/System B rows carry flags and type.
            TableFlavour::GroupObjectTableSystem300 | TableFlavour::GroupObjectTableSystemB => 2,

            TableFlavour::Unknown => 2,
        }
    }

    /// Check if this is a "small" format using u8 pairs for TSAP/ASAP.
    pub fn uses_u8_entries(&self) -> bool {
        matches!(
            self,
            TableFlavour::AssociationTableBcu1
                | TableFlavour::AssociationTableBcu2
                | TableFlavour::AssociationTableSystem7
                | TableFlavour::AssociationTableSystemBSmall
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DownwardCompatibleMasks` names the older masks whose programs
    /// a mask runs — the shape MV-0020 has in the real file.
    #[test]
    fn downward_compatible_masks_parse() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
      <DownwardCompatibleMasks>
        <DownwardCompatibleMask RefId="MV-0010" />
        <DownwardCompatibleMask RefId="MV-0011" />
        <DownwardCompatibleMask RefId="MV-0012" />
      </DownwardCompatibleMasks>
      <HawkConfigurationData />
    </MaskVersion>
    <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
      <HawkConfigurationData />
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("parses");

        let bcu2 = master.get_mask_version("MV-0020").expect("MV-0020");
        assert_eq!(bcu2.downward_compatible_masks().collect::<Vec<_>>(), vec![0x0010, 0x0011, 0x0012]);
        assert!(bcu2.is_downward_compatible_with(0x0012));
        assert!(bcu2.is_downward_compatible_with(0x0020), "a mask runs its own programs");
        assert!(!bcu2.is_downward_compatible_with(0x0705));

        let bcu1 = master.get_mask_version("MV-0012").expect("MV-0012");
        assert_eq!(bcu1.downward_compatible_masks().count(), 0, "absent element means none");
        assert!(bcu1.is_downward_compatible_with(0x0012));
    }

    /// `MaskEntries` resolve by their `_ME-` id suffix — a fixup's
    /// `FunctionRef` carries the *product's* mask prefix, and the
    /// lookup happens against the device's mask.
    #[test]
    fn mask_entries_resolve_by_suffix() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
      <HawkConfigurationData />
      <MaskEntries>
        <MaskEntry Id="MV-0020_ME-U.5FGetTMx" Name="U_GetTMx" Address="20579" />
      </MaskEntries>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let master: MasterData = xml.parse().expect("parses");
        let bcu2 = master.get_mask_version("MV-0020").expect("MV-0020");
        assert_eq!(bcu2.mask_entry_address("U.5FGetTMx"), Some(20579));
        assert_eq!(bcu2.mask_entry_address("U.5Fdeb30"), None);
    }

    #[test]
    fn project_11_master_data_does_not_require_an_id() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/11">
  <MasterData Version="420">
    <MaskVersions>
      <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1" />
    </MaskVersions>
  </MasterData>
</KNX>"#;

        let master: MasterData = xml.parse().expect("project-11 master data parses");

        assert_eq!(master.root.master_data.id, "");
        assert!(master.get_mask_version("MV-0012").is_some());
    }

    #[test]
    #[ignore] // Run with: cargo test -p zweidraehte-ets-files parse_master_data_file -- --ignored
    fn parse_master_data_file() {
        // manuf_tool_data sits at the workspace root (git-ignored:
        // licensed KNX XML stays out of the repository), two levels up
        // from this crate.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manuf_tool_data/VC-EASY-03_MDT_KP_V35/knx_master.xml");
        let master = MasterData::from_file(path).expect("Failed to parse master data");

        let old_schema_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/knx_master.xml"
        );
        let old_schema_master = MasterData::from_file(old_schema_path).expect("project-11 master data parses");

        println!("Loaded {} mask versions", master.mask_version_count());
        assert!(master.mask_version_count() > 0);
        assert!(old_schema_master.mask_version_count() > 0);

        // Test MV-07B0 (System B)
        let mv_07b0 = master.get_mask_version("MV-07B0").expect("MV-07B0 not found");
        assert_eq!(mv_07b0.name, "System B");
        assert!(mv_07b0.is_system_b());
        assert_eq!(mv_07b0.first_app_object_idx(), 6);

        let adt = mv_07b0.address_table().expect("Address table not found");
        assert_eq!(adt.address_space(), Some("RelativeMemory"));
        assert_eq!(adt.interface_object_ref(), Some(1));
        assert_eq!(adt.property_id(), Some(7));

        // Test MV-0705 (System 7.5)
        let mv_0705 = master.get_mask_version("MV-0705").expect("MV-0705 not found");
        assert_eq!(mv_0705.name, "7.5");
        assert!(mv_0705.is_system7());
        assert_eq!(mv_0705.first_app_object_idx(), 5);

        let adt_0705 = mv_0705.address_table().expect("Address table not found");
        assert_eq!(adt_0705.address_space(), Some("StandardMemory"));
        assert_eq!(adt_0705.start_address(), Some(16384)); // 0x4000

        // Check flavours
        let adt_flavour_0705 = adt_0705
            .resource_type
            .as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::parse_flavour(f))
            .unwrap_or(TableFlavour::Unknown);
        let adt_flavour_07b0 = adt
            .resource_type
            .as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::parse_flavour(f))
            .unwrap_or(TableFlavour::Unknown);

        println!("MV-0705 ADT flavour: {:?}, count_size: {}", adt_flavour_0705, adt_flavour_0705.count_size());
        println!("MV-07B0 ADT flavour: {:?}, count_size: {}", adt_flavour_07b0, adt_flavour_07b0.count_size());

        println!("MV-07B0: {:?}", mv_07b0.address_table().map(|r| &r.location));
        println!("MV-0705: {:?}", mv_0705.address_table().map(|r| &r.location));

        // ------------------------------------------------------------
        // Programming procedures.
        //
        // System 7 masks carry ONLY "Unload all" — the Load
        // procedures are product-specific and live in each product's
        // .knxprod. System B carries the full generic template set.
        // ------------------------------------------------------------
        let procs_0705 = mv_0705.procedures();
        assert_eq!(procs_0705.len(), 1, "MV-0705 must carry exactly the Unload-all procedure");
        let unload = &procs_0705[0];
        assert!(unload.is_unload());
        assert_eq!(unload.procedure_sub_type.as_deref(), Some("all"));
        // Connect, Unload LSM 1-4, Disconnect.
        assert_eq!(unload.controls.len(), 6);
        assert!(matches!(unload.controls[0], LoadControl::LdCtrlConnect(_)));
        for (i, lsm) in (1..=4).enumerate() {
            match &unload.controls[1 + i] {
                LoadControl::LdCtrlUnload(u) => assert_eq!(u.lsm_idx, Some(lsm)),
                other => panic!("expected LdCtrlUnload, got {other:?}"),
            }
        }
        assert!(matches!(unload.controls[5], LoadControl::LdCtrlDisconnect(_)));

        // `procedures()` reads the primary HawkConfigurationData only —
        // System B carries a second, `LegacyVersion="1"` config (with
        // its own Unload-all) that a current tool must not execute.
        let subtypes_07b0: Vec<_> =
            mv_07b0.procedures().iter().map(|p| (p.procedure_type.as_str(), p.procedure_sub_type.as_deref())).collect();
        assert_eq!(subtypes_07b0, [
            ("Load", Some("ap1")),
            ("Load", Some("all")),
            ("Load", Some("grp")),
            ("Load", Some("par")),
            ("Load", Some("par,grp")),
            ("Load", Some("cfg")),
            ("Unload", Some("all")),
        ]);
        assert_eq!(mv_07b0.hawk_configs.len(), 2, "System B has a primary and a LegacyVersion config");

        // The System B "Load all" template exercises the merge/splice
        // machinery: it must contain LdCtrlMerge points and
        // whole-blob relative writes.
        let load_all = mv_07b0.find_procedure("Load", "all").expect("System B Load-all template");
        assert!(load_all.allows_remote());
        assert!(load_all.controls.iter().any(|c| matches!(c, LoadControl::LdCtrlMerge(m) if m.merge_id == 4)));
        assert!(
            load_all
                .controls
                .iter()
                .any(|c| matches!(c, LoadControl::LdCtrlWriteRelMem(w) if w.obj_idx == Some(3) && w.verify))
        );
    }

    /// Hermetic exercise of the full master-data procedure vocabulary
    /// on a hand-written snippet (the licensed knx_master.xml stays
    /// out of the repository; this is our own minimal expression of
    /// the same element language, shaped after the project-23 file).
    #[test]
    fn parse_procedures_full_vocabulary() {
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote local1 local2">
              <LdCtrlConnect />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="true" />
              <LdCtrlLoadImageMem Address="278" Size="1" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="00" />
              <LdCtrlWriteMem Address="281" Size="230" Verify="true" />
              <LdCtrlCompareMem Address="278" Size="1" InlineData="01" />
              <LdCtrlDelay MilliSeconds="500" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
      <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="ap1" Access="remote local2">
              <LdCtrlConnect />
              <LdCtrlMerge MergeId="1" />
              <LdCtrlMapError OriginalError="3221498632" MappedError="0" />
              <LdCtrlUnload LsmIdx="5" />
              <LdCtrlLoad LsmIdx="3" />
              <LdCtrlRelSegment LsmIdx="3" Size="2" Mode="0" Fill="0" />
              <LdCtrlWriteRelMem ObjIdx="3" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlWriteProp ObjIdx="4" PropId="13" Verify="true" InlineData="0000000000" />
              <LdCtrlLoadImageProp ObjIdx="4" PropId="7" />
              <LdCtrlCompareProp ObjIdx="4" PropId="7" InlineData="00000000" />
              <LdCtrlLoadCompleted LsmIdx="3" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
      <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
        <HawkConfigurationData>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlTaskSegment LsmIdx="3" Address="17408" />
              <LdCtrlTaskPtr LsmIdx="3" InitPtr="284" SavePtr="285" SerialPtr="0" />
              <LdCtrlTaskCtrl1 LsmIdx="3" Address="0" Count="0" />
              <LdCtrlTaskCtrl2 LsmIdx="3" Callback="20609" Address="282" Seg0="208" Seg1="208" />
              <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="16384" Size="12" Access="255" MemType="3" SegFlags="128" />
              <LdCtrlWriteProp ObjIdx="1" PropId="53" Count="0" Verify="true" />
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="local1">
              <LdCtrlClearLCFilterTable UseFunctionProp="true" />
              <LdCtrlLoad ObjType="6" Occurrence="1" />
              <LdCtrlRelSegment ObjType="6" Occurrence="1" Size="8192" Mode="0" Fill="0" />
              <LdCtrlWriteMem AddressSpace="LcFilter" Address="0" Size="8192" Verify="false" />
              <LdCtrlMasterReset EraseCode="7" ChannelNumber="0" />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

        let master: MasterData = xml.parse().expect("snippet mirrors the master-data shape");

        // BCU1-style raw-memory download.
        let bcu1 = master.get_mask_version("MV-0012").expect("snippet defines MV-0012");
        let load = bcu1.find_procedure("Load", "all").expect("snippet defines Load all");
        assert!(load.allows_remote());
        assert_eq!(load.controls.len(), 8);
        assert!(matches!(&load.controls[1], LoadControl::LdCtrlSetControlVariable(v)
            if v.name == "EnableVerifyOnWriteDirect" && v.value == "true"));
        assert!(matches!(&load.controls[2], LoadControl::LdCtrlLoadImageMem(m)
            if m.address == 278 && m.size == 1));
        assert!(matches!(&load.controls[3], LoadControl::LdCtrlWriteMem(w)
            if w.address == 269 && w.inline_data.as_deref() == Some("00")));
        assert!(matches!(&load.controls[4], LoadControl::LdCtrlWriteMem(w)
            if w.size == 230 && w.inline_data.is_none()));
        assert!(matches!(&load.controls[5], LoadControl::LdCtrlCompareMem(c)
            if c.inline_data == "01"));
        assert!(matches!(&load.controls[6], LoadControl::LdCtrlDelay(d) if d.milli_seconds == 500));

        // System B template with merge/error scaffolding.
        let systemb = master.get_mask_version("MV-07B0").expect("snippet defines MV-07B0");
        let ap1 = systemb.find_procedure("Load", "ap1").expect("snippet defines Load ap1");
        assert!(matches!(&ap1.controls[1], LoadControl::LdCtrlMerge(m) if m.merge_id == 1));
        assert!(matches!(&ap1.controls[2], LoadControl::LdCtrlMapError(m)
            if m.original_error == 3221498632 && m.mapped_error == 0));
        assert!(matches!(&ap1.controls[5], LoadControl::LdCtrlRelSegment(r)
            if r.lsm_idx == Some(3) && r.applies_to.is_none() && r.size == 2));
        assert!(matches!(&ap1.controls[6], LoadControl::LdCtrlWriteRelMem(w)
            if w.obj_idx == Some(3) && w.size == 1_048_576 && w.verify));

        // BCU2 task plumbing + ObjType addressing + line-coupler ops.
        let bcu2 = master.get_mask_version("MV-0020").expect("snippet defines MV-0020");
        let load = bcu2.find_procedure("Load", "all").expect("snippet defines Load all");
        assert!(matches!(&load.controls[2], LoadControl::LdCtrlTaskPtr(t)
            if t.init_ptr == 284 && t.save_ptr == 285));
        assert!(matches!(&load.controls[4], LoadControl::LdCtrlTaskCtrl2(t)
            if t.callback == 20609 && t.seg0 == 208));
        assert!(matches!(&load.controls[5], LoadControl::LdCtrlAbsSegment(s)
            if s.address == 16384 && s.seg_flags == 128));
        assert!(matches!(&load.controls[6], LoadControl::LdCtrlWriteProp(w)
            if w.obj_idx == Some(1) && w.count == Some(0)));

        let unload = bcu2.find_procedure("Unload", "all").expect("snippet defines Unload all");
        assert!(!unload.allows_remote());
        assert!(matches!(&unload.controls[0], LoadControl::LdCtrlClearLCFilterTable(c)
            if c.use_function_prop == Some(true)));
        assert!(matches!(&unload.controls[1], LoadControl::LdCtrlLoad(l)
            if l.lsm_idx.is_none() && l.obj_type == Some(6) && l.occurrence == Some(1)));
        assert!(matches!(&unload.controls[3], LoadControl::LdCtrlWriteMem(w)
            if w.address_space.as_deref() == Some("LcFilter") && !w.verify));
        assert!(matches!(&unload.controls[4], LoadControl::LdCtrlMasterReset(m)
            if m.erase_code == 7 && m.channel_number == 0));
    }

    #[test]
    fn test_address_space_parsing() {
        let loc = Location {
            address_space: "RelativeMemory".to_string(),
            start_address: Some(0),
            interface_object_ref: Some(1),
            property_id: Some(7),
            ptr_resource: None,
        };

        let addr_space = loc.to_address_space();
        assert!(matches!(addr_space, AddressSpaceLocation::RelativeMemory {
            interface_object_ref: 1,
            property_id: 7,
            ..
        }));
    }

    #[test]
    fn test_table_flavour() {
        assert_eq!(TableFlavour::parse_flavour("AddressTable_SystemB"), TableFlavour::AddressTableSystemB);
        assert_eq!(TableFlavour::AddressTableSystemB.count_size(), 2);
        assert_eq!(TableFlavour::AddressTableBcu1.count_size(), 1);
    }

    #[test]
    fn group_object_flavours_preserve_their_physical_layouts() {
        for (name, flavour) in [
            ("GroupObjectTable_Bcu10", TableFlavour::GroupObjectTableBcu10),
            ("GroupObjectTable_Bcu11", TableFlavour::GroupObjectTableBcu11),
            ("GroupObjectTable_Bcu1PL", TableFlavour::GroupObjectTableBcu1Pl),
            ("GroupObjectTable_Bcu2", TableFlavour::GroupObjectTableBcu2),
        ] {
            assert_eq!(TableFlavour::parse_flavour(name), flavour);
            assert_eq!(flavour.count_size(), 1);
            assert_eq!(flavour.header_size(), 2);
            assert_eq!(flavour.entry_size(), 3);
        }

        let m112 = TableFlavour::parse_flavour("GroupObjectTable_M112");

        assert_eq!(m112, TableFlavour::GroupObjectTableM112);
        assert_eq!(m112.count_size(), 1);
        assert_eq!(m112.header_size(), 3);
        assert_eq!(m112.entry_size(), 4);

        assert_eq!(TableFlavour::parse_flavour("GroupObjectTable_System300"), TableFlavour::GroupObjectTableSystem300);
        assert_eq!(TableFlavour::parse_flavour("GroupObjectTable_SystemB"), TableFlavour::GroupObjectTableSystemB);
    }
}
