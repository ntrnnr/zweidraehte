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
//! use knxprod::master_data::{MasterData, ResourceName};
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

/// Root element of the KNX XML file (wraps MasterData).
#[derive(Debug, Clone, Deserialize)]
pub struct KnxRoot {
    #[serde(rename = "MasterData")]
    pub master_data: MasterDataElement,
}

/// MasterData element containing mask versions.
#[derive(Debug, Clone, Deserialize)]
pub struct MasterDataElement {
    #[serde(rename = "@Id")]
    pub id: String,

    #[serde(rename = "@Version")]
    pub version: String,

    #[serde(rename = "MaskVersions")]
    pub mask_versions: Option<MaskVersions>,
}

/// Convenience wrapper for working with KNX master data.
pub struct MasterData {
    root: KnxRoot,
}

impl MasterData {
    /// Parse master data from an XML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse master data from an XML string.
    pub fn from_str(xml: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root: KnxRoot = quick_xml::de::from_str(xml)?;
        Ok(Self { root })
    }

    /// Get the raw mask versions container.
    pub fn mask_versions(&self) -> Option<&MaskVersions> {
        self.root.master_data.mask_versions.as_ref()
    }

    /// Get a mask version by its ID (e.g., "MV-07B0").
    pub fn get_mask_version(&self, id: &str) -> Option<&MaskVersion> {
        self.mask_versions()
            .and_then(|mv| mv.versions.iter().find(|v| v.id == id))
    }

    /// Get a mask version by its numeric version code (e.g., 1968 for MV-07B0).
    pub fn get_mask_version_by_code(&self, code: u16) -> Option<&MaskVersion> {
        self.mask_versions()
            .and_then(|mv| mv.versions.iter().find(|v| v.mask_version_code == code))
    }

    /// Get total number of mask versions.
    pub fn mask_version_count(&self) -> usize {
        self.mask_versions()
            .map(|mv| mv.versions.len())
            .unwrap_or(0)
    }
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

    // Other elements we ignore
    #[serde(rename = "DownwardCompatibleMasks", default)]
    _downward_compatible_masks: IgnoredElement,

    #[serde(rename = "MaskEntries", default)]
    _mask_entries: IgnoredElement,
}

impl MaskVersion {
    /// Check if this is a System B mask version.
    pub fn is_system_b(&self) -> bool {
        self.management_model == "SystemB"
    }

    /// Check if this is a BIM M112 (System 7.5) mask version.
    pub fn is_bim_m112(&self) -> bool {
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
        self.get_feature("FirstAppObjectIdx")
            .and_then(|v| v.parse().ok())
            .unwrap_or(5)
    }

    /// Get a resource definition by name.
    pub fn get_resource(&self, name: ResourceName) -> Option<&Resource> {
        self.hawk_config().and_then(|hc| {
            hc.resources
                .as_ref()
                .and_then(|r| r.resources.iter().find(|res| res.name == name.as_str()))
        })
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

    /// Build a lookup table of all resources by name.
    pub fn resource_map(&self) -> HashMap<&str, &Resource> {
        let mut map = HashMap::new();
        if let Some(hc) = self.hawk_config() {
            if let Some(resources) = &hc.resources {
                for res in &resources.resources {
                    map.insert(res.name.as_str(), res);
                }
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
    /// Application program load control
    ApplicationProgramLoadControl,
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
            ResourceName::ApplicationProgramLoadControl => "ApplicationProgramLoadControl",
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

    // These are present but we skip them (use default to ignore)
    #[serde(rename = "InterfaceObjects", default)]
    _interface_objects: IgnoredElement,

    #[serde(rename = "MemorySegments", default)]
    _memory_segments: IgnoredElement,

    #[serde(rename = "Procedures", default)]
    _procedures: IgnoredElement,
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
        self.location
            .as_ref()
            .map(|l| l.address_space == "RelativeMemory")
            .unwrap_or(false)
    }

    /// Check if this resource uses standard memory (fixed address).
    pub fn is_standard_memory(&self) -> bool {
        self.location
            .as_ref()
            .map(|l| l.address_space == "StandardMemory")
            .unwrap_or(false)
    }

    /// Check if this resource is a system property.
    pub fn is_system_property(&self) -> bool {
        self.location
            .as_ref()
            .map(|l| l.address_space == "SystemProperty")
            .unwrap_or(false)
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
            "StandardMemory" => AddressSpaceLocation::StandardMemory {
                start_address: self.start_address.unwrap_or(0),
            },
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
            "Constant" => AddressSpaceLocation::Constant {
                value: self.start_address.unwrap_or(0),
            },
            "Pointer" => AddressSpaceLocation::Pointer {
                ptr_resource: self.ptr_resource.clone().unwrap_or_default(),
            },
            "ADC" => AddressSpaceLocation::Adc {
                channel: self.start_address.unwrap_or(0),
            },
            "None" | "" => AddressSpaceLocation::None,
            _ => AddressSpaceLocation::Unknown {
                address_space: self.address_space.clone(),
            },
        }
    }
}

/// Structured address space location for easier pattern matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressSpaceLocation {
    /// Fixed absolute address in device memory.
    StandardMemory { start_address: u32 },

    /// System property on an interface object.
    SystemProperty {
        interface_object_ref: u8,
        property_id: u8,
        start_address: u32,
    },

    /// Relative memory allocated via load state machine.
    RelativeMemory {
        interface_object_ref: u8,
        property_id: u8,
        start_address: u32,
    },

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableFlavour {
    /// BCU1-style address table (1-byte count + 2-byte entries)
    AddressTableBcu1,
    /// System B address table (2-byte count + 2-byte entries)
    AddressTableSystemB,
    /// BCU1-style association table
    AssociationTableBcu1,
    /// System B association table
    AssociationTableSystemB,
    /// Group object table
    GroupObjectTable,
    /// Unknown flavour
    Unknown,
}

impl TableFlavour {
    /// Parse from flavour string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "AddressTable_Bcu1" => TableFlavour::AddressTableBcu1,
            "AddressTable_SystemB" => TableFlavour::AddressTableSystemB,
            "AssociationTable_Bcu1" => TableFlavour::AssociationTableBcu1,
            "AssociationTable_SystemB" => TableFlavour::AssociationTableSystemB,
            s if s.contains("GroupObject") => TableFlavour::GroupObjectTable,
            _ => TableFlavour::Unknown,
        }
    }

    /// Get the count field size in bytes.
    pub fn count_size(&self) -> usize {
        match self {
            TableFlavour::AddressTableBcu1 => 1,
            TableFlavour::AssociationTableBcu1 => 1,
            _ => 2, // System B and others use 2-byte count
        }
    }

    /// Get the entry size in bytes.
    pub fn entry_size(&self) -> usize {
        match self {
            TableFlavour::AddressTableBcu1 | TableFlavour::AddressTableSystemB => 2,
            TableFlavour::AssociationTableBcu1 => 2, // TSAP only
            TableFlavour::AssociationTableSystemB => 4, // TSAP + ASAP
            TableFlavour::GroupObjectTable => 2, // Type + flags (System B)
            TableFlavour::Unknown => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Run with: cargo test -p knxprod parse_master_data_file -- --ignored
    fn parse_master_data_file() {
        // Tests run from workspace root
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../manuf_tool_data/VC-EASY-03_MDT_KP_V35/knx_master.xml"
        );
        let master = MasterData::from_file(path).expect("Failed to parse master data");

        println!("Loaded {} mask versions", master.mask_version_count());
        assert!(master.mask_version_count() > 0);

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
        assert!(mv_0705.is_bim_m112());
        assert_eq!(mv_0705.first_app_object_idx(), 5);

        let adt_0705 = mv_0705.address_table().expect("Address table not found");
        assert_eq!(adt_0705.address_space(), Some("StandardMemory"));
        assert_eq!(adt_0705.start_address(), Some(16384)); // 0x4000

        // Check flavours
        let adt_flavour_0705 = adt_0705.resource_type.as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::from_str(f))
            .unwrap_or(TableFlavour::Unknown);
        let adt_flavour_07b0 = adt.resource_type.as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::from_str(f))
            .unwrap_or(TableFlavour::Unknown);

        println!("MV-0705 ADT flavour: {:?}, count_size: {}", adt_flavour_0705, adt_flavour_0705.count_size());
        println!("MV-07B0 ADT flavour: {:?}, count_size: {}", adt_flavour_07b0, adt_flavour_07b0.count_size());

        println!("MV-07B0: {:?}", mv_07b0.address_table().map(|r| &r.location));
        println!("MV-0705: {:?}", mv_0705.address_table().map(|r| &r.location));
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
        assert!(matches!(
            addr_space,
            AddressSpaceLocation::RelativeMemory {
                interface_object_ref: 1,
                property_id: 7,
                ..
            }
        ));
    }

    #[test]
    fn test_table_flavour() {
        assert_eq!(
            TableFlavour::from_str("AddressTable_SystemB"),
            TableFlavour::AddressTableSystemB
        );
        assert_eq!(TableFlavour::AddressTableSystemB.count_size(), 2);
        assert_eq!(TableFlavour::AddressTableBcu1.count_size(), 1);
    }
}
