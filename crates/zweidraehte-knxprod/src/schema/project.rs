//! Project XML schema types for `.knxproj` files.
//!
//! A `.knxproj` archive contains two project-level XML files in addition to
//! the manufacturer data found in a `.knxprod`:
//!
//! - `project.xml` — project metadata (name, GUID, Puid counter)
//! - `0.xml` — topology with device instances in `UnassignedDevices`
//!
//! Both files share the same `<KNX>` root element as other KNX XML files but
//! contain a `<Project>` child instead of `<ManufacturerData>`.

use serde::{Deserialize, Serialize};

// ============================================================================
// Root Element (shared by both project.xml and 0.xml)
// ============================================================================

/// Root `<KNX>` element for project XML files.
///
/// Used for both `project.xml` (with [`ProjectInformation`]) and `0.xml`
/// (with [`Installations`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "KNX")]
pub struct ProjectKnx {
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: String,
    #[serde(rename = "@xmlns:xsd")]
    pub xmlns_xsd: String,
    #[serde(rename = "@CreatedBy")]
    pub created_by: String,
    #[serde(rename = "@ToolVersion")]
    pub tool_version: String,
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "Project")]
    pub project: Project,
}

impl Default for ProjectKnx {
    fn default() -> Self {
        Self {
            xmlns_xsi: "http://www.w3.org/2001/XMLSchema-instance".to_string(),
            xmlns_xsd: "http://www.w3.org/2001/XMLSchema".to_string(),
            created_by: "zweidraehte".to_string(),
            tool_version: "0.1.0".to_string(),
            xmlns: "http://knx.org/xml/project/23".to_string(),
            project: Project::default(),
        }
    }
}

// ============================================================================
// Project and ProjectInformation (project.xml)
// ============================================================================

/// `<Project>` element — wraps either metadata or topology content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Project {
    #[serde(rename = "@Id")]
    pub id: String,

    /// Present in `project.xml`.
    #[serde(rename = "ProjectInformation", skip_serializing_if = "Option::is_none")]
    pub project_information: Option<ProjectInformation>,

    /// Present in `0.xml`.
    #[serde(rename = "Installations", skip_serializing_if = "Option::is_none")]
    pub installations: Option<Installations>,
}

/// `<ProjectInformation>` — metadata about the ETS project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInformation {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@GroupAddressStyle")]
    pub group_address_style: String,
    #[serde(rename = "@Guid")]
    pub guid: String,
    #[serde(rename = "@LastUsedPuid")]
    pub last_used_puid: u32,
}

// ============================================================================
// Installations / Topology (0.xml)
// ============================================================================

/// `<Installations>` wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installations {
    #[serde(rename = "Installation")]
    pub installations: Vec<Installation>,
}

/// `<Installation>` — one physical installation in the project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installation {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@InstallationId")]
    pub installation_id: String,
    #[serde(rename = "Topology")]
    pub topology: Topology,
    #[serde(rename = "Locations")]
    pub locations: Locations,
    #[serde(rename = "GroupAddresses")]
    pub group_addresses: GroupAddresses,
}

/// `<Topology>` — network topology structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    /// Backbone area with a default line. ETS requires at least one
    /// `Area`/`Line` to exist in every installation.
    #[serde(rename = "Area")]
    pub area: Area,
    #[serde(rename = "UnassignedDevices")]
    pub unassigned_devices: UnassignedDevices,
}

/// `<Area>` — a KNX area in the topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Area {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Address")]
    pub address: String,
    #[serde(rename = "@Puid")]
    pub puid: u32,
    #[serde(rename = "Line")]
    pub line: Line,
}

/// `<Line>` — a KNX line within an area.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Line {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Address")]
    pub address: String,
    #[serde(rename = "@MediumTypeRefId")]
    pub medium_type_ref_id: String,
    /// `Line/@DomainAddress` — RF domain address for KNX-RF lines.
    /// The RF medium has a 48-bit domain address (`MediumType` MT-2 has
    /// `DomainAddressLength="48"`); other media omit this attribute.
    #[serde(rename = "@DomainAddress", skip_serializing_if = "Option::is_none")]
    pub domain_address: Option<u64>,
    #[serde(rename = "@Puid")]
    pub puid: u32,
}

/// `<UnassignedDevices>` — devices not yet placed on a line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnassignedDevices {
    #[serde(rename = "DeviceInstance")]
    pub device_instances: Vec<ProjectDeviceInstance>,
}

/// `<DeviceInstance>` — a device placed in the project.
///
/// References a product and application program from the manufacturer data
/// via `ProductRefId` and `Hardware2ProgramRefId`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDeviceInstance {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@ProductRefId")]
    pub product_ref_id: String,
    #[serde(rename = "@Hardware2ProgramRefId")]
    pub hardware2program_ref_id: String,
    #[serde(rename = "@Puid")]
    pub puid: u32,
}

/// `<Locations />` — empty placeholder required by ETS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locations;

/// `<GroupAddresses>` — contains group address ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupAddresses {
    #[serde(rename = "GroupRanges")]
    pub group_ranges: GroupRanges,
}

/// `<GroupRanges />` — empty placeholder required by ETS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRanges;
