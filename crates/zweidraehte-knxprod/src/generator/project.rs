//! Project XML generator for `.knxproj` files.
//!
//! Generates the two project-level XML files that distinguish a `.knxproj`
//! from a plain `.knxprod`:
//!
//! - `project.xml` — project metadata (name, GUID, Puid counter)
//! - `0.xml` — topology with device instances placed in `UnassignedDevices`

use crate::schema::{
    Area, GroupAddresses, GroupRanges, Installation, Installations, Line, Locations, Project, ProjectDeviceInstance,
    ProjectInformation, ProjectKnx, Topology, UnassignedDevices,
};
use crate::signing::KnxSchemaVersion;

use super::builder::{AppProgramRef, HardwareRef};
use super::mtxml::MtxmlGenerator;
use super::{ApplicationProgramDef, GeneratorError, HardwareDef};

// ============================================================================
// Public Input Type
// ============================================================================

/// Definition of a device instance to include in the project.
///
/// Each device instance becomes a `<DeviceInstance>` element inside
/// `<UnassignedDevices>` in the project topology.
pub struct DeviceInstanceDef<'a> {
    /// Display name for the device instance in the project.
    pub name: &'a str,
    /// Which hardware definition this instance references.
    pub hardware: HardwareRef,
    /// Which product within that hardware (identified by order number).
    pub product_order_number: &'a str,
    /// Which application program this instance uses.
    pub application_program: AppProgramRef,
}

// ============================================================================
// Generator
// ============================================================================

pub struct ProjectGenerator;

impl ProjectGenerator {
    /// Generate `project.xml` content — project metadata without topology.
    pub fn generate_project_xml(
        project_id: &str,
        project_name: &str,
        last_used_puid: u32,
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<String, GeneratorError> {
        let guid = uuid::Uuid::new_v4().to_string();

        let mut knx = ProjectKnx::default();
        if let Some(version) = schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }

        knx.project = Project {
            id: project_id.to_string(),
            project_information: Some(ProjectInformation {
                name: project_name.to_string(),
                group_address_style: "ThreeLevel".to_string(),
                guid,
                last_used_puid,
            }),
            installations: None,
        };

        Self::serialize(&knx)
    }

    /// Generate `0.xml` content — topology with device instances.
    ///
    /// Resolves `ProductRefId` and `Hardware2ProgramRefId` for each device
    /// instance from the registered hardware and application program
    /// definitions.
    pub fn generate_topology_xml(
        project_id: &str,
        manufacturer_id: u16,
        device_instances: &[DeviceInstanceDef],
        hardware_defs: &[HardwareDef],
        application_programs: &[&ApplicationProgramDef],
        schema_version: Option<KnxSchemaVersion>,
    ) -> Result<String, GeneratorError> {
        let manuf_str = format!("M-{:04X}", manufacturer_id);

        // ETS reserves Puid 1 and 2 for the installation and default line.
        const PUID_BASE: u32 = 3;

        let instances: Vec<ProjectDeviceInstance> = device_instances
            .iter()
            .enumerate()
            .map(|(i, def)| {
                let HardwareRef(hw_idx) = def.hardware;
                let AppProgramRef(app_idx) = def.application_program;
                let hw = &hardware_defs[hw_idx];
                let app = application_programs[app_idx];

                let serial_hex = hw.serial_number.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                let hardware_id = format!("{}_H-{}-{}", manuf_str, serial_hex, hw.hardware_version);

                let product_ref_id =
                    format!("{}_P-{}", hardware_id, MtxmlGenerator::encode_id(def.product_order_number));

                let app_hash = app.application_hash.unwrap_or("0000");
                let h2p_ref_id = format!(
                    "{}_HP-{:04X}-{:02X}-{}",
                    hardware_id, app.device.application_id, app.device.application_version, app_hash
                );

                let puid = PUID_BASE + i as u32;

                ProjectDeviceInstance {
                    id: format!("{}-0_DI-{}", project_id, i + 1),
                    product_ref_id,
                    hardware2program_ref_id: h2p_ref_id,
                    puid,
                }
            })
            .collect();

        let mut knx = ProjectKnx::default();
        if let Some(version) = schema_version {
            knx.xmlns = version.namespace_url();
            knx.tool_version = version.tool_version().to_string();
        }

        knx.project = Project {
            id: project_id.to_string(),
            project_information: None,
            installations: Some(Installations {
                installations: vec![Installation {
                    name: String::new(),
                    installation_id: "0".to_string(),
                    topology: Topology {
                        area: Area {
                            id: format!("{}-0_A-1", project_id),
                            name: "Backbone area".to_string(),
                            address: "0".to_string(),
                            puid: 1,
                            line: Line {
                                id: format!("{}-0_L-1", project_id),
                                name: "Backbone line".to_string(),
                                address: "0".to_string(),
                                // MT-5 is the master data reference for "Twisted Pair"
                                // media type — the standard backbone line medium.
                                medium_type_ref_id: "MT-5".to_string(),
                                puid: 2,
                            },
                        },
                        unassigned_devices: UnassignedDevices { device_instances: instances },
                    },
                    locations: Locations,
                    group_addresses: GroupAddresses { group_ranges: GroupRanges },
                }],
            }),
        };

        Self::serialize(&knx)
    }

    fn serialize(knx: &ProjectKnx) -> Result<String, GeneratorError> {
        let mut buffer = String::new();
        buffer.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

        let mut serializer = quick_xml::se::Serializer::new(&mut buffer);
        serializer.indent(' ', 2);

        serde::Serialize::serialize(knx, serializer).map_err(|e| GeneratorError::Serialization(e.to_string()))?;

        Ok(buffer)
    }
}
