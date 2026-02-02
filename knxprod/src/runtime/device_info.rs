//! Device Information for Programming
//!
//! This module provides a `DeviceInfo` struct that captures all the information
//! needed to program a KNX device. This includes device identification, memory
//! layout, load state machines, and table configurations.
//!
//! # Overview
//!
//! When loading an ApplicationProgram MTXML file, the `DeviceInfo` struct
//! extracts and organizes the programming-relevant information:
//!
//! - **Device Identification**: Manufacturer ID, application ID/version, mask version
//! - **Memory Layout**: Segment addresses, sizes, and load state machines
//! - **Table Configuration**: Address table, association table, and object table info
//! - **Load Procedures**: The sequence of load controls needed to program the device
//!
//! # Example
//!
//! ```rust,ignore
//! use knxprod::runtime::device_info::DeviceInfo;
//! use knxprod::MasterData;
//!
//! let program = parser::parse_file("device.mtxml")?;
//! let master = MasterData::from_file("knx_master.xml")?;
//!
//! let info = DeviceInfo::from_program(&program, Some(&master));
//! println!("Device: {} v{}", info.application_number, info.application_version);
//! println!("Mask: {} ({})", info.mask_version, info.mask_family);
//! ```

use crate::runtime::master_data::{MaskVersion, MasterData, ResourceName, TableFlavour};
use crate::schema::{ApplicationProgram, LoadControl, MaskFamily};

/// Complete device information needed for programming.
///
/// This struct captures all the information from an ApplicationProgram
/// and optional MasterData that would be needed to program a physical device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    // ========================================================================
    // Device Identification
    // ========================================================================
    /// Application program name
    pub name: String,

    /// Manufacturer ID (extracted from program ID, e.g., "0083" from "M-0083_...")
    pub manufacturer_id: String,

    /// Application number (unique identifier within manufacturer)
    pub application_number: u16,

    /// Application version
    pub application_version: u8,

    /// Mask version string (e.g., "MV-07B0")
    pub mask_version: String,

    /// Mask family (System7, SystemB, etc.)
    pub mask_family: MaskFamily,

    /// Human-readable mask name (e.g., "System B") if master data available
    pub mask_name: Option<String>,

    /// Management model (e.g., "SystemB", "BimM112")
    pub management_model: Option<String>,

    // ========================================================================
    // Memory Layout
    // ========================================================================
    /// Memory segments (both absolute and relative)
    pub segments: Vec<SegmentInfo>,

    /// Total parameter data size in bytes
    pub total_param_size: u32,

    // ========================================================================
    // Communication Objects
    // ========================================================================
    /// Number of communication objects defined
    pub com_object_count: u16,

    /// First application object index (from mask version features)
    pub first_app_object_idx: u8,

    // ========================================================================
    // Table Configuration
    // ========================================================================
    /// Address table configuration
    pub address_table: Option<TableInfo>,

    /// Association table configuration
    pub association_table: Option<TableInfo>,

    /// Communication object table configuration
    pub com_object_table: Option<TableInfo>,

    // ========================================================================
    // Load Procedure
    // ========================================================================
    /// Load procedure style (e.g., "MergedProcedure", "ProductProcedure")
    pub load_procedure_style: String,

    /// Load state machines (for System B)
    pub load_state_machines: Vec<LoadStateMachineInfo>,

    /// Whether the device uses dynamic table management
    pub dynamic_table_management: bool,
}

/// Information about a memory segment.
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// Segment ID from XML
    pub id: String,

    /// Whether this is an absolute or relative segment
    pub segment_type: SegmentKind,

    /// Start address (absolute) or offset (relative)
    pub address: u32,

    /// Size in bytes
    pub size: u32,

    /// Memory type (e.g., "RAM", "EEPROM")
    pub memory_type: Option<String>,

    /// Load state machine number (for relative segments)
    pub load_state_machine: Option<u8>,

    /// Whether this segment has data (vs. RAM allocation only)
    pub has_data: bool,
}

/// Type of memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// Absolute segment (System 7.x)
    Absolute,
    /// Relative segment (System B)
    Relative,
}

/// Information about a KNX table (address, association, object).
#[derive(Debug, Clone)]
pub struct TableInfo {
    /// Table flavour (entry format)
    pub flavour: TableFlavour,

    /// Whether the table uses relative memory addressing
    pub is_relative: bool,

    /// Interface object index (for property-based access)
    pub interface_object_idx: Option<u8>,

    /// Property ID (for property-based access)
    pub property_id: Option<u8>,

    /// Fixed address (for standard memory access)
    pub fixed_address: Option<u32>,

    /// Maximum entries (if known)
    pub max_entries: Option<u16>,
}

/// Information about a load state machine (System B).
#[derive(Debug, Clone)]
pub struct LoadStateMachineInfo {
    /// Load state machine index (1-4 typically)
    pub lsm_idx: u8,

    /// Merge ID (for MergedProcedure)
    pub merge_id: Option<u8>,

    /// Segments loaded by this state machine
    pub segment_ids: Vec<String>,

    /// Total size allocated by this state machine
    pub total_size: u32,
}

impl DeviceInfo {
    /// Extract device info from an ApplicationProgram and optional MasterData.
    ///
    /// If master data is provided, additional information like mask name,
    /// management model, and table configurations will be populated.
    pub fn from_program(program: &ApplicationProgram, master_data: Option<&MasterData>) -> Self {
        let mask_version_id = &program.mask_version;
        let mask_version_code = Self::parse_mask_version_code(mask_version_id);
        let mask_family = MaskFamily::from_mask_version(mask_version_code);

        // Get mask version from master data if available
        let mv = master_data.and_then(|md| md.get_mask_version(mask_version_id));

        // Extract manufacturer ID from program ID (format: "M-XXXX_...")
        let manufacturer_id = program.id.strip_prefix("M-").and_then(|s| s.split('_').next()).unwrap_or("").to_string();

        // Collect segments
        let segments = Self::collect_segments(program);

        // Calculate total parameter size
        let total_param_size = segments.iter().map(|s| s.size).sum();

        // Count communication objects
        let com_object_count =
            program.static_section.com_object_table.as_ref().map(|cot| cot.objects.len() as u16).unwrap_or(0);

        // Get first app object index
        let first_app_object_idx = mv.map(|m| m.first_app_object_idx()).unwrap_or(5);

        // Extract table info from master data
        let address_table = mv.and_then(|m| Self::extract_table_info(m, ResourceName::GroupAddressTable));
        let association_table = mv.and_then(|m| Self::extract_table_info(m, ResourceName::GroupAssociationTable));
        let com_object_table = mv.and_then(|m| Self::extract_table_info(m, ResourceName::GroupObjectTable));

        // Extract load state machine info
        let load_state_machines = Self::extract_load_state_machines(program);

        DeviceInfo {
            name: program.name.clone(),
            manufacturer_id,
            application_number: program.application_number,
            application_version: program.application_version,
            mask_version: mask_version_id.clone(),
            mask_family,
            mask_name: mv.map(|m| m.name.clone()),
            management_model: mv.map(|m| m.management_model.clone()),
            segments,
            total_param_size,
            com_object_count,
            first_app_object_idx,
            address_table,
            association_table,
            com_object_table,
            load_procedure_style: program.load_procedure_style.clone(),
            load_state_machines,
            dynamic_table_management: program.dynamic_table_management,
        }
    }

    /// Parse mask version code from ID string (e.g., "MV-07B0" -> 0x07B0)
    fn parse_mask_version_code(mask_version_id: &str) -> u16 {
        mask_version_id.strip_prefix("MV-").and_then(|s| u16::from_str_radix(s, 16).ok()).unwrap_or(0)
    }

    /// Collect all segments from the program's Code section.
    fn collect_segments(program: &ApplicationProgram) -> Vec<SegmentInfo> {
        let mut segments = Vec::new();

        if let Some(code) = &program.static_section.code {
            // Absolute segments (System 7.x)
            for seg in &code.absolute_segments {
                segments.push(SegmentInfo {
                    id: seg.id.clone(),
                    segment_type: SegmentKind::Absolute,
                    address: seg.address,
                    size: seg.size,
                    memory_type: seg.memory_type.clone(),
                    load_state_machine: None,
                    has_data: seg.data.is_some(),
                });
            }

            // Relative segments (System B)
            for seg in &code.relative_segments {
                segments.push(SegmentInfo {
                    id: seg.id.clone(),
                    segment_type: SegmentKind::Relative,
                    address: seg.offset,
                    size: seg.size,
                    memory_type: None,
                    load_state_machine: Some(seg.load_state_machine),
                    has_data: seg.data.is_some(),
                });
            }
        }

        segments
    }

    /// Extract table info from mask version resources.
    fn extract_table_info(mv: &MaskVersion, resource_name: ResourceName) -> Option<TableInfo> {
        let resource = mv.get_resource(resource_name)?;

        let flavour = resource
            .resource_type
            .as_ref()
            .and_then(|rt| rt.flavour.as_ref())
            .map(|f| TableFlavour::from_str(f))
            .unwrap_or_else(|| match resource_name {
                ResourceName::GroupAddressTable => TableFlavour::AddressTableSystemB,
                ResourceName::GroupAssociationTable => TableFlavour::AssociationTableSystemB,
                ResourceName::GroupObjectTable => TableFlavour::GroupObjectTable,
                _ => TableFlavour::AddressTableSystemB,
            });

        Some(TableInfo {
            flavour,
            is_relative: resource.is_relative_memory(),
            interface_object_idx: resource.interface_object_ref(),
            property_id: resource.property_id(),
            fixed_address: resource.start_address(),
            max_entries: None, // Would need to parse from resource type
        })
    }

    /// Extract load state machine information from load procedures.
    fn extract_load_state_machines(program: &ApplicationProgram) -> Vec<LoadStateMachineInfo> {
        let mut lsm_map: std::collections::HashMap<u8, LoadStateMachineInfo> = std::collections::HashMap::new();

        if let Some(procedures) = &program.static_section.load_procedures {
            for proc in &procedures.procedures {
                for control in &proc.controls {
                    if let LoadControl::LdCtrlRelSegment(rel_seg) = control {
                        let entry = lsm_map.entry(rel_seg.lsm_idx).or_insert_with(|| LoadStateMachineInfo {
                            lsm_idx: rel_seg.lsm_idx,
                            merge_id: proc.merge_id,
                            segment_ids: Vec::new(),
                            total_size: 0,
                        });

                        // Extract segment ID from applies_to (format: "M-XXXX_..._RS-1")
                        entry.segment_ids.push(rel_seg.applies_to.clone());
                        entry.total_size += rel_seg.size;
                    }
                }
            }
        }

        let mut result: Vec<_> = lsm_map.into_values().collect();
        result.sort_by_key(|lsm| lsm.lsm_idx);
        result
    }

    /// Check if this device uses System B load procedures.
    pub fn is_system_b(&self) -> bool {
        matches!(self.mask_family, MaskFamily::SystemB)
    }

    /// Check if this device uses relative memory segments.
    pub fn uses_relative_segments(&self) -> bool {
        self.segments.iter().any(|s| s.segment_type == SegmentKind::Relative)
    }

    /// Get segments for a specific load state machine.
    pub fn segments_for_lsm(&self, lsm_idx: u8) -> Vec<&SegmentInfo> {
        self.segments.iter().filter(|s| s.load_state_machine == Some(lsm_idx)).collect()
    }
}

impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Device: {}", self.name)?;
        writeln!(f, "  Application: {} v{}", self.application_number, self.application_version)?;
        writeln!(f, "  Manufacturer: {}", self.manufacturer_id)?;

        if let Some(name) = &self.mask_name {
            writeln!(f, "  Mask: {} ({})", self.mask_version, name)?;
        } else {
            writeln!(f, "  Mask: {}", self.mask_version)?;
        }

        if let Some(model) = &self.management_model {
            writeln!(f, "  Management Model: {}", model)?;
        }

        writeln!(f, "  Load Style: {}", self.load_procedure_style)?;
        writeln!(f, "  Segments: {}", self.segments.len())?;
        writeln!(f, "  Total Size: {} bytes", self.total_param_size)?;
        writeln!(f, "  Comm Objects: {}", self.com_object_count)?;
        writeln!(f, "  First App Object Idx: {}", self.first_app_object_idx)?;

        if !self.load_state_machines.is_empty() {
            writeln!(f, "  Load State Machines:")?;
            for lsm in &self.load_state_machines {
                writeln!(f, "    LSM {}: {} segments, {} bytes", lsm.lsm_idx, lsm.segment_ids.len(), lsm.total_size)?;
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for SegmentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentKind::Absolute => write!(f, "Absolute"),
            SegmentKind::Relative => write!(f, "Relative"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mask_version_code() {
        assert_eq!(DeviceInfo::parse_mask_version_code("MV-07B0"), 0x07B0);
        assert_eq!(DeviceInfo::parse_mask_version_code("MV-0705"), 0x0705);
        assert_eq!(DeviceInfo::parse_mask_version_code("MV-57B0"), 0x57B0);
        assert_eq!(DeviceInfo::parse_mask_version_code("invalid"), 0);
    }

    #[test]
    fn test_mask_family_detection() {
        assert!(matches!(MaskFamily::from_mask_version(0x07B0), MaskFamily::SystemB));
        assert!(matches!(MaskFamily::from_mask_version(0x0705), MaskFamily::System7));
        assert!(matches!(MaskFamily::from_mask_version(0x0912), MaskFamily::Bim));
    }

    #[test]
    fn test_device_info_from_mdt_device() {
        // Load a real MDT Push Button Lite device
        let path = "manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml";
        let path = std::path::Path::new(path);
        if path.exists() {
            let knx = crate::runtime::parser::parse_application_program_from_file(path).expect("Failed to parse MTXML");
            let program = knx.manufacturer_data.manufacturer.application_programs.programs.first().unwrap();

            let info = DeviceInfo::from_program(&program, None);

            // Verify basic device identification
            assert_eq!(info.manufacturer_id, "0083");
            assert_eq!(info.application_number, 155);
            assert_eq!(info.mask_version, "MV-07B0");
            assert!(matches!(info.mask_family, MaskFamily::SystemB));

            // Verify segments are extracted
            assert!(!info.segments.is_empty());
            assert!(info.segments.iter().all(|s| s.segment_type == SegmentKind::Relative));

            // Verify load state machines for System B
            assert!(!info.load_state_machines.is_empty());

            // Verify comm objects are counted
            assert!(info.com_object_count > 0);

            // Print for visual verification
            println!("{}", info);
        }
    }

    #[test]
    fn test_device_info_display() {
        // Load a real MDT Push Button Lite device
        let path = "manuf_tool_data/MDT_KP_BE_01_Push_Button_Lite_55_63_V14/M-0083/M-0083_A-009B-14-E59D.xml";
        let path = std::path::Path::new(path);
        if path.exists() {
            let knx = crate::runtime::parser::parse_application_program_from_file(path).expect("Failed to parse MTXML");
            let program = knx.manufacturer_data.manufacturer.application_programs.programs.first().unwrap();

            // Also test with master data if available
            let master_path = "manuf_tool_data/knx_master.xml";
            let master =
                if std::path::Path::new(master_path).exists() { MasterData::from_file(master_path).ok() } else { None };

            let info = DeviceInfo::from_program(&program, master.as_ref());

            // Print full info with master data
            println!("=== DeviceInfo with MasterData ===");
            println!("{}", info);

            // Verify management model is populated when master data is present
            if master.is_some() {
                assert!(info.mask_name.is_some());
                assert!(info.management_model.is_some());
            }
        }
    }
}
