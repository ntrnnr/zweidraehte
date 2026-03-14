//! Load procedure types for KNX device programming.

use serde::{Deserialize, Serialize};

// ============================================================================
// Load Procedures
// ============================================================================

/// Container for load procedures
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadProcedures {
    #[serde(rename = "LoadProcedure", default)]
    pub procedures: Vec<LoadProcedure>,
}

/// A load procedure containing load control elements.
/// For MergedProcedure style, merge_id is required.
/// For ProductProcedure style, merge_id is None (not serialized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadProcedure {
    #[serde(rename = "@MergeId", skip_serializing_if = "Option::is_none")]
    pub merge_id: Option<u8>,

    #[serde(rename = "$value", default)]
    pub controls: Vec<LoadControl>,
}

/// Load control elements (choice)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum LoadControl {
    // System B (MergedProcedure) controls
    LdCtrlRelSegment(LdCtrlRelSegment),
    LdCtrlWriteRelMem(LdCtrlWriteRelMem),
    LdCtrlLoadImageProp(LdCtrlLoadImageProp),
    // System 7 (ProductProcedure) controls
    LdCtrlConnect(LdCtrlConnect),
    LdCtrlDisconnect(LdCtrlDisconnect),
    LdCtrlCompareProp(LdCtrlCompareProp),
    LdCtrlUnload(LdCtrlUnload),
    LdCtrlLoad(LdCtrlLoad),
    LdCtrlAbsSegment(LdCtrlAbsSegment),
    LdCtrlTaskSegment(LdCtrlTaskSegment),
    LdCtrlLoadCompleted(LdCtrlLoadCompleted),
    LdCtrlRestart(LdCtrlRestart),
    LdCtrlWriteProp(LdCtrlWriteProp),
}

/// Relative segment load control (System B)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlRelSegment {
    #[serde(rename = "@AppliesTo")]
    pub applies_to: String,
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Mode")]
    pub mode: u8,
    #[serde(rename = "@Fill")]
    pub fill: u8,
}

/// Write relative memory load control (System B)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlWriteRelMem {
    #[serde(rename = "@AppliesTo")]
    pub applies_to: String,
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Verify")]
    pub verify: bool,
}

/// Load image property control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlLoadImageProp {
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@PropId")]
    pub prop_id: u8,
}

/// Connect control (System 7) - establishes connection to device
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlConnect {}

/// Disconnect control (System 7) - closes connection to device
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlDisconnect {}

/// Compare property control (System 7) - verifies device property matches expected value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlCompareProp {
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@PropId")]
    pub prop_id: u8,
    #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<String>,
    /// Range comparison format, e.g., "[4160,65535]u"
    #[serde(rename = "@Range", skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    /// Error handling for comparison failure
    #[serde(rename = "OnError", skip_serializing_if = "Option::is_none")]
    pub on_error: Option<OnError>,
}

/// Error handler for load control commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnError {
    #[serde(rename = "@Cause")]
    pub cause: String,
    #[serde(rename = "@MessageRef", skip_serializing_if = "Option::is_none")]
    pub message_ref: Option<String>,
}

/// Unload control (System 7) - unloads a load state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlUnload {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
}

/// Load control (System 7) - loads a load state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlLoad {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
}

/// Absolute segment load control (System 7) - defines memory segment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlAbsSegment {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@SegType")]
    pub seg_type: u8,
    #[serde(rename = "@Address")]
    pub address: u16,
    #[serde(rename = "@Size")]
    pub size: u16,
    #[serde(rename = "@Access")]
    pub access: u8,
    #[serde(rename = "@MemType")]
    pub mem_type: u8,
    #[serde(rename = "@SegFlags")]
    pub seg_flags: u8,
}

/// Task segment control (System 7) - sets task segment address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlTaskSegment {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Address")]
    pub address: u16,
}

/// Load completed control (System 7) - marks load state machine as loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlLoadCompleted {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
}

/// Restart control (System 7) - restarts the device
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlRestart {}

/// Write property control - writes a value to an interface object property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdCtrlWriteProp {
    #[serde(rename = "@ObjIdx")]
    pub obj_idx: u8,
    #[serde(rename = "@PropId")]
    pub prop_id: u8,
    #[serde(rename = "@Verify", skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// Inline data to write (hex encoded)
    #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<String>,
}
