//! Load procedure types for KNX device programming.
//!
//! One vocabulary, two documents:
//!
//! - **Product MTXML** (`ApplicationProgram/Static/LoadProcedures`)
//!   carries the product-specific procedures — System 7
//!   `ProductProcedure`s with absolute segments, System B
//!   `MergedProcedure` fragments spliced into the mask template at
//!   `LdCtrlMerge` points.
//! - **Master data** (`knx_master.xml`,
//!   `MaskVersion/HawkConfigurationData/Procedures`) carries the
//!   per-mask templates ETS merges those fragments into, using the
//!   same `LdCtrl*` elements plus a tool-side-only superset
//!   (`LdCtrlWriteMem`, `LdCtrlMerge`, `LdCtrlMapError`, …).
//!
//! The structs therefore cover the union: attributes that only one
//! document uses are `Option`s that stay off the wire when `None`
//! (`skip_serializing_if`), so MTXML generation output is unchanged.
//! Elements that address their target either by load-state-machine
//! index (`LsmIdx`) or by interface-object type (`ObjType` +
//! `Occurrence`) carry both forms as `Option`s; exactly one is
//! present in practice.
//!
//! The element vocabulary is closed against the project-23 master
//! data (identical procedure content to project-20) — an unknown
//! element is a parse error, not silently skipped, so a future
//! master-data revision that grows the language fails loudly.

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
    // Master-data-only vocabulary (mask templates in knx_master.xml)
    LdCtrlWriteMem(LdCtrlWriteMem),
    LdCtrlCompareMem(LdCtrlCompareMem),
    LdCtrlLoadImageMem(LdCtrlLoadImageMem),
    LdCtrlMerge(LdCtrlMerge),
    LdCtrlMapError(LdCtrlMapError),
    LdCtrlDelay(LdCtrlDelay),
    LdCtrlSetControlVariable(LdCtrlSetControlVariable),
    LdCtrlMasterReset(LdCtrlMasterReset),
    LdCtrlClearLCFilterTable(LdCtrlClearLCFilterTable),
    LdCtrlTaskPtr(LdCtrlTaskPtr),
    LdCtrlTaskCtrl1(LdCtrlTaskCtrl1),
    LdCtrlTaskCtrl2(LdCtrlTaskCtrl2),
}

/// Relative segment load control (System B).
///
/// MTXML fragments carry `AppliesTo` + `LsmIdx`; the master-data
/// templates omit `AppliesTo` and may address the machine by
/// `ObjType` (+ `Occurrence`) instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlRelSegment {
    #[serde(rename = "@AppliesTo", skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<String>,
    #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
    pub lsm_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Mode")]
    pub mode: u8,
    #[serde(rename = "@Fill")]
    pub fill: u8,
}

/// Write relative memory load control (System B)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlWriteRelMem {
    #[serde(rename = "@AppliesTo", skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<String>,
    #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
    pub obj_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
    #[serde(rename = "@Offset")]
    pub offset: u32,
    /// In master-data templates a huge value (1 MiB) means "the whole
    /// remaining blob" — the tool clamps to the actual data length.
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Verify")]
    pub verify: bool,
}

/// Load image property control
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlLoadImageProp {
    #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
    pub obj_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlCompareProp {
    #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
    pub obj_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlUnload {
    #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
    pub lsm_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
}

/// Load control (System 7) - loads a load state machine
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlLoad {
    #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
    pub lsm_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
}

/// Absolute segment load control (System 7) - defines memory segment
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlTaskSegment {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Address")]
    pub address: u16,
}

/// Load completed control (System 7) - marks load state machine as loaded
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlLoadCompleted {
    #[serde(rename = "@LsmIdx", skip_serializing_if = "Option::is_none")]
    pub lsm_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u8>,
}

/// Restart control (System 7) - restarts the device
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlRestart {}

/// Write property control - writes a value to an interface object property
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlWriteProp {
    #[serde(rename = "@ObjIdx", skip_serializing_if = "Option::is_none")]
    pub obj_idx: Option<u8>,
    #[serde(rename = "@ObjType", skip_serializing_if = "Option::is_none")]
    pub obj_type: Option<u16>,
    #[serde(rename = "@Occurrence", skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u16>,
    #[serde(rename = "@PropId")]
    pub prop_id: u16,
    #[serde(rename = "@StartElement", skip_serializing_if = "Option::is_none")]
    pub start_element: Option<u16>,
    #[serde(rename = "@Count", skip_serializing_if = "Option::is_none")]
    pub count: Option<u16>,
    #[serde(rename = "@Verify", skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// Inline data to write (hex encoded)
    #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<String>,
}

// ============================================================================
// Master-data-only controls
// ============================================================================
//
// The elements below only appear in the knx_master.xml mask templates
// (BCU1's raw-memory downloads, line-coupler filter handling, BCU2
// task plumbing, and the merge/error scaffolding ETS resolves at
// procedure-assembly time). Products never emit them in MTXML, but
// parsing the templates needs the full vocabulary.

/// Write absolute memory. Without `InlineData` the data comes from
/// the assembled device image at `Address`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlWriteMem {
    /// Non-standard address space selector (`LcFilter`, `LcSlave`)
    /// used by the line-coupler masks; plain device memory when
    /// absent.
    #[serde(rename = "@AddressSpace", skip_serializing_if = "Option::is_none")]
    pub address_space: Option<String>,
    #[serde(rename = "@Address")]
    pub address: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@Verify")]
    pub verify: bool,
    /// Literal bytes (hex) instead of image content.
    #[serde(rename = "@InlineData", skip_serializing_if = "Option::is_none")]
    pub inline_data: Option<String>,
}

/// Compare absolute memory against literal bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlCompareMem {
    #[serde(rename = "@Address")]
    pub address: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
    #[serde(rename = "@InlineData")]
    pub inline_data: String,
}

/// Read device memory into the tool's image before modifying it
/// (BCU1 masks preserve bytes adjacent to what they rewrite).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlLoadImageMem {
    #[serde(rename = "@Address")]
    pub address: u32,
    #[serde(rename = "@Size")]
    pub size: u32,
}

/// Splice point: ETS replaces this with the product's MTXML
/// `LoadProcedure` fragment carrying the same `MergeId`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlMerge {
    #[serde(rename = "@MergeId")]
    pub merge_id: u8,
}

/// Remap a tool-side error code for the following instruction(s) —
/// e.g. tolerate "LSM not present" while unloading an optional
/// machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlMapError {
    #[serde(rename = "@OriginalError")]
    pub original_error: u32,
    #[serde(rename = "@MappedError")]
    pub mapped_error: u32,
}

/// Fixed wait, e.g. after a restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlDelay {
    #[serde(rename = "@MilliSeconds")]
    pub milli_seconds: u32,
}

/// Set a tool-side control variable (`EnableVerifyOnWriteDirect`,
/// `EnableSegmentWrite`) steering how subsequent writes execute.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlSetControlVariable {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Value")]
    pub value: String,
}

/// Master reset (03/05/01 §4.32) with erase code and channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlMasterReset {
    #[serde(rename = "@EraseCode")]
    pub erase_code: u8,
    #[serde(rename = "@ChannelNumber")]
    pub channel_number: u8,
}

/// Clear a line coupler's filter table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlClearLCFilterTable {
    #[serde(rename = "@UseFunctionProp", skip_serializing_if = "Option::is_none")]
    pub use_function_prop: Option<bool>,
}

/// BCU2 task pointers (init/save/serial callbacks) for an
/// application load.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlTaskPtr {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@InitPtr")]
    pub init_ptr: u16,
    #[serde(rename = "@SavePtr")]
    pub save_ptr: u16,
    #[serde(rename = "@SerialPtr")]
    pub serial_ptr: u16,
}

/// BCU2 task control block, variant 1 (address + count).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlTaskCtrl1 {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Address")]
    pub address: u16,
    #[serde(rename = "@Count")]
    pub count: u16,
}

/// BCU2 task control block, variant 2 (callback + segment
/// descriptors).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdCtrlTaskCtrl2 {
    #[serde(rename = "@LsmIdx")]
    pub lsm_idx: u8,
    #[serde(rename = "@Callback")]
    pub callback: u16,
    #[serde(rename = "@Address")]
    pub address: u16,
    #[serde(rename = "@Seg0")]
    pub seg0: u16,
    #[serde(rename = "@Seg1")]
    pub seg1: u16,
}
