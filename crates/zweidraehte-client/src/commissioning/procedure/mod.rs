//! Typed commissioning procedure IR.
//!
//! Master Data load controls are the source language. This IR is the checked,
//! inspectable result after product fragments, automatic scopes, and tool-side
//! state have been resolved. The executor accepts only this representation;
//! raw XML controls can never mutate a device directly.

use std::collections::BTreeSet;

use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::messages::apdu::load_control::LoadState;

use crate::commissioning::catalog::profile::{ObjectSelector, ProcedureId, ResourceId};
use crate::commissioning::compiler::secrets::SecretPayloadReference;
use crate::commissioning::image::{ImageLocation, ImageSpace};

mod applicability;
mod operations;
mod record_segments;
pub(in crate::commissioning) use applicability::{AppliesToScope, parse_applies_to_token};

use crate::commissioning::error::CompileError;
pub use operations::{
    CachePolicy, Comparison, ComparisonPadding, DescribedPropertyAction, DescribedPropertyOperation, OperationData,
    OperationExtent, OperationTarget, ProcedureOperation, RangeBound, ServiceRead, WriteIntent, WritePolicy,
};

/// One immutable step in a normalized procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureStep {
    pub path: ControlPath,
    /// Encoded load-control record code used by filtered error mappings.
    /// Typed extension operations have no XML record code and use `None`;
    /// wildcard mappings still apply, while a nonzero filter cannot match.
    pub source_control_code: Option<u8>,
    /// Compiler-owned programming sections physically affected by this step.
    ///
    /// Master Data controls which only coordinate a load machine have no
    /// section here. Image-backed writes are annotated from the final
    /// manifest after procedure lowering, while extensions retain the section
    /// they were required to declare at their contribution boundary.
    pub sections: BTreeSet<ProgrammingSection>,
    pub operation: ProcedureOperation,
    pub on_error: Vec<ErrorHandler>,
    pub secure_only: bool,
}

/// Procedure accepted by the executor after complete preflight validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProcedure {
    pub id: ProcedureSourceId,
    pub initial_state: ToolState,
    pub steps: Vec<ProcedureStep>,
    pub stamp_output: DownloadStampOutput,
}

impl NormalizedProcedure {
    pub fn validate(&self) -> Result<(), CompileError> {
        if let DownloadStampOutput::ImageProperties(bindings) = &self.stamp_output {
            let mut resources = BTreeSet::new();
            let mut locations = BTreeSet::new();
            for binding in bindings {
                if !matches!(binding.image_location.space, ImageSpace::Property {
                    object: ObjectSelector::Index { .. },
                    property_id: 27
                }) || binding.image_location.offset != 0
                    || binding.read.extent != OperationExtent::property(8, 1)
                    || !resources.insert(&binding.id)
                    || !locations.insert(&binding.image_location)
                {
                    return Err(CompileError::invalid("procedure has invalid or ambiguous final-image stamp bindings"));
                }
            }
        }

        let mut session_depth = 0u16;
        let mut opened_session = false;

        for step in &self.steps {
            match &step.operation {
                ProcedureOperation::Connect => {
                    opened_session = true;
                    session_depth = session_depth.checked_add(1).ok_or(CompileError::at(
                        &step.path,
                        "procedure has too many nested device-management sessions",
                    ))?;
                }
                ProcedureOperation::Disconnect => {
                    // Authored procedures may close again after a restart.
                    // Keep the control and its handlers: a suppressed restart
                    // failure can leave a real session for it to close.
                    session_depth = session_depth.saturating_sub(1);
                }
                ProcedureOperation::LoadImage { target, extent, alignment, image_location } => {
                    let target_matches_image = match target {
                        OperationTarget::Memory { service, address: operands::MemoryAddress::Fixed(address) } => {
                            *alignment == 1
                                && extent.property_elements.is_none()
                                && *address == image_location.offset
                                && matches!(
                                    (&image_location.space, service),
                                    (
                                        ImageSpace::StandardMemory,
                                        operands::MemoryService::Classic | operands::MemoryService::Extended
                                    ) | (ImageSpace::UserMemory, operands::MemoryService::User)
                                )
                        }
                        OperationTarget::Property { address, start_element } => {
                            *start_element > 0
                                && matches!(&image_location.space, ImageSpace::Property {object, property_id}
                                    if crate::commissioning::procedure::operands::pure_property_address(object,*property_id).as_ref()==Ok(address))
                                && u32::from(*start_element - 1).checked_mul(*alignment) == Some(image_location.offset)
                                && extent
                                    .property_elements
                                    .is_some_and(|count| u32::from(*start_element) + u32::from(count) <= 65536)
                        }
                        _ => false,
                    };
                    if *alignment == 0
                        || !target_matches_image
                        || extent.byte_length == 0
                        || image_location.offset.checked_add(extent.byte_length).is_none()
                        || extent.byte_length % alignment != 0
                        || image_location.offset % alignment != 0
                        || extent.property_elements.is_some_and(|count| {
                            count == 0 || u32::from(count).checked_mul(*alignment) != Some(extent.byte_length)
                        })
                    {
                        return Err(CompileError::at(
                            &step.path,
                            "procedure image read has invalid alignment or extent",
                        ));
                    }
                }
                // Downloads reopen a session that an earlier restart or
                // reset closed (the reference's `AutoConnect` sessions), so a
                // terminating service needs only some earlier session. It
                // closes the reopened one again.
                ProcedureOperation::Restart { .. } => {
                    if !opened_session {
                        return Err(CompileError::at(&step.path, "procedure restarts without an open connection"));
                    }
                    session_depth = session_depth.saturating_sub(1);
                }
                ProcedureOperation::MasterReset { .. } => {
                    if !opened_session {
                        return Err(CompileError::at(
                            &step.path,
                            "procedure performs a master reset without an open connection",
                        ));
                    }
                    session_depth = session_depth.saturating_sub(1);
                }
                _ => {}
            }
        }

        if session_depth != 0 {
            return Err(CompileError::invalid(format!(
                "procedure leaves {session_depth} device-management sessions open"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;

/// Exact origin of a normalized procedure.
///
/// System 7 and other product-procedure profiles have no Master Data load
/// procedure to identify. Keeping product and Master Data origins distinct
/// avoids fabricated source indexes in diagnostics and persisted plans.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcedureSourceId {
    MasterData(ProcedureId),
    Product {
        product_id: String,
        source_index: usize,
        merge_id: Option<u8>,
    },
    /// A standard commissioning phase synthesized from resolved capabilities
    /// rather than copied from one XML procedure. The name is stable and
    /// descriptive so diagnostics and persisted previews never need a fake
    /// Master Data source index.
    Generated {
        name: String,
    },
}

/// Stable path back to the XML control that produced a plan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPath {
    pub mask_id: String,
    pub variant_index: usize,
    pub procedure: ProcedureSourceId,
    /// Present for built-in controls which have no XML control of their own.
    /// Ordinary XML controls remain identified
    /// by `procedure` plus their source indices.
    pub contribution: Option<&'static str>,
    pub control_indices: Vec<usize>,
}

impl ControlPath {
    pub fn child(&self, index: usize) -> Self {
        let mut path = self.clone();
        path.control_indices.push(index);
        path
    }
}

/// Cause selector on a per-control error handler.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoadControlCause {
    ResourceNotFound,
    CompareMismatch,
    DeviceReturnCode(u8),
    LegacyCode(u32),
    Symbolic(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAction {
    Ignore,
    MapTo(u32),
    FailWithMessage { message_reference: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorHandler {
    pub cause: LoadControlCause,
    pub action: ErrorAction,
}

/// Target of one load-state-machine command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoadMachineTarget {
    Index(u16),
    Object(ObjectSelector),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryByteOrder {
    BigEndian,
    LittleEndian,
}

/// Stateful tool variables defined by the load-control language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlVariable {
    EnableSegmentWrite,
    EnableVerifyOnWriteDirect,
    EnableOptimisticWrite,
    EnableMemoryAutoVerify,
}

/// Ordered compiler/executor state. Defaults match the load-control execution
/// model; controls modify this state for subsequent operations only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolState {
    pub segment_write: bool,
    pub verify_direct_writes: bool,
    pub optimistic_writes: bool,
    pub memory_auto_verify: Option<bool>,
    pub memory_byte_order: MemoryByteOrder,
}

impl Default for ToolState {
    fn default() -> Self {
        Self {
            segment_write: true,
            verify_direct_writes: false,
            optimistic_writes: true,
            memory_auto_verify: None,
            memory_byte_order: MemoryByteOrder::BigEndian,
        }
    }
}

impl ToolState {
    /// Authored controls have Boolean values. Byte order and automatic verify
    /// mode come from product initialization, not synthetic setter variants.
    pub fn set(&mut self, variable: ControlVariable, value: bool) {
        match variable {
            ControlVariable::EnableSegmentWrite => self.segment_write = value,
            ControlVariable::EnableVerifyOnWriteDirect => self.verify_direct_writes = value,
            ControlVariable::EnableOptimisticWrite => self.optimistic_writes = value,
            ControlVariable::EnableMemoryAutoVerify => self.memory_auto_verify = Some(value),
        }
    }
}

/// Encoded once against the selected load endpoint. A failed poll belongs to
/// the same authored control as the record write that precedes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadRecord {
    pub write: ServiceRead,
    pub bytes: Vec<u8>,
    pub poll: Option<(ServiceRead, LoadState)>,
    pub effect: LoadEffect,
}

impl LoadRecord {
    pub(crate) fn minimum_apdu(&self) -> Result<u16, crate::commissioning::error::CompileError> {
        // A type-addressed record may fall back to the located index.
        let prepared = self.write.target.fitted_minimum_apdu(self.write.extent)?;

        let atomic = match &self.write.target {
            OperationTarget::Memory { service, .. } => u16::try_from(self.bytes.len())
                .ok()
                .and_then(|length| length.checked_add(service.overhead()))
                .ok_or_else(|| {
                    crate::commissioning::procedure::operands::required_apdu_error("load record exceeds APDU length")
                })?,
            _ => prepared,
        };
        Ok(prepared.max(atomic))
    }
}

/// Known image effects invalidate observations before a potentially uncertain command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadEffect {
    None,
    Invalidate { location: ImageLocation, length: u32 },
    InvalidateAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTransfer {
    pub target: OperationTarget,
    pub data: OperationData,
    pub extent: OperationExtent,
    pub policy: WriteIntent,
}

/// One prepared stamp used for baseline reads and completed-image publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampDescriptor {
    pub id: ResourceId,
    pub read: ServiceRead,
    pub image_location: ImageLocation,
    pub optional: bool,
}

/// Evidence published only after the procedure and its cleanup succeed.
///
/// Downloads select complete properties from the final working image on every
/// management model. A read of another object's stamp still updates that
/// image, but does not thereby make the property eligible for the download
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadStampOutput {
    None,
    /// Retain the explicit `capture_as` snapshots of legacy read controls.
    /// Only procedures without a download-stamp selection keep this default.
    // TODO: no compiled control stages a read any more, because image
    // property reads never snapshot stamps. Remove this variant together with
    // `ReadIntoImage::capture_as` and its runtime staging.
    StagedReads(Vec<StampDescriptor>),
    ImageProperties(Vec<StampDescriptor>),
}

impl Default for DownloadStampOutput {
    fn default() -> Self {
        Self::StagedReads(Vec::new())
    }
}

impl DownloadStampOutput {
    /// Baseline resources and their concrete services in source order.
    pub fn descriptors(&self) -> &[StampDescriptor] {
        match self {
            Self::None => &[],
            Self::StagedReads(descriptors) | Self::ImageProperties(descriptors) => descriptors,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartKind {
    Basic,
    Confirmed,
}

/// Function-property operations used by newer coupler and medium profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionPropertyOperation {
    Invoke { address: crate::commissioning::procedure::operands::PropertyAddress, data: Vec<u8>, effect: LoadEffect },
    ReadResult { address: crate::commissioning::procedure::operands::PropertyAddress },
}

pub(crate) mod operands;
